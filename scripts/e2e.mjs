#!/usr/bin/env node
// End-to-end gate: speaks real MCP protocol over stdio to dist/index.js
// (initialize -> tools/list -> tools/call) and asserts behavior a real host
// would see. Runs in CI so wire-level regressions can't ship silently.
import { spawn } from "node:child_process";
import { statSync } from "node:fs";

const proc = spawn("node", ["dist/index.js"], { stdio: ["pipe", "pipe", "inherit"] });
let buf = "";
const pending = new Map();
proc.stdout.on("data", (d) => {
  buf += d.toString();
  let i;
  while ((i = buf.indexOf("\n")) !== -1) {
    const line = buf.slice(0, i);
    buf = buf.slice(i + 1);
    if (!line.trim()) continue;
    try {
      const m = JSON.parse(line);
      if (m.id !== undefined && pending.has(m.id)) {
        pending.get(m.id)(m);
        pending.delete(m.id);
      }
    } catch {}
  }
});

let failures = 0;
function check(name, cond, detail = "") {
  if (cond) {
    console.log(`ok - ${name}`);
  } else {
    failures++;
    console.error(`FAIL - ${name}${detail ? ` (${detail})` : ""}`);
  }
}

let nextId = 1;
function rpc(method, params) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timeout waiting for " + method)), 120_000);
    pending.set(id, (msg) => {
      clearTimeout(t);
      resolve(msg);
    });
    proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
  });
}

try {
  const init = await rpc("initialize", {
    protocolVersion: "2024-11-05",
    capabilities: {},
    clientInfo: { name: "e2e", version: "0" },
  });
  check("server identifies as shipcheck", init.result?.serverInfo?.name === "shipcheck");

  const tools = await rpc("tools/list", {});
  const names = tools.result.tools.map((t) => t.name).sort();
  check("exposes scan_repo and scan_diff", JSON.stringify(names) === '["scan_diff","scan_repo"]', JSON.stringify(names));

  // Full-repo scan of the vulnerable fixture: exact finding count per detector
  // is asserted by unit tests; here we assert wire shape and key content.
  const repoScan = await rpc("tools/call", {
    name: "scan_repo",
    arguments: { path: "./test-fixtures/vulnerable-app" },
  });
  check("scan_repo succeeds", !repoScan.result?.isError);
  const repoText = repoScan.result.content[0].text;
  const repoJson = JSON.parse(repoText);
  check("response has summary + findings", !!repoJson.summary && Array.isArray(repoJson.findings));
  check("committed .env flagged", repoJson.findings.some((f) => f.file === ".env"));
  check("prefixed env variant flagged", repoJson.findings.some((f) => f.file === "config/backend.env"));
  check("unauth debug route flagged", repoJson.findings.some((f) => f.description.includes("/debug/user-count")));
  check("output is compact JSON (no pretty-print)", !repoText.includes("\n  "), "found indentation");
  check(
    "summary counts match findings",
    repoJson.summary.total === repoJson.findings.length &&
      repoJson.summary.by_severity.critical +
        repoJson.summary.by_severity.high +
        repoJson.summary.by_severity.medium ===
        repoJson.summary.total,
  );
  check(
    "project_types inferred in summary",
    Array.isArray(repoJson.summary.project_types) && repoJson.summary.project_types.includes("Node.js"),
    JSON.stringify(repoJson.summary.project_types),
  );

  // Multi-stack endpoint detection through the wire (Go/Laravel/Spring/Flask).
  const stackScan = await rpc("tools/call", {
    name: "scan_repo",
    arguments: { path: "./test-fixtures/multi-stack" },
  });
  const stackJson = JSON.parse(stackScan.result.content[0].text);
  const goFinding = stackJson.findings.find((f) => f.description.startsWith("Go route"));
  const springFinding = stackJson.findings.find((f) => f.description.startsWith("Spring route"));
  const laravelFinding = stackJson.findings.find((f) => f.description.startsWith("Laravel route"));
  const flaskFinding = stackJson.findings.find((f) => f.description.startsWith("Flask route"));
  check("Go router finding via wire", !!goFinding);
  check("Spring finding via wire", !!springFinding);
  check("Laravel finding via wire", !!laravelFinding);
  check("Flask finding via wire", !!flaskFinding);
  check(
    "guarded neighbors not flagged (segment scoping)",
    !stackJson.findings.some(
      (f) => /admin\/stats|billing\/history|user\/settings/.test(f.description) || /billing\/invoices|admin-source/.test(f.description),
    ),
    JSON.stringify(stackJson.findings.map((f) => f.description)),
  );

  // Category filter narrows results.
  const secretsOnly = await rpc("tools/call", {
    name: "scan_repo",
    arguments: { path: "./test-fixtures/vulnerable-app", categories: ["exposed-secrets"] },
  });
  const secretsJson = JSON.parse(secretsOnly.result.content[0].text);
  check(
    "category filter runs only that category",
    secretsJson.findings.length > 0 && secretsJson.findings.every((f) => f.category === "exposed-secrets"),
  );

  // A typo'd path must be a loud error, never a silent zero-findings scan.
  const badPath = await rpc("tools/call", { name: "scan_repo", arguments: { path: "/tmp/definitely-not-here-xyz" } });
  check("nonexistent path errors loudly", badPath.result?.isError === true);

  // scan_diff against ShipCheck itself (this repo has real history).
  const diff = await rpc("tools/call", { name: "scan_diff", arguments: { path: "." } });
  check("scan_diff succeeds on a real repo", !diff.result?.isError);
  const diffJson = JSON.parse(diff.result.content[0].text);
  check(
    "diff scope fields always present",
    typeof diffJson.summary.scanned_files === "number" && !!diffJson.summary.diff_base,
  );
  check(
    "empty diff says nothing about repo as a whole",
    diffJson.summary.scanned_files !== 0 || /NOTHING about the repository/.test(diffJson.summary.note),
  );

  // scan_diff on a non-repo must fail with guidance toward scan_repo.
  const notRepo = await rpc("tools/call", { name: "scan_diff", arguments: { path: "/tmp" } });
  check(
    "scan_diff on non-repo points to scan_repo",
    notRepo.result?.isError === true && /scan_repo/.test(notRepo.result.content[0].text),
  );
} catch (err) {
  failures++;
  console.error("FAIL - unexpected exception:", err.message);
} finally {
  proc.kill();
}

process.exit(failures > 0 ? 1 : 0);
