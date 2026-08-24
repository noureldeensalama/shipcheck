#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fg from "fast-glob";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { createRequire } from "node:module";

// `ignore` is a CJS package whose type declarations don't interop cleanly
// with NodeNext + esModuleInterop as a default import; requiring it directly
// sidesteps the mismatch rather than fighting the type resolver.
const require = createRequire(import.meta.url);
const ignore: (opts?: unknown) => { add(s: string): unknown; ignores(p: string): boolean } = require("ignore");

import { secretsScanner } from "./detectors/secrets-scanner.js";
import { licenseCheck } from "./detectors/license-check.js";
import { unauthEndpoints } from "./detectors/unauth-endpoints.js";
import { piiConsentCheck } from "./detectors/pii-consent-check.js";
import { paymentHandling } from "./detectors/payment-handling.js";
import type { Category, Detector, Finding } from "./types.js";

const DETECTORS: Record<Category, Detector> = {
  "exposed-secrets": secretsScanner,
  "copyleft-license": licenseCheck,
  "unauthenticated-endpoint": unauthEndpoints,
  "pii-no-consent": piiConsentCheck,
  "client-side-payment": paymentHandling,
};

// Vendored dependency trees are third-party code, not project source.
// Scanning them produces overwhelming false-positive noise (library test
// fixtures with example keys, docstring examples) — every detector operates
// on project-owned files only. license-check reads installed packages'
// package.json / pubspec data directly from disk and does not need them in
// the file list.
const DEFAULT_EXCLUDES = [
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/coverage/**",
  "**/node_modules/**",
  "**/.venv/**",
  "**/venv/**",
  "**/.tox/**",
];

async function listFiles(rootDir: string): Promise<string[]> {
  let gitignoreContent = "";
  try {
    gitignoreContent = await readFile(join(rootDir, ".gitignore"), "utf-8");
  } catch {
    // no .gitignore, fine
  }
  const ig = ignore().add(gitignoreContent) as { ignores(p: string): boolean };

  const all = await fg(["**/*"], {
    cwd: rootDir,
    dot: true,
    onlyFiles: true,
    ignore: DEFAULT_EXCLUDES,
  });

  return all.filter((f) => !ig.ignores(f));
}

const server = new McpServer({
  name: "shipcheck",
  version: "0.1.0",
});

server.registerTool(
  "scan_repo",
  {
    title: "Scan a repo for pre-launch risk patterns",
    description:
      "Runs static risk detectors over a codebase: exposed secrets, copyleft-licensed dependencies in " +
      "closed-source use, unauthenticated data endpoints, PII collection without a privacy policy, and " +
      "client-side payment handling. Returns structured findings, never a pass/fail verdict — this is not " +
      "a legal compliance certification.",
    inputSchema: {
      path: z.string().default(".").describe("Path to the repo root to scan, defaults to the current directory."),
      categories: z
        .array(
          z.enum([
            "exposed-secrets",
            "copyleft-license",
            "unauthenticated-endpoint",
            "pii-no-consent",
            "client-side-payment",
          ]),
        )
        .optional()
        .describe("Limit the scan to specific categories. Omit to run all five."),
    },
  },
  async ({ path, categories }) => {
    const rootDir = path;
    const files = await listFiles(rootDir);
    const activeCategories = (categories?.length ? categories : Object.keys(DETECTORS)) as Category[];

    const results = await Promise.all(
      activeCategories.map(async (cat) => {
        try {
          return await DETECTORS[cat]({ rootDir, files });
        } catch (err) {
          // A single detector failing (e.g. malformed package.json) should
          // never take down the whole scan.
          return [
            {
              category: cat,
              severity: "medium",
              file: rootDir,
              description: `Detector '${cat}' failed to run: ${(err as Error).message}`,
              why_it_matters: "This category could not be checked — treat it as unscanned, not as clean.",
              suggested_fix: "Check the repo path is correct and re-run; report a bug if it persists.",
            } satisfies Finding,
          ];
        }
      }),
    );

    const findings = results.flat();
    const summary = {
      total: findings.length,
      by_severity: {
        critical: findings.filter((f) => f.severity === "critical").length,
        high: findings.filter((f) => f.severity === "high").length,
        medium: findings.filter((f) => f.severity === "medium").length,
      },
      note: "These are risk-pattern findings, not a legal compliance determination. Zero findings means nothing in these five categories was detected — it does not mean the app is safe to ship.",
    };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ summary, findings }, null, 2),
        },
      ],
    };
  },
);

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("ShipCheck MCP server failed to start:", err);
  process.exit(1);
});
