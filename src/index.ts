#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { stat } from "node:fs/promises";
import { listFiles } from "./lib/list-files.js";
import { buildScanResult } from "./lib/scan-response.js";
import { getChangedFiles } from "./lib/git-diff.js";

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

function errorResult(message: string) {
  return {
    isError: true,
    content: [{ type: "text" as const, text: message }],
  };
}

function activeCategoriesOrAll(categories?: Category[]): Category[] {
  return categories?.length ? categories : (Object.keys(DETECTORS) as Category[]);
}

/** Shared detector runner for scan_repo and scan_diff — identical behavior, scope is the only difference. */
async function runDetectors(rootDir: string, files: string[], activeCategories: Category[]) {
  // One shared content cache per invocation: every file is read from disk
  // exactly once no matter how many detectors need it.
  const contentCache = new Map<string, string | null>();
  const results = await Promise.all(
    activeCategories.map(async (cat) => {
      try {
        return await DETECTORS[cat]({ rootDir, files, contentCache });
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

  const result = buildScanResult(results.flat());
  return {
    content: [
      {
        type: "text" as const,
        // Compact, not pretty-printed: this text goes straight into the
        // calling model's context and every byte is paid for.
        text: JSON.stringify(result),
      },
    ],
  };
}

const server = new McpServer({
  name: "shipcheck",
  version: "0.3.0",
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

    // A typo'd path must NOT look like a clean scan: zero findings on a
    // directory that doesn't exist would read as "nothing detected" to the
    // calling agent. Fail loudly instead.
    try {
      const st = await stat(rootDir);
      if (!st.isDirectory()) {
        return errorResult(`'${rootDir}' is not a directory — give the path to a repository root.`);
      }
    } catch {
      return errorResult(`Path '${rootDir}' does not exist or is not readable. Check for typos and use an absolute path if the repo is outside the current working directory.`);
    }
    const files = await listFiles(rootDir);
    return runDetectors(rootDir, files, activeCategoriesOrAll(categories));
  },
);

server.registerTool(
  "scan_diff",
  {
    title: "Scan uncommitted changes for pre-launch risk patterns",
    description:
      "Scans only what changed since a git ref (default HEAD, i.e. staged + unstaged work plus " +
      "new untracked files) with the same five detectors as scan_repo. Built for the " +
      "\"check it before you commit\" loop — fast and cheap where scan_repo is thorough. Same " +
      "caveat: risk-pattern findings, not a pass/fail or compliance verdict.",
    inputSchema: {
      path: z.string().default(".").describe("Path to the git repository root to check."),
      base: z
        .string()
        .optional()
        .describe("Git ref to diff against. Omit for uncommitted work vs HEAD; use a branch/tag/sha to review a whole branch."),
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
  async ({ path, base, categories }) => {
    const rootDir = path;
    try {
      const st = await stat(rootDir);
      if (!st.isDirectory()) {
        return errorResult(`'${rootDir}' is not a directory — give the path to a repository root.`);
      }
    } catch {
      return errorResult(`Path '${rootDir}' does not exist or is not readable. Check for typos and use an absolute path if the repo is outside the current working directory.`);
    }

    const available = await listFiles(rootDir);
    let resolution;
    try {
      resolution = await getChangedFiles(rootDir, base, available);
    } catch (err) {
      return errorResult((err as Error).message);
    }

    // Honesty guard: an empty diff must never read as "the app is fine."
    if (resolution.files.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              summary: {
                scanned_files: 0,
                diff_base: base && base.length > 0 ? base : "HEAD (uncommitted work)",
                reported_changed_by_git: resolution.reportedChanged,
                total: 0,
                by_severity: { critical: 0, high: 0, medium: 0 },
                note:
                  "No scannable files in this diff (nothing changed, changes are only deletions, or they are gitignored). This says NOTHING about the repository as a whole — run scan_repo for a full check.",
              },
              findings: [],
            }),
          },
        ],
      };
    }

    const result = await runDetectors(rootDir, resolution.files, activeCategoriesOrAll(categories));
    const enriched = JSON.parse(result.content[0].text);
    enriched.summary.scanned_files = resolution.files.length;
    enriched.summary.diff_base = base && base.length > 0 ? base : "HEAD (uncommitted work)";
    return { content: [{ type: "text", text: JSON.stringify(enriched) }] };
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
