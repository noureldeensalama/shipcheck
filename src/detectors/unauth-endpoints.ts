import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { Detector, Finding } from "../types.js";

/**
 * v1 scope was intentionally narrow: Express (Node) and FastAPI (Python) route
 * definitions only. See PRD section 10 — this category has the highest false
 * positive risk of the five, so we don't try to generalize to every framework
 * yet. A route is flagged only when it clearly touches something that looks
 * like user/account data AND has no auth-looking guard within a few lines.
 *
 * Added after v1 dogfooding: Next.js API routes (both the App Router
 * "app/api/.../route.ts" style and the older "pages/api/*.ts" style), since
 * AI-agent scaffolds produce those constantly. Flutter/Dart backend routes are
 * deliberately NOT covered here — Flutter is a client framework and defines no
 * server routes.
 */

const EXPRESS_ROUTE = /\b(app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g;
const FASTAPI_ROUTE = /@(app|router)\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g;

// Next.js App Router: `app/api/**/route.ts` exporting named method handlers.
const NEXT_APP_HANDLER =
  /export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g;
// Next.js Pages Router: `pages/api/**` exporting a default request handler.
const NEXT_PAGES_HANDLER = /export\s+(?:default\s+)?(?:async\s+)?function\s+\w*handler\w*/i;

const SENSITIVE_PATH_HINTS = /(user|account|profile|admin|billing|payment|order|invoice|settings|private|me\b)/i;

const AUTH_GUARD_HINTS =
  /(requireAuth|isAuthenticated|authMiddleware|verifyToken|jwt\.verify|passport\.authenticate|Depends\(get_current_user|Depends\(verify|@login_required|auth\.uid\(\)|checkAuth|withAuth|@requires_auth)/;

// FastAPI projects commonly define their own guard dependency with a
// project-specific name (`Depends(require_admin)`, `Depends(get_current_user)`,
// `Depends(verify_session)`...). Rather than whitelisting names one by one,
// treat ANY Depends() argument whose identifier carries an auth-ish word as a
// guard. Generic infrastructure dependencies like Depends(get_db) do not match.
const FASTAPI_CUSTOM_GUARD_HINTS =
  /Depends\(\s*[A-Za-z_]*(auth|admin|guard|permission|session|current_user|require|token)[A-Za-z_]*\s*\)/i;

// Next.js-specific guard idioms (NextAuth/Auth.js, Clerk, Supabase server
// sessions). Kept separate so each framework's guards stay auditable.
const NEXT_AUTH_GUARD_HINTS =
  /(getServerSession|withApiAuthRequired|auth\(\)|currentUser\(|verifySession|checkSession|requireAdmin|getSession\(\{|\bauthOptions\b|clerkClient|auth\(\)\.protect)/;

function windowAround(content: string, index: number, chars = 400): string {
  const start = Math.max(0, index - chars);
  const end = Math.min(content.length, index + chars);
  return content.slice(start, end);
}

function lineNumberAt(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

function scanWithPattern(relPath: string, content: string, pattern: RegExp, framework: string, findings: Finding[]) {
  pattern.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(content)) !== null) {
    const routePath = match[3];
    if (!SENSITIVE_PATH_HINTS.test(routePath)) continue;

    const nearby = windowAround(content, match.index);
    if (AUTH_GUARD_HINTS.test(nearby) || FASTAPI_CUSTOM_GUARD_HINTS.test(nearby)) continue; // looks guarded, skip

    findings.push({
      category: "unauthenticated-endpoint",
      severity: "high",
      file: relPath,
      line: lineNumberAt(content, match.index),
      description: `${framework} route '${routePath}' looks like it handles user/account data but no auth check was found nearby.`,
      why_it_matters:
        "A route matching this naming pattern with no visible auth guard is a common way user data ends up readable or writable by anyone who finds the URL — the same class of bug as a missing Supabase RLS policy, generalized to any backend.",
      suggested_fix:
        "Add an auth check (middleware, decorator, or explicit session/token verification) before this handler runs, or confirm this route is intentionally public and rename it clearly if so.",
    });
  }
}

/**
 * Derives the served URL from a Next.js file path, e.g.
 *   app/api/user/profile/route.ts -> /api/user/profile
 *   pages/api/account/settings.ts -> /api/account/settings
 */
function nextRouteFromFile(relPath: string): string | null {
  const normalized = relPath.split("\\").join("/");
  const appMatch = normalized.match(/^(?:src\/)?app\/api\/(.+)\/route\.[cm]?[jt]sx?$/);
  if (appMatch) return `/api/${appMatch[1].replace(/\/index$/, "")}`;
  const pagesMatch = normalized.match(/^(?:src\/)?pages\/api\/(.+)\.[cm]?[jt]sx?$/);
  if (pagesMatch) return `/api/${pagesMatch[1].replace(/\/index$/, "")}`;
  return null;
}

function scanNextJsFile(relPath: string, content: string, findings: Finding[]) {
  const routePath = nextRouteFromFile(relPath);
  if (!routePath) return;
  if (!SENSITIVE_PATH_HINTS.test(routePath)) return;

  const isAppRouter = /\/route\.[cm]?[jt]sx?$/.test(relPath);
  let firstHandlerIndex = -1;

  if (isAppRouter) {
    NEXT_APP_HANDLER.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = NEXT_APP_HANDLER.exec(content)) !== null) {
      // HEAD/OPTIONS handlers are metadata endpoints, not data access.
      if (match[1] === "HEAD" || match[1] === "OPTIONS") continue;
      if (firstHandlerIndex === -1) firstHandlerIndex = match.index;
    }
    if (firstHandlerIndex === -1) return;
  } else {
    const m = content.match(NEXT_PAGES_HANDLER);
    if (!m || m.index === undefined) return;
    firstHandlerIndex = m.index;
  }

  const nearby = windowAround(content, firstHandlerIndex);
  if (AUTH_GUARD_HINTS.test(nearby) || NEXT_AUTH_GUARD_HINTS.test(nearby)) return; // looks guarded, skip

  findings.push({
      category: "unauthenticated-endpoint",
      severity: "high",
      file: relPath,
      line: lineNumberAt(content, firstHandlerIndex),
      description: `Next.js API route '${routePath}' looks like it handles user/account data but no auth check was found in the handler file.`,
      why_it_matters:
        "A route matching this naming pattern with no visible auth guard is a common way user data ends up readable or writable by anyone who finds the URL. In Next.js, every file under app/api or pages/api is publicly routable unless you protect it.",
      suggested_fix:
        "Add an auth check (e.g. getServerSession / withApiAuthRequired for NextAuth, or your own token verification) at the top of the handler before reading or writing data.",
    });
}

export const unauthEndpoints: Detector = async (ctx) => {
  const findings: Finding[] = [];

  for (const relPath of ctx.files) {
    if (!/\.(js|ts|jsx|tsx|py)$/.test(relPath)) continue;
    if (relPath.includes("node_modules") || relPath.includes(".test.") || relPath.includes("__tests__")) continue;

    let content: string;
    try {
      content = await readFile(join(ctx.rootDir, relPath), "utf-8");
    } catch {
      continue;
    }

    if (/\.(js|ts|jsx|tsx)$/.test(relPath)) {
      scanWithPattern(relPath, content, EXPRESS_ROUTE, "Express", findings);
      if (nextRouteFromFile(relPath) !== null) {
        scanNextJsFile(relPath, content, findings);
      }
    } else if (relPath.endsWith(".py")) {
      scanWithPattern(relPath, content, FASTAPI_ROUTE, "FastAPI", findings);
    }
  }

  return findings;
};
