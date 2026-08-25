import { join } from "node:path";
import type { Detector, Finding } from "../types.js";
import { loadFile } from "../lib/content.js";

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
// Flask reuses FastAPI's decorator shape (`@app.route(...)` / `@app.get(...)`).
const FASTAPI_ROUTE = /@(app|router|api|bp|blueprint)\.(get|post|put|patch|delete|route)\s*\(\s*['"`]([^'"`]+)['"`]/g;

// Go HTTP frameworks with inline middleware chains (gin, echo, fiber, chi):
//   router.GET("/users", AuthMiddleware(), listUsers)
// A route is considered guarded when any argument after the path looks like
// auth middleware. net/http's http.HandleFunc has no inline guard convention
// and stays out of scope deliberately.
const GO_ROUTE =
  /\b(?:router|r|app|api|e|h|srv)\.(GET|POST|PUT|PATCH|DELETE)\s*\(\s*"([^"]+)"\s*,\s*([^)]*)\)/g;
const GO_GROUP_PREFIX = /\b(?:router|r|app|e|h|api)\.Group\(\s*"([^"]+)"/;
const GO_GUARD_ARGS = /(Auth|Jwt|Session|Admin|Middleware|Protect|Guard|Login|Permission)/;

// Laravel route DSL:
//   Route::get('/account/settings', [Controller::class, 'edit'])->middleware('auth');
const LARAVEL_ROUTE = /Route::(get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/g;
const LARAVEL_GUARD = /->middleware\s*\(([^)]*)\)/i;

// Spring Boot mappings + annotation guards:
//   @PreAuthorize(...) / @Secured("...") / @RolesAllowed(...) above @GetMapping("/profile")
const SPRING_MAPPING = /@(?:Get|Post|Put|Patch|Delete)Mapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/g;
const SPRING_CLASS_PREFIX_SOURCE =
  /@RequestMapping\s*\(\s*(?:value\s*=\s*)?["']([^"']+)["']/.source;
const SPRING_GUARD = /@(PreAuthorize|Secured|RolesAllowed|PostAuthorize)|SecurityFilterChain/i;

// Next.js App Router: `app/api/**/route.ts` exporting named method handlers.
const NEXT_APP_HANDLER =
  /export\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\b/g;
// Next.js Pages Router: `pages/api/**` exporting a default request handler.
const NEXT_PAGES_HANDLER = /export\s+(?:default\s+)?(?:async\s+)?function\s+\w*handler\w*/i;

// "debug"/"internal" routes are included deliberately: dogfooding found an
// unauthenticated /api/debug route that queried user data with a service key.
// Diagnostic endpoints are a favorite AI-agent scaffold artifact and rarely
// meant to be public.
const SENSITIVE_PATH_HINTS =
  /(user|account|profile|admin|billing|payment|order|invoice|settings|private|debug|internal|me\b)/i;

const AUTH_GUARD_HINTS =
  /(requireAuth|isAuthenticated|authMiddleware|verifyToken|jwt\.verify|passport\.authenticate|Depends\(get_current_user|Depends\(verify|@login_required|auth\.uid\(\)|checkAuth|withAuth|@requires_auth)/;

// FastAPI projects commonly define their own guard dependency with a
// project-specific name (`Depends(require_admin)`, `Depends(get_current_user)`,
// `Depends(verify_session)`...). Rather than whitelisting names one by one,
// treat ANY Depends() argument whose identifier carries an auth-ish word as a
// guard. Generic infrastructure dependencies like Depends(get_db) do not match.
const FASTAPI_CUSTOM_GUARD_HINTS =
  /Depends\(\s*[A-Za-z_]*(auth|admin|guard|permission|session|current_user|require|token)[A-Za-z_]*\s*\)/i;

// Hand-rolled header-token guards: the handler declares an `authorization`
// Header parameter and verifies the bearer token inside its body (common for
// webhook and one-shot admin endpoints). Found during dogfooding on a
// migration endpoint guarded exactly this way.
const FASTAPI_HEADER_AUTH_HINTS = /\bauthorization\b[^\n(]{0,40}Header\s*\(/i;

// Next.js-specific guard idioms (NextAuth/Auth.js, Clerk, Supabase server
// sessions). Kept separate so each framework's guards stay auditable.
const NEXT_AUTH_GUARD_HINTS =
  /(getServerSession|withApiAuthRequired|auth\(\)|currentUser\(|verifySession|checkSession|requireAdmin|getSession\(\{|\bauthOptions\b|clerkClient|auth\(\)\.protect)/;

function windowAround(content: string, index: number, chars = 400): string {
  const start = Math.max(0, index - chars);
  const end = Math.min(content.length, index + chars);
  return content.slice(start, end);
}

/**
 * Segment-scoped guard search (see scanWithPattern): how far BACK of a route
 * decorator its own annotations may sit, and how far FORWARD to search when
 * the route is the last in the file.
 */
const GUARD_LOOKBEHIND = 150;
const GUARD_FORWARD_MAX = 600;

/**
 * Removes comment text from a guard-search segment: a comment mentioning
 * "@login_required" or "@PreAuthorize" documents nothing about runtime auth.
 * Line-comment markers require leading whitespace so URLs (https://) survive.
 */
function withoutComments(s: string): string {
  return s
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|\n)(\s*)(\/\/|#|--)[^\n]*/g, "$1")
    .replace(/(\s)(\/\/|#)[^\n]*/g, " ");
}

function lineNumberAt(content: string, index: number): number {
  return content.slice(0, index).split("\n").length;
}

function scanWithPattern(relPath: string, content: string, pattern: RegExp, framework: string, findings: Finding[]) {
  // Routers commonly declare a prefix once — FastAPI `APIRouter(prefix="/admin")`,
  // Flask `Blueprint(..., url_prefix="/api")` — that every decorator mounts under.
  // Without it we'd report '/users' instead of '/admin/users', losing the
  // segment that often carries the sensitive-path signal. Best-effort: first
  // prefix in the file wins.
  const apiRouterMatch = content.match(/APIRouter\([^)]*?prefix\s*=\s*["']([^"']+)["']/);
  const blueprintMatch = content.match(/Blueprint\([^)]*?url_prefix\s*=\s*["']([^"']+)["']/);
  const routerPrefix =
    framework === "Flask"
      ? blueprintMatch
        ? blueprintMatch[1]
        : ""
      : apiRouterMatch
        ? apiRouterMatch[1]
        : "";

  pattern.lastIndex = 0;
  // Collect all matches first so each route's guard search can be scoped to
  // its OWN segment: from a little before the decorator (its own annotations)
  // to just before the next route. A symmetric window would let an adjacent
  // route's @login_required suppress its unguarded neighbor — a precision bug
  // on small files and back-to-back endpoints.
  const all: RegExpExecArray[] = [];
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(content)) !== null) all.push(match);

  for (let i = 0; i < all.length; i++) {
    const m = all[i];
    const routePath = routerPrefix + m[3];
    if (!SENSITIVE_PATH_HINTS.test(routePath)) continue;

    const segStart = Math.max(0, m.index - GUARD_LOOKBEHIND);
    const nextIdx = i + 1 < all.length ? all[i + 1].index : Math.min(content.length, m.index + GUARD_FORWARD_MAX);
    const segment = withoutComments(content.slice(segStart, nextIdx));
    if (
      AUTH_GUARD_HINTS.test(segment) ||
      FASTAPI_CUSTOM_GUARD_HINTS.test(segment) ||
      FASTAPI_HEADER_AUTH_HINTS.test(segment)
    ) {
      continue; // looks guarded, skip
    }

    findings.push({
      category: "unauthenticated-endpoint",
      severity: "high",
      file: relPath,
      line: lineNumberAt(content, m.index),
      description: `${framework} route '${routePath}' looks like it handles user/account data but no auth check was found nearby.`,
      why_it_matters:
        "Anyone on the internet who guesses this address can read or change other people's information. There's no lock on the door.",
      suggested_fix:
        "Add a login check so this address turns away anyone who isn't signed in (every framework has a standard way to do this), or make it obvious the address is meant to be public.",
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
        "In Next.js, every file in your API folders becomes a live web address automatically — and this one has no login check, so anyone who guesses the address can read or change other people's information.",
      suggested_fix:
        "Make the address check for a signed-in user before doing anything (NextAuth's getServerSession is the usual way), or make it obvious the address is meant to be public.",
    });
}

/**
 * Go frameworks (gin/echo/fiber/chi style): inline middleware args ARE the
 * guard convention — `router.GET("/admin/stats", AuthMiddleware(), h)` is
 * guarded, `router.GET("/users", h)` alone is not.
 */
function scanGoFile(relPath: string, content: string, findings: Finding[]) {
  const prefixMatch = content.match(GO_GROUP_PREFIX);
  const prefix = prefixMatch ? prefixMatch[1] : "";

  GO_ROUTE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = GO_ROUTE.exec(content)) !== null) {
    const routePath = prefix + match[2];
    if (!SENSITIVE_PATH_HINTS.test(routePath)) continue;

    const nearby = windowAround(content, match.index);
    // The chain args are THE guard location in these routers — a neighboring
    // route's middleware must never guard this one, so no window fallback.
    if (GO_GUARD_ARGS.test(match[3] ?? "")) {
      continue; // middleware arg present
    }
    void nearby;

    findings.push({
      category: "unauthenticated-endpoint",
      severity: "high",
      file: relPath,
      line: lineNumberAt(content, match.index),
      description: `Go route '${routePath}' looks like it handles user/account data but no auth middleware was found in its arguments.`,
      why_it_matters:
        "In these Go routers, the lock lives inside the same line as the route — a list of helper functions between the address and the handler. This line has helpers but none of them look like a login check, so anyone can reach it.",
      suggested_fix:
        "Add your login-checking helper into that chain (like router.GET(path, AuthMiddleware(), handler)) — or make it obvious this address is meant to be public.",
    });
  }
}

/** Laravel: guard = ->middleware('auth'…) within the SAME statement. */
function scanLaravelFile(relPath: string, content: string, findings: Finding[]) {
  LARAVEL_ROUTE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = LARAVEL_ROUTE.exec(content)) !== null) {
    const routePath = match[2];
    if (!SENSITIVE_PATH_HINTS.test(routePath)) continue;

    // Statement scope: from this route to the next Route:: / class end —
    // an adjacent route's ->middleware must never guard this one.
    const nextRoute = content.slice(match.index + 1).search(/\nRoute::/);
    const statementEnd =
      nextRoute === -1 ? Math.min(content.length, match.index + GUARD_FORWARD_MAX) : match.index + 1 + nextRoute;
    const statement = withoutComments(content.slice(match.index, statementEnd));

    const mw = statement.match(LARAVEL_GUARD);
    if (mw && /(auth|admin|can:|role|permission|sanctum|passport)/i.test(mw[1])) continue;

    findings.push({
      category: "unauthenticated-endpoint",
      severity: "high",
      file: relPath,
      line: lineNumberAt(content, match.index),
      description: `Laravel route '${routePath}' looks like it handles user/account data but no auth middleware was found.`,
      why_it_matters:
        "Laravel routes are open to everyone until you attach a guard. This user-data route has none, so anyone who guesses the address gets in.",
      suggested_fix:
        "Attach ->middleware('auth') to this route (or put it in a group that already has guards).",
    });
  }
}

/** Spring Boot: annotation guards within the mapping's own segment; class @RequestMapping composes as prefix. */
function scanSpringFile(relPath: string, content: string, findings: Finding[]) {
  const prefixMatch = content.match(new RegExp(SPRING_CLASS_PREFIX_SOURCE));
  const prefix = prefixMatch ? prefixMatch[1] : "";

  SPRING_MAPPING.lastIndex = 0;
  const all: RegExpExecArray[] = [];
  let match: RegExpExecArray | null;
  while ((match = SPRING_MAPPING.exec(content)) !== null) all.push(match);

  for (let i = 0; i < all.length; i++) {
    const m = all[i];
    const routePath = prefix + m[1];
    if (!SENSITIVE_PATH_HINTS.test(routePath)) continue;

    // Spring guards annotate ABOVE the mapping and nowhere else — backward
    // only. Any forward reach swallows the NEXT endpoint's @PreAuthorize on
    // small files and suppresses an unguarded neighbor.
    const segment = withoutComments(content.slice(Math.max(0, m.index - GUARD_LOOKBEHIND), m.index));
    if (SPRING_GUARD.test(segment) || AUTH_GUARD_HINTS.test(segment)) continue;

    findings.push({
      category: "unauthenticated-endpoint",
      severity: "high",
      file: relPath,
      line: lineNumberAt(content, m.index),
      description: `Spring route '${routePath}' looks like it handles user/account data but no security annotation was found nearby (@PreAuthorize/@Secured/@RolesAllowed).`,
      why_it_matters:
        "Spring only locks a route when a security note (@PreAuthorize and friends) sits on it, or a global rule covers it. This user-data route has neither, so visitors without accounts may get in.",
      suggested_fix:
        "Put @PreAuthorize or @Secured on this method (or cover it with a SecurityFilterChain rule), or make it obvious the route is meant to be public.",
    });
  }
}

export const unauthEndpoints: Detector = async (ctx) => {
  const findings: Finding[] = [];

  for (const relPath of ctx.files) {
    if (!/\.(js|ts|jsx|tsx|py|go|php|java|kt)$/.test(relPath)) continue;
    if (relPath.includes("node_modules") || relPath.includes(".test.") || relPath.includes("__tests__")) continue;

    const loaded = await loadFile(ctx, relPath);
    if (loaded.state === "skipped") continue;
    const content = loaded.content;

    if (/\.(js|ts|jsx|tsx)$/.test(relPath)) {
      scanWithPattern(relPath, content, EXPRESS_ROUTE, "Express", findings);
      if (nextRouteFromFile(relPath) !== null) {
        scanNextJsFile(relPath, content, findings);
      }
    } else if (relPath.endsWith(".py")) {
      // Flask and FastAPI share the decorator shape; label by import.
      const framework = /from\s+flask|import\s+flask/i.test(content) ? "Flask" : "FastAPI";
      scanWithPattern(relPath, content, FASTAPI_ROUTE, framework, findings);
    } else if (relPath.endsWith(".go")) {
      scanGoFile(relPath, content, findings);
    } else if (relPath.endsWith(".php")) {
      scanLaravelFile(relPath, content, findings);
    } else if (/\.(java|kt)$/.test(relPath)) {
      scanSpringFile(relPath, content, findings);
    }
  }

  return findings;
};
