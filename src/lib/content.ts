import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import type { DetectorContext } from "../types.js";

/**
 * Files larger than this are treated as data dumps, not source code, and are
 * skipped by all content-based detectors. Uniform rule so every detector sees
 * exactly the same corpus.
 */
export const MAX_CONTENT_BYTES = 2 * 1024 * 1024;

export type LoadedFile =
  | { state: "ok"; content: string }
  | { state: "skipped" };

/**
 * Reads a file once per scan and shares it across all detectors.
 *
 * Before this cache, a full scan read every text file up to five times (once
 * per content-based detector) — pure wasted I/O on large repos. The cache is
 * created fresh per scan_repo/scan_diff invocation, so memory is bounded by
 * the scanned tree; a hard byte ceiling clears it defensively on huge trees.
 */
export async function loadFile(ctx: DetectorContext, relPath: string): Promise<LoadedFile> {
  const cache = ctx.contentCache;
  const hit = cache?.get(relPath);
  if (hit !== undefined) {
    return hit === null ? { state: "skipped" } : { state: "ok", content: hit };
  }

  let loaded: LoadedFile;
  try {
    const st = await stat(join(ctx.rootDir, relPath));
    if (st.size > MAX_CONTENT_BYTES) {
      loaded = { state: "skipped" };
    } else {
      loaded = { state: "ok", content: await readFile(join(ctx.rootDir, relPath), "utf-8") };
    }
  } catch {
    loaded = { state: "skipped" }; // vanished, unreadable, or undecodable
  }

  // Defensive ceiling: if a pathological repo would cache >64MB of text,
  // drop the cache rather than grow unbounded. Correctness is unaffected —
  // misses simply re-read from disk.
  if (cache) {
    if (loaded.state === "ok" && loaded.content.length > 64 * 1024 * 1024) {
      cache.clear();
    }
    cache.set(relPath, loaded.state === "ok" ? loaded.content : null);
  }
  return loaded;
}
