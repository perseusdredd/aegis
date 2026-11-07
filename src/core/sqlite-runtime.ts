import { createRequire } from "node:module";
import type { DatabaseSync } from "node:sqlite";

const require = createRequire(import.meta.url);

let cachedAvailable: boolean | undefined;
let cachedClass: typeof DatabaseSync | null | undefined;

/**
 * Probe whether the current Node runtime exposes a usable `node:sqlite`
 * `DatabaseSync` with custom scalar `function()` support (Node ^22.13 || >=24).
 * Result is memoized for the process lifetime.
 */
export function isNodeSqliteAvailable(): boolean {
  if (cachedAvailable !== undefined) return cachedAvailable;
  cachedAvailable = tryGetDatabaseSyncClass() !== null;
  return cachedAvailable;
}

/**
 * Load `DatabaseSync` when available; return `null` on unsupported runtimes
 * (Node < 22.13, `--no-experimental-sqlite`, or missing `function` API).
 * Prefer this for optional/degraded paths; use `getDatabaseSyncClass()` when
 * SQLite is required and a clear hard-error is appropriate.
 */
export function tryGetDatabaseSyncClass(): typeof DatabaseSync | null {
  if (cachedClass !== undefined) return cachedClass;
  try {
    const mod = require("node:sqlite") as { DatabaseSync?: typeof DatabaseSync };
    if (
      typeof mod.DatabaseSync !== "function" ||
      typeof mod.DatabaseSync.prototype?.function !== "function"
    ) {
      cachedClass = null;
      return null;
    }
    cachedClass = mod.DatabaseSync;
    return cachedClass;
  } catch {
    cachedClass = null;
    return null;
  }
}

/** Load lazily so non-SQLite commands can still explain an unsupported setup. */
export function getDatabaseSyncClass(): typeof DatabaseSync {
  const cls = tryGetDatabaseSyncClass();
  if (cls) return cls;
  throw new Error(
    `BLA SQLite support requires Node.js 22.x >=22.13.0 or Node.js >=24.0.0 ` +
      `with node:sqlite enabled (current runtime: ${process.version}). ` +
      "Upgrade Node.js and remove --no-experimental-sqlite if set.",
  );
}
