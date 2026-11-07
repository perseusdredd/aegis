import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const BLA_ROOT = resolve(__dirname, "../../..");
// Empty/whitespace REA_ROOT is unset (CI passes "" when sibling REA is absent).
const REA_ROOT_ENV = (process.env.REA_ROOT ?? "").trim();
export const REA_ROOT = resolve(REA_ROOT_ENV || join(BLA_ROOT, "..", "rea"));
export const REDTEAM_OUT_DIR = join(BLA_ROOT, "docs/redteam");
export const REDTEAM_REPORT_MD = join(
  REDTEAM_OUT_DIR,
  "empirical-rea-validation.md",
);
export const REDTEAM_REPORT_JSON = join(
  REDTEAM_OUT_DIR,
  "empirical-rea-validation.json",
);

/** Filesystem path to a compiled REA module. */
export function resolveReaDist(rel) {
  return join(REA_ROOT, "dist", rel);
}

/**
 * ESM specifier for the same module. On Windows a bare `C:\...` path is
 * rejected by the default loader ("unsupported ESM URL scheme c:"), so callers
 * that `import()` must use this URL form instead of `resolveReaDist`.
 */
export function reaDistSpecifier(rel) {
  return pathToFileURL(resolveReaDist(rel)).href;
}

export function reaDistReady() {
  return existsSync(resolveReaDist("go/GoBinaryImage.js"));
}

/** User-local Wireshark extract (no root required on this box). */
export function resolveTsharkEnv() {
  // Explicit override wins, so a Windows install or a custom prefix is usable
  // without the Linux user-local layout below.
  const override = (process.env.BLA_TSHARK ?? "").trim();
  if (override) {
    return existsSync(override)
      ? { available: true, bin: override, env: process.env }
      : { available: false, bin: null, env: process.env };
  }
  const winTshark = "C:/Program Files/Wireshark/tshark.exe";
  if (process.platform === "win32" && existsSync(winTshark)) {
    return { available: true, bin: winTshark, env: process.env };
  }
  const home = process.env.HOME ?? "";
  const prefix = join(home, "opt/wireshark");
  const bin = join(prefix, "usr/bin/tshark");
  const lib = [
    join(prefix, "usr/lib/x86_64-linux-gnu"),
    join(prefix, "lib/x86_64-linux-gnu"),
  ].join(":");
  if (!existsSync(bin)) {
    return { available: false, bin: null, env: process.env };
  }
  return {
    available: true,
    bin,
    env: {
      ...process.env,
      PATH: `${join(prefix, "usr/bin")}:${process.env.PATH ?? ""}`,
      LD_LIBRARY_PATH: `${lib}${process.env.LD_LIBRARY_PATH ? `:${process.env.LD_LIBRARY_PATH}` : ""}`,
    },
  };
}

/** User-local WABT 1.0.42 tools (REA_WABT_BIN_DIRECTORY). Soft-skip when absent. */
export function resolveWabtEnv() {
  const fromEnv = process.env.REA_WABT_BIN_DIRECTORY;
  const home = process.env.HOME ?? "";
  const candidates = [
    fromEnv,
    join(home, "opt/wabt-1.0.42/bin"),
    join(home, "wabt/bin"),
  ].filter(Boolean);
  for (const dir of candidates) {
    const validate = join(dir, "wasm-validate");
    const objdump = join(dir, "wasm-objdump");
    const wasm2wat = join(dir, "wasm2wat");
    if (existsSync(validate) && existsSync(objdump) && existsSync(wasm2wat)) {
      return {
        available: true,
        directory: dir,
        env: { ...process.env, REA_WABT_BIN_DIRECTORY: dir },
      };
    }
  }
  return { available: false, directory: null, env: process.env };
}
