import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, it } from "vitest";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCRIPT = join(ROOT, "scripts", "verify-rea-constants.mjs");
const tmp = mkdtempSync(join(tmpdir(), "aegis-drift-registry-"));
afterAll(() => rmSync(tmp, { recursive: true, force: true }));

function fakeRea(name: string, source: string): string {
  const root = join(tmp, name);
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "limits.ts"), source);
  return root;
}

function runDrift(reaRoot: string): { status: number | null; out: string } {
  const r = spawnSync(process.execPath, [SCRIPT], {
    encoding: "utf8",
    env: { ...process.env, REA_ROOT: reaRoot },
    timeout: 120_000,
  });
  return { status: r.status, out: `${r.stdout}${r.stderr}` };
}

// Needs `npm run build` (the drift script loads dist/config/rea-budgets.config.js).
describe("drift check covers the budget registry", () => {
  it("a REA constant matching the registry value yields a PASS Registry row", () => {
    const { out } = runDrift(fakeRea("match", "export const TSHARK_JSON_MAX_BYTES = 8 * 1024 * 1024;\n"));
    expect(out).toMatch(/PASS\s+Registry:TSHARK_JSON_MAX_BYTES\s+8388608/);
    expect(out).toMatch(/Registry:summary\s+\d+ entries: \d+ verified by name/);
  }, 130_000);

  it("a drifted REA constant yields a FAIL Registry row and a non-zero exit", () => {
    const { status, out } = runDrift(fakeRea("drift", "export const TSHARK_JSON_MAX_BYTES = 1024;\n"));
    expect(out).toMatch(/FAIL\s+Registry:TSHARK_JSON_MAX_BYTES\s+AEGIS tracks 8388608, REA has 1024/);
    expect(status).toBe(1);
  }, 130_000);
});
