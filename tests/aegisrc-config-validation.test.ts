import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadAegisConfig } from "../src/core/config.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "aegis-config-validation-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe(".aegisrc/config validation", () => {
  it("loads a valid config", () => {
    const dir = createTempDir();
    writeFileSync(
      join(dir, ".aegisrc"),
      JSON.stringify({ intensity: "maximum", seed: "project-seed", emitManifest: true }),
      "utf8",
    );
    const loaded = loadAegisConfig(dir);
    expect(loaded.sourcePath).toBe(join(dir, ".aegisrc"));
    expect(loaded.config.intensity).toBe("maximum");
    expect(loaded.config.emitManifest).toBe(true);
  });

  it("fails loudly on malformed JSON instead of silently falling back", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".aegisrc"), "{ not json", "utf8");
    expect(() => loadAegisConfig(dir)).toThrow(/Invalid AEGIS config at .*\.aegisrc/);
  });

  it("fails loudly on an invalid intensity value", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".aegisrc"), JSON.stringify({ intensity: "nope" }), "utf8");
    expect(() => loadAegisConfig(dir)).toThrow(/intensity.*stealth, balanced, maximum, bankrupt/);
  });

  it("fails loudly on a non-boolean boolean field", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".aegisrc"), JSON.stringify({ selfSeal: "yes" }), "utf8");
    expect(() => loadAegisConfig(dir)).toThrow(/selfSeal.*boolean/);
  });

  it("rejects config files above the size cap", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, ".aegisrc"), "{}\n" + " ".repeat(70 * 1024), "utf8");
    expect(() => loadAegisConfig(dir)).toThrow(/file is .* bytes/);
  });

  it("validates an explicit --config path and the package.json aegis field", () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "custom.json"), JSON.stringify({ intensity: "stealth" }), "utf8");
    expect(loadAegisConfig(dir, "custom.json").config.intensity).toBe("stealth");

    const pkgDir = createTempDir();
    writeFileSync(
      join(pkgDir, "package.json"),
      JSON.stringify({ name: "x", aegis: { intensity: "nope" } }),
      "utf8",
    );
    expect(() => loadAegisConfig(pkgDir)).toThrow(/package\.json \(aegis field\)/);
  });
});