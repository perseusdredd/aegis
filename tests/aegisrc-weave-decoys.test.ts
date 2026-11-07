import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DEFAULT_AEGIS_CONFIG,
  initAegisConfig,
  loadAegisConfig,
} from "../src/core/config.js";
import { parseCliArgs } from "../src/cli.js";

describe(".aegisrc weaveDecoys parity with CLI --weave-decoys / MCP weave_decoys", () => {
  it("DEFAULT_AEGIS_CONFIG exposes weaveDecoys:false (opt-in)", () => {
    expect(DEFAULT_AEGIS_CONFIG.weaveDecoys).toBe(false);
  });

  it("initAegisConfig writes weaveDecoys:false into starter config", () => {
    const dir = mkdtempSync(join(tmpdir(), "aegis-weave-cfg-"));
    try {
      const res = initAegisConfig(dir);
      expect(res.config.weaveDecoys).toBe(false);
      const loaded = loadAegisConfig(dir);
      expect(loaded.config.weaveDecoys).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("loadAegisConfig honors weaveDecoys:true from .aegisrc", () => {
    const dir = mkdtempSync(join(tmpdir(), "aegis-weave-aegisrc-"));
    try {
      writeFileSync(
        join(dir, ".aegisrc"),
        JSON.stringify({
          intensity: "bankrupt",
          weaveDecoys: true,
          seed: "aegis-test-weave-decoys-seed-01",
        }),
        "utf8",
      );
      const loaded = loadAegisConfig(dir);
      expect(loaded.config.weaveDecoys).toBe(true);
      expect(loaded.sourcePath).toBe(join(dir, ".aegisrc"));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("parseCliArgs sets weaveDecoys from --weave-decoys", () => {
    const off = parseCliArgs(["harden", "."]);
    expect(off.weaveDecoys).toBe(false);
    const on = parseCliArgs(["harden", ".", "--weave-decoys"]);
    expect(on.weaveDecoys).toBe(true);
  });
});
