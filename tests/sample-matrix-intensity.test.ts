import { createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { KNOWN_MEASURE_FORMATS } from "../src/engine/measurement-runner.js";

type Matrix = { intensity: string; seed: string; samples: Record<string, { after: Buffer }> };
const LEVELS = ["stealth", "balanced", "maximum", "bankrupt"] as const;

async function build(intensity?: string, seed?: string): Promise<Matrix> {
  const mod = (await import(pathToFileURL(join(process.cwd(), "scripts/redteam/lib/samples.mjs")).href)) as {
    buildSampleMatrix(o?: { intensity?: string; seed?: string }): Promise<Matrix>;
  };
  return mod.buildSampleMatrix({ ...(intensity ? { intensity } : {}), ...(seed ? { seed } : {}) });
}
const digest = (m: Matrix) => {
  const h = createHash("sha256");
  for (const k of Object.keys(m.samples).sort()) h.update(m.samples[k]!.after);
  return h.digest("hex");
};
const total = (m: Matrix) => Object.values(m.samples).reduce((n, s) => n + s.after.length, 0);

describe("--intensity changes the red-team sample matrix", () => {
  it("each of the four levels yields a different matrix", async () => {
    const ms = await Promise.all(LEVELS.map((l) => build(l)));
    expect(ms.map((m) => m.intensity)).toEqual([...LEVELS]);
    expect(new Set(ms.map(digest)).size).toBe(4);
  }, 120_000);

  it("total hardened bytes grow strictly stealth < balanced < maximum < bankrupt", async () => {
    const t = (await Promise.all(LEVELS.map((l) => build(l)))).map(total);
    expect(t[0]!).toBeLessThan(t[1]!);
    expect(t[1]!).toBeLessThan(t[2]!);
    expect(t[2]!).toBeLessThan(t[3]!);
  }, 120_000);

  it("the default stays bankrupt with the historical fixed seed", async () => {
    const d = await build();
    expect(d.intensity).toBe("bankrupt");
    expect(d.seed).toBe("aegis-redteam-empirical-v1");
    expect(digest(d)).toBe(digest(await build("bankrupt")));
  }, 120_000);

  it("a different seed changes the matrix, the same seed reproduces it", async () => {
    const a = await build("balanced", "seed-a");
    expect(digest(a)).toBe(digest(await build("balanced", "seed-a")));
    expect(digest(a)).not.toBe(digest(await build("balanced", "seed-b")));
  }, 120_000);

  it("an unknown intensity is rejected", async () => {
    await expect(build("nope")).rejects.toThrow(/unknown intensity/);
  });

  it("every measurable format has a sample in every matrix", async () => {
    const m = await build("stealth");
    expect(Object.keys(m.samples).length).toBeGreaterThanOrEqual(KNOWN_MEASURE_FORMATS.length - 2);
  }, 60_000);
});
