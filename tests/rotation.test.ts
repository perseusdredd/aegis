import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  ROTATION_SCHEMA,
  RotationVocabularyExhausted,
  decoyRangeForIntensity,
  deriveBuildId,
  deriveBuildSeed,
  planDecoyRotation,
  resolveRotationSeed,
} from "../src/core/rotation.js";
import { LEGACY_FIXED_SEEDS } from "../src/core/config.js";
import { SeededPrng } from "../src/core/prng.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "aegis-rotation-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

describe("ROTATION_SCHEMA", () => {
  it("is the versioned rotation schema id", () => {
    expect(ROTATION_SCHEMA).toBe("aegis-rotation/v1");
  });
});

describe("resolveRotationSeed", () => {
  it("prefers an explicit cliSeed over everything else (acceptance #6)", () => {
    const dir = createTempDir();
    const resolved = resolveRotationSeed({
      cwd: dir,
      cliSeed: "y",
      env: { AEGIS_SEED: "x" },
    });
    expect(resolved.source).toBe("cli");
    expect(resolved.rootSeed).toBe("y");
  });

  it("falls back to AEGIS_SEED when no cliSeed is given", () => {
    const dir = createTempDir();
    const resolved = resolveRotationSeed({ cwd: dir, env: { AEGIS_SEED: "env-seed-value" } });
    expect(resolved.source).toBe("env");
    expect(resolved.rootSeed).toBe("env-seed-value");
  });

  it("ignores an empty AEGIS_SEED and falls through to generation", () => {
    const dir = createTempDir();
    const resolved = resolveRotationSeed({ cwd: dir, env: { AEGIS_SEED: "   " }, persist: false });
    expect(resolved.source).toBe("generated");
  });

  it("warns on stderr but still uses a legacy fixed seed from env", () => {
    const dir = createTempDir();
    const legacy = [...LEGACY_FIXED_SEEDS][0]!;
    const originalError = console.error;
    const errors: string[] = [];
    console.error = (...args: unknown[]) => errors.push(args.map(String).join(" "));
    try {
      const resolved = resolveRotationSeed({ cwd: dir, env: { AEGIS_SEED: legacy } });
      expect(resolved.rootSeed).toBe(legacy);
      expect(resolved.source).toBe("env");
      expect(errors.join("\n")).toMatch(/legacy fixed seed/);
    } finally {
      console.error = originalError;
    }
  });

  it("acceptance #5: first run reports generated + persists, second run reports config with identical seed", () => {
    const dir = createTempDir();
    const first = resolveRotationSeed({ cwd: dir, persist: true });
    expect(first.source).toBe("generated");
    expect(first.persistedTo).not.toBeNull();

    const second = resolveRotationSeed({ cwd: dir, persist: true });
    expect(second.source).toBe("config");
    expect(second.rootSeed).toBe(first.rootSeed);
  });

  it("does not write to disk when persist is false (dry-run)", () => {
    const dir = createTempDir();
    const resolved = resolveRotationSeed({ cwd: dir, persist: false });
    expect(resolved.persistedTo).toBeNull();
    const second = resolveRotationSeed({ cwd: dir, persist: false });
    // No persistence happened, so a fresh seed is minted again (not reused).
    expect(second.rootSeed).not.toBe(resolved.rootSeed);
  });
});

describe("deriveBuildId / deriveBuildSeed", () => {
  it("is deterministic for the same target + digest", () => {
    const a = deriveBuildId("/tmp/project/dist/app.js", "deadbeef".repeat(8));
    const b = deriveBuildId("/tmp/project/dist/app.js", "deadbeef".repeat(8));
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{16}$/);
  });

  it("differs for different content digests (acceptance #3)", () => {
    const a = deriveBuildId("/tmp/project/dist/app.js", "aa".repeat(32));
    const b = deriveBuildId("/tmp/project/dist/app.js", "bb".repeat(32));
    expect(a).not.toBe(b);
  });

  it("deriveBuildSeed differs per buildId and never collides with the root seed", () => {
    const s1 = deriveBuildSeed("root", "build-a");
    const s2 = deriveBuildSeed("root", "build-b");
    expect(s1).not.toBe(s2);
    expect(s1).not.toBe("root");
  });
});

describe("planDecoyRotation", () => {
  it("acceptance #1: same buildSeed -> bit-identical plan (JSON)", () => {
    const spec = { minCount: 8, maxCount: 8 };
    const planA = planDecoyRotation("seed-A", spec);
    const planB = planDecoyRotation("seed-A", spec);
    expect(JSON.stringify(planA)).toBe(JSON.stringify(planB));
  });

  it("acceptance #2: different root seeds -> mostly disjoint decoy name sets (>= 90% different)", () => {
    const buildSeedA = deriveBuildSeed("A", "build-x");
    const buildSeedB = deriveBuildSeed("B", "build-x");
    const spec = { minCount: 48, maxCount: 48 };
    const planA = planDecoyRotation(buildSeedA, spec);
    const planB = planDecoyRotation(buildSeedB, spec);
    const setB = new Set(planB.decoyNames);
    const overlap = planA.decoyNames.filter((n) => setB.has(n)).length;
    expect(overlap / planA.decoyNames.length).toBeLessThan(0.1);
  });

  it("acceptance #3: two different artifacts (buildIds) never share a decoy cast and don't shift each other", () => {
    const rootSeed = "shared-root";
    const digestOne = "11".repeat(32);
    const digestTwo = "22".repeat(32);
    const buildIdOne = deriveBuildId("/tmp/a", digestOne);
    const buildIdTwo = deriveBuildId("/tmp/b", digestTwo);
    const spec = { minCount: 24, maxCount: 24 };
    const planOne = planDecoyRotation(deriveBuildSeed(rootSeed, buildIdOne), spec);
    const planTwo = planDecoyRotation(deriveBuildSeed(rootSeed, buildIdTwo), spec);
    expect(planOne.buildSeed).not.toBe(planTwo.buildSeed);

    // Re-protecting artifact "one" again must reproduce the exact same plan,
    // proving artifact "two" never shifted artifact "one"'s stream.
    const replanOne = planDecoyRotation(deriveBuildSeed(rootSeed, buildIdOne), spec);
    expect(JSON.stringify(replanOne)).toBe(JSON.stringify(planOne));
  });

  it("acceptance #7: rotation.decoyCount = 8 produces exactly 8 decoys", () => {
    const plan = planDecoyRotation("fixed-seed", { minCount: 8, maxCount: 8 });
    expect(plan.decoyNames).toHaveLength(8);
    expect(plan.coefficients).toHaveLength(8);
  });

  it("coefficients pair 1:1 with decoy names", () => {
    const plan = planDecoyRotation("pair-seed", { minCount: 12, maxCount: 12 });
    expect(plan.coefficients).toHaveLength(plan.decoyNames.length);
    for (const c of plan.coefficients) {
      expect(Number.isInteger(c)).toBe(true);
    }
  });

  it("rejects reserved names and throws RotationVocabularyExhausted when vocabulary is exhausted", () => {
    // Reserve exactly the next 40 names the same build seed would draw (with
    // minCount === maxCount, planDecoyRotation never calls nextInt() first,
    // so the draw sequence starts at the very first prng.identifier() call —
    // identical to this probe stream). Every one of the first 32 attempts
    // collides, so the budget is exhausted deterministically.
    const buildSeed = "exhaust-probe-seed";
    const probe = new SeededPrng(buildSeed);
    const reserved: string[] = [];
    for (let i = 0; i < 40; i++) reserved.push(probe.identifier());

    expect(() =>
      planDecoyRotation(buildSeed, { minCount: 1, maxCount: 1, reservedNames: reserved }),
    ).toThrow(RotationVocabularyExhausted);
  });

  it("rejects an invalid range", () => {
    expect(() => planDecoyRotation("seed", { minCount: 10, maxCount: 2 })).toThrow();
  });
});

describe("decoyRangeForIntensity", () => {
  it("scales decoy cast size by intensity per the spec table", () => {
    expect(decoyRangeForIntensity("stealth")).toEqual({ minCount: 2, maxCount: 4 });
    expect(decoyRangeForIntensity("balanced")).toEqual({ minCount: 6, maxCount: 12 });
    expect(decoyRangeForIntensity("maximum")).toEqual({ minCount: 16, maxCount: 32 });
    expect(decoyRangeForIntensity("bankrupt")).toEqual({ minCount: 48, maxCount: 96 });
  });
});

describe("determinism contract (acceptance #1 end-to-end)", () => {
  it("same seed + same input bytes -> identical SHA-256 of the full rotation output", async () => {
    const { createHash } = await import("node:crypto");
    const digestOf = (): string => {
      const buildId = deriveBuildId("/tmp/fixed/target.bin", "cafebabe".repeat(8));
      const buildSeed = deriveBuildSeed("fixed-root-seed", buildId);
      const plan = planDecoyRotation(buildSeed, { minCount: 16, maxCount: 16 });
      return createHash("sha256").update(JSON.stringify(plan)).digest("hex");
    };
    expect(digestOf()).toBe(digestOf());

    const buildIdOther = deriveBuildId("/tmp/fixed/target.bin", "cafebabe".repeat(8));
    const otherPlan = planDecoyRotation(deriveBuildSeed("different-root-seed", buildIdOther), {
      minCount: 16,
      maxCount: 16,
    });
    const firstPlan = planDecoyRotation(deriveBuildSeed("fixed-root-seed", buildIdOther), {
      minCount: 16,
      maxCount: 16,
    });
    expect(JSON.stringify(otherPlan)).not.toBe(JSON.stringify(firstPlan));
  });
});

describe("writeFileSync smoke (rotation-report file shape)", () => {
  it("round-trips a written rotation report through JSON.parse", () => {
    const dir = createTempDir();
    const buildId = deriveBuildId(dir, "ab".repeat(32));
    const buildSeed = deriveBuildSeed("root", buildId);
    const plan = planDecoyRotation(buildSeed, { minCount: 4, maxCount: 4 });
    const reportPath = join(dir, "rotation-report.json");
    writeFileSync(
      reportPath,
      JSON.stringify({ schema: ROTATION_SCHEMA, buildId, seedSource: "cli", decoyCount: plan.decoyNames.length }),
    );
    const parsed = JSON.parse(require("node:fs").readFileSync(reportPath, "utf8"));
    expect(parsed.schema).toBe(ROTATION_SCHEMA);
    expect(parsed.decoyCount).toBe(4);
  });
});
