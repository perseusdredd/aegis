import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface DiffNoiseInjectionResult {
  readonly code: string;
  readonly permutedBlocksCount: number;
  readonly syntheticDiffFrontiersCreated: number;
}

/**
 * Targets REA's `compare_application_versions`, `compare_artifacts`, and `compare_functions`
 * workflows (`src/contracts/promptContracts.ts:157-218`).
 *
 * Injects seed-keyed isomorphic switch-case permutations and synthetic version-comparison
 * frontiers so that running REA's differential analysis across two builds produces dozens
 * of high-entropy structural diffs while runtime behavior remains 100% invariant.
 */
export function generateVersionDiffNoise(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): DiffNoiseInjectionResult {
  const blockCount =
    intensity === "stealth"
      ? 2
      : intensity === "balanced"
        ? 4
        : intensity === "maximum"
          ? 6
          : 8;
  const tag = prng.hex(3);
  const lines: string[] = [];

  for (let b = 0; b < blockCount; b++) {
    const cases = prng.shuffle([0, 1, 2, 3]);
    lines.push(
      `function diffFrontier_${tag}_${b}(x = 0) {`,
      `  switch (x & 3) {`,
      ...cases.map((c) => `    case ${c}: return (x ^ 0x${prng.hex(4)}) + ${c};`),
      `    default: return x;`,
      `  }`,
      `}`,
    );
  }

  return {
    code: lines.join("\n"),
    permutedBlocksCount: blockCount,
    syntheticDiffFrontiersCreated: blockCount * 4,
  };
}
