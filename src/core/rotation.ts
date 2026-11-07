import { createHash } from "node:crypto";
import { resolve } from "node:path";
import { deriveSeedLabel, SeededPrng } from "./prng.js";
import {
  LEGACY_FIXED_SEEDS,
  generateProjectSeed,
  loadAegisConfig,
  resolveProjectSeed,
} from "./config.js";

/**
 * AEGIS rotation column (docs/AEGIS-ROTATION.md).
 * Single responsibility: derive a deterministic per-build decoy rotation plan
 * from a root seed + build identity. No encryption, only derivation.
 */
export const ROTATION_SCHEMA = "aegis-rotation/v1";

export type RotationSeedSource = "cli" | "env" | "config" | "generated";

export interface RotationSeedInput {
  readonly cwd: string;
  readonly cliSeed?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly configPath?: string;
  /** Skip persisting a freshly generated seed to disk (dry-run). */
  readonly persist?: boolean;
}

export interface RotationSeed {
  readonly rootSeed: string;
  readonly source: RotationSeedSource;
  readonly persistedTo: string | null;
}

/** Thrown when 32 draws from the build PRNG cannot produce a unique decoy name. */
export class RotationVocabularyExhausted extends Error {
  constructor(message = "RotationVocabularyExhausted: could not mint a unique decoy name in 32 attempts") {
    super(message);
    this.name = "RotationVocabularyExhausted";
  }
}

/** Thrown when the rotation target's content digest cannot be computed. */
export class RotationTargetUnreadable extends Error {
  constructor(targetPath: string, cause?: unknown) {
    super(
      `RotationTargetUnreadable: cannot read/digest target '${targetPath}'${
        cause instanceof Error ? `: ${cause.message}` : ""
      }`,
    );
    this.name = "RotationTargetUnreadable";
  }
}

/**
 * Resolve the root seed following the priority order:
 * 1. explicit `--seed` (cliSeed)
 * 2. `AEGIS_SEED` env var (empty → skipped; legacy fixed seed → warn but used)
 * 3. non-legacy `seed` already stored in project config
 * 4. otherwise mint + persist a fresh per-project seed (unless persist === false)
 */
export function resolveRotationSeed(input: RotationSeedInput): RotationSeed {
  const env = input.env ?? process.env;

  if (input.cliSeed !== undefined && input.cliSeed.trim().length > 0) {
    return { rootSeed: input.cliSeed, source: "cli", persistedTo: null };
  }

  const envSeed = env?.AEGIS_SEED;
  if (typeof envSeed === "string" && envSeed.trim().length > 0) {
    if (LEGACY_FIXED_SEEDS.has(envSeed)) {
      console.error("warning: legacy fixed seed, per-build rotation weak");
    }
    return { rootSeed: envSeed, source: "env", persistedTo: null };
  }

  const persist = input.persist !== false;

  if (!persist) {
    const loaded = loadAegisConfig(input.cwd, input.configPath);
    const cfgSeed = loaded.config.seed;
    if (typeof cfgSeed === "string" && cfgSeed.length > 0 && !LEGACY_FIXED_SEEDS.has(cfgSeed)) {
      return { rootSeed: cfgSeed, source: "config", persistedTo: null };
    }
    return { rootSeed: generateProjectSeed(), source: "generated", persistedTo: null };
  }

  const resolved = resolveProjectSeed(input.cwd, undefined, input.configPath);
  return {
    rootSeed: resolved.seed,
    source: resolved.persisted ? "generated" : "config",
    persistedTo: resolved.persisted ? resolved.sourcePath : null,
  };
}

/**
 * Build identity: normalized target path + first 16 hex chars of the content
 * digest, hashed down to a stable 16-hex id. Two different artifacts never
 * collide; re-running on the same bytes at the same path reproduces the id.
 */
export function deriveBuildId(targetPath: string, contentDigest: string): string {
  if (typeof contentDigest !== "string" || contentDigest.length === 0) {
    throw new RotationTargetUnreadable(targetPath);
  }
  const normalized = resolve(targetPath).replace(/\\/g, "/");
  const digestPrefix = contentDigest.slice(0, 16);
  return createHash("sha256").update(`${normalized}:${digestPrefix}`).digest("hex").slice(0, 16);
}

/**
 * Build-specific sub-seed. Same (rootSeed, buildId) -> same sub-seed.
 * Different builds never share PRNG state (independent HMAC substream).
 */
export function deriveBuildSeed(rootSeed: string, buildId: string): string {
  return deriveSeedLabel(rootSeed, buildId);
}

export interface DecoySpec {
  readonly minCount: number;
  readonly maxCount: number;
  /** A name colliding with one of these is rejected, not merely skipped. */
  readonly reservedNames?: readonly string[];
}

export interface DecoyPlan {
  readonly buildId: string;
  readonly buildSeed: string;
  readonly decoyNames: readonly string[];
  readonly coefficients: readonly number[];
}

const INT32_MIN = -(2 ** 31);
const INT32_MAX = 2 ** 31 - 1;
const MAX_NAME_ATTEMPTS = 32;

/** Decoy cast derived purely from the sub-seed. Same input -> same output. */
export function planDecoyRotation(buildSeed: string, spec: DecoySpec): DecoyPlan {
  if (spec.maxCount < spec.minCount) {
    throw new Error("planDecoyRotation: maxCount must be >= minCount");
  }
  const prng = new SeededPrng(buildSeed);
  const range = spec.maxCount - spec.minCount + 1;
  const count = spec.minCount + (range > 1 ? prng.nextInt(0, range - 1) : 0);

  const reserved = new Set(spec.reservedNames ?? []);
  const used = new Set<string>();
  const names: string[] = [];
  for (let i = 0; i < count; i++) {
    let name = "";
    let attempt = 0;
    let unique = false;
    while (attempt < MAX_NAME_ATTEMPTS) {
      name = prng.identifier();
      attempt++;
      if (!reserved.has(name) && !used.has(name)) {
        unique = true;
        break;
      }
    }
    if (!unique) {
      throw new RotationVocabularyExhausted();
    }
    used.add(name);
    names.push(name);
  }

  const coefficients = names.map(() => prng.nextInt(INT32_MIN, INT32_MAX));

  // Position shuffle: artifact write order is independent from mint order so
  // consecutive builds don't place decoys at the same offsets, while each
  // name keeps its own coefficient (pairing preserved through the permutation).
  const order = prng.shuffle(names.map((_, i) => i));
  const shuffledNames = order.map((i) => names[i]!);
  const shuffledCoefficients = order.map((i) => coefficients[i]!);

  const buildId = createHash("sha256").update(buildSeed).digest("hex").slice(0, 16);

  return {
    buildId,
    buildSeed,
    decoyNames: shuffledNames,
    coefficients: shuffledCoefficients,
  };
}

/** Decoy cast size range for a given protection intensity, per the rotation spec. */
export function decoyRangeForIntensity(
  intensity: "stealth" | "balanced" | "maximum" | "bankrupt",
): { minCount: number; maxCount: number } {
  switch (intensity) {
    case "stealth":
      return { minCount: 2, maxCount: 4 };
    case "balanced":
      return { minCount: 6, maxCount: 12 };
    case "maximum":
      return { minCount: 16, maxCount: 32 };
    case "bankrupt":
      return { minCount: 48, maxCount: 96 };
    default:
      return { minCount: 6, maxCount: 12 };
  }
}
