import { REA_INTERNAL_LIMITS } from "../identity.js";
import { REA_BUDGET_BREAKER_MATRIX } from "../shields/exhaustion/rea-budget-matrix.js";
import type { ProtectionIntensity } from "../core/types.js";

/**
 * AEGIS "deeper budgets" column (docs/AEGIS-BUDGETS.md).
 *
 * Master Budget Registry: a single, queryable catalog of every REA internal
 * resource/parsing limit AEGIS tracks, with a computed TARGET value AEGIS
 * emitters should aim to exceed, and env-var overrides for tuning without a
 * code change. This file does not itself change any existing shield's
 * default emission behavior — it is additive. Existing shields keep reading
 * their own literals from `REA_INTERNAL_LIMITS` / `REA_BUDGET_BREAKER_MATRIX`
 * unchanged; this registry is the consolidated reference point new/updated
 * emitters should consult going forward (per docs/AEGIS-BUDGETS.md section 4).
 */

export type BudgetStrategy = "dense-padding" | "ast-nesting" | "sparse-header" | "state-expansion";

export interface TargetBudgetSpec {
  /** Stable id, derived from the REA constant name (kebab-ish, lowercase). */
  readonly id: string;
  /** Exact REA constant name this budget tracks. */
  readonly reaConstant: string;
  /** Where AEGIS currently sources the value from ("identity" | "matrix"). */
  readonly reaSource: "identity" | "matrix";
  /** REA's own hard limit value, as AEGIS currently tracks it. */
  readonly reaValue: number;
  readonly unit: "bytes" | "levels" | "states" | "ms" | "ratio";
  /** Multiplier applied to reaValue (or additive levels for nesting) to compute targetValue. */
  readonly multiplier: number;
  /** The value AEGIS emitters should aim to exceed REA's limit by. */
  readonly targetValue: number;
  readonly strategy: BudgetStrategy;
  /** Whether this id is already wired to a live constant (true for everything in this registry). */
  readonly wired: boolean;
}

const BYTES_NAME_RE = /BYTES$/;
const NESTING_NAME_RE = /(NESTING|DEPTH)$/;
const TIME_NAME_RE = /(_MS$|DEADLINE_MS$|TIMEOUT)/;

function classify(name: string, value: number): { strategy: BudgetStrategy; unit: TargetBudgetSpec["unit"]; multiplier: number } {
  if (TIME_NAME_RE.test(name)) {
    return { strategy: "state-expansion", unit: "ms", multiplier: 1.5 };
  }
  if (NESTING_NAME_RE.test(name)) {
    // Spec section 2: nesting budgets grow by +4 levels, which for typical
    // (32-256 level) REA ceilings works out to roughly 1.12x-1.40x.
    return { strategy: "ast-nesting", unit: "levels", multiplier: (value + 4) / value };
  }
  if (BYTES_NAME_RE.test(name)) {
    const MIB = 1_048_576;
    if (value <= MIB) return { strategy: "dense-padding", unit: "bytes", multiplier: 1.5 };
    if (value <= 8 * MIB) return { strategy: "dense-padding", unit: "bytes", multiplier: 1.35 };
    if (value <= 32 * MIB) return { strategy: "dense-padding", unit: "bytes", multiplier: 1.25 };
    if (value <= 256 * MIB) return { strategy: "sparse-header", unit: "bytes", multiplier: 1.1 };
    return { strategy: "sparse-header", unit: "bytes", multiplier: 1.05 };
  }
  // Everything else: row/record/frame/entry/atom/token/region/count-style ceilings.
  return {
    strategy: "state-expansion",
    unit: "states",
    multiplier: value <= 64 ? 1.2 : 1.15,
  };
}

function toId(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

function buildRegistry(): TargetBudgetSpec[] {
  const out: TargetBudgetSpec[] = [];
  const seen = new Set<string>();

  for (const [name, rawValue] of Object.entries(REA_INTERNAL_LIMITS)) {
    if (typeof rawValue !== "number" || !Number.isFinite(rawValue)) continue;
    if (seen.has(name)) continue;
    seen.add(name);
    const { strategy, unit, multiplier } = classify(name, rawValue);
    const targetValue =
      strategy === "ast-nesting" ? rawValue + 4 : Math.ceil(rawValue * multiplier);
    out.push({
      id: toId(name),
      reaConstant: name,
      reaSource: "identity",
      reaValue: rawValue,
      unit,
      multiplier,
      targetValue,
      strategy,
      wired: true,
    });
  }

  for (const entry of REA_BUDGET_BREAKER_MATRIX) {
    if (seen.has(entry.constantName)) continue;
    seen.add(entry.constantName);
    if (typeof entry.hardLimit !== "number" || !Number.isFinite(entry.hardLimit)) continue;
    const { strategy, unit, multiplier } = classify(entry.constantName, entry.hardLimit);
    const targetValue =
      strategy === "ast-nesting" ? entry.hardLimit + 4 : Math.ceil(entry.hardLimit * multiplier);
    out.push({
      id: toId(entry.constantName),
      reaConstant: entry.constantName,
      reaSource: "matrix",
      reaValue: entry.hardLimit,
      unit,
      multiplier,
      targetValue,
      strategy,
      wired: true,
    });
  }

  return out;
}

/** The full Master Budget Registry (docs/AEGIS-BUDGETS.md section 4). */
export const REA_BUDGET_REGISTRY: readonly TargetBudgetSpec[] = Object.freeze(buildRegistry());

/** Per-intensity scale applied on top of each entry's base multiplier. */
export function intensityScaleFactor(intensity: ProtectionIntensity): number {
  switch (intensity) {
    case "stealth":
      return 0.9;
    case "balanced":
      return 1.0;
    case "maximum":
      return 1.15;
    case "bankrupt":
      return 1.4;
    default:
      return 1.0;
  }
}

function envIntensity(env: NodeJS.ProcessEnv): ProtectionIntensity | null {
  const raw = env.AEGIS_BUDGET_INTENSITY;
  if (raw === "stealth" || raw === "balanced" || raw === "maximum" || raw === "bankrupt") return raw;
  return null;
}

function envScale(env: NodeJS.ProcessEnv): number {
  const raw = env.AEGIS_BUDGET_SCALE;
  if (typeof raw !== "string" || raw.trim().length === 0) return 1;
  const parsed = Number(raw);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 1;
}

function envOverrideKeyFor(reaConstant: string): string {
  return `AEGIS_OVERRIDE_${reaConstant}`;
}

/**
 * Resolve the effective target value for one budget id, applying (in order):
 * 1. `AEGIS_OVERRIDE_<CONSTANT_NAME>` — an explicit numeric override, wins outright.
 * 2. `AEGIS_BUDGET_INTENSITY` — scales the base multiplier (stealth < balanced < maximum < bankrupt).
 * 3. `AEGIS_BUDGET_SCALE` — an additional arbitrary numeric multiplier.
 * Deterministic: the same (id, env) pair always resolves to the same number.
 */
export function resolveBudgetTarget(
  id: string,
  env: NodeJS.ProcessEnv = process.env,
): number {
  const spec = REA_BUDGET_REGISTRY.find((entry) => entry.id === id);
  if (!spec) {
    throw new Error(`resolveBudgetTarget: unknown budget id '${id}'`);
  }

  const overrideRaw = env[envOverrideKeyFor(spec.reaConstant)];
  if (typeof overrideRaw === "string" && overrideRaw.trim().length > 0) {
    const parsed = Number(overrideRaw);
    if (Number.isFinite(parsed)) return parsed;
  }

  const intensity = envIntensity(env);
  const scale = envScale(env);
  const intensityFactor = intensity ? intensityScaleFactor(intensity) : 1;

  if (spec.strategy === "ast-nesting") {
    // Levels are additive, not multiplicative: scale the "+4" extra budget,
    // never shrink below the REA hard limit itself.
    const extra = Math.max(0, spec.targetValue - spec.reaValue);
    return spec.reaValue + Math.ceil(extra * intensityFactor * scale);
  }

  return Math.ceil(spec.reaValue * spec.multiplier * intensityFactor * scale);
}

/** Lookup one registry entry by id, or undefined. */
export function getBudgetSpec(id: string): TargetBudgetSpec | undefined {
  return REA_BUDGET_REGISTRY.find((entry) => entry.id === id);
}

/** Number of registry entries actually tracking a live REA constant (acceptance #1). */
export function countWiredBudgets(): number {
  return REA_BUDGET_REGISTRY.filter((entry) => entry.wired).length;
}
