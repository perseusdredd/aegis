import { describe, expect, it } from "vitest";
import {
  REA_BUDGET_REGISTRY,
  countWiredBudgets,
  getBudgetSpec,
  intensityScaleFactor,
  resolveBudgetTarget,
} from "../src/config/rea-budgets.config.js";

describe("REA_BUDGET_REGISTRY", () => {
  it("covers at least 100 distinct REA limits (acceptance criterion: >=100/122)", () => {
    expect(REA_BUDGET_REGISTRY.length).toBeGreaterThanOrEqual(100);
  });

  it("every entry targets strictly more than REA's own hard limit", () => {
    for (const entry of REA_BUDGET_REGISTRY) {
      expect(entry.targetValue).toBeGreaterThan(entry.reaValue);
    }
  });

  it("has no duplicate ids", () => {
    const ids = REA_BUDGET_REGISTRY.map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("every entry uses one of the four documented strategies", () => {
    const allowed = new Set(["dense-padding", "ast-nesting", "sparse-header", "state-expansion"]);
    for (const entry of REA_BUDGET_REGISTRY) {
      expect(allowed.has(entry.strategy)).toBe(true);
    }
  });

  it("countWiredBudgets matches the registry length (all entries are live-sourced)", () => {
    expect(countWiredBudgets()).toBe(REA_BUDGET_REGISTRY.length);
  });

  it("getBudgetSpec resolves a known id and returns undefined for an unknown one", () => {
    const known = REA_BUDGET_REGISTRY[0]!;
    expect(getBudgetSpec(known.id)).toEqual(known);
    expect(getBudgetSpec("not-a-real-budget-id")).toBeUndefined();
  });
});

describe("intensityScaleFactor", () => {
  it("orders stealth < balanced < maximum < bankrupt", () => {
    expect(intensityScaleFactor("stealth")).toBeLessThan(intensityScaleFactor("balanced"));
    expect(intensityScaleFactor("balanced")).toBeLessThan(intensityScaleFactor("maximum"));
    expect(intensityScaleFactor("maximum")).toBeLessThan(intensityScaleFactor("bankrupt"));
  });
});

describe("resolveBudgetTarget", () => {
  it("throws for an unknown id", () => {
    expect(() => resolveBudgetTarget("nope")).toThrow(/unknown budget id/);
  });

  it("is deterministic: same id + same env always resolves to the same number", () => {
    const id = REA_BUDGET_REGISTRY[0]!.id;
    const env = { ...process.env, AEGIS_BUDGET_INTENSITY: "bankrupt" };
    expect(resolveBudgetTarget(id, env)).toBe(resolveBudgetTarget(id, env));
  });

  it("with no env overrides, matches the registry's precomputed targetValue (default behavior preserved)", () => {
    const entry = REA_BUDGET_REGISTRY.find((e) => e.strategy !== "ast-nesting")!;
    expect(resolveBudgetTarget(entry.id, {})).toBe(entry.targetValue);
  });

  it("AEGIS_BUDGET_SCALE multiplies the resolved target", () => {
    const entry = REA_BUDGET_REGISTRY.find((e) => e.strategy === "state-expansion")!;
    const base = resolveBudgetTarget(entry.id, {});
    const scaled = resolveBudgetTarget(entry.id, { AEGIS_BUDGET_SCALE: "2" });
    expect(scaled).toBeGreaterThanOrEqual(base * 2 - 1);
  });

  it("AEGIS_BUDGET_INTENSITY=bankrupt yields a target >= the balanced-equivalent", () => {
    const entry = REA_BUDGET_REGISTRY.find((e) => e.strategy === "dense-padding")!;
    const balanced = resolveBudgetTarget(entry.id, { AEGIS_BUDGET_INTENSITY: "balanced" });
    const bankrupt = resolveBudgetTarget(entry.id, { AEGIS_BUDGET_INTENSITY: "bankrupt" });
    expect(bankrupt).toBeGreaterThan(balanced);
  });

  it("AEGIS_OVERRIDE_<CONSTANT_NAME> wins outright over intensity/scale", () => {
    const entry = REA_BUDGET_REGISTRY[0]!;
    const env = {
      [`AEGIS_OVERRIDE_${entry.reaConstant}`]: "999999",
      AEGIS_BUDGET_INTENSITY: "bankrupt",
      AEGIS_BUDGET_SCALE: "5",
    };
    expect(resolveBudgetTarget(entry.id, env)).toBe(999_999);
  });

  it("ast-nesting strategy never shrinks below REA's own hard limit, even at scale 0.01", () => {
    const entry = REA_BUDGET_REGISTRY.find((e) => e.strategy === "ast-nesting");
    if (!entry) return; // tolerate absence if classification heuristics shift
    const resolved = resolveBudgetTarget(entry.id, { AEGIS_BUDGET_SCALE: "0.01" });
    expect(resolved).toBeGreaterThanOrEqual(entry.reaValue);
  });
});
