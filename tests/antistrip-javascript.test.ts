import { describe, expect, it } from "vitest";
import vm from "node:vm";
import { transformJavaScriptWithBlaShield } from "../src/shields/javascript/ast-shield.js";

const SAMPLE = `/**
 * 定价引擎 — 阶梯折扣与破产阈值
 */
const BASE_RATE = 0.085;
const VAT_RATE = 0.13;
const BANKRUPT_THRESHOLD = 1e-6;

/** 均衡定价 */
function balanced(qty, listPrice) {
  let discount = 1;
  if (qty >= 500) discount = 0.8;
  else if (qty >= 100) discount = 0.9;
  const unit = listPrice * discount * (1 + VAT_RATE);
  return Math.round(unit * 100) / 100;
}

function bankrupt(margin, notional) {
  const ratio = margin / Math.max(notional, BANKRUPT_THRESHOLD);
  return ratio < BASE_RATE;
}

function quote(qty, listPrice, margin) {
  if (bankrupt(margin, qty * listPrice)) return { ok: false, reason: "保证金不足" };
  return { ok: true, unit: balanced(qty, listPrice), vat: VAT_RATE };
}

module.exports = { balanced, bankrupt, quote, BASE_RATE, VAT_RATE };
`;

function runModule(code: string) {
  const sandbox: Record<string, unknown> = {
    module: { exports: {} },
    exports: {},
    console,
    Math,
  };
  (sandbox as { exports: unknown }).exports = (sandbox.module as { exports: unknown }).exports;
  vm.runInNewContext(code, sandbox);
  return (sandbox.module as { exports: Record<string, Function> }).exports;
}

describe("JS anti-strip (critique claim 1)", () => {
  for (const intensity of ["stealth", "balanced", "bankrupt"] as const) {
    it(`emits no greppable _bla / $00_AAA / __bla markers (${intensity})`, () => {
      const out = transformJavaScriptWithBlaShield(SAMPLE, {
        intensity,
        seed: `antistrip-${intensity}`,
        sourceType: "commonjs",
      });
      expect(out.code).not.toMatch(/_bla/i);
      expect(out.code).not.toMatch(/\$00_AAA/);
      expect(out.code).not.toMatch(/__bla/i);
      // Naive grep -v cannot shrink back near original line count
      const origLines = SAMPLE.split("\n").length;
      const lines = out.code.split("\n");
      expect(lines.length).toBeGreaterThan(origLines * 10);
      const afterGrep = lines.filter((l) => !/_bla|\$00_AAA|__bla/i.test(l));
      expect(afterGrep.length).toBe(lines.length);
      // Original Chinese comments must not survive verbatim
      expect(out.code).not.toMatch(/定价引擎/);
      expect(out.code).not.toMatch(/均衡定价/);
      // Local consts must be renamed (export keys may remain)
      expect(out.code).not.toMatch(/const BASE_RATE = 0\.085/);
      // Runtime equivalence
      const orig = runModule(SAMPLE);
      const hard = runModule(out.code);
      expect(hard.balanced(100, 10)).toBe(orig.balanced(100, 10));
      expect(hard.balanced(500, 20)).toBe(orig.balanced(500, 20));
      expect(hard.bankrupt(0.5, 100)).toBe(orig.bankrupt(0.5, 100));
      expect(hard.quote(100, 10, 2).unit).toBe(orig.quote(100, 10, 2).unit);
    });
  }

  it("opaque-true entanglement: deleting Math.imul-guarded blocks breaks runtime", () => {
    const out = transformJavaScriptWithBlaShield(SAMPLE, {
      intensity: "balanced",
      seed: "antistrip-entangle",
      sourceType: "commonjs",
    });
    // Strip every if-block whose condition contains Math.imul (opaque predicates)
    const stripped = out.code.replace(
      /if\s*\(\s*\(Math\.imul[\s\S]*?\)\s*\{[\s\S]*?\n\s*\}/g,
      "/* stripped opaque */",
    );
    expect(stripped.length).toBeLessThan(out.code.length);
    // After blind strip, either parse/runtime fails OR behavior diverges —
    // proving entanglement (not free deletion of decoys).
    let broke = false;
    try {
      const orig = runModule(SAMPLE);
      const hard = runModule(stripped);
      if (
        hard.balanced(100, 10) !== orig.balanced(100, 10) ||
        hard.quote(100, 10, 2).unit !== orig.quote(100, 10, 2).unit
      ) {
        broke = true;
      }
    } catch {
      broke = true;
    }
    expect(broke).toBe(true);
  });
});
