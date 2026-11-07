import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { transformJavaScriptWithAegisShield } from "../src/shields/javascript/ast-shield.js";

const DTS = [
  "export declare class SeededPrng { constructor(seed: string); next(): number; }\nexport declare function pick<T>(xs: readonly T[]): T;\nexport interface Opts { a: number }\nexport type Mode = \"x\" | \"y\";\n",
  "declare namespace N { const k: number; function f(): void }\nexport { N };\nexport declare const v: unique symbol;\n",
];

describe(".d.ts hardening does not crash on scope-less bindings", () => {
  for (const [i, src] of DTS.entries()) {
    it(`synthetic declaration #${i}`, () => {
      expect(() =>
        transformJavaScriptWithAegisShield(src, { intensity: "bankrupt", seed: "dts", filename: `t${i}.d.ts` }),
      ).not.toThrow();
    });
  }

  it("real compiled declarations in dist/ transform without throwing", () => {
    for (const f of ["core/prng.d.ts", "core/rotation.d.ts", "core/release-plan.d.ts"]) {
      let src: string;
      try {
        src = readFileSync(join(process.cwd(), "dist", f), "utf8");
      } catch {
        continue; // dist not built
      }
      expect(() =>
        transformJavaScriptWithAegisShield(src, { intensity: "bankrupt", seed: "dts", filename: f }),
      ).not.toThrow();
    }
  });
});
