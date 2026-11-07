import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { generateCdpShapeBudgetBreaker } from "../src/shields/exhaustion/cdp-shape-budget-breaker.js";
import {
  REA_FRIDA_CAPTURE_LIMITS,
  generateFridaCaptureSaturation,
} from "../src/shields/exhaustion/frida-capture-saturation.js";

describe("CDP Shape Budget & Frida Capture Saturation Shields", () => {
  it("exceeds REA CdpCaptureEvents shape allowance (>= 760 JSON nesting levels)", () => {
    const prng = new SeededPrng("cdp-shape");
    const res = generateCdpShapeBudgetBreaker(prng, "bankrupt");
    expect(res.exceedsReaShapeAllowance).toBe(true);
    expect(res.jsonNestingDepth).toBeGreaterThanOrEqual(760);
    expect(res.code).toContain("overBudgetJsonEnvelope");
  });

  it("exceeds REA Frida capture limits (MAX_JSON_DEPTH = 64 and MAX_MESSAGE_TEXT_BYTES = 32768)", () => {
    const prng = new SeededPrng("frida-sat");
    const res = generateFridaCaptureSaturation(prng, "bankrupt");
    expect(res.payloadJsonDepth).toBeGreaterThan(
      REA_FRIDA_CAPTURE_LIMITS.MAX_JSON_DEPTH,
    );
    expect(res.messageTextBytes).toBeGreaterThan(
      REA_FRIDA_CAPTURE_LIMITS.MAX_MESSAGE_TEXT_BYTES,
    );
    expect(res.triggeredFridaLimits).toEqual(["json_depth", "message_text"]);
  });
});
