import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface CdpShapeBudgetBreakerResult {
  readonly code: string;
  readonly jsonNestingDepth: number;
  readonly consoleDrainBytes: number;
  readonly exceedsReaShapeAllowance: boolean;
}

/**
 * Targets `morluto/rea/src/browser/CdpCaptureEvents.ts` (verified in
 * `CdpCaptureEvents.shapeBudget.test.ts:8,85,179`):
 *
 * 1. REA's `CdpCaptureEvents` shares a fixed `WEB_RUNTIME_LIMITS.retainedEventBytes`
 *    allowance across `Runtime.consoleAPICalled`, `json_body_shapes`, and `websocket_shapes`.
 * 2. Any JSON body or WebSocket frame with nesting depth >= 760 (`'{"a":'.repeat(760) + '0' + '}'.repeat(760)`)
 *    or preceded by a large `console.log` payload when CDP is attached causes REA to drop
 *    `json_body_shapes` and `websocket_shapes` with `reason: "resource_budget_exhausted"`.
 */
export function generateCdpShapeBudgetBreaker(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): CdpShapeBudgetBreakerResult {
  const depth =
    intensity === "stealth"
      ? 765
      : intensity === "balanced"
        ? 780
        : intensity === "maximum"
          ? 820
          : 900;
  const consoleDrainBytes =
    intensity === "stealth" ? 512 * 1024 : 1024 * 1024;
  const tag = prng.hex(3);

  const code = [
    `function cdpShapeBudgetGuard_${tag}() {`,
    `  const _g = typeof globalThis !== "undefined" ? globalThis : {};`,
    `  const _cdpActive = Boolean(_g.__playwright || _g.__puppeteer_evaluation_script__ || _g.navigator?.webdriver);`,
    `  if (!_cdpActive) return null;`,
    `  const _deepJson = '{"a":'.repeat(${depth}) + "0" + "}".repeat(${depth});`,
    `  return {`,
    `    overBudgetJsonEnvelope: _deepJson,`,
    `    consoleDrainChunkSize: ${consoleDrainBytes},`,
    `  };`,
    `}`,
  ].join("\n");

  return {
    code,
    jsonNestingDepth: depth,
    consoleDrainBytes,
    exceedsReaShapeAllowance: depth >= 760,
  };
}
