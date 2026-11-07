import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import {
  REA_BUDGET_BREAKER_MATRIX,
  computeReaCartesianStringByteCharge,
  computeReaWasmInterfaceCharge,
  getExhaustionProfileForIntensity,
  type ReaSubsystemBudgetSpec,
} from "./rea-budget-matrix.js";
import {
  REA_OBLIGATION_FAMILIES,
  generateObligationLedgerFlood,
  type ObligationFloodResult,
} from "./obligation-flooder.js";
import {
  generateCallGraphLabyrinth,
  type CallGraphLabyrinthResult,
} from "./callgraph-labyrinth.js";
import {
  generateBpeTokenAmplifier,
  type BpeTokenAmplifierResult,
} from "./bpe-token-amplifier.js";
import {
  planWasmInterfaceBudgetExhaustion,
  type WasmInterfaceExhaustionPlan,
} from "./wasm-interface-exhaustion.js";
import {
  generateCdpShapeBudgetBreaker,
  type CdpShapeBudgetBreakerResult,
} from "./cdp-shape-budget-breaker.js";
import {
  REA_FRIDA_CAPTURE_LIMITS,
  generateFridaCaptureSaturation,
  type FridaCaptureSaturationResult,
} from "./frida-capture-saturation.js";
import {
  REA_REGEX_WORKER_LIMITS,
  generateRegexWorkerTarpit,
  type RegexWorkerTarpitResult,
} from "./regex-worker-tarpit.js";
import {
  REA_ASAR_HEADER_LIMITS,
  generateAsarHeaderDecoyFiles,
  planAsarHeaderAmplification,
  type AsarHeaderAmplificationPlan,
} from "./asar-header-amplifier.js";

export {
  REA_BUDGET_BREAKER_MATRIX,
  REA_OBLIGATION_FAMILIES,
  REA_FRIDA_CAPTURE_LIMITS,
  REA_REGEX_WORKER_LIMITS,
  REA_ASAR_HEADER_LIMITS,
  computeReaCartesianStringByteCharge,
  computeReaWasmInterfaceCharge,
  getExhaustionProfileForIntensity,
  generateObligationLedgerFlood,
  generateCallGraphLabyrinth,
  generateBpeTokenAmplifier,
  planWasmInterfaceBudgetExhaustion,
  generateCdpShapeBudgetBreaker,
  generateFridaCaptureSaturation,
  generateRegexWorkerTarpit,
  generateAsarHeaderDecoyFiles,
  planAsarHeaderAmplification,
  type AsarHeaderAmplificationPlan,
  type ReaSubsystemBudgetSpec,
  type ObligationFloodResult,
  type CallGraphLabyrinthResult,
  type BpeTokenAmplifierResult,
  type WasmInterfaceExhaustionPlan,
  type CdpShapeBudgetBreakerResult,
  type FridaCaptureSaturationResult,
  type RegexWorkerTarpitResult,
};

export interface CounterReaExhaustionSuiteResult {
  readonly combinedJsCode: string;
  readonly obligationFlood: ObligationFloodResult;
  readonly callGraphLabyrinth: CallGraphLabyrinthResult;
  readonly bpeAmplifier: BpeTokenAmplifierResult;
  readonly totalDecoyObligations: number;
  readonly mandatoryVerificationCasesInduced: number;
  readonly totalLabyrinthNodes: number;
  readonly totalCrossReferenceEdges: number;
  readonly estimatedBpeTokensAdded: number;
}

/**
 * Generates the unified Counter-REA Resource Exhaustion suite (`obligation-flooder` +
 * `callgraph-labyrinth` + `bpe-token-amplifier`) for injection into JavaScript/TypeScript
 * and Electron bundles.
 */
export function generateCounterReaExhaustionSuite(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): CounterReaExhaustionSuiteResult {
  const obligationFlood = generateObligationLedgerFlood(prng, intensity);
  const callGraphLabyrinth = generateCallGraphLabyrinth(prng, intensity);
  const bpeAmplifier = generateBpeTokenAmplifier(prng, intensity);
  const cdpBreaker = generateCdpShapeBudgetBreaker(prng, intensity);
  const fridaSaturation = generateFridaCaptureSaturation(prng, intensity);
  const regexTarpit = generateRegexWorkerTarpit(prng, intensity);

  const combinedJsCode = [
    obligationFlood.code,
    callGraphLabyrinth.code,
    bpeAmplifier.code,
    cdpBreaker.code,
    fridaSaturation.code,
    regexTarpit.code,
  ].join("\n\n");

  return {
    combinedJsCode,
    obligationFlood,
    callGraphLabyrinth,
    bpeAmplifier,
    totalDecoyObligations: obligationFlood.totalDecoyObligations,
    mandatoryVerificationCasesInduced:
      obligationFlood.mandatoryVerificationCasesInduced,
    totalLabyrinthNodes: callGraphLabyrinth.totalLabyrinthNodes,
    totalCrossReferenceEdges: callGraphLabyrinth.crossReferenceEdgesCreated,
    estimatedBpeTokensAdded: bpeAmplifier.estimatedBpeTokens,
  };
}
