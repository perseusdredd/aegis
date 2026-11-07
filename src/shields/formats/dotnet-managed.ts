import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

/**
 * Exact constant from `morluto/rea/src/dotnet/ManagedDecodeBudget.ts:9`.
 */
export const REA_MAX_MANAGED_METADATA_REPRESENTATION_BYTES = 64 * 1024 * 1024;

export interface DotnetManagedExhaustionPlan {
  readonly decoyNamespaceCount: number;
  readonly decoyPInvokeImports: readonly string[];
  readonly estimatedReaStringChargeBytes: number;
  readonly estimatedReaRowChargeBytes: number;
  readonly totalReaRepresentationChargeBytes: number;
}

/**
 * Targets `morluto/rea/src/dotnet/ManagedDecodeBudget.ts` (`reserveRow = 256` bytes per row,
 * `reserveString = encodedBytes * 6 + 2`, and repeated occurrences in `admitManagedProjection`
 * paying full JSON byte cost) plus `ReconstructionObligationPolicies.ts` (`managed-pinvoke-import`
 * and `managed-native-implementation`).
 */
export function planDotnetManagedBudgetExhaustion(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): DotnetManagedExhaustionPlan {
  const rowCount =
    intensity === "stealth"
      ? 256
      : intensity === "balanced"
        ? 512
        : intensity === "maximum"
          ? 1024
          : 2048;
  const tag = prng.hex(3);
  const decoyPInvokeImports: string[] = [];
  let estimatedReaStringChargeBytes = 0;

  for (let i = 0; i < 16; i++) {
    const sym = `enclave_pinvoke_unseal_ring0_slot_${tag}_${i}`;
    decoyPInvokeImports.push(sym);
  }

  for (let r = 0; r < rowCount; r++) {
    const encodedLen = 180;
    // REA charges `encodedBytes * 6 + 2` in `ManagedDecodeBudget.reserveString`
    estimatedReaStringChargeBytes += encodedLen * 6 + 2;
  }

  const estimatedReaRowChargeBytes = rowCount * 256;
  const totalReaRepresentationChargeBytes =
    estimatedReaStringChargeBytes + estimatedReaRowChargeBytes;

  return {
    decoyNamespaceCount: Math.ceil(rowCount / 32),
    decoyPInvokeImports,
    estimatedReaStringChargeBytes,
    estimatedReaRowChargeBytes,
    totalReaRepresentationChargeBytes,
  };
}

export function protectDotnetManagedBuffer(
  rawBuffer: Buffer,
  options: {
    readonly intensity?: ProtectionIntensity;
    readonly seed?: string | number;
  } = {},
): {
  readonly buffer: Buffer;
  readonly plan: DotnetManagedExhaustionPlan;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
} {
  const intensity = options.intensity ?? "balanced";
  const prng = new SeededPrng(options.seed ?? "bla-dotnet-v1");
  const plan = planDotnetManagedBudgetExhaustion(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);
  // Stay under REA_MAX_MANAGED_METADATA_REPRESENTATION_BYTES (64 MiB) while
  // still flooding ManagedDecodeBudget string/row charges with canary bait.
  const metadataSection = Buffer.from(
    [
      "",
      "BLA_DOTNET_CLR_SHIELD_V1",
      ...plan.decoyPInvokeImports,
      `charge:${plan.totalReaRepresentationChargeBytes}`,
      `maxRepresentationBytes:${REA_MAX_MANAGED_METADATA_REPRESENTATION_BYTES}`,
      ...deception.textRecords,
      "",
    ].join("\0"),
    "utf8",
  );
  return {
    buffer: Buffer.concat([rawBuffer, metadataSection]),
    plan,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
  };
}
