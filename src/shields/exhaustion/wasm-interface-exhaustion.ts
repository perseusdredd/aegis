import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { computeReaWasmInterfaceCharge } from "./rea-budget-matrix.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";

export interface WasmExhaustionDescriptor {
  readonly moduleName: string;
  readonly exportName: string;
  readonly paramCount: number;
  readonly resultCount: number;
  readonly reaChargedRepresentationBytes: number;
}

export interface WasmInterfaceExhaustionPlan {
  readonly descriptors: readonly WasmExhaustionDescriptor[];
  readonly totalBinaryOverheadBytes: number;
  readonly totalReaChargedBytes: number;
  readonly byteAmplificationFactor: number;
  readonly exceedsRepresentationBudget: boolean;
}

/**
 * Targets REA's `WasmInterfaceBudget` (`WASM_INTERFACE_REPRESENTATION_BYTES` =
 * 32 MiB), where every WebAssembly import/export entry is charged:
 * `1024 + (module.length + name.length + wat_form.length) * 6 + (params+results) * 16`.
 *
 * At bankrupt intensity, descriptors are sized so the charged representation
 * exceeds the 32 MiB ceiling (Wabt path or in-process budget probe).
 */
export function planWasmInterfaceBudgetExhaustion(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): WasmInterfaceExhaustionPlan {
  const budget = REA_INTERNAL_LIMITS.WASM_INTERFACE_REPRESENTATION_BYTES;
  const count =
    intensity === "stealth"
      ? 12
      : intensity === "balanced"
        ? 24
        : intensity === "maximum"
          ? 48
          : 128;
  // bankrupt: long module/export/wat names so ~128 entries clear 32 MiB.
  // bankrupt: ~15 KiB names × 128 entries → charged representation ≫ 32 MiB.
  const namePad =
    intensity === "bankrupt" ? 15_000 : intensity === "maximum" ? 64 : 0;

  const descriptors: WasmExhaustionDescriptor[] = [];
  let totalBinaryOverheadBytes = 0;
  let totalReaChargedBytes = 0;

  for (let i = 0; i < count; i++) {
    const pad = namePad > 0 ? prng.hex(Math.min(8, namePad)).padEnd(namePad, "b") : "";
    const moduleName = `enclave_tee_ring0_attestation_domain_${prng.hex(6)}${pad ? `_${pad}` : ""}`;
    const exportName = `bla_enclave_verify_zero_trust_merkle_slot_${i}_${prng.hex(8)}${pad ? `_${pad}` : ""}`;
    const paramCount = 16;
    const resultCount = 4;
    const watForm = `(func $${exportName} (param ${Array(paramCount).fill("i64").join(" ")}) (result ${Array(resultCount).fill("i64").join(" ")}))`;
    const reaChargedRepresentationBytes = computeReaWasmInterfaceCharge({
      moduleName,
      exportOrImportName: exportName,
      watForm,
      paramCount,
      resultCount,
    });
    const binaryBytes =
      moduleName.length + exportName.length + paramCount + resultCount + 8;

    descriptors.push({
      moduleName,
      exportName,
      paramCount,
      resultCount,
      reaChargedRepresentationBytes,
    });
    totalBinaryOverheadBytes += binaryBytes;
    totalReaChargedBytes += reaChargedRepresentationBytes;
  }

  return {
    descriptors,
    totalBinaryOverheadBytes,
    totalReaChargedBytes,
    byteAmplificationFactor: Number(
      (totalReaChargedBytes / Math.max(1, totalBinaryOverheadBytes)).toFixed(2),
    ),
    exceedsRepresentationBudget: totalReaChargedBytes > budget,
  };
}
