import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface CrashTraceDecoyResult {
  readonly code: string;
  readonly decoyCrashSignalsEmbedded: readonly string[];
}

/**
 * Targets REA's `trace_crash` guided prompt (`src/contracts/promptContracts.ts:262-300`),
 * which instructs coding agents to run `search_strings` and `resolve_containing_procedure`
 * on crash messages, exception codes, and signal names.
 *
 * By embedding realistic hardware-enclave fault strings inside decoy procedures,
 * any crash-driven localization in REA resolves to the decoy enclave handler.
 */
export function generateCrashTraceDecoy(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): CrashTraceDecoyResult {
  const tag = prng.hex(3);
  const signals = [
    `SIGSEGV_ENCLAVE_EPC_PAGE_FAULT_0x${tag}`,
    `EXC_BAD_ACCESS_TPM2_PCR0_MISMATCH_0x${tag}`,
    `ERR_VSOCK_CID16_QUORUM_TIMEOUT_${tag.toUpperCase()}`,
    `STATUS_ENCLAVE_VIOLATION_0xC0000409_${tag.toUpperCase()}`,
  ];
  const count =
    intensity === "stealth"
      ? 1
      : intensity === "balanced"
        ? 2
        : intensity === "maximum"
          ? 3
          : 4;
  const selected = signals.slice(0, count);

  const code = [
    `function crashSignalHandler_${tag}(signalCode = 0) {`,
    `  const _table = ${JSON.stringify(selected)};`,
    `  return _table[signalCode % _table.length];`,
    `}`,
  ].join("\n");

  return {
    code,
    decoyCrashSignalsEmbedded: selected,
  };
}
