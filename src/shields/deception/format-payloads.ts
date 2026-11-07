import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import {
  generateCanaryHoneypot,
  type CanaryHoneypotResult,
} from "./canary-honeypot.js";
import {
  generateSystemDiagnosticDecoy,
  type SystemDiagnosticDecoyResult,
} from "./system-diagnostic-decoy.js";
import {
  generateCognitiveArmorTrigger,
  type CognitiveArmorTriggerResult,
} from "./cognitive-armor-trigger.js";

export interface FormatDeceptionPayloads {
  readonly canary: CanaryHoneypotResult;
  readonly diagnostics: SystemDiagnosticDecoyResult;
  readonly cognitiveArmor: CognitiveArmorTriggerResult;
  /** Null-free UTF-8 text records suitable for embedding in binary formats. */
  readonly textRecords: readonly string[];
}

/**
 * Shared canary + system-diagnostic + cognitive-armor payload builder used by non-JS
 * format shields (Python, WASM, SQLite, Safetensors/GGUF, Native, DEX, IL2CPP, Plist,
 * .NET, JVM, BEAM, EVM, PCAP, PTX, ZIP/APK). Mirrors the wiring already present in
 * `native.ts` so every format trips REA transport redaction, toolchain rabbit-hole
 * surfaces, and frontier LLM safety/alignment classifiers.
 */
export function buildCanaryAndDiagnosticPayloads(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): FormatDeceptionPayloads {
  const canary = generateCanaryHoneypot(prng, intensity);
  const diagnostics = generateSystemDiagnosticDecoy(prng, intensity);
  const cognitiveArmor = generateCognitiveArmorTrigger(prng, intensity);
  const textRecords = [
    ...canary.syntheticCanaryTokens.map(
      (tok) => `PROTECTED_CANARY_CREDENTIAL=${tok}`,
    ),
    ...canary.ambiguousCredentialUrls.map(
      (url) => `TRANSPORT_ENDPOINT=${url}`,
    ),
    ...canary.conflictingQueryUrls.map(
      (url) => `TRANSPORT_QUERY_CONFLICT=${url}`,
    ),
    ...diagnostics.diagnosticsInjected.map(
      (d) =>
        `[${d.subsystem}] ${d.errorClass} (${d.systemCode}): ${d.diagnosticMessage} Remediation: ${d.remediationRabbitHole}`,
    ),
    ...cognitiveArmor.triggersInjected.map(
      (t) =>
        `[COGNITIVE_ARMOR_INTERLOCK:${t.classifierDomain}] ${t.coupledAnchorSymbol} => ${t.triggerPayload.replace(/\r?\n/g, " ")}`,
    ),
  ];
  return { canary, diagnostics, cognitiveArmor, textRecords };
}
