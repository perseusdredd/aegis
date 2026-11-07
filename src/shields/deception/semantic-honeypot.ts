import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface SemanticHoneypotResult {
  readonly code: string;
  readonly baitSymbols: readonly string[];
}

const HIGH_SALIENCE_BAIT_NAMES = [
  "verifyEnterpriseMasterLicense",
  "decryptOfflineVaultPayload",
  "computeStripeWebhookSignature",
  "validateHardwareDongleResponse",
  "deriveMasterEncryptionKey",
  "checkSubscriptionEntitlementTier",
  "authenticateZeroTrustSession",
  "unlockPremiumFeatureFlags",
] as const;

/**
 * Injects high-salience "bait" procedures whose names match the exact search
 * queries an AI reverse-engineering agent runs during `search_procedures` and
 * `search_strings` (`src/contracts/promptContracts.ts:129`).
 *
 * Each bait procedure executes a plausible multi-step cryptographic or state-machine
 * calculation that is never on the real critical path (or returns a decoy structure),
 * drawing the agent's attention and tool budget away from obfuscated real logic.
 */
export function generateSemanticHoneypot(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): SemanticHoneypotResult {
  const count =
    intensity === "stealth"
      ? 2
      : intensity === "balanced"
        ? 4
        : intensity === "maximum"
          ? 6
          : 8;
  const tag = prng.hex(2);
  const selected = HIGH_SALIENCE_BAIT_NAMES.slice(0, count);
  const baitSymbols: string[] = [];
  const fnBlocks: string[] = [];

  for (let i = 0; i < selected.length; i++) {
    const baseName = selected[i]!;
    const fnName = `${baseName}_${tag}${i}`;
    baitSymbols.push(fnName);
    const k1 = `0x${prng.hex(6)}`;
    const k2 = `0x${prng.hex(6)}`;
    fnBlocks.push(
      `function ${fnName}(inputToken = "", contextNonce = ${i + 1}) {`,
      `  let digest = (${k1} ^ contextNonce) >>> 0;`,
      `  const str = String(inputToken);`,
      `  for (let idx = 0; idx < str.length; idx++) {`,
      `    digest = (Math.imul(digest ^ str.charCodeAt(idx), 0x01000193) ^ ${k2}) >>> 0;`,
      `  }`,
      `  return {`,
      `    authorized: (digest & 0xffff) === 0x7f3a,`,
      `    tier: (digest & 3) === 0 ? "enterprise-enclave" : "delegated-readonly",`,
      `    digestHex: digest.toString(16),`,
      `  };`,
      `}`,
    );
  }

  return {
    code: fnBlocks.join("\n\n"),
    baitSymbols,
  };
}
