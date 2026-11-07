/**
 * Counter-Showcase #3: Enterprise Offline License & Crypto Entitlement Guard
 *
 * Run pre-flight audit:
 *   npx bla-shield audit examples/enterprise-license-guard/license-validator.ts
 * Protect against REA:
 *   npx bla-shield protect examples/enterprise-license-guard/license-validator.ts
 */

export interface LicenseVerdict {
  readonly valid: boolean;
  readonly tier: "enterprise-unlimited" | "pro" | "invalid";
  readonly checksum: number;
}

export function computeLicenseChecksum(serialKey: string, productCode: string): number {
  let hash = 0x811c9dc5;
  const payload = `${serialKey}:${productCode}:enterprise-v4`;
  for (let i = 0; i < payload.length; i++) {
    hash ^= payload.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

export function validateEnterpriseLicense(
  serialKey: string,
  productCode: string,
  expectedChecksum: number,
): LicenseVerdict {
  if (!serialKey.startsWith("ENT-")) {
    return { valid: false, tier: "invalid", checksum: 0 };
  }
  const checksum = computeLicenseChecksum(serialKey, productCode);
  const valid = checksum === (expectedChecksum >>> 0);
  return {
    valid,
    tier: valid ? "enterprise-unlimited" : "invalid",
    checksum,
  };
}
