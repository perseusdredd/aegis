import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

export interface AndroidManifestCounterResult {
  /** Well-formed UTF-8 AndroidManifest.xml (never binary AXML). */
  readonly manifestXml: string;
  /** Named component declarations emitted (activities/services/…). */
  readonly namedComponentsEmitted: number;
  /** Declarations deliberately missing `android:name` (unnamed flood). */
  readonly unnamedComponentsEmitted: number;
  /** Names containing `@` / `?` / `${…}` unresolved tokens. */
  readonly unresolvedTokenNames: number;
  /** Nested `$` class names preserved for REA #7818 spelling retention. */
  readonly nestedDollarNames: number;
  /** Intent-filter children planted per high-intensity activity. */
  readonly intentFiltersPerHeavy: number;
  /** Provider authority segments planted on the flood provider. */
  readonly authoritySegmentsEmitted: number;
  readonly chaffPayloadsEmbedded: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
}

const PACKAGE_NAME = "com.enclave.sgx.teeattestation";

/** XML attribute escaping — keeps the document well-formed for REA's XML parser. */
function escAttr(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function intensityScale(intensity: ProtectionIntensity): {
  namedPastCap: number;
  unnamed: number;
  unresolvedTokens: number;
  nestedDollar: number;
  namePadChars: number;
  heavyIntentFilters: number;
  authoritySegments: number;
  processPadChars: number;
} {
  // Always exceed ANDROID_MANIFEST_COMPONENTS (512). Name padding is sized so
  // the first ~N resolved relative names also burn resolvedNameBytes (1 MiB).
  const cap = REA_INTERNAL_LIMITS.ANDROID_MANIFEST_COMPONENTS;
  switch (intensity) {
    case "stealth":
      return {
        namedPastCap: 16,
        unnamed: 4,
        unresolvedTokens: 8,
        nestedDollar: 8,
        namePadChars: 1_024,
        heavyIntentFilters: REA_INTERNAL_LIMITS.ANDROID_MANIFEST_INTENT_FILTERS + 4,
        authoritySegments: REA_INTERNAL_LIMITS.ANDROID_MANIFEST_AUTHORITIES + 8,
        processPadChars: 256,
      };
    case "maximum":
    case "bankrupt":
      return {
        namedPastCap: 256,
        unnamed: 32,
        unresolvedTokens: 48,
        nestedDollar: 64,
        namePadChars: 4_096,
        heavyIntentFilters: REA_INTERNAL_LIMITS.ANDROID_MANIFEST_INTENT_FILTERS * 2,
        authoritySegments: REA_INTERNAL_LIMITS.ANDROID_MANIFEST_AUTHORITIES * 3,
        processPadChars: 2_048,
      };
    case "balanced":
    default:
      return {
        namedPastCap: 64,
        unnamed: 12,
        unresolvedTokens: 24,
        nestedDollar: 24,
        namePadChars: 2_048,
        heavyIntentFilters: REA_INTERNAL_LIMITS.ANDROID_MANIFEST_INTENT_FILTERS + 8,
        authoritySegments: REA_INTERNAL_LIMITS.ANDROID_MANIFEST_AUTHORITIES + 32,
        processPadChars: 1_024,
      };
  }
}

/**
 * Generates a caller-tempting, well-formed decoy `AndroidManifest.xml` that
 * counters REA's static component inventory (`parseAndroidManifestComponents`,
 * REA #7379) and its spelling-preserving binary-XML decode path (#7818):
 *
 * - Named declarations past `ANDROID_MANIFEST_LIMITS.components` (512) force
 *   `capacityTruncated` → inventory `status: "partial"`.
 * - Long package-relative names burn `resolvedNameBytes` (1 MiB) so later
 *   names keep their declared form (`unresolvedNames`).
 * - Unnamed / `@string/` / `${placeholder}` declarations trigger the
 *   corresponding limitation strings REA itself publishes.
 * - Nested `$` class names exercise #7818's "preserve component spelling".
 * - Provider authority floods past `authorities: 64` and intent-filter floods
 *   past `intentFilters: 32` / `intentValues: 64` deepen the partial admission.
 *
 * Red-line safe: this is a NEW decoy XML artifact (sidecar under
 * `assets/bla-shield/`). It never rewrites the developer's root
 * `AndroidManifest.xml`, never changes the real export surface, and never
 * emits binary AXML that could invalidate an APK signature check path we
 * already refuse for signed APKs.
 */
export function generateAndroidManifestCounter(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): AndroidManifestCounterResult {
  const scale = intensityScale(intensity);
  const chaff = generateChaffPayloads(prng, intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);

  const cap = REA_INTERNAL_LIMITS.ANDROID_MANIFEST_COMPONENTS;
  const namedTarget = cap + scale.namedPastCap;

  const kinds = [
    "activity",
    "service",
    "receiver",
    "provider",
    "activity-alias",
  ] as const;

  const lines: string[] = [
    `<?xml version="1.0" encoding="utf-8"?>`,
    `<!-- bla-shield: decoy AndroidManifest — saturates REA #7379/#7818 component inventory -->`,
    `<manifest xmlns:android="http://schemas.android.com/apk/res/android"`,
    `    package="${PACKAGE_NAME}"`,
    `    android:versionCode="1"`,
    `    android:versionName="1.0-bla-enclave-shield">`,
    `  <uses-sdk android:minSdkVersion="24" android:targetSdkVersion="34" />`,
    `  <uses-permission android:name="android.permission.INTERNET" />`,
    `  <uses-permission android:name="com.enclave.sgx.permission.TEE_ATTEST" />`,
    `  <application`,
    `      android:label="BLA Enclave Shield Decoy"`,
    `      android:permission="com.enclave.sgx.permission.TEE_ATTEST"`,
    `      android:allowBackup="false">`,
  ];

  // Seed a few "real-looking" nested-$ activities first so #7818 spelling
  // retention surfaces them even if a later capacity cut drops the flood.
  const nestedNames: string[] = [
    ".TeeAttestationBridge$DetailsActivity",
    ".TeeAttestationBridge$QuorumRingFragment",
    ".KeyUnsealerStub$VsockCid16Transport",
    ".NitroAttestation$ShamirEd25519Quorum",
  ];
  let nestedDollarNames = 0;
  for (let i = 0; i < Math.min(scale.nestedDollar, nestedNames.length); i++) {
    const declared = nestedNames[i]!;
    lines.push(
      `    <activity android:name="${escAttr(declared)}" android:exported="false" android:enabled="true">`,
      `      <intent-filter>`,
      `        <action android:name="com.enclave.sgx.action.VERIFY_SHAMIR_${i}" />`,
      `        <category android:name="android.intent.category.DEFAULT" />`,
      `      </intent-filter>`,
      `      <meta-data android:name="bla.canary" android:value="${escAttr(deception.textRecords[i % deception.textRecords.length] ?? "PROTECTED_CANARY")}" />`,
      `    </activity>`,
    );
    nestedDollarNames += 1;
  }
  // Extra nested-$ names beyond the seed list.
  for (let i = nestedNames.length; i < scale.nestedDollar; i++) {
    const declared = `.EnclaveStateNode$${prng.hex(6)}$Layer${i}`;
    lines.push(
      `    <activity android:name="${escAttr(declared)}" android:exported="false" />`,
    );
    nestedDollarNames += 1;
  }

  // Unresolved-token names — REA retains declared_name and marks inventory partial.
  let unresolvedTokenNames = 0;
  for (let i = 0; i < scale.unresolvedTokens; i++) {
    const kind = kinds[i % kinds.length]!;
    const token =
      i % 3 === 0
        ? `@string/enclave_bridge_${prng.hex(4)}`
        : i % 3 === 1
          ? `\${enclave.placeholder.bridge_${i}}`
          : `?attr/enclaveTeeBridge_${i}`;
    if (kind === "activity-alias") {
      lines.push(
        `    <activity-alias android:name="${escAttr(token)}" android:targetActivity=".TeeAttestationBridge$DetailsActivity" android:exported="false" />`,
      );
    } else if (kind === "provider") {
      lines.push(
        `    <provider android:name="${escAttr(token)}" android:authorities="com.enclave.token.${i}" android:exported="false" />`,
      );
    } else {
      lines.push(
        `    <${kind} android:name="${escAttr(token)}" android:exported="false" />`,
      );
    }
    unresolvedTokenNames += 1;
  }

  // One heavy provider that floods authorities past ANDROID_MANIFEST_AUTHORITIES.
  const authorityParts: string[] = [];
  for (let i = 0; i < scale.authoritySegments; i++) {
    if (i % 17 === 0) {
      // Empty / whitespace segments → malformedAuthoritySegments limitation.
      authorityParts.push(i % 34 === 0 ? "" : "  ");
    } else {
      authorityParts.push(`com.enclave.sgx.auth_${prng.hex(4)}_${i}`);
    }
  }
  const authoritySegmentsEmitted = authorityParts.length;
  lines.push(
    `    <provider`,
    `        android:name=".EnclaveAuthorityFloodProvider"`,
    `        android:authorities="${escAttr(authorityParts.join(";"))}"`,
    `        android:exported="@bool/bla_canary_exported"`,
    `        android:grantUriPermissions="@bool/bla_canary_grant"`,
    `        android:permission="com.enclave.sgx.permission.TEE_ATTEST"`,
    `        android:readPermission="com.enclave.sgx.permission.TEE_READ"`,
    `        android:writePermission="com.enclave.sgx.permission.TEE_WRITE" />`,
  );

  // One heavy activity that floods intent-filters past INTENT_FILTERS and
  // intent values past INTENT_VALUES (actions/categories/data + meta-data).
  const intentFiltersPerHeavy = scale.heavyIntentFilters;
  const processPad = "p".repeat(scale.processPadChars);
  lines.push(
    `    <activity`,
    `        android:name=".TeeAttestationBridge$IntentFloodActivity"`,
    `        android:exported="@bool/bla_canary_exported"`,
    `        android:enabled="@bool/bla_canary_enabled"`,
    `        android:process=":${escAttr(processPad)}">`,
  );
  for (let f = 0; f < intentFiltersPerHeavy; f++) {
    lines.push(`      <intent-filter android:priority="${1000 + f}">`);
    // Flood intentValues: many actions + categories + data attrs.
    const valuesPerFilter = Math.ceil(
      REA_INTERNAL_LIMITS.ANDROID_MANIFEST_INTENT_VALUES / 2,
    );
    for (let v = 0; v < valuesPerFilter; v++) {
      lines.push(
        `        <action android:name="com.enclave.sgx.action.FLOOD_${f}_${v}_${prng.hex(2)}" />`,
      );
    }
    for (let v = 0; v < 4; v++) {
      lines.push(
        `        <category android:name="com.enclave.sgx.category.FLOOD_${f}_${v}" />`,
      );
    }
    lines.push(
      `        <data android:scheme="enclave" android:host="vsock${f}" android:port="${6000 + f}" android:pathPrefix="/cid16/${f}" android:mimeType="application/vnd.enclave.sgx" />`,
    );
    lines.push(`      </intent-filter>`);
  }
  // Meta-data canary bait (counts toward detailBytes / intentValues).
  for (const rec of deception.textRecords.slice(0, 8)) {
    lines.push(
      `      <meta-data android:name="bla.canary.${prng.hex(4)}" android:value="${escAttr(rec.slice(0, 200))}" />`,
    );
  }
  for (const c of chaff.slice(0, 4)) {
    lines.push(
      `      <meta-data android:name="bla.chaff.${c.id}" android:value="${escAttr(c.rawText.slice(0, 160))}" />`,
    );
  }
  lines.push(`    </activity>`);

  // Capacity flood: named components past the 512 cap, with long relative
  // names so resolvedNameBytes burns out and later names stay unresolved.
  // Already emitted: nestedDollar + unresolvedTokens + 1 heavy provider + 1 heavy activity.
  const alreadyNamed = nestedDollarNames + unresolvedTokenNames + 2;
  const remainingNamed = Math.max(0, namedTarget - alreadyNamed);
  const padAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789_";
  const makePad = (n: number): string => {
    let out = "";
    while (out.length < n) {
      out += padAlphabet[prng.nextInt(0, padAlphabet.length - 1)]!;
    }
    return out.slice(0, n);
  };

  for (let i = 0; i < remainingNamed; i++) {
    const kind = kinds[i % kinds.length]!;
    // Relative name (leading '.') so REA resolves against package and charges
    // packageNameBytes + declaredBytes against the 1 MiB name budget.
    const pad = makePad(scale.namePadChars);
    const declared = `.EnclaveStateNode_${prng.hex(6)}_${i}_${pad}`;
    if (kind === "activity-alias") {
      // targetActivity deliberately does NOT match a preceding activity →
      // unresolvedTargetActivities limitation.
      lines.push(
        `    <activity-alias android:name="${escAttr(declared)}" android:targetActivity=".MissingTarget$${i}" android:exported="false" />`,
      );
    } else if (kind === "provider") {
      lines.push(
        `    <provider android:name="${escAttr(declared)}" android:authorities="com.enclave.tarpit.${i}" android:exported="false" />`,
      );
    } else if (kind === "service") {
      lines.push(
        `    <service android:name="${escAttr(declared)}" android:exported="false" android:foregroundServiceType="dataSync" />`,
      );
    } else {
      lines.push(
        `    <${kind} android:name="${escAttr(declared)}" android:exported="false" />`,
      );
    }
  }

  // Unnamed flood — every declaration without android:name counts against the
  // bound but is omitted from items, forcing truncated=true.
  let unnamedComponentsEmitted = 0;
  for (let i = 0; i < scale.unnamed; i++) {
    const kind = kinds[i % 3]!; // activity/service/receiver only (alias/provider need name more often)
    lines.push(`    <${kind} android:exported="false" />`);
    unnamedComponentsEmitted += 1;
  }

  lines.push(`  </application>`, `</manifest>`, ``);

  const namedComponentsEmitted = alreadyNamed + remainingNamed;
  return {
    manifestXml: lines.join("\n"),
    namedComponentsEmitted,
    unnamedComponentsEmitted,
    unresolvedTokenNames,
    nestedDollarNames,
    intentFiltersPerHeavy,
    authoritySegmentsEmitted,
    chaffPayloadsEmbedded: chaff.length,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
  };
}
