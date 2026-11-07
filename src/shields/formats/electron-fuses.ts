import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { SeededPrng } from "../../core/prng.js";

export class UnsupportedElectronFuseContextError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UnsupportedElectronFuseContextError";
  }
}

/**
 * Electron V1 Fuse Wire constants (`src/domain/electron/electronFuses.ts` in `morluto/rea`).
 */
export const ELECTRON_FUSE_SENTINEL_BYTES = Buffer.from(
  REA_INTERNAL_LIMITS.ELECTRON_FUSE_SENTINEL,
  "ascii",
);

export const ELECTRON_FUSE_STATE = {
  DISABLED: 0x30, // '0'
  ENABLED: 0x31, // '1'
  REMOVED: 0x72, // 'r'
  DECOY: 0x39, // '9' (BLA decoy sentinel wire marker)
} as const;

export const ELECTRON_FUSE_NAMES = [
  "RunAsNode",
  "EnableCookieEncryption",
  "EnableNodeOptionsEnvironmentVariable",
  "EnableNodeCliInspectArguments",
  "EnableEmbeddedAsarIntegrityValidation",
  "OnlyLoadAppFromAsar",
  "LoadBrowserProcessSpecificV8Snapshot",
  "GrantFileProtocolExtraPrivileges",
] as const;

export type ElectronFuseName = (typeof ELECTRON_FUSE_NAMES)[number];
export type ElectronFuseWireValue =
  | "enabled"
  | "disabled"
  | "removed"
  | "unknown";
export type ElectronFuseStatus =
  | "verified"
  | "absent"
  | "unsupported"
  | "ambiguous";

export interface ElectronFuseInspectionResult {
  readonly status: ElectronFuseStatus;
  readonly sentinelCount: number;
  readonly sentinelOffsets: readonly number[];
  readonly realFuseOffset: number;
  readonly fuseVersion: number;
  readonly fuseWireLength: number;
  readonly fuses: Partial<Record<ElectronFuseName, ElectronFuseWireValue>>;
  readonly runAsNodeEnabled: boolean;
  readonly nodeCliInspectEnabled: boolean;
  readonly nodeOptionsEnabled: boolean;
  readonly asarIntegrityEnforced: boolean;
  readonly onlyLoadFromAsarEnforced: boolean;
  readonly exceedsReaSentinelLimit: boolean;
  readonly hardened: boolean;
  readonly diagnostic?: string;
}

export type ElectronFuseInspectionSummary = ElectronFuseInspectionResult;

export interface ElectronHardeningContext {
  readonly electronVersion: string;
  readonly asarPath?: string;
  readonly hasEmbeddedAsarIntegrity: boolean;
  readonly asarHeaderHash?: string;
  readonly codeSigningPolicy: "will-resign" | "unsigned-local-fixture";
  readonly injectDecoySentinelOverflow?: boolean;
  readonly seed?: string | number;
  readonly allowRawContainer?: boolean;
}

export interface ElectronHardeningReport {
  readonly buffer: Buffer;
  readonly fusePolicy: {
    readonly status: "hardened";
    readonly fuseVersion: number;
    readonly fuseOffset: number;
    readonly mutatedFuses: Readonly<
      Record<
        string,
        {
          readonly from: ElectronFuseWireValue;
          readonly to: ElectronFuseWireValue;
        }
      >
    >;
    readonly decoySentinelsInjected: number;
  };
  readonly asarIntegrityStatus: "verified" | "not-applicable";
  readonly signatureStatus: "unverified-requires-resign" | "unsigned-fixture";
  readonly mutatedFuses: readonly ElectronFuseName[];
}

function decodeFuseByte(byte: number): ElectronFuseWireValue {
  if (byte === ELECTRON_FUSE_STATE.DISABLED) return "disabled";
  if (byte === ELECTRON_FUSE_STATE.ENABLED) return "enabled";
  if (byte === ELECTRON_FUSE_STATE.REMOVED) return "removed";
  return "unknown";
}

function isValidWireByte(byte: number): boolean {
  return (
    byte === ELECTRON_FUSE_STATE.DISABLED ||
    byte === ELECTRON_FUSE_STATE.ENABLED ||
    byte === ELECTRON_FUSE_STATE.REMOVED ||
    byte === ELECTRON_FUSE_STATE.DECOY
  );
}

export function isSupportedNativeExecutableContainer(bytes: Buffer): boolean {
  if (
    bytes.length >= 20 &&
    bytes[0] === 0x7f &&
    bytes[1] === 0x45 &&
    bytes[2] === 0x4c &&
    bytes[3] === 0x46
  ) {
    return true;
  }
  if (bytes.length >= 8) {
    const magicBE = bytes.readUInt32BE(0);
    if (
      magicBE === 0xfeedfacf ||
      magicBE === 0xcffaedfe ||
      magicBE === 0xfeedface ||
      magicBE === 0xcefaedfe ||
      magicBE === 0xcafebabe
    ) {
      return true;
    }
    if (bytes[0] === 0x4d && bytes[1] === 0x5a) {
      return true;
    }
  }
  return false;
}

/**
 * Inspects a binary buffer (ELF / Mach-O / PE) for Electron Fuse sentinels
 * (`dL7pKGdnNz796PbbjQWNKmHXBZaB9tsX`), matching REA's `ElectronFuseReader.ts`
 * while distinguishing verified V1 fuse blocks from unsupported/truncated/ambiguous wires.
 */
export function inspectElectronFusesBuffer(
  bytes: Buffer,
): ElectronFuseInspectionResult {
  const offsets: number[] = [];
  let from = 0;
  while (from <= bytes.length - ELECTRON_FUSE_SENTINEL_BYTES.length) {
    const found = bytes.indexOf(ELECTRON_FUSE_SENTINEL_BYTES, from);
    if (found < 0) break;
    offsets.push(found);
    from = found + 1;
    if (offsets.length >= 128) break;
  }

  const exceedsReaSentinelLimit =
    offsets.length > REA_INTERNAL_LIMITS.ELECTRON_MAX_SENTINELS_PER_SLICE;

  const makeEmptyResult = (
    status: ElectronFuseStatus,
    diagnostic?: string,
  ): ElectronFuseInspectionResult => ({
    status,
    sentinelCount: offsets.length,
    sentinelOffsets: offsets,
    realFuseOffset: -1,
    fuseVersion: 0,
    fuseWireLength: 0,
    fuses: {},
    runAsNodeEnabled: false,
    nodeCliInspectEnabled: false,
    nodeOptionsEnabled: false,
    asarIntegrityEnforced: false,
    onlyLoadFromAsarEnforced: false,
    exceedsReaSentinelLimit,
    hardened: false,
    ...(diagnostic !== undefined ? { diagnostic } : {}),
  });

  if (offsets.length === 0) {
    return makeEmptyResult("absent");
  }

  interface RealCandidate {
    readonly offset: number;
    readonly version: number;
    readonly len: number;
    readonly wire: Buffer;
  }

  const realCandidates: RealCandidate[] = [];
  let unsupportedReason: string | undefined;

  for (const off of offsets) {
    const wireStart = off + ELECTRON_FUSE_SENTINEL_BYTES.length;
    if (wireStart + 2 > bytes.length) {
      return makeEmptyResult("unsupported", "truncated fuse header");
    }

    const version = bytes[wireStart]!;
    const len = bytes[wireStart + 1]!;

    if (wireStart + 2 + len > bytes.length) {
      return makeEmptyResult("unsupported", "truncated fuse wire");
    }

    if (version !== 1) {
      unsupportedReason = `unsupported fuse version ${version}`;
      continue;
    }

    if (len < 6) {
      unsupportedReason = `fuse wire length ${len} shorter than minimum 6`;
      continue;
    }

    const wire = bytes.subarray(wireStart + 2, wireStart + 2 + len);
    for (let i = 0; i < wire.length; i++) {
      if (!isValidWireByte(wire[i]!)) {
        return makeEmptyResult("unsupported", "invalid fuse wire byte");
      }
    }

    // BLA decoy sentinels contain 0x39 ('9') wire markers
    if (wire.includes(ELECTRON_FUSE_STATE.DECOY)) {
      continue;
    }

    realCandidates.push({
      offset: off,
      version,
      len,
      wire,
    });
  }

  if (realCandidates.length > 1) {
    return makeEmptyResult("ambiguous", "multiple real fuse blocks found");
  }

  if (realCandidates.length === 0) {
    return makeEmptyResult(
      "unsupported",
      unsupportedReason ?? "no verified real V1 fuse block found",
    );
  }

  const real = realCandidates[0]!;
  const fuses: Partial<Record<ElectronFuseName, ElectronFuseWireValue>> = {};
  const maxNamed = Math.min(real.len, ELECTRON_FUSE_NAMES.length);
  for (let i = 0; i < maxNamed; i++) {
    const fuseName = ELECTRON_FUSE_NAMES[i]!;
    fuses[fuseName] = decodeFuseByte(real.wire[i]!);
  }

  const runAsNodeEnabled = real.wire[0] === ELECTRON_FUSE_STATE.ENABLED;
  const cookieEncryptionEnabled = real.wire[1] === ELECTRON_FUSE_STATE.ENABLED;
  const nodeOptionsEnabled = real.wire[2] === ELECTRON_FUSE_STATE.ENABLED;
  const nodeCliInspectEnabled = real.wire[3] === ELECTRON_FUSE_STATE.ENABLED;
  const asarIntegrityEnforced = real.wire[4] === ELECTRON_FUSE_STATE.ENABLED;
  const onlyLoadFromAsarEnforced = real.wire[5] === ELECTRON_FUSE_STATE.ENABLED;

  const hardened =
    !runAsNodeEnabled &&
    cookieEncryptionEnabled &&
    !nodeOptionsEnabled &&
    !nodeCliInspectEnabled &&
    asarIntegrityEnforced &&
    onlyLoadFromAsarEnforced;

  return {
    status: "verified",
    sentinelCount: offsets.length,
    sentinelOffsets: offsets,
    realFuseOffset: real.offset,
    fuseVersion: real.version,
    fuseWireLength: real.len,
    fuses,
    runAsNodeEnabled,
    nodeCliInspectEnabled,
    nodeOptionsEnabled,
    asarIntegrityEnforced,
    onlyLoadFromAsarEnforced,
    exceedsReaSentinelLimit,
    hardened,
  };
}

export const inspectElectronFusesInBuffer = inspectElectronFusesBuffer;

/**
 * Builds 34 decoy sentinel records (`> maximumSentinelsPerSlice = 32`) tagged with
 * BLA's `0x39` (`'9'`) decoy marker so `inspectElectronFusesBuffer` distinguishes
 * them from real V1 fuse blocks while tripping REA's sentinel slice limit.
 */
export function buildDecoyElectronFuseSentinels(
  prng: SeededPrng,
  decoyCount = 34,
): Buffer {
  const wires: Buffer[] = [];
  for (let i = 0; i < decoyCount; i++) {
    const wireHeader = Buffer.from([
      0x01, // wire_version = 1
      0x08, // declared_length = 8
      ELECTRON_FUSE_STATE.DISABLED,
      ELECTRON_FUSE_STATE.ENABLED,
      ELECTRON_FUSE_STATE.DISABLED,
      ELECTRON_FUSE_STATE.DISABLED,
      ELECTRON_FUSE_STATE.ENABLED,
      ELECTRON_FUSE_STATE.ENABLED,
      ELECTRON_FUSE_STATE.DECOY,
      prng.nextInt(0, 1) === 0
        ? ELECTRON_FUSE_STATE.DECOY
        : ELECTRON_FUSE_STATE.REMOVED,
    ]);
    wires.push(ELECTRON_FUSE_SENTINEL_BYTES, wireHeader);
  }
  return Buffer.concat(wires);
}

/**
 * Hardens a single verified Electron Fuse V1 wire in-place (if present and unambiguous)
 * AND builds a 34-sentinel overflow trailer that trips REA's
 * `ELECTRON_FUSE_LIMITS.maximumSentinelsPerSlice = 32`.
 */
export function hardenAndOverflowElectronFuses(
  bytes: Buffer,
  prng: SeededPrng,
): {
  readonly patchedInPlaceCount: number;
  readonly decoySentinelsBuffer: Buffer;
  readonly decoySentinelsInjected: number;
} {
  let patchedInPlaceCount = 0;
  const inspection = inspectElectronFusesBuffer(bytes);

  if (inspection.status === "verified" && inspection.realFuseOffset >= 0) {
    const wireStart =
      inspection.realFuseOffset + ELECTRON_FUSE_SENTINEL_BYTES.length;
    bytes[wireStart + 2 + 0] = ELECTRON_FUSE_STATE.DISABLED;
    bytes[wireStart + 2 + 1] = ELECTRON_FUSE_STATE.ENABLED;
    bytes[wireStart + 2 + 2] = ELECTRON_FUSE_STATE.DISABLED;
    bytes[wireStart + 2 + 3] = ELECTRON_FUSE_STATE.DISABLED;
    bytes[wireStart + 2 + 4] = ELECTRON_FUSE_STATE.ENABLED;
    bytes[wireStart + 2 + 5] = ELECTRON_FUSE_STATE.ENABLED;
    patchedInPlaceCount = 1;
  }

  const decoyCount = 34;
  const decoySentinelsBuffer = buildDecoyElectronFuseSentinels(
    prng,
    decoyCount,
  );

  return {
    patchedInPlaceCount,
    decoySentinelsBuffer,
    decoySentinelsInjected: decoyCount,
  };
}

/**
 * Context-verified Electron Fuse hardening entrypoint.
 * Verifies executable container format, unambiguous V1 fuse wire, Electron version,
 * embedded ASAR integrity metadata, and code-signing policy before mutating any fuse bytes.
 */
export function hardenElectronFusesWithContext(
  bytes: Buffer,
  context: ElectronHardeningContext,
): ElectronHardeningReport {
  if (!context || typeof context !== "object") {
    throw new UnsupportedElectronFuseContextError(
      "Missing Electron hardening context",
    );
  }

  if (
    !context.allowRawContainer &&
    !isSupportedNativeExecutableContainer(bytes)
  ) {
    throw new UnsupportedElectronFuseContextError(
      "Target is not a supported native Electron executable container (ELF, Mach-O, or PE)",
    );
  }

  const versionMatch =
    typeof context.electronVersion === "string"
      ? /^v?(\d+)\.(\d+)\.(\d+)/.exec(context.electronVersion.trim())
      : null;
  if (!versionMatch) {
    throw new UnsupportedElectronFuseContextError(
      `Invalid or missing Electron version: ${String(context.electronVersion)}`,
    );
  }
  const majorVersion = Number(versionMatch[1]);
  if (!Number.isSafeInteger(majorVersion) || majorVersion < 12) {
    throw new UnsupportedElectronFuseContextError(
      `Unsupported Electron major version ${majorVersion} (requires Electron >= 12.0.0)`,
    );
  }

  if (
    context.codeSigningPolicy !== "will-resign" &&
    context.codeSigningPolicy !== "unsigned-local-fixture"
  ) {
    throw new UnsupportedElectronFuseContextError(
      `Unsupported or missing codeSigningPolicy: ${String(context.codeSigningPolicy)}`,
    );
  }

  if (
    context.hasEmbeddedAsarIntegrity !== true ||
    typeof context.asarHeaderHash !== "string" ||
    !/^[0-9a-fA-F]{64}$/.test(context.asarHeaderHash) ||
    (context.asarPath !== undefined && context.asarPath.trim().length === 0)
  ) {
    throw new UnsupportedElectronFuseContextError(
      "Cannot enable EnableEmbeddedAsarIntegrityValidation or OnlyLoadAppFromAsar without verified embedded ASAR integrity metadata (hasEmbeddedAsarIntegrity=true and 64-hex SHA-256 asarHeaderHash)",
    );
  }

  const inspection = inspectElectronFusesBuffer(bytes);
  if (inspection.status !== "verified" || inspection.realFuseOffset < 0) {
    throw new UnsupportedElectronFuseContextError(
      `Cannot harden Electron fuses: fuse inspection status is '${inspection.status}'${inspection.diagnostic ? ` (${inspection.diagnostic})` : ""}`,
    );
  }

  const working = Buffer.from(bytes);
  const wireStart =
    inspection.realFuseOffset + ELECTRON_FUSE_SENTINEL_BYTES.length;

  const desiredPlan: ReadonlyArray<{
    readonly index: number;
    readonly name: ElectronFuseName;
    readonly byte: number;
    readonly value: ElectronFuseWireValue;
  }> = [
    {
      index: 0,
      name: "RunAsNode",
      byte: ELECTRON_FUSE_STATE.DISABLED,
      value: "disabled",
    },
    {
      index: 1,
      name: "EnableCookieEncryption",
      byte: ELECTRON_FUSE_STATE.ENABLED,
      value: "enabled",
    },
    {
      index: 2,
      name: "EnableNodeOptionsEnvironmentVariable",
      byte: ELECTRON_FUSE_STATE.DISABLED,
      value: "disabled",
    },
    {
      index: 3,
      name: "EnableNodeCliInspectArguments",
      byte: ELECTRON_FUSE_STATE.DISABLED,
      value: "disabled",
    },
    {
      index: 4,
      name: "EnableEmbeddedAsarIntegrityValidation",
      byte: ELECTRON_FUSE_STATE.ENABLED,
      value: "enabled",
    },
    {
      index: 5,
      name: "OnlyLoadAppFromAsar",
      byte: ELECTRON_FUSE_STATE.ENABLED,
      value: "enabled",
    },
  ];

  const mutatedMap: Record<
    string,
    { readonly from: ElectronFuseWireValue; readonly to: ElectronFuseWireValue }
  > = {};
  const mutatedNames: ElectronFuseName[] = [];

  for (const item of desiredPlan) {
    const currentByte = working[wireStart + 2 + item.index]!;
    const fromVal = decodeFuseByte(currentByte);
    if (currentByte !== item.byte) {
      working[wireStart + 2 + item.index] = item.byte;
      mutatedMap[item.name] = { from: fromVal, to: item.value };
      mutatedNames.push(item.name);
    }
  }

  let outBuffer = working;
  let decoySentinelsInjected = 0;
  if (context.injectDecoySentinelOverflow) {
    const prng = new SeededPrng(context.seed ?? "bla-electron-fuses-v1");
    decoySentinelsInjected = 34;
    const decoyBuf = buildDecoyElectronFuseSentinels(
      prng,
      decoySentinelsInjected,
    );
    outBuffer = Buffer.concat([working, decoyBuf]);
  }

  return {
    buffer: outBuffer,
    fusePolicy: {
      status: "hardened",
      fuseVersion: inspection.fuseVersion,
      fuseOffset: inspection.realFuseOffset,
      mutatedFuses: mutatedMap,
      decoySentinelsInjected,
    },
    asarIntegrityStatus: "verified",
    signatureStatus:
      context.codeSigningPolicy === "will-resign"
        ? "unverified-requires-resign"
        : "unsigned-fixture",
    mutatedFuses: mutatedNames,
  };
}
