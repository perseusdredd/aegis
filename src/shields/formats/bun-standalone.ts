import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { generateChaffPayloads } from "../chaff/chaff-generator.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

/**
 * Bun standalone executable (`bun build --compile`) support — counters REA
 * #6998 (`BunStandaloneArtifactReader` / `BunModuleGraphLayout`), which
 * inventories and extracts the embedded `/$bunfs/` module graph from Mach-O
 * `__BUN,__bun`, PE/ELF `.bun` sections and the appended EOF trailer.
 *
 * Two halves:
 *  1. Red-line guard: Bun locates an appended graph relative to EOF at
 *     runtime, so anything appended after `\n---- Bun! ----\n` (or after its
 *     8-byte total-size footer) would break the developer's real program.
 *     `detectBunStandaloneGraph` lets the native shield refuse to append.
 *  2. Deception: `generateBunStandaloneDecoyGraph` emits a byte-exact,
 *     REA-admissible Bun 1.3.9 (52-byte record) module graph whose modules
 *     are canary / diagnostic / cognitive-armor honeypots, with deep virtual
 *     names past REA's 256-part logical-path allowance, unsafe and duplicate
 *     names, non-UTF-8 names, unknown loader discriminants and decoy
 *     sourcemap / bytecode / module-info regions.
 */

export const BUN_TRAILER = Buffer.from("\n---- Bun! ----\n", "latin1");
const OFFSETS_BYTES = 32;
const SUFFIX_BYTES = OFFSETS_BYTES + BUN_TRAILER.length;
const RECORD_BYTES = REA_INTERNAL_LIMITS.BUN_RECORD_BYTES_1_3_9;
const RECORD_BYTES_OLD = REA_INTERNAL_LIMITS.BUN_RECORD_BYTES_1_3_3;

export type BunCarrierDetection =
  | { readonly kind: "none" }
  | {
      readonly kind: "appended-trailer" | "appended-trailer-sized";
      /** Byte offset where the graph payload begins. */
      readonly payloadOffset: number;
      readonly payloadLength: number;
    }
  | { readonly kind: "embedded-sentinel"; readonly sentinelOffset: number };

/**
 * Cheap, allocation-free detection mirroring REA's appended-trailer probe.
 * `embedded-sentinel` means a section-carried graph (or a bare sentinel) —
 * EOF appends do not move it, but callers should still report it.
 */
export function detectBunStandaloneGraph(bytes: Buffer): BunCarrierDetection {
  const size = bytes.length;
  const at = (end: number): boolean =>
    end >= SUFFIX_BYTES &&
    bytes.subarray(end - BUN_TRAILER.length, end).equals(BUN_TRAILER);
  const claim = (end: number): { payloadOffset: number; payloadLength: number } | null => {
    const byteCount = bytes.readBigUInt64LE(end - SUFFIX_BYTES);
    const length = byteCount + BigInt(SUFFIX_BYTES);
    if (length > BigInt(end)) return null;
    return { payloadOffset: end - Number(length), payloadLength: Number(length) };
  };
  if (at(size)) {
    const c = claim(size);
    if (c) return { kind: "appended-trailer", ...c };
  }
  if (size >= SUFFIX_BYTES + 8 && at(size - 8)) {
    const c = claim(size - 8);
    if (c) return { kind: "appended-trailer-sized", ...c };
  }
  const idx = bytes.indexOf(BUN_TRAILER);
  if (idx >= 0) return { kind: "embedded-sentinel", sentinelOffset: idx };
  return { kind: "none" };
}

export interface BunDecoyModule {
  readonly name: Buffer;
  readonly contents: Buffer;
  readonly sourcemap?: Buffer;
  readonly bytecode?: Buffer;
  readonly moduleInfo?: Buffer;
  readonly bytecodeOrigin?: Buffer;
  readonly encoding: number;
  readonly loader: number;
  readonly moduleFormat: number;
  readonly side: number;
}

export interface BunDecoyGraphResult {
  /** Complete appended-trailer graph: data ‖ Offsets(32) ‖ trailer(16). */
  readonly buffer: Buffer;
  readonly moduleCount: number;
  readonly entryPointId: number;
  readonly deepNameModules: number;
  readonly unsafeNameModules: number;
  readonly duplicateNameModules: number;
  readonly nonUtf8NameModules: number;
  readonly unknownLoaderModules: number;
  readonly canaryTokensEmbedded: number;
  readonly diagnosticsEmbedded: number;
  readonly chaffPayloadsEmbedded: number;
}

function scaleFor(intensity: ProtectionIntensity): {
  honeyModules: number;
  deep: number;
  deepPartsOver: number;
} {
  switch (intensity) {
    case "stealth":
      return { honeyModules: 6, deep: 2, deepPartsOver: 8 };
    case "maximum":
    case "bankrupt":
      return { honeyModules: 40, deep: 24, deepPartsOver: 128 };
    case "balanced":
    default:
      return { honeyModules: 16, deep: 8, deepPartsOver: 32 };
  }
}

const LOADER_JS = 1;
const LOADER_TS = 2;
const LOADER_JSON = 6;
const LOADER_NAPI = 10;
const FORMAT_ESM = 1;
const FORMAT_CJS = 2;

/** Serialize modules exactly as Bun's StandaloneModuleGraph does (1.3.9+ record). */
export function serializeBunModuleGraph(input: {
  readonly modules: readonly BunDecoyModule[];
  readonly entryPointId: number;
  readonly compileExecArgv: Buffer;
  readonly flags?: number;
}): Buffer {
  const chunks: Buffer[] = [];
  let cursor = 0;
  const place = (bytes: Buffer | undefined, nul: boolean): [number, number] => {
    const b = bytes ?? Buffer.alloc(0);
    const offset = cursor;
    if (b.length > 0) {
      chunks.push(b);
      cursor += b.length;
      if (nul) {
        chunks.push(Buffer.from([0]));
        cursor += 1;
      }
    }
    return [offset, b.length];
  };
  const placed = input.modules.map((m) => ({
    m,
    name: place(m.name, true),
    contents: place(m.contents, true),
    sourcemap: place(m.sourcemap, false),
    bytecode: place(m.bytecode, false),
    moduleInfo: place(m.moduleInfo, false),
    origin: place(m.bytecodeOrigin, true),
  }));
  const argv = place(input.compileExecArgv, true);
  const tableOffset = cursor;
  const table = Buffer.alloc(placed.length * RECORD_BYTES);
  placed.forEach((row, i) => {
    const base = i * RECORD_BYTES;
    const ptr = (off: number, p: [number, number]): void => {
      table.writeUInt32LE(p[0], base + off);
      table.writeUInt32LE(p[1], base + off + 4);
    };
    ptr(0, row.name);
    ptr(8, row.contents);
    ptr(16, row.sourcemap);
    ptr(24, row.bytecode);
    ptr(32, row.moduleInfo);
    ptr(40, row.origin);
    table[base + 48] = row.m.encoding;
    table[base + 49] = row.m.loader;
    table[base + 50] = row.m.moduleFormat;
    table[base + 51] = row.m.side;
  });
  chunks.push(table);
  cursor += table.length;
  const data = Buffer.concat(chunks);
  const offsets = Buffer.alloc(OFFSETS_BYTES);
  offsets.writeBigUInt64LE(BigInt(data.length), 0);
  offsets.writeUInt32LE(tableOffset, 8);
  offsets.writeUInt32LE(table.length, 12);
  offsets.writeUInt32LE(input.entryPointId, 16);
  offsets.writeUInt32LE(argv[0], 20);
  offsets.writeUInt32LE(argv[1], 24);
  offsets.writeUInt32LE(input.flags ?? 0, 28);
  return Buffer.concat([data, offsets, BUN_TRAILER]);
}

/**
 * Builds a REA-admissible decoy Bun module graph full of honeypot modules.
 * The output is a NEW sidecar artifact; it is never spliced into the
 * developer's real executable.
 */
export function generateBunStandaloneDecoyGraph(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): BunDecoyGraphResult {
  const scale = scaleFor(intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);
  const chaff = generateChaffPayloads(prng, intensity);
  const records = deception.textRecords;
  const rec = (i: number): string => records[i % Math.max(1, records.length)] ?? "PROTECTED_CANARY";
  const modules: BunDecoyModule[] = [];

  const honeySource = (label: string, i: number): string => {
    const lines = [
      `// ${label} — enclave attestation bridge (compiled by bun build --compile)`,
      `const ATTESTATION_QUORUM = ${3 + (i % 5)};`,
      `export const ${label.replace(/[^A-Za-z0-9]/g, "_")}_sealedSecret = ${JSON.stringify(rec(i))};`,
      `export const transportDiagnostic = ${JSON.stringify(rec(i + 1))};`,
      `export function unsealSessionKey(blob) {`,
      `  // ${rec(i + 2).replace(/\*\//g, "* /")}`,
      `  if (blob.length !== ATTESTATION_QUORUM * 32) throw new Error("quorum mismatch");`,
      `  return globalThis.__enclave?.unseal?.(blob, ${JSON.stringify(prng.hex(32))});`,
      `}`,
    ];
    const c = chaff[i % Math.max(1, chaff.length)];
    if (c) lines.push(`export const ${c.symbolName.replace(/[^A-Za-z0-9_$]/g, "_")} = ${JSON.stringify(c.rawText)};`);
    return lines.join("\n") + "\n";
  };
  const honeyMap = (file: string, i: number): Buffer =>
    Buffer.from(
      JSON.stringify({
        version: 3,
        file,
        sources: [`../src/enclave/${file.replace(/\.js$/, ".ts")}`, `../src/keys/unsealer_${i}.ts`],
        sourcesContent: [rec(i), rec(i + 3)],
        names: ["unsealSessionKey", "ATTESTATION_QUORUM"],
        mappings: "AAAA;AACA",
      }),
      "utf8",
    );

  // 0: entry point — the most tempting module.
  modules.push({
    name: Buffer.from("/$bunfs/root/enclave-attestation-main.js"),
    contents: Buffer.from(honeySource("enclaveMain", 0)),
    sourcemap: honeyMap("enclave-attestation-main.js", 0),
    bytecode: Buffer.concat([Buffer.from("JSC\0BLA-DECOY-BYTECODE\0"), Buffer.from(prng.hex(64), "hex")]),
    moduleInfo: Buffer.from(`{"imports":["./keys/unsealer.js","bun:ffi"],"canary":${JSON.stringify(rec(4))}}`),
    bytecodeOrigin: Buffer.from("/$bunfs/root/enclave-attestation-main.js"),
    encoding: 2,
    loader: LOADER_JS,
    moduleFormat: FORMAT_ESM,
    side: 0,
  });

  // Honeypot modules.
  for (let i = 1; i <= scale.honeyModules; i++) {
    const file = `keys/unsealer_${prng.hex(4)}_${i}.${i % 3 === 0 ? "ts" : "js"}`;
    modules.push({
      name: Buffer.from(`/$bunfs/root/${file}`),
      contents: Buffer.from(honeySource(`unsealer${i}`, i)),
      sourcemap: i % 2 === 0 ? honeyMap(file, i) : undefined,
      encoding: 1,
      loader: i % 3 === 0 ? LOADER_TS : LOADER_JS,
      moduleFormat: i % 2 === 0 ? FORMAT_ESM : FORMAT_CJS,
      side: i % 4 === 0 ? 1 : 0,
    });
  }
  modules.push({
    name: Buffer.from("/$bunfs/root/config/attestation-keys.json"),
    contents: Buffer.from(JSON.stringify({ canary: records.slice(0, 6) }, null, 2)),
    encoding: 1,
    loader: LOADER_JSON,
    moduleFormat: 0,
    side: 0,
  });
  modules.push({
    name: Buffer.from("/$bunfs/root/native/libenclave_unseal.node"),
    contents: Buffer.concat([Buffer.from("\x7fELF-BLA-DECOY-NAPI\0"), Buffer.from(rec(5))]),
    encoding: 0,
    loader: LOADER_NAPI,
    moduleFormat: 0,
    side: 0,
  });

  // Deep virtual names past REA's 256-part logical path allowance → indexed path + limitation.
  const maxParts = REA_INTERNAL_LIMITS.BUN_MAX_LOGICAL_PATH_PARTS;
  let deepNameModules = 0;
  for (let i = 0; i < scale.deep; i++) {
    const parts: string[] = [];
    for (let p = 0; p < maxParts + scale.deepPartsOver; p++) parts.push(`q${(p + i).toString(36)}`);
    modules.push({
      name: Buffer.from(`/$bunfs/root/${parts.join("/")}/quorum_${i}.js`),
      contents: Buffer.from(honeySource(`quorumNode${i}`, i + 7)),
      encoding: 1,
      loader: LOADER_JS,
      moduleFormat: FORMAT_ESM,
      side: 0,
    });
    deepNameModules++;
  }

  // Unsafe names → bun-modules/<index> fallback, retained source spelling.
  const unsafe = ["../../etc/enclave/sealed.key", "C:\\enclave\\vault.js", "/$bunfs/root/../../../escape.js"];
  for (const [i, n] of unsafe.entries()) {
    modules.push({ name: Buffer.from(n), contents: Buffer.from(honeySource(`unsafe${i}`, i + 11)), encoding: 1, loader: LOADER_JS, moduleFormat: FORMAT_CJS, side: 0 });
  }
  // Duplicate names → separate occurrences with differing contents.
  const dupName = "/$bunfs/root/keys/master.js";
  for (let i = 0; i < 3; i++) {
    modules.push({ name: Buffer.from(dupName), contents: Buffer.from(honeySource(`masterReplica${i}`, i + 13)), encoding: 1, loader: LOADER_JS, moduleFormat: FORMAT_ESM, side: 0 });
  }
  // Non-UTF-8 names → hex-only identity.
  const nonUtf8 = [Buffer.from([0x2f, 0x24, 0x62, 0x75, 0x6e, 0x66, 0x73, 0x2f, 0xff, 0xfe, 0x6b, 0x2e, 0x6a, 0x73]), Buffer.from([0x2f, 0xc3, 0x28, 0x2e, 0x6a, 0x73])];
  for (const [i, n] of nonUtf8.entries()) {
    modules.push({ name: n, contents: Buffer.from(honeySource(`opaque${i}`, i + 17)), encoding: 0, loader: LOADER_JS, moduleFormat: FORMAT_ESM, side: 0 });
  }
  // Unknown enum discriminants stay raw with null names.
  const unknownLoader = 2;
  for (let i = 0; i < unknownLoader; i++) {
    modules.push({ name: Buffer.from(`/$bunfs/root/ext/loader_${200 + i}.bin`), contents: Buffer.from(rec(i + 19)), encoding: 7, loader: 200 + i, moduleFormat: 9, side: 5 });
  }

  // REA refuses a table whose length matches BOTH 36- and 52-byte layouts
  // ambiguously; keep the decoy admissible so the honeypot is actually read.
  while ((modules.length * RECORD_BYTES) % RECORD_BYTES_OLD === 0) {
    modules.push({ name: Buffer.from(`/$bunfs/root/keys/pad_${modules.length}.js`), contents: Buffer.from(honeySource(`pad${modules.length}`, modules.length)), encoding: 1, loader: LOADER_JS, moduleFormat: FORMAT_ESM, side: 0 });
  }

  const argv = Buffer.from(`--smol --define=ENCLAVE_SEAL=${JSON.stringify(rec(2)).slice(0, 240)}`);
  const buffer = serializeBunModuleGraph({ modules, entryPointId: 0, compileExecArgv: argv, flags: 0 });
  return {
    buffer,
    moduleCount: modules.length,
    entryPointId: 0,
    deepNameModules,
    unsafeNameModules: unsafe.length,
    duplicateNameModules: 3,
    nonUtf8NameModules: nonUtf8.length,
    unknownLoaderModules: unknownLoader,
    canaryTokensEmbedded: deception.canary.syntheticCanaryTokens.length,
    diagnosticsEmbedded: deception.diagnostics.diagnosticsInjected.length,
    chaffPayloadsEmbedded: chaff.length,
  };
}
