/**
 * Counter REA #8154 — `feat(android): trace callers of external DEX methods`.
 *
 * REA's JADX bridge (`ReaJadxBridge.java`) walks every method body for
 * `INVOKE_*` opcodes targeting an exact external class/method, then budgets
 * the resulting prototype + caller inventories against
 * `MAX_EXTERNAL_XREF_BYTES = (8 MiB - 1 KiB) / 8` (≈ 1_048_448 bytes).
 *
 * This module emits a standalone, byte-valid Dalvik Executable (`dex\n035\0`)
 * whose only purpose is to saturate that budget:
 *   - One external target: `android.util.Log.d(String, String)` (no class_def).
 *   - N decoy caller classes, each with a static `bait()` that contains a real
 *     `invoke-static` to that target — so JADX's instruction visitor sees them.
 *
 * The developer's own `classes.dex` is NEVER rewritten by this generator; the
 * decoy is planted as an additional `classesN.dex` multidex member (see
 * `archive.ts`). Header checksum / signature / file_size are recomputed so
 * any tool that validates the DEX container still accepts it.
 */
import { createHash } from "node:crypto";
import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";
import { REA_INTERNAL_LIMITS } from "../../identity.js";
import { buildCanaryAndDiagnosticPayloads } from "../deception/format-payloads.js";

export interface AndroidDexXrefCounterResult {
  readonly dexBuffer: Buffer;
  /** Number of decoy caller classes that invoke the external Log.d target. */
  readonly callerClassesEmitted: number;
  /** External method refs planted (currently always 1 — Log.d). */
  readonly externalMethodRefs: number;
  /** Marker string embedded for inspect/detect. */
  readonly marker: string;
}

function encodeUleb128(value: number): Buffer {
  const bytes: number[] = [];
  let v = value >>> 0;
  do {
    let byte = v & 0x7f;
    v >>>= 7;
    if (v !== 0) byte |= 0x80;
    bytes.push(byte);
  } while (v !== 0);
  return Buffer.from(bytes);
}

function align4(n: number): number {
  return (n + 3) & ~3;
}

function intensityCallerCount(intensity: ProtectionIntensity): number {
  // Escaped JSON per caller row is hundreds of bytes under InvokeBudget's
  // 12× character bound. Aim past ANDROID_EXTERNAL_XREF_BYTES at maximum /
  // bankrupt; keep stealth/balanced smaller but still meaningful.
  switch (intensity) {
    case "stealth":
      return 96;
    case "balanced":
      return 384;
    case "maximum":
      return 2_048;
    case "bankrupt":
      return 6_144;
    default:
      return 384;
  }
}

interface BuiltDex {
  readonly buffer: Buffer;
  readonly callerCount: number;
}

/**
 * Build a minimal but structurally valid DEX 035 containing `callerCount`
 * static caller classes that each `invoke-static` `Landroid/util/Log;->d`.
 */
function buildExternalInvokeDex(
  prng: SeededPrng,
  callerCount: number,
  extraStrings: readonly string[],
): BuiltDex {
  const marker = "BLA-DEX-XREF-V1";

  // ----- string pool (order matters; indices are referenced below) -----
  const strings: string[] = [];
  const strIndex = new Map<string, number>();
  const addStr = (s: string): number => {
    const existing = strIndex.get(s);
    if (existing !== undefined) return existing;
    const idx = strings.length;
    strings.push(s);
    strIndex.set(s, idx);
    return idx;
  };

  // Fixed descriptor / name strings used by the external target + callers.
  const sVoid = addStr("V");
  const sObject = addStr("Ljava/lang/Object;");
  const sString = addStr("Ljava/lang/String;");
  const sLog = addStr("Landroid/util/Log;");
  const sShortyLogD = addStr("VLL"); // return V, two reference args
  const sShortyVoid = addStr("V");
  const sMethodD = addStr("d");
  const sMethodBait = addStr("bait");
  const sMarker = addStr(marker);
  const sSource = addStr("BlaDexXref.java");

  const callerTypeStrIdx: number[] = [];
  for (let i = 0; i < callerCount; i++) {
    const hex = prng.hex(6);
    callerTypeStrIdx.push(
      addStr(`Lcom/enclave/xref/ExternalInvokeCaller_${hex}_${i};`),
    );
  }

  for (const extra of extraStrings) {
    // DEX MUTF-8 string_data cannot contain U+0000; keep payloads clean.
    addStr(extra.replace(/\0/g, " ").slice(0, 200));
  }

  // ----- type_ids (index into string_ids) -----
  const types: number[] = [];
  const typeIndex = new Map<number, number>(); // stringIdx -> typeIdx
  const addType = (stringIdx: number): number => {
    const existing = typeIndex.get(stringIdx);
    if (existing !== undefined) return existing;
    const idx = types.length;
    types.push(stringIdx);
    typeIndex.set(stringIdx, idx);
    return idx;
  };

  const tVoid = addType(sVoid);
  const tObject = addType(sObject);
  const tString = addType(sString);
  const tLog = addType(sLog);
  const callerTypeIdx: number[] = callerTypeStrIdx.map((si) => addType(si));
  void tVoid; // referenced via proto return; kept for clarity

  // ----- proto_ids -----
  // proto 0: (Ljava/lang/String;Ljava/lang/String;)V   — Log.d
  // proto 1: ()V                                       — bait()
  // We write type_lists into the data section later; record placeholders.
  interface ProtoRec {
    shortyIdx: number;
    returnTypeIdx: number;
    /** 0 = no params; else offset filled after layout. */
    paramTypeIdxs: number[];
  }
  const protos: ProtoRec[] = [
    { shortyIdx: sShortyLogD, returnTypeIdx: tVoid, paramTypeIdxs: [tString, tString] },
    { shortyIdx: sShortyVoid, returnTypeIdx: tVoid, paramTypeIdxs: [] },
  ];

  // ----- method_ids -----
  // method 0: Log.d (external — no class_def for Log)
  // method 1..N: Caller_i.bait
  interface MethodRec {
    classIdx: number;
    protoIdx: number;
    nameIdx: number;
  }
  const methods: MethodRec[] = [
    { classIdx: tLog, protoIdx: 0, nameIdx: sMethodD },
  ];
  for (let i = 0; i < callerCount; i++) {
    methods.push({
      classIdx: callerTypeIdx[i]!,
      protoIdx: 1,
      nameIdx: sMethodBait,
    });
  }

  // ----- Lay out the data section -----
  // We'll assemble: string_data → type_list(s) → code_item(s) → class_data →
  // map_list. Offsets are relative to start of file; header + id tables come
  // first so we compute their size up front.
  const headerSize = 0x70;
  const stringIdsSize = strings.length * 4;
  const typeIdsSize = types.length * 4;
  const protoIdsSize = protos.length * 12;
  const fieldIdsSize = 0;
  const methodIdsSize = methods.length * 8;
  const classDefsSize = callerCount * 32;
  const idsEnd =
    headerSize +
    stringIdsSize +
    typeIdsSize +
    protoIdsSize +
    fieldIdsSize +
    methodIdsSize +
    classDefsSize;

  let dataCursor = idsEnd;
  const dataChunks: { offset: number; buf: Buffer }[] = [];
  const place = (buf: Buffer, align = false): number => {
    if (align) {
      const padded = align4(dataCursor) - dataCursor;
      if (padded > 0) {
        dataChunks.push({ offset: dataCursor, buf: Buffer.alloc(padded, 0) });
        dataCursor += padded;
      }
    }
    const off = dataCursor;
    dataChunks.push({ offset: off, buf });
    dataCursor += buf.length;
    return off;
  };

  // string_data_item[] — MUTF-8 with uleb128 utf16_size prefix + NUL
  const stringDataOffs: number[] = [];
  for (const s of strings) {
    const utf8 = Buffer.from(s, "utf8");
    // Approximate utf16 length as utf8 length for ASCII-heavy payloads (our
    // strings are ASCII). Canary payloads may contain non-BMP rarely; DEX
    // requires modified UTF-8 — for BMP-only JS strings, utf16_size === code units.
    let utf16Size = 0;
    for (const ch of s) {
      const cp = ch.codePointAt(0)!;
      utf16Size += cp > 0xffff ? 2 : 1;
    }
    const item = Buffer.concat([encodeUleb128(utf16Size), utf8, Buffer.from([0])]);
    stringDataOffs.push(place(item));
  }

  // type_list for Log.d params (String, String) — size uint32 + type_idx[] uint16, align 4
  let logParamListOff = 0;
  {
    const paramBuf = Buffer.alloc(4 + 2 * 2);
    paramBuf.writeUInt32LE(2, 0);
    paramBuf.writeUInt16LE(tString, 4);
    paramBuf.writeUInt16LE(tString, 6);
    logParamListOff = place(paramBuf, true);
  }
  const protoParamOffs = [logParamListOff, 0];

  // code_item for bait(): invoke-static {v0,v1}, Log.d ; return-void
  // Format 35c invoke-static: op=0x71, A=2 args, method_idx=0, regs C=0 D=1
  const insnBytes = Buffer.from([
    0x71, 0x20, 0x00, 0x00, 0x10, 0x00, // invoke-static {v0, v1}, method@0 (Log.d)
    0x0e, 0x00, // return-void
  ]);
  const codeItemSize = 16 + insnBytes.length; // header 16 + 8 insn bytes
  const codeItemTemplate = Buffer.alloc(codeItemSize);
  codeItemTemplate.writeUInt16LE(2, 0); // registers_size
  codeItemTemplate.writeUInt16LE(0, 2); // ins_size
  codeItemTemplate.writeUInt16LE(2, 4); // outs_size
  codeItemTemplate.writeUInt16LE(0, 6); // tries_size
  codeItemTemplate.writeUInt32LE(0, 8); // debug_info_off
  codeItemTemplate.writeUInt32LE(insnBytes.length / 2, 12); // insns_size (code units)
  insnBytes.copy(codeItemTemplate, 16);

  // Each caller gets its own code_item (identical body; unique off required by class_data)
  const codeOffs: number[] = [];
  for (let i = 0; i < callerCount; i++) {
    codeOffs.push(place(Buffer.from(codeItemTemplate), true));
  }

  // class_data_item per caller: 0 static fields, 0 instance, 1 direct method, 0 virtual
  const classDataOffs: number[] = [];
  for (let i = 0; i < callerCount; i++) {
    // method_idx_diff: methods[0] is Log.d; Caller_i.bait is methods[1+i]
    // First direct method diff = (1+i) - 0 = 1+i
    const methodIdxDiff = 1 + i;
    const accessFlags = 0x0009; // public static
    const parts = Buffer.concat([
      encodeUleb128(0), // static_fields_size
      encodeUleb128(0), // instance_fields_size
      encodeUleb128(1), // direct_methods_size
      encodeUleb128(0), // virtual_methods_size
      encodeUleb128(methodIdxDiff),
      encodeUleb128(accessFlags),
      encodeUleb128(codeOffs[i]!),
    ]);
    classDataOffs.push(place(parts));
  }

  // map_list — required; list every section
  // We'll finalize map after we know map's own offset.
  const mapStart = align4(dataCursor);
  if (mapStart !== dataCursor) {
    place(Buffer.alloc(mapStart - dataCursor, 0));
  }

  // map entries (type, unused, size, offset) — 12 bytes each, plus uint32 size header
  // Types from dalvik docs:
  const TYPE_HEADER_ITEM = 0x0000;
  const TYPE_STRING_ID_ITEM = 0x0001;
  const TYPE_TYPE_ID_ITEM = 0x0002;
  const TYPE_PROTO_ID_ITEM = 0x0003;
  const TYPE_METHOD_ID_ITEM = 0x0005;
  const TYPE_CLASS_DEF_ITEM = 0x0006;
  const TYPE_CODE_ITEM = 0x2001;
  const TYPE_STRING_DATA_ITEM = 0x2002;
  const TYPE_TYPE_LIST = 0x1001;
  const TYPE_CLASS_DATA_ITEM = 0x2000;
  const TYPE_MAP_LIST = 0x1000;

  const mapEntries: { type: number; size: number; offset: number }[] = [
    { type: TYPE_HEADER_ITEM, size: 1, offset: 0 },
    { type: TYPE_STRING_ID_ITEM, size: strings.length, offset: headerSize },
    {
      type: TYPE_TYPE_ID_ITEM,
      size: types.length,
      offset: headerSize + stringIdsSize,
    },
    {
      type: TYPE_PROTO_ID_ITEM,
      size: protos.length,
      offset: headerSize + stringIdsSize + typeIdsSize,
    },
    {
      type: TYPE_METHOD_ID_ITEM,
      size: methods.length,
      offset:
        headerSize + stringIdsSize + typeIdsSize + protoIdsSize + fieldIdsSize,
    },
    {
      type: TYPE_CLASS_DEF_ITEM,
      size: callerCount,
      offset:
        headerSize +
        stringIdsSize +
        typeIdsSize +
        protoIdsSize +
        fieldIdsSize +
        methodIdsSize,
    },
    { type: TYPE_TYPE_LIST, size: 1, offset: logParamListOff },
    {
      type: TYPE_CODE_ITEM,
      size: callerCount,
      offset: codeOffs[0]!,
    },
    {
      type: TYPE_STRING_DATA_ITEM,
      size: strings.length,
      offset: stringDataOffs[0]!,
    },
    {
      type: TYPE_CLASS_DATA_ITEM,
      size: callerCount,
      offset: classDataOffs[0]!,
    },
  ];

  const mapListSize = 4 + (mapEntries.length + 1) * 12; // +1 for MAP_LIST itself
  const mapOff = dataCursor;
  const mapBuf = Buffer.alloc(mapListSize);
  mapBuf.writeUInt32LE(mapEntries.length + 1, 0);
  let mapAt = 4;
  for (const e of mapEntries) {
    mapBuf.writeUInt16LE(e.type, mapAt);
    mapBuf.writeUInt16LE(0, mapAt + 2);
    mapBuf.writeUInt32LE(e.size, mapAt + 4);
    mapBuf.writeUInt32LE(e.offset, mapAt + 8);
    mapAt += 12;
  }
  // Self entry
  mapBuf.writeUInt16LE(TYPE_MAP_LIST, mapAt);
  mapBuf.writeUInt16LE(0, mapAt + 2);
  mapBuf.writeUInt32LE(1, mapAt + 4);
  mapBuf.writeUInt32LE(mapOff, mapAt + 8);
  place(mapBuf);

  const fileSize = dataCursor;

  // ----- Write the full file -----
  const out = Buffer.alloc(fileSize, 0);
  // header
  out.write("dex\n035\0", 0, "ascii");
  // checksum + signature filled later
  out.writeUInt32LE(fileSize, 32);
  out.writeUInt32LE(headerSize, 36);
  out.writeUInt32LE(0x12345678, 40); // endian_tag
  out.writeUInt32LE(0, 44); // link_size
  out.writeUInt32LE(0, 48); // link_off
  out.writeUInt32LE(mapOff, 52);
  out.writeUInt32LE(strings.length, 56);
  out.writeUInt32LE(headerSize, 60); // string_ids_off
  out.writeUInt32LE(types.length, 64);
  out.writeUInt32LE(headerSize + stringIdsSize, 68); // type_ids_off
  out.writeUInt32LE(protos.length, 72);
  out.writeUInt32LE(headerSize + stringIdsSize + typeIdsSize, 76); // proto_ids_off
  out.writeUInt32LE(0, 80); // field_ids_size
  out.writeUInt32LE(0, 84); // field_ids_off
  out.writeUInt32LE(methods.length, 88);
  out.writeUInt32LE(
    headerSize + stringIdsSize + typeIdsSize + protoIdsSize + fieldIdsSize,
    92,
  ); // method_ids_off
  out.writeUInt32LE(callerCount, 96);
  out.writeUInt32LE(
    headerSize +
      stringIdsSize +
      typeIdsSize +
      protoIdsSize +
      fieldIdsSize +
      methodIdsSize,
    100,
  ); // class_defs_off
  out.writeUInt32LE(fileSize - idsEnd, 104); // data_size
  out.writeUInt32LE(idsEnd, 108); // data_off

  // string_ids
  let at = headerSize;
  for (const off of stringDataOffs) {
    out.writeUInt32LE(off, at);
    at += 4;
  }
  // type_ids
  for (const si of types) {
    out.writeUInt32LE(si, at);
    at += 4;
  }
  // proto_ids
  for (let i = 0; i < protos.length; i++) {
    const p = protos[i]!;
    out.writeUInt32LE(p.shortyIdx, at);
    out.writeUInt32LE(p.returnTypeIdx, at + 4);
    out.writeUInt32LE(protoParamOffs[i]!, at + 8);
    at += 12;
  }
  // method_ids
  for (const m of methods) {
    out.writeUInt16LE(m.classIdx, at);
    out.writeUInt16LE(m.protoIdx, at + 2);
    out.writeUInt32LE(m.nameIdx, at + 4);
    at += 8;
  }
  // class_defs
  for (let i = 0; i < callerCount; i++) {
    out.writeUInt32LE(callerTypeIdx[i]!, at); // class_idx
    out.writeUInt32LE(0x0001, at + 4); // ACC_PUBLIC
    out.writeUInt32LE(tObject, at + 8); // superclass
    out.writeUInt32LE(0, at + 12); // interfaces_off
    out.writeUInt32LE(sSource, at + 16); // source_file_idx
    out.writeUInt32LE(0, at + 20); // annotations_off
    out.writeUInt32LE(classDataOffs[i]!, at + 24); // class_data_off
    out.writeUInt32LE(0, at + 28); // static_values_off
    at += 32;
  }

  // data chunks
  for (const chunk of dataChunks) {
    chunk.buf.copy(out, chunk.offset);
  }

  // Keep marker reachable for inspect
  void sMarker;

  // SHA-1 signature over bytes [32..end] → [12..32]
  const sha1 = createHash("sha1").update(out.subarray(32)).digest();
  sha1.copy(out, 12);
  // Adler32 checksum over bytes [12..end] → [8..12]
  let a = 1;
  let b = 0;
  for (let i = 12; i < out.length; i++) {
    a = (a + out[i]!) % 65521;
    b = (b + a) % 65521;
  }
  out.writeUInt32LE(((b << 16) | a) >>> 0, 8);

  return { buffer: out, callerCount };
}

/**
 * Generate a decoy DEX that saturates REA #8154's external-invoke caller
 * inventory (`MAX_EXTERNAL_XREF_BYTES`).
 */
export function generateAndroidDexXrefCounter(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): AndroidDexXrefCounterResult {
  const callerCount = intensityCallerCount(intensity);
  const deception = buildCanaryAndDiagnosticPayloads(prng, intensity);
  // Embed a handful of canary/diagnostic strings so string-pool scanners also
  // surface honeypots; does not affect invoke budgets.
  const extras = deception.textRecords.slice(0, 12);
  const built = buildExternalInvokeDex(prng, callerCount, extras);

  // Sanity: callers should exceed what a single ~1 MiB inventory comfortably holds
  // at bankrupt/maximum. We don't assert the byte math here — unit tests do.
  void REA_INTERNAL_LIMITS.ANDROID_EXTERNAL_XREF_BYTES;

  return {
    dexBuffer: built.buffer,
    callerClassesEmitted: built.callerCount,
    externalMethodRefs: 1,
    marker: "BLA-DEX-XREF-V1",
  };
}

/** Next free `classesN.dex` name given existing ZIP entry names. */
export function nextMultidexName(existingNames: readonly string[]): string {
  let max = 1; // classes.dex counts as 1
  for (const name of existingNames) {
    const base = name.split("/").pop() ?? name;
    if (/^classes\.dex$/i.test(base)) {
      max = Math.max(max, 1);
      continue;
    }
    const m = /^classes(\d+)\.dex$/i.exec(base);
    if (m) max = Math.max(max, Number(m[1]));
  }
  return `classes${max + 1}.dex`;
}
