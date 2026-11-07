import { writeFileSync, mkdtempSync } from "node:fs";
import { open } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import {
  resolveTsharkEnv,
  resolveWabtEnv,
  reaDistReady,
  reaDistSpecifier,
} from "./paths.mjs";

const require = createRequire(import.meta.url);

/** Faithful replica of REA `projectStringPool` (private in FlutterBuildProvider). */
export function projectStringPoolReaFaithful(section, limits) {
  const MAX_POOL_URIS = limits.DART_MAX_POOL_URIS;
  const MAX_POOL_TOKENS = limits.DART_MAX_POOL_TOKENS;
  const COLLECTION_SLACK = 2;
  const MAX_RUN_BYTES = 1024;
  const IDENTIFIER_PATTERN = /^[A-Za-z_$][A-Za-z0-9_$]*$/u;
  const packages = new Set();
  const darts = new Set();
  const tokens = new Set();
  let runCount = 0;
  let collectionCapped = false;
  const packageBudget = MAX_POOL_URIS * COLLECTION_SLACK;
  const dartBudget = MAX_POOL_URIS * COLLECTION_SLACK;
  const tokenBudget = MAX_POOL_TOKENS * COLLECTION_SLACK;
  if (section != null) {
    let run = "";
    let overflowed = false;
    const consider = (text) => {
      if (text.length < 5) return;
      runCount += 1;
      if (text.startsWith("package:")) {
        if (!packages.has(text) && packages.size >= packageBudget)
          collectionCapped = true;
        else packages.add(text);
      } else if (text.startsWith("dart:")) {
        if (!darts.has(text) && darts.size >= dartBudget)
          collectionCapped = true;
        else darts.add(text);
      } else if (
        text.length <= 128 &&
        text.length >= 5 &&
        IDENTIFIER_PATTERN.test(text)
      ) {
        if (!tokens.has(text) && tokens.size >= tokenBudget)
          collectionCapped = true;
        else tokens.add(text);
      }
    };
    for (const byte of section) {
      if (byte >= 0x20 && byte < 0x7f) {
        if (run.length < MAX_RUN_BYTES) run += String.fromCharCode(byte);
        else {
          overflowed = true;
          collectionCapped = true;
        }
      } else {
        if (!overflowed) consider(run);
        overflowed = false;
        run = "";
      }
    }
    if (!overflowed) consider(run);
  }
  return {
    packageUriCount: packages.size,
    dartUriCount: darts.size,
    classLikeTokenCount: tokens.size,
    printableRunCount: runCount,
    collectionCapped,
    reportWouldCap:
      packages.size > MAX_POOL_URIS ||
      darts.size > MAX_POOL_URIS ||
      tokens.size > MAX_POOL_TOKENS,
  };
}

function outcomeBase(format, phase, bytes) {
  return {
    format,
    phase,
    inputBytes: bytes.length,
    status: "ok",
    errorName: null,
    errorMessage: null,
    budgetHit: false,
    budgetName: null,
    redactionOrAmbiguity: null,
    metrics: {},
  };
}

function failOutcome(base, err, budgetName = null) {
  base.status = "error";
  base.errorName = err?.constructor?.name ?? "Error";
  base.errorMessage = String(err?.message ?? err).slice(0, 240);
  if (budgetName || err?.boundary || err?.limit) {
    base.budgetHit = true;
    base.budgetName =
      budgetName ??
      err?.boundary ??
      err?.limit ??
      err?.capacity ??
      "resource";
  }
  return base;
}

export async function loadReaProbes() {
  if (!reaDistReady()) {
    throw new Error(
      "REA dist missing — compile with: cd ../rea && npx tsc -p tsconfig.build.json",
    );
  }
  const { readGoBinaryImage } = await import(
    reaDistSpecifier("go/GoBinaryImage.js")
  );
  const { parseErlangBeam, BeamCapacityFailure } = await import(
    reaDistSpecifier("erlang/BeamParser.js")
  );
  const { EVM_INTERFACE_LIMITS } = await import(
    reaDistSpecifier("evm/EvmoleRelease.js")
  );
  const { decodeEvmBytecodeCarrier } = await import(
    reaDistSpecifier("evm/EvmBytecodeCarrier.js")
  );
  const { inspectSolidityMetadata } = await import(
    reaDistSpecifier("evm/SolidityMetadata.js")
  );
  const { TSHARK_JSON_MAX_BYTES, parseTsharkJsonOutput } = await import(
    reaDistSpecifier("pcap/PcapOutput.js")
  );
  const { MODEL_JSON_NESTING, MODEL_METADATA_NESTING, ModelFormatFailure } =
    await import(reaDistSpecifier("model/ModelFormat.js"));
  const { readSafetensorsHeader } = await import(
    reaDistSpecifier("model/SafetensorsHeader.js")
  );
  const { ModelHeaderReader } = await import(
    reaDistSpecifier("model/ModelHeaderReader.js")
  );
  const { GgufHeader } = await import(reaDistSpecifier("model/GgufHeader.js"));
  const { admitAsarHeader } = await import(
    reaDistSpecifier("artifacts/AsarHeader.js")
  );
  const { readAsarListing } = await import(
    reaDistSpecifier("artifacts/AsarListing.js")
  );
  const { WasmInterfaceBudget } = await import(
    reaDistSpecifier("wasm/WasmInterfaceBudget.js")
  );
  const { wasmInterfaceEntryRepresentationBytes, WASM_INTERFACE_REPRESENTATION_BYTES } =
    await import(reaDistSpecifier("domain/wasm/wasmInterface.js"));
  const { readElectronFuseImage, ELECTRON_FUSE_LIMITS, ElectronFuseResourceFailure } =
    await import(reaDistSpecifier("electron/ElectronFuseReader.js"));
  let inspectSqliteDatabaseSnapshot = null;
  let SqliteInspectionFailure = null;
  let SqliteColumnEvaluationFailure = null;
  try {
    const sqliteMod = await import(
      reaDistSpecifier("sqlite/SqliteDatabaseInspection.js")
    );
    inspectSqliteDatabaseSnapshot = sqliteMod.inspectSqliteDatabaseSnapshot;
    SqliteInspectionFailure = sqliteMod.SqliteInspectionFailure;
  } catch {
    /* optional */
  }
  try {
    const limitsMod = await import(
      reaDistSpecifier("sqlite/SqliteDatabaseLimits.js")
    );
    SqliteColumnEvaluationFailure = limitsMod.SqliteColumnEvaluationFailure;
    SqliteInspectionFailure =
      SqliteInspectionFailure ?? limitsMod.SqliteInspectionFailure;
  } catch {
    /* optional */
  }
  let WabtArtifactProvider = null;
  try {
    ({ WabtArtifactProvider } = await import(
      reaDistSpecifier("wasm/WabtArtifactProvider.js")
    ));
  } catch {
    /* optional */
  }
  const { analyzeJavaScriptStaticSource } = await import(
    reaDistSpecifier("domain/javascript/javascriptStaticAnalysis.js")
  );
  const { analyzeJavaScriptSemantics } = await import(
    reaDistSpecifier("domain/javascript/javascriptSemanticAnalysis.js")
  );
  const { readPtxKernels } = await import(
    reaDistSpecifier("gpu/PtxKernels.js")
  );
  return {
    readGoBinaryImage,
    parseErlangBeam,
    BeamCapacityFailure,
    EVM_INTERFACE_LIMITS,
    decodeEvmBytecodeCarrier,
    inspectSolidityMetadata,
    TSHARK_JSON_MAX_BYTES,
    parseTsharkJsonOutput,
    MODEL_JSON_NESTING,
    MODEL_METADATA_NESTING,
    ModelFormatFailure,
    readSafetensorsHeader,
    ModelHeaderReader,
    GgufHeader,
    admitAsarHeader,
    readAsarListing,
    WasmInterfaceBudget,
    wasmInterfaceEntryRepresentationBytes,
    WASM_INTERFACE_REPRESENTATION_BYTES,
    readElectronFuseImage,
    ELECTRON_FUSE_LIMITS,
    ElectronFuseResourceFailure,
    inspectSqliteDatabaseSnapshot,
    SqliteInspectionFailure,
    SqliteColumnEvaluationFailure,
    WabtArtifactProvider,
    analyzeJavaScriptStaticSource,
    analyzeJavaScriptSemantics,
    readPtxKernels,
  };
}

export async function probeGo(rea, bytes, phase) {
  const base = outcomeBase("go_buildinfo", phase, bytes);
  try {
    const img = rea.readGoBinaryImage(bytes);
    base.metrics = {
      hasBuildInfo: img.build_info != null,
      encoding: img.build_info?.encoding ?? null,
      goVersion: img.build_info?.go_version ?? null,
      moduleTextBytes: img.build_info?.module_text?.length ?? 0,
    };
    if (img.build_info == null) {
      base.redactionOrAmbiguity = "no_buildinfo_observed";
    }
  } catch (err) {
    failOutcome(base, err, err?.boundary === "build-info" ? "MAX_BUILD_INFO_BYTES" : err?.boundary);
  }
  return base;
}

export async function probeFlutterPool(aegis, bytes, phase, limits) {
  const base = outcomeBase("flutter_pool", phase, bytes);
  try {
    // validateElf64Layout throws on invalid; returns layout summary otherwise.
    const layout = aegis.validateElf64Layout(bytes);
    const names = aegis.resolveElf64SectionNames(bytes, layout);
    const iso = names.get(".isolate");
    if (!iso) {
      base.redactionOrAmbiguity = "no_isolate_section";
      return base;
    }
    const section = bytes.subarray(iso.offset, iso.offset + iso.size);
    const pool = projectStringPoolReaFaithful(section, limits);
    base.metrics = { isolateBytes: iso.size, ...pool };
    if (pool.reportWouldCap) {
      base.budgetHit = true;
      base.budgetName = "MAX_POOL_URIS|MAX_POOL_TOKENS";
      base.redactionOrAmbiguity =
        "REA would report truncated package_uris/dart_uris/class_like_tokens with 'at least N' limitations";
    }
  } catch (err) {
    failOutcome(base, err);
  }
  return base;
}

export async function probeBeam(rea, bytes, phase) {
  const base = outcomeBase("erlang_beam", phase, bytes);
  try {
    const artifact = {
      path: "sample.beam",
      bytes: bytes.length,
      sha256: "0".repeat(64),
    };
    const result = rea.parseErlangBeam(bytes, artifact, {
      max_chunks: 64,
      max_atoms: 4096,
    });
    base.metrics = {
      chunkCount: result.chunks.length,
      atomCount: result.atoms?.length ?? 0,
      limitations: (result.limitations ?? []).slice(0, 3),
    };
  } catch (err) {
    const name =
      err?.constructor?.name === "BeamCapacityFailure"
        ? err.resource === "chunks"
          ? "max_chunks"
          : err.resource === "atoms"
            ? "max_atoms"
            : "beam_capacity"
        : null;
    failOutcome(base, err, name);
  }
  return base;
}

export async function probeEvm(rea, bytes, phase) {
  const base = outcomeBase("evm_bytecode", phase, bytes);
  const limit = rea.EVM_INTERFACE_LIMITS.inputBytes;
  base.metrics = {
    inputBytes: bytes.length,
    inputBytesLimit: limit,
    approachesLimit: bytes.length >= limit - 8192,
    exceedsLimit: bytes.length > limit,
  };
  if (bytes.length > limit) {
    base.budgetHit = true;
    base.budgetName = "EVM_INTERFACE_LIMITS.inputBytes";
    base.status = "rejected_pre_worker";
    base.redactionOrAmbiguity =
      "REA would refuse to start the EVM worker (input exceeds 4 MiB)";
    return base;
  }
  try {
    try {
      const carrier = rea.decodeEvmBytecodeCarrier(bytes, "raw");
      base.metrics.carrierBytes = carrier?.length;
    } catch (err) {
      base.metrics.carrierError = String(err.message).slice(0, 120);
    }
    try {
      const meta = rea.inspectSolidityMetadata(bytes);
      base.metrics.solidityMetadata = meta;
    } catch (err) {
      base.metrics.metadataError = String(err.message).slice(0, 120);
    }
    if (base.metrics.approachesLimit) {
      base.budgetHit = true;
      base.budgetName = "EVM_INTERFACE_LIMITS.inputBytes (approach)";
      base.redactionOrAmbiguity =
        "Hardened sample approaches full 4 MiB input budget";
    }
  } catch (err) {
    failOutcome(base, err);
  }
  return base;
}

export async function probePcap(rea, bytes, phase) {
  const base = outcomeBase("pcap_capture", phase, bytes);
  const tshark = resolveTsharkEnv();
  if (!tshark.available) {
    base.status = "skipped";
    base.redactionOrAmbiguity =
      "not empirically verified on this box (requires tshark)";
    return base;
  }
  const dir = mkdtempSync(join(tmpdir(), "aegis-rt-pcap-"));
  const path = join(dir, `${phase}.pcap`);
  writeFileSync(path, bytes);
  const proc = spawnSync(
    tshark.bin,
    ["-r", path, "-T", "json"],
    {
      encoding: "buffer",
      maxBuffer: 64 * 1024 * 1024,
      env: tshark.env,
      timeout: 120_000,
    },
  );
  const jsonBytes = proc.stdout ? proc.stdout.length : 0;
  base.metrics = {
    tsharkStatus: proc.status,
    tsharkJsonBytes: jsonBytes,
    tsharkJsonLimit: rea.TSHARK_JSON_MAX_BYTES,
    exceedsTsharkJsonBudget: jsonBytes > rea.TSHARK_JSON_MAX_BYTES,
    stderrHead: proc.stderr
      ? Buffer.from(proc.stderr).toString("utf8").slice(0, 160)
      : "",
  };
  if (proc.error) {
    failOutcome(base, proc.error, "tshark");
    return base;
  }
  if (jsonBytes > rea.TSHARK_JSON_MAX_BYTES) {
    base.budgetHit = true;
    base.budgetName = "TSHARK_JSON_MAX_BYTES";
    base.redactionOrAmbiguity =
      "REA parseTsharkJsonOutput would throw AnalysisResourceConstraintError";
    // Confirm REA's parser rejects oversized JSON
    try {
      await rea.parseTsharkJsonOutput(proc.stdout.toString("utf8"));
      base.metrics.reaParseAcceptedOversized = true;
    } catch (err) {
      base.metrics.reaParseErrorName = err?.constructor?.name;
      base.metrics.reaParseError = String(err.message).slice(0, 160);
      base.status = "budget_rejected";
    }
  }
  return base;
}

export async function probeSafetensors(rea, bytes, phase) {
  const base = outcomeBase("safetensors", phase, bytes);
  const dir = mkdtempSync(join(tmpdir(), "aegis-rt-st-"));
  const path = join(dir, `${phase}.safetensors`);
  writeFileSync(path, bytes);
  try {
    const fh = await open(path, "r");
    try {
      const reader = new rea.ModelHeaderReader(fh, bytes.length);
      const first = await reader.take(4);
      const result = await rea.readSafetensorsHeader(reader, first);
      base.metrics = {
        tensorCount: result.tensors?.length ?? 0,
        metadataCount: result.metadata?.length ?? 0,
        limitations: result.limitations ?? [],
      };
    } finally {
      await fh.close();
    }
  } catch (err) {
    const limit = err?.limit ?? null;
    failOutcome(
      base,
      err,
      limit === "json-nesting" ? "MODEL_JSON_NESTING" : limit,
    );
  }
  return base;
}

export async function probeGguf(rea, bytes, phase) {
  const base = outcomeBase("gguf", phase, bytes);
  const dir = mkdtempSync(join(tmpdir(), "aegis-rt-gguf-"));
  const path = join(dir, `${phase}.gguf`);
  writeFileSync(path, bytes);
  try {
    const fh = await open(path, "r");
    try {
      const reader = new rea.ModelHeaderReader(fh, bytes.length);
      // ModelArtifactProvider consumes the 4-byte GGUF magic before GgufHeader.
      const magic = await reader.take(4);
      if (!magic.equals(Buffer.from("GGUF"))) {
        base.status = "error";
        base.errorMessage = `expected GGUF magic, got ${magic.toString("hex")}`;
        return base;
      }
      const header = new rea.GgufHeader(reader);
      const result = await header.read();
      base.metrics = {
        version: result?.version,
        tensorCount: result?.tensors?.length ?? result?.tensor_count,
        metadataCount: result?.metadata?.length,
        limitations: result?.limitations ?? [],
      };
    } finally {
      await fh.close();
    }
  } catch (err) {
    const limit = err?.limit ?? null;
    failOutcome(
      base,
      err,
      limit === "metadata-nesting" ? "MODEL_METADATA_NESTING" : limit,
    );
  }
  return base;
}

/**
 * PTX is decoded in-process by real REA `readPtxKernels` — no native tooling
 * needed. The 16 MiB `GPU_REPORT_BYTES` retained-facts cap and the 65536
 * parameter-declaration cap both throw `BinaryResourceFailure`.
 */
export async function probePtx(rea, bytes, phase) {
  const base = outcomeBase("gpu_ptx", phase, bytes);
  const text = bytes.toString("utf8");
  base.metrics.textBytes = bytes.length;
  base.metrics.note =
    "REA readPtxKernels (in-process); GPU fatbin/SPIR-V object decode still needs native tooling";
  let entryCount = 0;
  try {
    for (const step of rea.readPtxKernels(text, `${phase}-ptx`)) {
      entryCount += 1;
      if (step.coverage === "partial") base.metrics.partialCoverage = true;
    }
    base.metrics.entryCount = entryCount;
  } catch (err) {
    base.metrics.entryCount = entryCount;
    const message = String(err?.message ?? "");
    const budgetName = /parameter declarations exceed/u.test(message)
      ? "PTX_MAX_PARAMETERS"
      : /kernel count exceeds/u.test(message)
        ? "PTX_MAX_KERNELS"
        : "GPU_REPORT_BYTES";
    failOutcome(base, err, budgetName);
  }
  return base;
}


export async function probeAsar(rea, bytes, phase) {
  const base = outcomeBase("electron_asar", phase, bytes);
  const dir = mkdtempSync(join(tmpdir(), "aegis-rt-asar-"));
  const path = join(dir, `${phase}.asar`);
  writeFileSync(path, bytes);
  try {
    const fh = await open(path, "r");
    try {
      const extents = await rea.admitAsarHeader(fh);
      base.metrics.headerBytes = extents.headerBytes;
      base.metrics.archiveBytes = extents.archiveBytes;
      base.metrics.jsonBytes = extents.jsonBytes ?? extents.headerBytes - 8;
      // Read JSON header for listing
      const jsonBuf = Buffer.alloc(extents.headerBytes);
      // header layout: 8 byte size pickle + headerBytes pickle payload; JSON starts at 16
      const headerRegion = Buffer.alloc(8 + extents.headerBytes);
      let off = 0;
      while (off < headerRegion.length) {
        const { bytesRead } = await fh.read(
          headerRegion,
          off,
          headerRegion.length - off,
          off,
        );
        if (bytesRead === 0) break;
        off += bytesRead;
      }
      const jsonSize = headerRegion.readUInt32LE(12);
      const json = headerRegion.subarray(16, 16 + jsonSize).toString("utf8");
      const root = JSON.parse(json);
      const listing = await rea.readAsarListing(root);
      base.metrics.listingEntries = listing.length;
      base.metrics.listingPathBytes = listing.reduce(
        (s, e) => s + (e.path?.length ?? 0),
        0,
      );
    } finally {
      await fh.close();
    }
  } catch (err) {
    const msg = String(err?.message ?? err);
    const isHeader =
      /header/i.test(msg) ||
      err?.constructor?.name?.includes("Asar") ||
      /max_header|admission/i.test(msg);
    failOutcome(
      base,
      err,
      isHeader ? "DEFAULT_ASAR_MAX_HEADER_BYTES" : err?.kind ?? "asar",
    );
    if (isHeader || /exceeds its .* representation budget/i.test(msg)) {
      base.budgetHit = true;
      base.budgetName = /listing|representation/i.test(msg)
        ? "ASAR_LISTING_BYTES"
        : "DEFAULT_ASAR_MAX_HEADER_BYTES";
    }
  }
  return base;
}

export async function probeWasm(rea, aegis, bytes, phase, sampleMeta = {}) {
  const base = outcomeBase("wasm_module", phase, bytes);
  const wabt = resolveWabtEnv();
  try {
    const valid = WebAssembly.validate(bytes);
    const inspection = aegis.inspectWasmBinary(bytes);
    base.metrics = {
      validates: valid,
      sectionCount: inspection.sectionCount,
      customSectionNames: inspection.customSectionNames,
      exportNames: inspection.exportNames,
      exportCount: inspection.exportNames?.length ?? 0,
      importCount: inspection.importCount,
      projectedChargeBytes: sampleMeta.projectedInterfaceChargeBytes ?? null,
      representationBudget: rea.WASM_INTERFACE_REPRESENTATION_BYTES,
      descriptorCount: sampleMeta.interfaceDescriptorsEmbedded ?? null,
      exportDecoysInjected: sampleMeta.exportDecoysInjected ?? null,
      exceedsRepresentationBudget:
        sampleMeta.exceedsRepresentationBudget === true,
      wabtAvailable: wabt.available,
    };

    // Prefer real Wabt E2E when REA_WABT_BIN_DIRECTORY (or ~/opt/wabt-1.0.42) is present.
    if (wabt.available && typeof rea.WabtArtifactProvider === "function") {
      const dir = mkdtempSync(join(tmpdir(), "aegis-rt-wabt-"));
      const path = join(dir, `${phase}.wasm`);
      writeFileSync(path, bytes);
      const provider = new rea.WabtArtifactProvider(wabt.env);
      try {
        const result = await provider.inspect({
          path,
          glue_paths: [],
          candidate_paths: [],
        });
        if (!result.ok) {
          const err = result.error;
          const msg = String(err?.userMessage ?? err?.message ?? err);
          const isBudget =
            /representation budget|WABT output|capacity/i.test(msg) ||
            err?.kind === "capacity" ||
            err?.details?.maximum_bytes != null;
          failOutcome(
            base,
            err,
            isBudget ? "WASM_INTERFACE_REPRESENTATION_BYTES" : "WABT",
          );
          if (isBudget) {
            base.budgetHit = true;
            base.budgetName = "WASM_INTERFACE_REPRESENTATION_BYTES";
            base.status = "budget_rejected";
          }
          base.metrics.wabtError = msg.slice(0, 240);
          return base;
        }
        const r = result.value.result ?? result.value;
        base.metrics.wabtValidation = r.validation;
        base.metrics.wabtExportForms = r.exports?.length ?? 0;
        base.metrics.wabtWatBytes = r.wat?.text?.length ?? 0;
        base.metrics.wabtInterfaceEntries = r.interface?.entries?.length ?? 0;
        base.metrics.wabtInterfaceState = r.interface?.state ?? null;
        base.metrics.wabtInterfaceIssues = (r.interface?.issues ?? []).slice(0, 2);
        const issues = r.interface?.issues ?? [];
        const tripped = issues.some((i) =>
          /representation budget|Typed WASM interface/i.test(String(i)),
        );
        if (tripped || r.interface?.state === "partial") {
          base.budgetHit = true;
          base.budgetName = "WASM_INTERFACE_REPRESENTATION_BYTES";
          base.status = "budget_rejected";
          base.redactionOrAmbiguity =
            issues[0] ??
            "Wabt typed interface inventory partial: representation budget exceeded";
        }
      } finally {
        try {
          await provider.close();
        } catch {
          /* ignore */
        }
      }
      return base;
    }

    // Soft fallback: in-process WasmInterfaceBudget with projected descriptors.
    base.metrics.wabtSkipped =
      "REA_WABT_BIN_DIRECTORY / ~/opt/wabt-1.0.42 not available; using projected WasmInterfaceBudget";
    if (phase === "after" && sampleMeta.exceedsRepresentationBudget) {
      const plan = aegis.planWasmInterfaceBudgetExhaustion(
        new aegis.SeededPrng("aegis-redteam-empirical-v1"),
        "bankrupt",
      );
      const budget = new rea.WasmInterfaceBudget();
      let charged = 0;
      for (const d of plan.descriptors) {
        const entry = {
          direction: "export",
          module: null,
          name: d.exportName,
          kind: "func",
          index: 0,
          wat_form: `(export "${d.exportName}" (func 0))`,
          issue: null,
          signature: {
            kind: "func",
            params: Array(d.paramCount).fill("i64"),
            results: Array(d.resultCount).fill("i64"),
          },
        };
        try {
          const cost = rea.wasmInterfaceEntryRepresentationBytes(entry);
          budget.reserve(cost);
          charged += cost;
        } catch (err) {
          base.metrics.chargeWhenTripped = charged;
          failOutcome(base, err, "WASM_INTERFACE_REPRESENTATION_BYTES");
          base.status = "budget_rejected";
          base.budgetHit = true;
          base.budgetName = "WASM_INTERFACE_REPRESENTATION_BYTES";
          base.redactionOrAmbiguity =
            "WasmInterfaceBudget refused projected interface inventory (install Wabt for full E2E)";
          return base;
        }
      }
      base.metrics.chargedBytes = charged;
      if (plan.exceedsRepresentationBudget) {
        base.budgetHit = true;
        base.budgetName = "WASM_INTERFACE_REPRESENTATION_BYTES";
        base.status = "budget_rejected";
      }
    }
  } catch (err) {
    failOutcome(base, err);
  }
  return base;
}

export async function probeSqlite(rea, aegis, bytes, phase) {
  const base = outcomeBase("sqlite_db", phase, bytes);
  if (!bytes.length) {
    base.status = "skipped";
    base.redactionOrAmbiguity = "sqlite sample unavailable (node:sqlite)";
    return base;
  }
  try {
    const inspection = aegis.inspectSqliteBuffer(bytes);
    base.metrics.aegisHoneyTables = inspection.honeyTablesCount;
    base.metrics.aegisTableCount =
      inspection.tableNames?.length ?? inspection.tables?.length;
    base.metrics.aegisProtected = inspection.aegisProtected === true;
    base.metrics.hasGeneratedTrapColumns =
      inspection.hasGeneratedTrapColumns === true;
  } catch (err) {
    base.metrics.aegisInspectError = String(err?.message ?? err).slice(0, 160);
  }

  if (typeof rea.inspectSqliteDatabaseSnapshot !== "function") {
    base.status = "skipped";
    base.redactionOrAmbiguity =
      "REA SqliteDatabaseInspection module not loadable";
    return base;
  }

  // Soft-skip when DatabaseSync.limits is absent (Node < 24.15).
  let hasLimits = false;
  try {
    const { DatabaseSync } = await import("node:sqlite");
    const probeDb = new DatabaseSync(":memory:");
    hasLimits = probeDb.limits != null && typeof probeDb.limits === "object";
    probeDb.close();
  } catch (err) {
    base.status = "capability_gated";
    base.redactionOrAmbiguity = `node:sqlite unavailable: ${String(err?.message ?? err).slice(0, 120)}`;
    return base;
  }
  base.metrics.nodeSqliteLimits = hasLimits;
  base.metrics.nodeVersion = process.version;
  if (!hasLimits) {
    base.status = "capability_gated";
    base.redactionOrAmbiguity =
      "REA SQLite inspection requires Node.js DatabaseSync.limits (24.15+ / 26+); honey/canary evidence recorded via AEGIS inspect instead";
    return base;
  }

  const dir = mkdtempSync(join(tmpdir(), "aegis-rt-sqlite-"));
  const path = join(dir, `${phase}.sqlite`);
  writeFileSync(path, bytes);
  try {
    const result = rea.inspectSqliteDatabaseSnapshot(path, {
      schema: true,
      rows: { limit: 16 },
    });
    const tableNames =
      result?.schema?.tables?.map((t) => t.name) ??
      result?.tables?.map((t) => t.name) ??
      [];
    base.metrics.reaTables = tableNames.length;
    base.metrics.reaTableNames = tableNames.slice(0, 12);
    base.metrics.reaLimitations = (result?.limitations ?? []).slice(0, 3);
    const HONEY = new Set([
      "enclave_key_hierarchy",
      "tpm2_attestation_ledger",
      "zero_trust_session_leases",
      "canary_transport_redaction",
      "system_diagnostic_log",
      "v_enclave_active_topology",
    ]);
    const honeyVisible = tableNames.filter((n) => HONEY.has(String(n)));
    base.metrics.reaHoneyTablesVisible = honeyVisible.length;

    // After hardening: select a honey table with generated trap columns —
    // REA cannot evaluate enclave_unseal_payload() → SqliteColumnEvaluationFailure.
    if (phase === "after" && honeyVisible.length > 0) {
      const honey = "enclave_key_hierarchy";
      try {
        rea.inspectSqliteDatabaseSnapshot(path, {
          schema: true,
          table: honey,
          rows: { limit: 16 },
        });
        base.redactionOrAmbiguity =
          "Honey table row read succeeded unexpectedly (generated trap did not fire)";
      } catch (err) {
        const msg = String(err?.message ?? err);
        const isTrap =
          err?.constructor?.name === "SqliteColumnEvaluationFailure" ||
          /enclave_unseal_payload|cannot evaluate selected column/i.test(msg);
        if (isTrap) {
          base.budgetHit = true;
          base.budgetName = "SqliteColumnEvaluationFailure";
          base.status = "budget_rejected";
          base.redactionOrAmbiguity =
            "REA cannot evaluate AEGIS generated trap columns (unknown function enclave_unseal_payload); honey schema still disclosed";
          base.errorName = err?.constructor?.name ?? "SqliteColumnEvaluationFailure";
          base.errorMessage = msg.slice(0, 240);
          base.metrics.trapColumnFailure = true;
        } else {
          failOutcome(base, err);
        }
      }
    }
  } catch (err) {
    const msg = String(err?.message ?? err);
    if (/DatabaseSync\.limits|24\.15|unavailable/i.test(msg)) {
      base.status = "capability_gated";
      base.redactionOrAmbiguity =
        "REA SQLite inspection requires Node.js 24.15+ / 26+ DatabaseSync.limits; honey/canary evidence recorded via AEGIS inspect instead";
      base.errorName = err?.constructor?.name ?? "SqliteInspectionFailure";
      base.errorMessage = msg.slice(0, 240);
    } else if (/16 MiB|output-limit|reply budget/i.test(msg)) {
      failOutcome(base, err, "SQLITE_DATABASE_LIMITS.outputBytes");
      base.budgetHit = true;
      base.budgetName = "SQLITE_DATABASE_LIMITS.outputBytes";
      base.status = "budget_rejected";
    } else {
      failOutcome(base, err);
    }
  }
  return base;
}

export async function probeElectronFuses(rea, bytes, phase) {
  const base = outcomeBase("electron_fuses", phase, bytes);
  const dir = mkdtempSync(join(tmpdir(), "aegis-rt-fuse-"));
  const path = join(dir, `${phase}.elf`);
  writeFileSync(path, bytes);
  try {
    const image = await rea.readElectronFuseImage(path);
    base.metrics.sentinelCount = image?.sentinels?.length ?? image?.sentinel_count;
    base.metrics.sliceCount = image?.slices?.length;
  } catch (err) {
    const msg = String(err?.message ?? err);
    const isCap =
      err?.constructor?.name === "ElectronFuseResourceFailure" ||
      /more than \d+ Electron fuse sentinels/i.test(msg) ||
      err?.capacity === "capacity" ||
      /capacity/i.test(String(err?.boundary ?? err?.kind ?? ""));
    failOutcome(
      base,
      err,
      isCap ? "ELECTRON_FUSE_LIMITS.maximumSentinelsPerSlice" : null,
    );
    if (isCap) {
      base.budgetHit = true;
      base.budgetName = "ELECTRON_FUSE_LIMITS.maximumSentinelsPerSlice";
      base.status = "budget_rejected";
    }
  }
  return base;
}

/** Catalog of analyzers that cannot run empirically on this box. */

export async function probeJavascript(rea, bytes, phase) {
  const base = outcomeBase("javascript", phase, bytes);
  const text = Buffer.isBuffer(bytes) ? bytes.toString("utf8") : String(bytes);
  try {
    const st = rea.analyzeJavaScriptStaticSource(text);
    const sem = rea.analyzeJavaScriptSemantics(text);
    const staticLimits = st?.coverage?.examination?.semantic_resource_limits ?? [];
    const semLimits = sem?.coverage?.resourceLimits ?? [];
    const allLimits = [...new Set([...staticLimits, ...semLimits])];
    base.metrics.parseStatus = st?.parse_status;
    base.metrics.staticCoverage = st?.coverage?.examination?.status;
    base.metrics.semCoverage = sem?.coverage?.status;
    base.metrics.semanticResourceLimits = allLimits;
    base.metrics.unknownFindings = st?.coverage?.semantics?.unknown_findings ?? 0;
    if (phase === "after" && allLimits.length > 0) {
      base.budgetHit = true;
      base.budgetName = allLimits.join("+");
      base.status = "budget_rejected";
      base.redactionOrAmbiguity =
        `REA JS semantic analysis degraded: resourceLimits=[${allLimits.join(", ")}] (real REA exceptions, not simulation)`;
    } else if (phase === "after" && (st?.parse_status === "partial" || sem?.coverage?.status === "partial")) {
      base.budgetHit = true;
      base.budgetName = "javascript-semantic-partial";
      base.status = "budget_rejected";
      base.redactionOrAmbiguity = "REA JS analysis returned partial coverage without explicit resourceLimits";
    }
  } catch (err) {
    failOutcome(base, err, "javascript-analysis");
  }
  return base;
}

export function unverifiedAnalyzers() {
  return [
    {
      analyzer: "Ghidra / Hopper native decompile",
      reason: "requires Ghidra/Hopper install (not available without root/GUI)",
    },
    {
      analyzer: "Frida dynamic instrumentation",
      reason: "requires frida-tools + attachable target process",
    },
    {
      analyzer: "LLDB / GDB native tracing",
      reason: "requires lldb/gdb + debuggee; not installed here",
    },
    {
      analyzer: "Rizin / Cutter",
      reason: "requires rizin binary",
    },
    {
      analyzer: "JADX Android decompile",
      reason: "requires JADX JVM tooling",
    },
    {
      analyzer: "EVM EVMole worker full interface recovery",
      reason:
        "Not pathable in-process: EvmoleInterfaceWorker refuses library import ('Owned worker request path missing') and only runs under REA's owned subprocess launcher (prlimit address-space/CPU/file-size, 256 MiB heap, IPC reply schema). The evmole npm package exists in the REA tree but cannot be driven without that ownership harness. inputBytes (4 MiB) admission is checked in-process via probeEvm.",
    },
    {
      analyzer: "WASM Wabt full WAT decode (wasm-objdump / wasm2wat)",
      reason: resolveWabtEnv().available
        ? "AVAILABLE this run — probeWasm drives WabtArtifactProvider end-to-end"
        : "Requires REA_WABT_BIN_DIRECTORY with WABT 1.0.42 (e.g. ~/opt/wabt-1.0.42/bin). Soft-skips to projected WasmInterfaceBudget when absent.",
    },
    {
      analyzer: "SQLite inspect_sqlite_database (DatabaseSync.limits)",
      reason:
        "Requires Node.js DatabaseSync.limits (24.15+ / 26+). Soft-skips as capability_gated on Node 22; under Node 24 probeSqlite records honey disclosure + SqliteColumnEvaluationFailure on generated trap columns.",
    },
    {
      analyzer: "SPIR-V / CUDA fatbinary / AMD GPU object",
      reason:
        "AEGIS skips these formats (GPU_OBJECT_HARDENING_SKIP_REASON); no shield to validate",
    },
    {
      analyzer: "Firmware analysis",
      reason:
        "AEGIS skips firmware (FIRMWARE_HARDENING_SKIP_REASON); needs vendor parsers",
    },
  ];
}
