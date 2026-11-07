import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import {
  AEGIS_PACKAGE_ROOT,
  reaCheckoutPresent,
  reaDistReady,
  resolveReaRoot,
} from "./rea-observability.js";
import { AEGIS_IDENTITY } from "../identity.js";

/**
 * AEGIS "measurement" column (docs/AEGIS-MEASUREMENT.md).
 *
 * Empirically runs real REA parsers (via scripts/redteam/lib/probes.mjs +
 * lib/samples.mjs, reused unmodified) against AEGIS-hardened samples and
 * compares AEGIS's own `sampleMeta` budget-trip claims to what REA's real
 * code actually reports, producing a numeric overclaim/underclaim deviation.
 */

// scripts/redteam/lib/{samples,probes}.mjs are plain, uncompiled JS reused
// verbatim here (never rewritten); these are minimal structural types for
// the handful of exports this runner actually calls.
interface RedteamSamplesModule {
  buildSampleMatrix(options?: { intensity?: string; seed?: string }): Promise<{
    aegis: { REA_INTERNAL_LIMITS: Record<string, unknown> } & Record<string, unknown>;
    intensity: string;
    seed: string;
    samples: Record<string, { format: string; before: Buffer; after: Buffer; meta: Record<string, unknown> }>;
  }>;
}

interface RedteamProbesModule {
  loadReaProbes(): Promise<Record<string, unknown>>;
  probeGo(rea: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
  probeFlutterPool(
    aegis: unknown,
    bytes: Buffer,
    phase: "before" | "after",
    limits: unknown,
  ): Promise<Record<string, unknown>>;
  probeBeam(rea: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
  probeEvm(rea: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
  probePcap(rea: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
  probeSafetensors(rea: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
  probeGguf(rea: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
  probePtx(rea: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
  probeAsar(rea: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
  probeWasm(
    rea: unknown,
    aegis: unknown,
    bytes: Buffer,
    phase: "before" | "after",
    sampleMeta?: Record<string, unknown>,
  ): Promise<Record<string, unknown>>;
  probeSqlite(rea: unknown, aegis: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
  probeElectronFuses(rea: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
  probeJavascript(rea: unknown, bytes: Buffer, phase: "before" | "after"): Promise<Record<string, unknown>>;
}

export const MEASURE_SCHEMA = "aegis-measure/v1";

/**
 * The formats scripts/redteam/run.mjs actually measures today. (The spec
 * prose says "14"; the live sample matrix + probe wiring currently covers
 * these 13 — go_buildinfo and flutter_pool share one ELF sample. This list
 * reflects the real runnable set, not the prose count.)
 */
export const KNOWN_MEASURE_FORMATS = [
  "go_buildinfo",
  "flutter_pool",
  "erlang_beam",
  "evm_bytecode",
  "pcap_capture",
  "safetensors",
  "gguf",
  "gpu_ptx",
  "electron_asar",
  "wasm_module",
  "sqlite_db",
  "electron_fuses",
  "javascript",
] as const;

export type MeasureFormat = (typeof KNOWN_MEASURE_FORMATS)[number];

const FORMAT_SAMPLE_KEY: Record<MeasureFormat, string> = {
  go_buildinfo: "go_flutter_elf",
  flutter_pool: "go_flutter_elf",
  erlang_beam: "erlang_beam",
  evm_bytecode: "evm_bytecode",
  pcap_capture: "pcap_capture",
  safetensors: "safetensors",
  gguf: "gguf",
  gpu_ptx: "gpu_ptx",
  electron_asar: "electron_asar",
  wasm_module: "wasm_module",
  sqlite_db: "sqlite_db",
  electron_fuses: "electron_fuses",
  javascript: "javascript",
};

export type ProtectionIntensityName = "stealth" | "balanced" | "maximum" | "bankrupt";

export interface MeasureOptions {
  readonly formats?: readonly string[];
  readonly seed?: string;
  readonly intensity?: ProtectionIntensityName;
  readonly outDir?: string;
  readonly timeoutMs?: number;
  readonly reaRoot?: string;
}

export interface MeasureFormatRecord {
  readonly format: MeasureFormat;
  readonly status: "measured" | "skipped" | "failed";
  readonly durationMs: number;
  readonly timeout: boolean;
  readonly beforeBudgetHit: boolean;
  readonly afterBudgetHit: boolean;
  readonly afterBudgetName: string | null;
  readonly estimatedTrip: boolean | null;
  readonly deviation: 0 | 1 | null;
  readonly deviationKind: "overclaim" | "underclaim" | null;
  readonly inputBytesBefore: number;
  readonly inputBytesAfter: number;
  readonly growthRatio: number | null;
  readonly errorName: string | null;
  readonly errorMessage: string | null;
  readonly metrics: Record<string, unknown>;
}

export interface MeasureSkip {
  readonly format: MeasureFormat;
  readonly reason: string;
}

export interface MeasureSummary {
  readonly selected: number;
  readonly measured: number;
  readonly skipped: number;
  readonly passed: number;
  readonly remaining: number;
  readonly divergences: number;
  readonly overclaims: number;
  readonly underclaims: number;
  readonly formatCoverage: number;
  readonly totalDurationMs: number;
  readonly medianDurationMs: number;
  readonly verdict: "pass" | "inconclusive" | "fail";
}

export interface MeasureDocument {
  readonly schema: "aegis-measure/v1";
  readonly generatedAt: string;
  readonly aegisVersion: string;
  readonly rea: { readonly root: string; readonly commit: string | null; readonly distReady: boolean };
  readonly run: { readonly seed: string; readonly intensity: string; readonly nodeVersion: string };
  readonly summary: MeasureSummary;
  readonly formats: readonly MeasureFormatRecord[];
  readonly skips: readonly MeasureSkip[];
}

export type MeasureRunResult =
  | { readonly kind: "rea-not-ready"; readonly reaRoot: string }
  | { readonly kind: "locked"; readonly lockPath: string; readonly holderPid: number | null }
  | { readonly kind: "invalid-format"; readonly invalid: readonly string[]; readonly valid: readonly string[] }
  | { readonly kind: "ok"; readonly document: MeasureDocument; readonly jsonPath: string; readonly mdPath: string };

/**
 * Pure deviation calculation (acceptance criterion #6): compares AEGIS's own
 * `estimatedTrip` claim to REA's empirically-observed `afterBudgetHit`.
 * `estimatedTrip === null` means AEGIS makes no claim for this format — no
 * deviation can be computed.
 */
/**
 * REA reports a budget trip as a thrown error (e.g. BinaryResourceFailure,
 * BeamCapacityFailure) that the probe records as status "error" with
 * `budgetHit: true`. That is the measured outcome AEGIS aims for, not a failed
 * measurement; only an "error" WITHOUT a budget hit is a genuine probe failure.
 */
export function isBudgetTripError(after: Record<string, unknown> | null | undefined): boolean {
  return after?.status === "error" && after.budgetHit === true;
}

export function computeDeviation(
  estimatedTrip: boolean | null,
  afterBudgetHit: boolean,
): { deviation: 0 | 1 | null; deviationKind: "overclaim" | "underclaim" | null } {
  if (estimatedTrip === null) return { deviation: null, deviationKind: null };
  if (afterBudgetHit === estimatedTrip) return { deviation: 0, deviationKind: null };
  return { deviation: 1, deviationKind: estimatedTrip === true ? "overclaim" : "underclaim" };
}

/** Pure verdict calculation (docs/AEGIS-MEASUREMENT.md section 4). */
export function computeVerdict(params: {
  readonly divergences: number;
  readonly anyBeforeBudgetHit: boolean;
  readonly formatCoverage: number;
  readonly totalDurationMs: number;
}): "pass" | "inconclusive" | "fail" {
  if (params.divergences > 0 || params.anyBeforeBudgetHit) return "fail";
  if (params.formatCoverage < 0.85 || params.totalDurationMs > 600_000) return "inconclusive";
  return "pass";
}

function median(values: readonly number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1]! + sorted[mid]!) / 2 : sorted[mid]!;
}

function estimatedTripFor(format: MeasureFormat, meta: Record<string, unknown> | undefined): boolean | null {
  if (!meta) return null;
  switch (format) {
    case "go_buildinfo":
      return typeof meta.goTripsMax === "boolean" ? meta.goTripsMax : null;
    case "erlang_beam":
      return typeof meta.exceedsDefaultChunkBudget === "boolean" ? meta.exceedsDefaultChunkBudget : null;
    case "evm_bytecode":
      return typeof meta.approachesInputBudget === "boolean" ? meta.approachesInputBudget : null;
    case "pcap_capture":
      return typeof meta.exceedsTsharkJsonBudget === "boolean" ? meta.exceedsTsharkJsonBudget : null;
    case "safetensors":
      return typeof meta.triggeredJsonNestingBreaker === "boolean" ? meta.triggeredJsonNestingBreaker : null;
    case "gguf":
      return typeof meta.triggeredMetadataNestingBreaker === "boolean" ? meta.triggeredMetadataNestingBreaker : null;
    case "electron_asar":
      return typeof meta.exceedsDefaultAdmission === "boolean" ? meta.exceedsDefaultAdmission : null;
    case "wasm_module":
      return typeof meta.exceedsRepresentationBudget === "boolean" ? meta.exceedsRepresentationBudget : null;
    case "electron_fuses":
      return typeof meta.electronFuseSentinelsInjected === "number" ? meta.electronFuseSentinelsInjected > 32 : null;
    case "javascript":
      return typeof meta.decoyFunctionsInjected === "number" ? meta.decoyFunctionsInjected > 0 : null;
    case "flutter_pool":
    case "gpu_ptx":
    case "sqlite_db":
      return null;
    default:
      return null;
  }
}

async function withTimeout<T>(fn: () => Promise<T>, timeoutMs: number): Promise<{ value: T; timedOut: false } | { value: null; timedOut: true }> {
  let timer: NodeJS.Timeout | null = null;
  try {
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`measurement timed out after ${timeoutMs}ms`)), timeoutMs);
    });
    const value = await Promise.race([fn(), timeout]);
    return { value, timedOut: false };
  } catch (err) {
    if (err instanceof Error && err.message.includes("timed out after")) {
      return { value: null, timedOut: true };
    }
    throw err;
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function reaCommit(reaRoot: string): string | null {
  try {
    const result = spawnSync("git", ["-C", reaRoot, "rev-parse", "--short", "HEAD"], {
      encoding: "utf8",
      timeout: 5_000,
    });
    if (result.status === 0 && typeof result.stdout === "string") {
      const trimmed = result.stdout.trim();
      return trimmed.length > 0 ? trimmed : null;
    }
  } catch {
    /* git unavailable: never fatal */
  }
  return null;
}

/** Build the markdown summary, hard-capped at 40 lines (acceptance #9). */
export function renderMeasureMarkdown(doc: MeasureDocument): string {
  const lines: string[] = [];
  const { summary } = doc;
  lines.push(
    `# AEGIS measure — ${summary.verdict.toUpperCase()} (coverage ${(summary.formatCoverage * 100).toFixed(1)}%, divergences ${summary.divergences})`,
  );
  lines.push("");
  lines.push("## Divergences");
  const diverging = doc.formats.filter((f) => f.deviation === 1);
  if (diverging.length === 0) {
    lines.push("(none)");
  } else {
    for (const f of diverging) {
      lines.push(`- ${f.format}: ${f.deviationKind} (estimatedTrip=${f.estimatedTrip}, afterBudgetHit=${f.afterBudgetHit})`);
    }
  }
  lines.push("");
  lines.push("## Skipped");
  if (doc.skips.length === 0) {
    lines.push("(none)");
  } else {
    for (const s of doc.skips) lines.push(`- ${s.format}: ${s.reason}`);
  }
  lines.push("");
  lines.push("## Durations");
  for (const f of doc.formats) lines.push(`- ${f.format}: ${f.durationMs}ms (${f.status})`);
  lines.push("");
  lines.push("## Environment");
  lines.push(`- REA root: ${doc.rea.root} (commit ${doc.rea.commit ?? "unknown"})`);
  lines.push(`- Node: ${doc.run.nodeVersion}, seed: ${doc.run.seed}, intensity: ${doc.run.intensity}`);

  const MAX_LINES = 40;
  if (lines.length <= MAX_LINES) return lines.join("\n");
  return [...lines.slice(0, MAX_LINES - 1), "truncated: true"].join("\n");
}

/**
 * Run the measurement pass. Reuses scripts/redteam/lib/{samples,probes}.mjs
 * verbatim via dynamic import — never reimplements REA-probing logic.
 */
export async function runMeasurement(options: MeasureOptions = {}): Promise<MeasureRunResult> {
  const reaRoot = resolveReaRoot(options.reaRoot);
  // Preflight first so a not-ready / invalid call never creates a lock or any file.
  if (!reaCheckoutPresent(reaRoot) || !reaDistReady(reaRoot)) {
    return { kind: "rea-not-ready", reaRoot };
  }
  const requested = options.formats && options.formats.length > 0 ? options.formats : undefined;
  if (requested) {
    const invalid = requested.filter((f) => !(KNOWN_MEASURE_FORMATS as readonly string[]).includes(f));
    if (invalid.length > 0) return { kind: "invalid-format", invalid, valid: KNOWN_MEASURE_FORMATS };
  }

  const outDir = options.outDir ?? process.env.AEGIS_MEASURE_OUT_DIR ?? join(AEGIS_PACKAGE_ROOT, "docs", "measure");
  const lock = acquireMeasureLock(outDir);
  if (!lock.acquired) {
    return { kind: "locked", lockPath: measureLockPath(outDir), holderPid: lock.holderPid };
  }
  try {
    return await measureCore({ ...options, outDir });
  } finally {
    releaseMeasureLock(outDir);
  }
}

async function measureCore(options: MeasureOptions): Promise<MeasureRunResult> {
  const reaRoot = resolveReaRoot(options.reaRoot);
  if (!reaCheckoutPresent(reaRoot) || !reaDistReady(reaRoot)) {
    return { kind: "rea-not-ready", reaRoot };
  }

  const requested = options.formats && options.formats.length > 0 ? options.formats : undefined;
  if (requested) {
    const invalid = requested.filter((f) => !(KNOWN_MEASURE_FORMATS as readonly string[]).includes(f));
    if (invalid.length > 0) {
      return { kind: "invalid-format", invalid, valid: KNOWN_MEASURE_FORMATS };
    }
  }

  const samplesModUrl = pathToFileURL(join(AEGIS_PACKAGE_ROOT, "scripts/redteam/lib/samples.mjs")).href;
  const probesModUrl = pathToFileURL(join(AEGIS_PACKAGE_ROOT, "scripts/redteam/lib/probes.mjs")).href;
  // scripts/redteam/lib/*.mjs are plain, uncompiled JS (reused verbatim, not
  // rewritten) — no .d.ts exists, so these are loaded as untyped modules.
  const samplesMod = (await import(samplesModUrl)) as RedteamSamplesModule;
  const probesMod = (await import(probesModUrl)) as RedteamProbesModule;

  const { aegis, intensity, seed, samples } = await samplesMod.buildSampleMatrix({
    ...(options.intensity !== undefined ? { intensity: options.intensity } : {}),
    ...(options.seed !== undefined ? { seed: options.seed } : {}),
  });
  const rea = await probesMod.loadReaProbes();
  const limits = aegis.REA_INTERNAL_LIMITS;
  const timeoutMs = options.timeoutMs ?? 120_000;

  const selectedFormats: MeasureFormat[] = requested
    ? (requested as MeasureFormat[])
    : [...KNOWN_MEASURE_FORMATS];

  async function callProbe(format: MeasureFormat, phase: "before" | "after"): Promise<Record<string, unknown>> {
    const sample = (samples as Record<string, { before: Buffer; after: Buffer; meta: Record<string, unknown> }>)[
      FORMAT_SAMPLE_KEY[format]
    ]!;
    const bytes = phase === "before" ? sample.before : sample.after;
    switch (format) {
      case "go_buildinfo":
        return probesMod.probeGo(rea, bytes, phase);
      case "flutter_pool":
        return probesMod.probeFlutterPool(aegis, bytes, phase, limits);
      case "erlang_beam":
        return probesMod.probeBeam(rea, bytes, phase);
      case "evm_bytecode":
        return probesMod.probeEvm(rea, bytes, phase);
      case "pcap_capture":
        return probesMod.probePcap(rea, bytes, phase);
      case "safetensors":
        return probesMod.probeSafetensors(rea, bytes, phase);
      case "gguf":
        return probesMod.probeGguf(rea, bytes, phase);
      case "gpu_ptx":
        return probesMod.probePtx(rea, bytes, phase);
      case "electron_asar":
        return probesMod.probeAsar(rea, bytes, phase);
      case "wasm_module":
        return probesMod.probeWasm(rea, aegis, bytes, phase, sample.meta);
      case "sqlite_db":
        return probesMod.probeSqlite(rea, aegis, bytes, phase);
      case "electron_fuses":
        return probesMod.probeElectronFuses(rea, bytes, phase);
      case "javascript":
        return probesMod.probeJavascript(rea, bytes, phase);
      default:
        throw new Error(`unreachable format: ${format}`);
    }
  }

  const records: MeasureFormatRecord[] = [];
  const skips: MeasureSkip[] = [];

  for (const format of selectedFormats) {
    const sampleMeta = (samples as Record<string, { meta: Record<string, unknown> }>)[FORMAT_SAMPLE_KEY[format]]!.meta;
    const start = Date.now();
    let before: Record<string, unknown> | null = null;
    let after: Record<string, unknown> | null = null;
    let timedOut = false;
    let thrown: unknown = null;

    try {
      const beforeResult = await withTimeout(() => callProbe(format, "before"), timeoutMs);
      if (beforeResult.timedOut) {
        timedOut = true;
      } else {
        before = beforeResult.value;
        const afterResult = await withTimeout(() => callProbe(format, "after"), timeoutMs);
        if (afterResult.timedOut) timedOut = true;
        else after = afterResult.value;
      }
    } catch (err) {
      thrown = err;
    }

    const durationMs = Date.now() - start;
    const inputBytesBefore = typeof before?.inputBytes === "number" ? (before.inputBytes as number) : 0;
    const inputBytesAfter = typeof after?.inputBytes === "number" ? (after.inputBytes as number) : 0;
    const growthRatio = inputBytesBefore > 0 ? Number((inputBytesAfter / inputBytesBefore).toFixed(3)) : null;

    const afterStatus = typeof after?.status === "string" ? (after.status as string) : null;
    const skipStatuses = new Set(["skipped", "capability_gated"]);

    let status: "measured" | "skipped" | "failed";
    let skipReason: string | null = null;

    if (timedOut) {
      status = "failed";
    } else if (thrown) {
      status = "failed";
      skipReason = String((thrown as Error)?.message ?? thrown).slice(0, 200);
    } else if (afterStatus && skipStatuses.has(afterStatus)) {
      status = "skipped";
      skipReason =
        typeof after?.redactionOrAmbiguity === "string" ? (after.redactionOrAmbiguity as string) : afterStatus;
    } else if (afterStatus === "error" && !isBudgetTripError(after)) {
      status = "failed";
      skipReason = typeof after?.errorMessage === "string" ? (after.errorMessage as string) : "error";
    } else {
      status = "measured";
    }

    const afterBudgetHit = after?.budgetHit === true;
    const beforeBudgetHit = before?.budgetHit === true;
    const afterBudgetName = typeof after?.budgetName === "string" ? (after.budgetName as string) : null;
    const estimatedTrip = status === "measured" ? estimatedTripFor(format, sampleMeta) : null;

    const { deviation, deviationKind } =
      status === "measured" ? computeDeviation(estimatedTrip, afterBudgetHit) : { deviation: null, deviationKind: null };

    if (status !== "measured") {
      skips.push({ format, reason: skipReason ?? "unknown" });
    }

    records.push({
      format,
      status,
      durationMs,
      timeout: timedOut,
      beforeBudgetHit,
      afterBudgetHit,
      afterBudgetName,
      estimatedTrip,
      deviation,
      deviationKind,
      inputBytesBefore,
      inputBytesAfter,
      growthRatio,
      errorName: typeof after?.errorName === "string" ? (after.errorName as string) : null,
      errorMessage: typeof after?.errorMessage === "string" ? (after.errorMessage as string) : null,
      metrics: (after?.metrics as Record<string, unknown>) ?? {},
    });
  }

  const selected = records.length;
  const measured = records.filter((r) => r.status === "measured").length;
  const skipped = records.filter((r) => r.status !== "measured").length;
  const divergences = records.filter((r) => r.deviation === 1).length;
  const overclaims = records.filter((r) => r.deviationKind === "overclaim").length;
  const underclaims = records.filter((r) => r.deviationKind === "underclaim").length;
  const passed = measured - divergences;
  const remaining = skipped;
  const formatCoverage = selected > 0 ? Number((measured / selected).toFixed(3)) : 0;
  const totalDurationMs = records.reduce((sum, r) => sum + r.durationMs, 0);
  const medianDurationMs = Math.round(median(records.map((r) => r.durationMs)));
  const anyBeforeHit = records.some((r) => r.beforeBudgetHit);

  const verdict = computeVerdict({
    divergences,
    anyBeforeBudgetHit: anyBeforeHit,
    formatCoverage,
    totalDurationMs,
  });

  const summary: MeasureSummary = {
    selected,
    measured,
    skipped,
    passed,
    remaining,
    divergences,
    overclaims,
    underclaims,
    formatCoverage,
    totalDurationMs,
    medianDurationMs,
    verdict,
  };

  const document: MeasureDocument = {
    schema: MEASURE_SCHEMA,
    generatedAt: new Date().toISOString(),
    aegisVersion: AEGIS_IDENTITY.version,
    rea: { root: reaRoot, commit: reaCommit(reaRoot), distReady: true },
    run: { seed, intensity, nodeVersion: process.version },
    summary,
    formats: records,
    skips,
  };

  const outDir = options.outDir ?? process.env.AEGIS_MEASURE_OUT_DIR ?? join(AEGIS_PACKAGE_ROOT, "docs", "measure");
  mkdirSync(outDir, { recursive: true });
  const stamp = document.generatedAt.replace(/[:.]/g, "-");
  const jsonPath = join(outDir, `measure-${stamp}.json`);
  const mdPath = join(outDir, `measure-${stamp}.md`);
  writeFileSync(jsonPath, JSON.stringify(document, null, 2));
  writeFileSync(mdPath, renderMeasureMarkdown(document));

  return { kind: "ok", document, jsonPath, mdPath };
}

export function measureLockPath(outDir: string): string {
  return join(outDir, ".measure-lock");
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "EPERM";
  }
}

/**
 * Atomic (`wx`) lock so two concurrent `aegis measure` runs cannot share an
 * output dir. A lock whose holder pid is dead is stale and is taken over.
 */
export function acquireMeasureLock(outDir: string): { acquired: boolean; holderPid: number | null } {
  const lockPath = measureLockPath(outDir);
  mkdirSync(outDir, { recursive: true });
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      writeFileSync(lockPath, String(process.pid), { flag: "wx" });
      return { acquired: true, holderPid: process.pid };
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "EEXIST") throw err;
      let holder: number | null = null;
      try {
        const n = Number.parseInt(readFileSync(lockPath, "utf8").trim(), 10);
        holder = Number.isFinite(n) ? n : null;
      } catch {
        continue; // vanished between EEXIST and read: retry
      }
      if (holder !== null && pidAlive(holder)) return { acquired: false, holderPid: holder };
      try {
        unlinkSync(lockPath); // stale
      } catch {
        /* raced with another cleaner */
      }
    }
  }
  return { acquired: false, holderPid: null };
}

export function releaseMeasureLock(outDir: string): void {
  const lockPath = measureLockPath(outDir);
  try {
    if (readFileSync(lockPath, "utf8").trim() === String(process.pid)) unlinkSync(lockPath);
  } catch {
    /* best effort */
  }
}
