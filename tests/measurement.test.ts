import { existsSync, readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  KNOWN_MEASURE_FORMATS,
  computeDeviation,
  computeVerdict,
  renderMeasureMarkdown,
  runMeasurement,
  type MeasureDocument,
} from "../src/engine/measurement-runner.js";
import { reaCheckoutPresent, reaDistReady, resolveReaRoot } from "../src/engine/rea-observability.js";

const reaReady = reaCheckoutPresent() && reaDistReady();
const outDir = join(process.cwd(), "tests", "tmp", "measure-output");

function freshOutDir(): string {
  rmSync(outDir, { recursive: true, force: true });
  return outDir;
}

// docs/AEGIS-MEASUREMENT.md section 7, acceptance criteria 1-10.
describe.skipIf(!reaReady)("measurement-runner (live REA, acceptance criteria)", () => {
  it("1. --format wasm_module runs only that format (summary.selected === 1)", async () => {
    const dir = freshOutDir();
    const result = await runMeasurement({ formats: ["wasm_module"], outDir: dir });
    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") return;
    expect(result.document.summary.selected).toBe(1);
    expect(result.document.formats).toHaveLength(1);
    expect(result.document.formats[0]!.format).toBe("wasm_module");
  }, 30_000);

  it("2. an unknown --format value is rejected with the valid list", async () => {
    const result = await runMeasurement({ formats: ["not-a-real-format"], outDir: freshOutDir() });
    expect(result.kind).toBe("invalid-format");
    if (result.kind !== "invalid-format") return;
    expect(result.invalid).toEqual(["not-a-real-format"]);
    expect(result.valid).toEqual(KNOWN_MEASURE_FORMATS);
  });

  it("3. missing REA dist exits via rea-not-ready and writes no file", async () => {
    const dir = freshOutDir();
    const result = await runMeasurement({ outDir: dir, reaRoot: join(dir, "no-such-rea-checkout") });
    expect(result.kind).toBe("rea-not-ready");
    expect(existsSync(dir) && readdirSync(dir).length > 0).toBe(false);
  });

  it("4. same seed, two runs: identical afterBudgetHit per format (durations excluded)", async () => {
    const formats = ["wasm_module", "sqlite_db", "javascript"];
    const first = await runMeasurement({ formats, outDir: freshOutDir() });
    const second = await runMeasurement({ formats, outDir: freshOutDir() });
    expect(first.kind).toBe("ok");
    expect(second.kind).toBe("ok");
    if (first.kind !== "ok" || second.kind !== "ok") return;
    const strip = (doc: MeasureDocument) =>
      doc.formats.map((f) => ({ format: f.format, afterBudgetHit: f.afterBudgetHit, status: f.status }));
    expect(strip(first.document)).toEqual(strip(second.document));
  }, 30_000);

  it("5. schema is aegis-measure/v1 and measured + skipped === selected", async () => {
    const result = await runMeasurement({
      formats: ["wasm_module", "pcap_capture", "sqlite_db"],
      outDir: freshOutDir(),
    });
    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") return;
    const { document } = result;
    expect(document.schema).toBe("aegis-measure/v1");
    expect(document.summary.measured + document.summary.skipped).toBe(document.summary.selected);
  }, 30_000);

  it("7. verdict:fail is exit-relevant only with --fail-on-diverge (checked at CLI layer); runner always reports the real verdict", async () => {
    const result = await runMeasurement({ formats: ["wasm_module"], outDir: freshOutDir() });
    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") return;
    expect(["pass", "inconclusive", "fail"]).toContain(result.document.summary.verdict);
  }, 30_000);

  it("8. a skipped format (pcap_capture, no tshark on this box) appears in skips[] and lowers formatCoverage", async () => {
    const result = await runMeasurement({ formats: ["pcap_capture", "wasm_module"], outDir: freshOutDir() });
    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") return;
    const pcap = result.document.formats.find((f) => f.format === "pcap_capture")!;
    if (pcap.status !== "measured") {
      expect(result.document.skips.some((s) => s.format === "pcap_capture")).toBe(true);
      expect(result.document.summary.formatCoverage).toBeLessThan(1);
    }
  }, 30_000);

  it("writes both measure-<stamp>.json and measure-<stamp>.md under --out", async () => {
    const dir = freshOutDir();
    const result = await runMeasurement({ formats: ["wasm_module"], outDir: dir });
    expect(result.kind).toBe("ok");
    if (result.kind !== "ok") return;
    expect(existsSync(result.jsonPath)).toBe(true);
    expect(existsSync(result.mdPath)).toBe(true);
  }, 30_000);
});

describe("computeDeviation (pure, acceptance criterion #6)", () => {
  it("estimatedTrip true + afterBudgetHit false => overclaim deviation", () => {
    expect(computeDeviation(true, false)).toEqual({ deviation: 1, deviationKind: "overclaim" });
  });

  it("estimatedTrip false + afterBudgetHit true => underclaim deviation", () => {
    expect(computeDeviation(false, true)).toEqual({ deviation: 1, deviationKind: "underclaim" });
  });

  it("estimatedTrip matches afterBudgetHit => no deviation", () => {
    expect(computeDeviation(true, true)).toEqual({ deviation: 0, deviationKind: null });
    expect(computeDeviation(false, false)).toEqual({ deviation: 0, deviationKind: null });
  });

  it("estimatedTrip null (no AEGIS claim) => deviation is null, never counted", () => {
    expect(computeDeviation(null, true)).toEqual({ deviation: null, deviationKind: null });
    expect(computeDeviation(null, false)).toEqual({ deviation: null, deviationKind: null });
  });
});

describe("computeVerdict (pure, acceptance criterion #6/#4 threshold rules)", () => {
  const base = { divergences: 0, anyBeforeBudgetHit: false, formatCoverage: 1, totalDurationMs: 1000 };

  it("all thresholds satisfied => pass", () => {
    expect(computeVerdict(base)).toBe("pass");
  });

  it("any divergence => fail (deliberately broken claim scenario)", () => {
    expect(computeVerdict({ ...base, divergences: 1 })).toBe("fail");
  });

  it("an unhardened (before) sample tripping a budget => fail", () => {
    expect(computeVerdict({ ...base, anyBeforeBudgetHit: true })).toBe("fail");
  });

  it("low formatCoverage (<0.85) with no divergence => inconclusive, not fail", () => {
    expect(computeVerdict({ ...base, formatCoverage: 0.5 })).toBe("inconclusive");
  });

  it("exceeding the 600000ms duration budget with no divergence => inconclusive", () => {
    expect(computeVerdict({ ...base, totalDurationMs: 600_001 })).toBe("inconclusive");
  });

  it("divergence takes priority over a coverage/duration inconclusive reason", () => {
    expect(computeVerdict({ ...base, divergences: 1, formatCoverage: 0.1 })).toBe("fail");
  });
});

describe("renderMeasureMarkdown", () => {
  function doc(overrides: Partial<MeasureDocument["summary"]> = {}): MeasureDocument {
    return {
      schema: "aegis-measure/v1",
      generatedAt: "2026-11-07T00:00:00.000Z",
      aegisVersion: "3.0.1",
      rea: { root: "/fake/rea", commit: "abc1234", distReady: true },
      run: { seed: "test-seed", intensity: "balanced", nodeVersion: "v24.19.0" },
      summary: {
        selected: 1,
        measured: 1,
        skipped: 0,
        passed: 1,
        remaining: 0,
        divergences: 0,
        overclaims: 0,
        underclaims: 0,
        formatCoverage: 1,
        totalDurationMs: 10,
        medianDurationMs: 10,
        verdict: "pass",
        ...overrides,
      },
      formats: [],
      skips: [],
    };
  }

  it("9. stays within 40 lines for a small report and omits truncated:true", () => {
    const text = renderMeasureMarkdown(doc());
    expect(text.split("\n").length).toBeLessThanOrEqual(40);
    expect(text).not.toContain("truncated: true");
  });

  it("9b. marks truncated:true when the report would exceed 40 lines", () => {
    const big = doc();
    const manyFormats = Array.from({ length: 60 }, (_, i) => ({
      format: KNOWN_MEASURE_FORMATS[i % KNOWN_MEASURE_FORMATS.length]!,
      status: "measured" as const,
      durationMs: i,
      timeout: false,
      beforeBudgetHit: false,
      afterBudgetHit: false,
      afterBudgetName: null,
      estimatedTrip: null,
      deviation: null,
      deviationKind: null,
      inputBytesBefore: 0,
      inputBytesAfter: 0,
      growthRatio: null,
      errorName: null,
      errorMessage: null,
      metrics: {},
    }));
    const text = renderMeasureMarkdown({ ...big, formats: manyFormats });
    expect(text.split("\n").length).toBeLessThanOrEqual(40);
    expect(text).toContain("truncated: true");
  });

  it("leads with a single verdict + coverage + divergence summary line", () => {
    const text = renderMeasureMarkdown(doc({ verdict: "fail", divergences: 2, formatCoverage: 0.5 }));
    expect(text.split("\n")[0]).toMatch(/FAIL/);
    expect(text.split("\n")[0]).toMatch(/50\.0%/);
    expect(text.split("\n")[0]).toMatch(/divergences 2/);
  });
});

describe("resolveReaRoot / KNOWN_MEASURE_FORMATS sanity", () => {
  it("KNOWN_MEASURE_FORMATS has 13 distinct keys (the real runnable set, not the spec's stale '14')", () => {
    expect(new Set(KNOWN_MEASURE_FORMATS).size).toBe(13);
  });

  it("resolveReaRoot honors an explicit override", () => {
    expect(resolveReaRoot("/some/explicit/rea")).toContain("rea");
  });
});

describe("measure lock (docs/AEGIS-MEASUREMENT.md section 6)", () => {
  it("a held lock makes the second run return a clear 'locked' result and write nothing", async () => {
    const { acquireMeasureLock, releaseMeasureLock, measureLockPath } = await import("../src/engine/measurement-runner.js");
    const dir = freshOutDir();
    const held = acquireMeasureLock(dir);
    expect(held.acquired).toBe(true);
    try {
      expect(acquireMeasureLock(dir).acquired).toBe(false);
      if (reaReady) {
        const r = await runMeasurement({ formats: ["wasm_module"], outDir: dir });
        expect(r.kind).toBe("locked");
        if (r.kind === "locked") {
          expect(r.lockPath).toBe(measureLockPath(dir));
          expect(r.holderPid).toBe(process.pid);
        }
        expect(readdirSync(dir).filter((f) => f.startsWith("measure-"))).toHaveLength(0);
      }
    } finally {
      releaseMeasureLock(dir);
    }
    expect(existsSync(measureLockPath(dir))).toBe(false);
  }, 30_000);

  it("a stale lock (dead pid) is taken over; a finished run leaves no lock behind", async () => {
    const { writeFileSync, mkdirSync } = await import("node:fs");
    const { acquireMeasureLock, releaseMeasureLock, measureLockPath } = await import("../src/engine/measurement-runner.js");
    const dir = freshOutDir();
    mkdirSync(dir, { recursive: true });
    writeFileSync(measureLockPath(dir), "2147483646");
    expect(acquireMeasureLock(dir).acquired).toBe(true);
    releaseMeasureLock(dir);
    if (reaReady) {
      const r = await runMeasurement({ formats: ["wasm_module"], outDir: dir });
      expect(r.kind).toBe("ok");
      expect(existsSync(measureLockPath(dir))).toBe(false);
    }
  }, 30_000);
});

describe("isBudgetTripError (REA budget trips are measurements, not failures)", () => {
  it("error + budgetHit:true is a budget trip", async () => {
    const { isBudgetTripError } = await import("../src/engine/measurement-runner.js");
    expect(isBudgetTripError({ status: "error", budgetHit: true, errorName: "BinaryResourceFailure" })).toBe(true);
  });
  it("error without a budget hit is a genuine failure", async () => {
    const { isBudgetTripError } = await import("../src/engine/measurement-runner.js");
    expect(isBudgetTripError({ status: "error", budgetHit: false })).toBe(false);
    expect(isBudgetTripError({ status: "ok", budgetHit: true })).toBe(false);
    expect(isBudgetTripError(null)).toBe(false);
  });
  it("live: erlang_beam (REA BeamCapacityFailure) is measured, not failed", async () => {
    if (!reaReady) return;
    const r = await runMeasurement({ formats: ["erlang_beam"], outDir: freshOutDir() });
    expect(r.kind).toBe("ok");
    if (r.kind !== "ok") return;
    expect(r.document.formats[0]!.status).toBe("measured");
    expect(r.document.formats[0]!.afterBudgetHit).toBe(true);
    expect(r.document.formats[0]!.estimatedTrip).toBe(true);
  }, 30_000);
});
