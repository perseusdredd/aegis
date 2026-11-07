import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { REA_INTERNAL_LIMITS } from "../src/identity.js";
import {
  buildJniDecoyElf64,
  buildJniExportNames,
  generateAndroidR8Counter,
  mangleJniIdentifier,
} from "../src/shields/formats/android-r8.js";

describe("android R8 / JNI counter (REA #7456 / #7472)", () => {
  it("mangles JNI identifiers the same way REA escape() does", () => {
    expect(mangleJniIdentifier("com/enclave/sgx/Tee")).toBe("com_enclave_sgx_Tee");
    expect(mangleJniIdentifier("a_b")).toBe("a_1b");
    expect(mangleJniIdentifier("x;")).toBe("x_2");
    expect(mangleJniIdentifier("y[")).toBe("y_3");
  });

  it("builds an ELF64 ET_DYN with Java_* dynsym export names", () => {
    const names = buildJniExportNames(new SeededPrng("elf"), 4);
    const elf = buildJniDecoyElf64(names);
    expect(elf[0]).toBe(0x7f);
    expect(elf.subarray(1, 4).toString("latin1")).toBe("ELF");
    expect(elf.readUInt16LE(16)).toBe(3); // ET_DYN
    expect(elf.readUInt16LE(18)).toBe(183); // EM_AARCH64
    for (const n of names) {
      expect(elf.includes(Buffer.from(n + "\0", "utf8"))).toBe(true);
    }
  });

  it("emits residual conflicts past PROGUARD_MAPPING_CANDIDATES and malformed past MALFORMED_SAMPLES", () => {
    const res = generateAndroidR8Counter(new SeededPrng("r8-balanced"), "balanced");
    expect(res.residualConflictCount).toBeGreaterThan(
      REA_INTERNAL_LIMITS.PROGUARD_MAPPING_CANDIDATES,
    );
    expect(res.malformedSampleCount).toBeGreaterThan(
      REA_INTERNAL_LIMITS.PROGUARD_MAPPING_MALFORMED_SAMPLES,
    );
    expect(res.classRecordsEmitted).toBeGreaterThan(res.residualConflictCount);
    expect(res.jniExportNames.length).toBeGreaterThan(8);
    expect(res.jniElfBuffer.length).toBeGreaterThan(256);
    expect(res.mappingText).toMatch(/^# compiler: R8/m);
    // Count residual collision lines
    const residualLines = res.mappingText
      .split("\n")
      .filter((l) => l.endsWith(" -> a.a.a:"));
    expect(residualLines.length).toBe(res.residualConflictCount);
    const malformed = res.mappingText
      .split("\n")
      .filter((l) => l.includes("MALFORMED_MAPPING_BAIT_"));
    expect(malformed.length).toBe(res.malformedSampleCount);
  });

  it("scales past candidates at every intensity", () => {
    for (const intensity of ["stealth", "balanced", "maximum", "bankrupt"] as const) {
      const res = generateAndroidR8Counter(new SeededPrng(`r8-${intensity}`), intensity);
      expect(res.residualConflictCount).toBeGreaterThan(
        REA_INTERNAL_LIMITS.PROGUARD_MAPPING_CANDIDATES,
      );
      expect(res.mappingText.length).toBeGreaterThan(100);
    }
  });
});
