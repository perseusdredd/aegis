import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { REA_INTERNAL_LIMITS } from "../src/identity.js";
import {
  generateAndroidDexXrefCounter,
  nextMultidexName,
} from "../src/shields/formats/android-dex-xref.js";
import {
  protectZipOrApkBuffer,
  readZipEntries,
  writeZipArchive,
} from "../src/shields/formats/archive.js";
import { inspectAndroidDex } from "../src/shields/formats/mobile-game.js";

function adler32(bytes: Buffer, start = 0): number {
  let a = 1;
  let b = 0;
  for (let i = start; i < bytes.length; i++) {
    a = (a + bytes[i]!) % 65521;
    b = (b + a) % 65521;
  }
  return ((b << 16) | a) >>> 0;
}

describe("android DEX external-invoke decoy (REA #8154)", () => {
  it("emits a structurally valid DEX 035 with matching checksum/signature", () => {
    const res = generateAndroidDexXrefCounter(
      new SeededPrng("xref-valid"),
      "balanced",
    );
    const dex = res.dexBuffer;
    expect(dex.subarray(0, 8).toString("latin1")).toBe("dex\n035\0");
    expect(dex.readUInt32LE(32)).toBe(dex.length);
    expect(dex.readUInt32LE(36)).toBe(0x70);
    expect(dex.readUInt32LE(40)).toBe(0x12345678);

    const sha1 = createHash("sha1").update(dex.subarray(32)).digest();
    expect(Buffer.compare(sha1, dex.subarray(12, 32))).toBe(0);
    expect(dex.readUInt32LE(8)).toBe(adler32(dex, 12));

    expect(dex.includes(Buffer.from("BLA-DEX-XREF-V1", "utf8"))).toBe(true);
    expect(dex.includes(Buffer.from("Landroid/util/Log;", "utf8"))).toBe(true);
    expect(res.callerClassesEmitted).toBeGreaterThan(100);
    expect(res.externalMethodRefs).toBe(1);

    const inspected = inspectAndroidDex(dex);
    expect(inspected.validDex).toBe(true);
  });

  it("scales caller classes with intensity and exceeds budget math at bankrupt", () => {
    const stealth = generateAndroidDexXrefCounter(
      new SeededPrng("xref-s"),
      "stealth",
    );
    const balanced = generateAndroidDexXrefCounter(
      new SeededPrng("xref-b"),
      "balanced",
    );
    const bankrupt = generateAndroidDexXrefCounter(
      new SeededPrng("xref-k"),
      "bankrupt",
    );
    expect(balanced.callerClassesEmitted).toBeGreaterThan(
      stealth.callerClassesEmitted,
    );
    expect(bankrupt.callerClassesEmitted).toBeGreaterThan(
      balanced.callerClassesEmitted,
    );
    // InvokeBudget.admit charges ≥256 bytes base per row before string accounting;
    // bankrupt caller count × 256 exceeds MAX_EXTERNAL_XREF_BYTES.
    expect(bankrupt.callerClassesEmitted * 256).toBeGreaterThan(
      REA_INTERNAL_LIMITS.ANDROID_EXTERNAL_XREF_BYTES,
    );
  });

  it("nextMultidexName skips past existing classesN.dex", () => {
    expect(nextMultidexName([])).toBe("classes2.dex");
    expect(nextMultidexName(["classes.dex"])).toBe("classes2.dex");
    expect(nextMultidexName(["classes.dex", "classes2.dex"])).toBe(
      "classes3.dex",
    );
    expect(
      nextMultidexName(["lib/classes.dex", "classes5.dex", "assets/x.txt"]),
    ).toBe("classes6.dex");
  });

  it("unsigned APK path plants decoy classesN.dex without rewriting root manifest", () => {
    const dex = Buffer.alloc(112, 0);
    dex.write("dex\n035\0", 0, "ascii");
    dex.writeUInt32LE(112, 32);
    dex.writeUInt32LE(112, 36);
    dex.writeUInt32LE(0x12345678, 40);

    const input = writeZipArchive([
      { name: "AndroidManifest.xml", data: Buffer.from("<manifest/>", "utf8") },
      { name: "classes.dex", data: dex },
    ]);
    const res = protectZipOrApkBuffer(input, {
      intensity: "balanced",
      seed: "apk-xref",
      isApk: true,
    });
    expect(res.androidDexXrefCallers).toBeGreaterThan(100);
    expect(res.androidDexXrefBytes).toBeGreaterThan(1_000);

    const entries = readZipEntries(res.buffer);
    const names = entries.map((e) => e.name);
    expect(names).toContain("classes.dex");
    expect(names.some((n) => /^classes\d+\.dex$/.test(n))).toBe(true);
    // Root manifest must stay byte-identical (red line).
    const rootMf = entries.find((e) => e.name === "AndroidManifest.xml")!;
    expect(rootMf.data.toString("utf8")).toBe("<manifest/>");

    const decoy = entries.find((e) => /^classes\d+\.dex$/.test(e.name))!;
    expect(decoy.data.includes(Buffer.from("BLA-DEX-XREF-V1", "utf8"))).toBe(
      true,
    );
    expect(decoy.data.includes(Buffer.from("Landroid/util/Log;", "utf8"))).toBe(
      true,
    );
    // invoke-static opcode 0x71 must appear in the decoy code items.
    expect(decoy.data.includes(Buffer.from([0x71, 0x20]))).toBe(true);
  });
});
