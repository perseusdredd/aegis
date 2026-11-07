import { afterEach, describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { protectZipOrApkBuffer, readZipEntries, UnsupportedApkProtectionError, UnsupportedArchiveError, validateZipProtectionInput, writeZipArchive } from "../src/shields/formats/archive.js";
import { protectTarget } from "../src/engine/protector.js";

const fixture = () => writeZipArchive([{ name: "file.txt", data: Buffer.from("harmless content ".repeat(8)) }]);
const centralOffset = (b: Buffer) => b.readUInt32LE(b.length - 6);
function mutate(change: (b: Buffer, c: number) => void): Buffer {
  const b = fixture(); change(b, centralOffset(b)); return b;
}
function gapBeforeDirectory(asCompressedData: boolean): Buffer {
  const b = fixture(); const c = centralOffset(b);
  const result = Buffer.concat([b.subarray(0, c), Buffer.from([0]), b.subarray(c)]);
  result.writeUInt32LE(c + 1, result.length - 6);
  if (asCompressedData) {
    result.writeUInt32LE(b.readUInt32LE(18) + 1, 18);
    result.writeUInt32LE(b.readUInt32LE(18) + 1, c + 1 + 20);
  }
  return result;
}
const bad: [string, () => Buffer][] = [
  ["unrepresented signing-block-like gap", () => gapBeforeDirectory(false)],
  ["trailing compressed garbage", () => gapBeforeDirectory(true)],
  ["extra fields", () => mutate((b, c) => { b.writeUInt16LE(1, c + 30); })],
  ["central/local mismatch", () => mutate((b, c) => { b[c + 46] = 120; })],
  ["trailing archive bytes", () => Buffer.concat([fixture(), Buffer.from([0])])],
  ["data descriptors", () => mutate((b, c) => { b.writeUInt16LE(8, 6); b.writeUInt16LE(8, c + 8); })],
  ["encryption", () => mutate((b, c) => { b.writeUInt16LE(1, 6); b.writeUInt16LE(1, c + 8); })],
  ["unknown compression", () => mutate((b, c) => { b.writeUInt16LE(99, 8); b.writeUInt16LE(99, c + 10); })],
  ["truncated EOCD", () => fixture().subarray(0, -1)],
  ["bad CRC", () => mutate((b, c) => { b.writeUInt32LE(0, 14); b.writeUInt32LE(0, c + 16); })],
  ["invalid deflate", () => mutate((b) => { b[38] = 0xff; })],
  ["decoded size mismatch", () => mutate((b, c) => { b.writeUInt32LE(1, 22); b.writeUInt32LE(1, c + 24); })],
  ["oversized declared output", () => mutate((b, c) => { b.writeUInt32LE(64 * 1024 * 1024 + 1, 22); b.writeUInt32LE(64 * 1024 * 1024 + 1, c + 24); })],
  ["missing entries", () => mutate((b) => { b.writeUInt16LE(2, b.length - 14); b.writeUInt16LE(2, b.length - 12); })],
  ["incorrect local offset", () => mutate((b, c) => { b.writeUInt32LE(1, c + 42); })],
  ["unpreserved timestamps", () => mutate((b, c) => { b.writeUInt16LE(33, 12); b.writeUInt16LE(33, c + 14); })],
  ["unpreserved attributes", () => mutate((b, c) => { b.writeUInt32LE(0x81a40000, c + 38); })],
  ["truncated entry", () => mutate((b, c) => { b.writeUInt32LE(c, 18); b.writeUInt32LE(c, c + 20); })],
  ["ZIP64", () => mutate((b) => { b.writeUInt16LE(0xffff, b.length - 12); })],
];

describe("archive admission preserves bytes or fails closed", () => {
  const dirs: string[] = [];
  afterEach(() => { for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true }); });
  it("reads an independently specified classic stored ZIP fixture", () => {
    const input = Buffer.from([
      "504b03041400000000000000000086a610360500000005000000010000006168656c6c6f",
      "504b010214001400000000000000000086a61036050000000500000001000000000000000000000000000000000061",
      "504b050600000000010001002f000000240000000000",
    ].join(""), "hex");
    expect(readZipEntries(input)[0]?.data.toString()).toBe("hello");
  });
  it("preserves stored and deflated file contents", () => {
    const originals = [{ name: "short", data: Buffer.from("hello") }, { name: "long", data: Buffer.from("plain content ".repeat(20)) }];
    const input = writeZipArchive(originals);
    const result = protectZipOrApkBuffer(input, { intensity: "stealth", seed: "integrity" });
    const entries = readZipEntries(result.buffer);
    for (const item of originals) expect(entries.find((e) => e.name === item.name)?.data).toEqual(item.data);
  });
  it.each(bad)("rejects %s without changing the supplied buffer", (_name, create) => {
    const input = create(); const before = Buffer.from(input);
    expect(() => readZipEntries(input)).toThrow(UnsupportedArchiveError);
    expect(() => protectZipOrApkBuffer(input)).toThrow(UnsupportedArchiveError);
    expect(input).toEqual(before);
  });
  it("hardens unsigned APK member DEX while refusing signed APKs", () => {
    // Minimal DEX header (112 bytes) embedded as classes.dex inside an unsigned APK-shaped ZIP.
    const dex = Buffer.alloc(112, 0);
    dex.write("dex\n035\0", 0, "ascii");
    dex.writeUInt32LE(112, 32);
    dex.writeUInt32LE(112, 36);
    dex.writeUInt32LE(0x12345678, 40);
    const unsignedApk = writeZipArchive([
      { name: "AndroidManifest.xml", data: Buffer.from("<manifest/>") },
      { name: "classes.dex", data: dex },
    ]);
    const res = protectZipOrApkBuffer(unsignedApk, { isApk: true, intensity: "stealth", seed: "apk-member" });
    expect(res.membersHardened).toBe(1);
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    expect(res.diagnosticsEmbedded).toBeGreaterThan(0);
    const entries = readZipEntries(res.buffer);
    const outDex = entries.find((e) => e.name === "classes.dex")!.data;
    expect(outDex.toString("latin1")).toContain("BLA-DEX-SHIELD");
    expect(outDex.toString("latin1")).toContain("PROTECTED_CANARY_CREDENTIAL=");
    expect(entries.some((e) => e.name.startsWith("assets/bla-shield/"))).toBe(true);
    // REA #7456 / #7472 counters: R8 mapping bait + JNI decoy .so with real Java_* dynsym.
    expect(res.androidR8MappingBytes).toBeGreaterThan(200);
    expect(res.androidJniExportsPlanted).toBeGreaterThan(8);
    expect(entries.some((e) => e.name === "assets/bla-shield/mapping.txt")).toBe(true);
    expect(entries.some((e) => e.name === "assets/bla-shield/proguard-mapping.txt")).toBe(true);
    expect(entries.some((e) => e.name === "lib/arm64-v8a/libbla_enclave_jni.so")).toBe(true);
    const elf = entries.find((e) => e.name === "lib/arm64-v8a/libbla_enclave_jni.so")!.data;
    expect(elf[0]).toBe(0x7f);
    expect(elf.subarray(1, 4).toString("latin1")).toBe("ELF");
    expect(elf.includes(Buffer.from("Java_com_enclave_sgx_TeeAttestationBridge_verifyShamirEd25519QuorumRing"))).toBe(true);
    const mapping = entries.find((e) => e.name === "assets/bla-shield/mapping.txt")!.data.toString("utf8");
    expect(mapping).toMatch(/# compiler: R8/);
    expect(mapping).toMatch(/-> a\.a\.a:/);
    expect(outDex.toString("latin1")).toContain("Java_com_enclave_sgx_TeeAttestationBridge");
    // REA #7379 / #7818: decoy AndroidManifest.xml under assets/bla-shield/ (root untouched).
    expect(res.androidManifestDecoyBytes).toBeGreaterThan(2_000);
    expect(res.androidManifestNamedComponents).toBeGreaterThan(512);
    expect(entries.some((e) => e.name === "assets/bla-shield/AndroidManifest.xml")).toBe(true);
    expect(entries.some((e) => e.name === "assets/bla-shield/AndroidManifest-decoy.xml")).toBe(true);
    const rootMf = entries.find((e) => e.name === "AndroidManifest.xml")!.data.toString("utf8");
    expect(rootMf).toBe("<manifest/>");
    const decoyMf = entries.find((e) => e.name === "assets/bla-shield/AndroidManifest.xml")!.data.toString("utf8");
    expect(decoyMf).toContain("TeeAttestationBridge$DetailsActivity");

    // Signed APK still fails closed.
    const signed = writeZipArchive([
      { name: "AndroidManifest.xml", data: Buffer.from("<manifest/>") },
      { name: "META-INF/CERT.RSA", data: Buffer.from("not a real signature") },
      { name: "classes.dex", data: dex },
    ]);
    expect(() => protectZipOrApkBuffer(signed, { isApk: true })).toThrow(UnsupportedApkProtectionError);
  });
  it("auto-detects AndroidManifest ZIPs as unsigned APK-shaped archives and refuses signed ones", () => {
    const renamed = writeZipArchive([{ name: "AndroidManifest.xml", data: Buffer.from("fixture") }]);
    const res = protectZipOrApkBuffer(renamed, { intensity: "stealth", seed: "manifest-zip" });
    expect(res.canaryTokensEmbedded).toBeGreaterThan(0);
    expect(readZipEntries(res.buffer).some((e) => e.name.startsWith("assets/bla-shield/"))).toBe(true);
    expect(() => protectZipOrApkBuffer(writeZipArchive([{ name: "META-INF/TEST.RSA", data: Buffer.from("not a real signature") }]))).toThrow(/signing-aware/);
    expect(() => readZipEntries(writeZipArchive([{ name: "a", data: Buffer.from("1") }, { name: "a", data: Buffer.from("2") }]))).toThrow(/duplicate/);
  });
  it("reserves output entries below the classic ZIP sentinel before filesystem changes", () => {
    // 0xfffe - 16 = 65_518 usable input entries after decoy/R8/JNI reservation.
    const files = Array.from({ length: 65_519 }, (_, i) => ({ name: `f${i}`, data: Buffer.alloc(0) }));
    const accepted = writeZipArchive(files.slice(0, -1));
    expect(validateZipProtectionInput(accepted)).toHaveLength(65_518);
    const rejected = writeZipArchive(files); const original = Buffer.from(rejected);
    expect(readZipEntries(rejected)).toHaveLength(65_519);
    expect(() => protectZipOrApkBuffer(rejected, { intensity: "stealth" })).toThrow(/entry-count capacity/);
    expect(rejected.equals(original)).toBe(true);
    const dir = mkdtempSync(join(tmpdir(), "bla-archive-count-")); dirs.push(dir);
    const input = join(dir, "input.zip"); const output = join(dir, "output.zip");
    writeFileSync(input, rejected); writeFileSync(output, "existing");
    expect(() => protectTarget({ inputPath: input, outputPath: output })).toThrow(/entry-count capacity/);
    expect(readFileSync(output, "utf8")).toBe("existing");
    expect(() => protectTarget({ inputPath: input, outputPath: join(dir, "new", "output.zip") })).toThrow(/entry-count capacity/);
    expect(existsSync(join(dir, "new"))).toBe(false);
    expect(readFileSync(input).equals(original)).toBe(true);
  });
  it.each(["assets", "assets/enclave", "enclave"])("refuses reserved parent file %s without modification", (name) => {
    const input = writeZipArchive([{ name, data: Buffer.from("original regular file") }]);
    const original = Buffer.from(input);
    expect(() => protectZipOrApkBuffer(input)).toThrow(/reserved output namespace/);
    expect(input).toEqual(original);
    const dir = mkdtempSync(join(tmpdir(), "bla-archive-parent-")); dirs.push(dir);
    const file = join(dir, "input.zip"); writeFileSync(file, input);
    expect(() => protectTarget({ inputPath: file, inPlace: true })).toThrow(/reserved output namespace/);
    expect(readFileSync(file)).toEqual(original);
    expect(() => protectTarget({ inputPath: file, outputPath: join(dir, "new", "output.zip") })).toThrow(/reserved output namespace/);
    expect(existsSync(join(dir, "new"))).toBe(false);
  });
  it("retains input/output and creates no directory for malformed ZIP", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-archive-")); dirs.push(dir);
    const input = join(dir, "bad.zip"); const output = join(dir, "existing.zip");
    const bytes = bad[0]![1]();
    writeFileSync(input, bytes); writeFileSync(output, "existing output");
    expect(() => protectTarget({ inputPath: input, outputPath: output })).toThrow();
    expect(readFileSync(output, "utf8")).toBe("existing output");
    expect(() => protectTarget({ inputPath: input, inPlace: true })).toThrow();
    expect(readFileSync(input)).toEqual(bytes);
    expect(() => protectTarget({ inputPath: input, outputPath: join(dir, "new", "out.zip") })).toThrow();
    expect(existsSync(join(dir, "new"))).toBe(false);
  });
  it("protects unsigned.apk in-place without touching unrelated outputs", () => {
    const dir = mkdtempSync(join(tmpdir(), "bla-archive-apk-")); dirs.push(dir);
    const input = join(dir, "unsigned.apk");
    const unrelated = join(dir, "existing.zip");
    const dex = Buffer.alloc(112, 0);
    dex.write("dex\n035\0", 0, "ascii");
    dex.writeUInt32LE(112, 32);
    dex.writeUInt32LE(112, 36);
    dex.writeUInt32LE(0x12345678, 40);
    const bytes = writeZipArchive([
      { name: "AndroidManifest.xml", data: Buffer.from("<manifest/>") },
      { name: "classes.dex", data: dex },
    ]);
    writeFileSync(input, bytes);
    writeFileSync(unrelated, "existing output");
    const res = protectTarget({ inputPath: input, outputPath: join(dir, "out.apk") });
    expect(res.outputPath).toContain("out.apk");
    expect(readFileSync(unrelated, "utf8")).toBe("existing output");
    expect(readFileSync(input)).toEqual(bytes);
  });
});
