import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
  chmodSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { REA_INTERNAL_LIMITS } from "../src/identity.js";
import { protectTarget } from "../src/engine/protector.js";
import {
  BUN_TRAILER,
  detectBunStandaloneGraph,
  generateBunStandaloneDecoyGraph,
} from "../src/shields/formats/bun-standalone.js";
import { protectNativeBinary } from "../src/shields/formats/native.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BLA_ROOT = resolve(__dirname, "..");
const REA_ROOT = resolve(
  (process.env.REA_ROOT ?? "").trim() || join(BLA_ROOT, "..", "rea"),
);
const REA_BUN_READER = join(REA_ROOT, "src/artifacts/BunStandaloneArtifactReader.ts");
const REA_TSX = join(REA_ROOT, "node_modules/.bin/tsx");
const HOST_ELF = "/bin/true";

function decodeSuffix(buf: Buffer): { byteCount: bigint; tableLength: number; entry: number } {
  const off = buf.length - BUN_TRAILER.length - 32;
  return {
    byteCount: buf.readBigUInt64LE(off),
    tableLength: buf.readUInt32LE(off + 12),
    entry: buf.readUInt32LE(off + 16),
  };
}

describe("Bun standalone module graph counter (REA #6998)", () => {
  it("emits an admissible 52-byte-record graph with deep / unsafe / duplicate / non-UTF-8 honeypots", () => {
    for (const intensity of ["stealth", "balanced", "maximum", "bankrupt"] as const) {
      const r = generateBunStandaloneDecoyGraph(new SeededPrng(`bun-${intensity}`), intensity);
      expect(r.buffer.subarray(-BUN_TRAILER.length).equals(BUN_TRAILER)).toBe(true);
      const s = decodeSuffix(r.buffer);
      expect(Number(s.byteCount) + 48).toBe(r.buffer.length);
      expect(s.tableLength).toBe(r.moduleCount * REA_INTERNAL_LIMITS.BUN_RECORD_BYTES_1_3_9);
      // Never ambiguous with the 36-byte layout (REA would refuse the graph).
      expect(s.tableLength % REA_INTERNAL_LIMITS.BUN_RECORD_BYTES_1_3_3).not.toBe(0);
      expect(s.entry).toBe(0);
      expect(r.deepNameModules).toBeGreaterThan(0);
      expect(r.unsafeNameModules).toBeGreaterThan(0);
      expect(r.duplicateNameModules).toBeGreaterThan(1);
      expect(r.nonUtf8NameModules).toBeGreaterThan(0);
      expect(r.unknownLoaderModules).toBeGreaterThan(0);
      expect(r.moduleCount).toBeLessThan(REA_INTERNAL_LIMITS.BUN_MAX_MODULE_COUNT);
      expect(r.buffer.length).toBeLessThan(REA_INTERNAL_LIMITS.BUN_MAX_RETAINED_BYTES);
      const text = r.buffer.toString("latin1");
      expect(text).toContain("/$bunfs/root/enclave-attestation-main.js");
      expect(text).toContain("PROTECTED_CANARY_CREDENTIAL=");
      const deepParts = REA_INTERNAL_LIMITS.BUN_MAX_LOGICAL_PATH_PARTS;
      expect(text).toMatch(new RegExp(`(?:/q[0-9a-z]+){${deepParts},}`));
      expect(detectBunStandaloneGraph(r.buffer)).toMatchObject({
        kind: "appended-trailer",
        payloadOffset: 0,
        payloadLength: r.buffer.length,
      });
    }
  });

  it("passes Bun appended-trailer executables through byte-exact (runtime red line)", () => {
    const elf = Buffer.alloc(256, 0);
    elf.write("\x7fELF", 0, "latin1");
    const graph = generateBunStandaloneDecoyGraph(new SeededPrng("real"), "stealth").buffer;
    const plain = Buffer.concat([elf, graph]);
    const sizeFooter = Buffer.alloc(8);
    sizeFooter.writeBigUInt64LE(BigInt(plain.length + 8));
    const sized = Buffer.concat([plain, sizeFooter]);
    for (const [bin, kind] of [
      [plain, "appended-trailer"],
      [sized, "appended-trailer-sized"],
    ] as const) {
      const res = protectNativeBinary(bin, { intensity: "maximum", seed: "bun" });
      expect(res.bunStandaloneCarrier).toBe(kind);
      expect(res.bunStandaloneGraphPreserved).toBe(true);
      expect(res.binarySectionsPatched).toBe(0);
      expect(res.buffer.equals(bin)).toBe(true);
    }
  });

  it("keeps the ordinary native trailer path for non-Bun binaries", () => {
    if (!existsSync(HOST_ELF)) return;
    const elf = readFileSync(HOST_ELF);
    const res = protectNativeBinary(elf, { seed: "plain" });
    expect(res.bunStandaloneCarrier).toBe("none");
    expect(res.buffer.length).toBeGreaterThan(elf.length);
    expect(res.buffer.subarray(0, elf.length).equals(elf)).toBe(true);
  });

  it("protectTarget leaves a runnable Bun-style executable intact and plants a decoy graph sidecar", () => {
    if (!existsSync(HOST_ELF)) return;
    const dir = mkdtempSync(join(tmpdir(), "bla-bun-"));
    try {
      const input = join(dir, "app");
      const output = join(dir, "out", "app");
      copyFileSync(HOST_ELF, input);
      const graph = generateBunStandaloneDecoyGraph(new SeededPrng("embedded"), "stealth").buffer;
      writeFileSync(input, Buffer.concat([readFileSync(input), graph]));
      chmodSync(input, 0o755);
      const result = protectTarget({ inputPath: input, outputPath: output, intensity: "balanced", seed: "bun-e2e" });
      expect(result.counteredReaVectors).toContain("bun-standalone-module-graph");
      expect(readFileSync(output).equals(readFileSync(input))).toBe(true);
      chmodSync(output, 0o755);
      execFileSync(output); // still runs, exit 0
      const sidecar = readFileSync(`${output}.bunfs-snapshot`);
      expect(detectBunStandaloneGraph(sidecar).kind).toBe("appended-trailer");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("real REA BunStandaloneArtifactReader admits the decoy and publishes indexed-path limitations", () => {
    if (!existsSync(REA_BUN_READER) || !existsSync(REA_TSX)) return;
    const dir = mkdtempSync(join(tmpdir(), "bla-bun-rea-"));
    try {
      const r = generateBunStandaloneDecoyGraph(new SeededPrng("rea-live"), "balanced");
      const decoy = join(dir, "app.bunfs-snapshot");
      writeFileSync(decoy, r.buffer);
      const script = join(dir, "probe.mts");
      writeFileSync(
        script,
        `import { BunStandaloneArtifactReader } from ${JSON.stringify(REA_BUN_READER)};
import { buffer } from "node:stream/consumers";
const reader = new BunStandaloneArtifactReader(${JSON.stringify(decoy)});
const entries = [];
for await (const e of reader.entries()) entries.push(e);
const limited = entries.filter((e) => JSON.stringify(e).includes("logical path allowance")).length;
const indexed = entries.filter((e) => String(e.path).startsWith("bun-modules/")).length;
const first = (await buffer(await reader.open(entries[0]))).toString();
await reader.close();
console.log(JSON.stringify({ count: entries.length, limited, indexed, first: entries[0].path, canary: first.includes("PROTECTED_CANARY_CREDENTIAL=") }));
`,
      );
      const out = execFileSync(REA_TSX, [script], { cwd: REA_ROOT, encoding: "utf8", timeout: 120_000 });
      const res = JSON.parse(out.trim().split("\n").pop()!);
      expect(res.count).toBeGreaterThanOrEqual(r.moduleCount);
      expect(res.limited).toBe(r.deepNameModules);
      expect(res.indexed).toBeGreaterThanOrEqual(r.deepNameModules + r.unsafeNameModules);
      expect(res.first).toBe("$bunfs/root/enclave-attestation-main.js");
      expect(res.canary).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 180_000);
});
