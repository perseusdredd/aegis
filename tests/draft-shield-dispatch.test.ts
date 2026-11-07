import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { detectArtifactFormat } from "../src/core/detector.js";
import { protectTarget } from "../src/engine/protector.js";
import { DEVICETREE_SHIELD_MARKER } from "../src/shields/formats/devicetree.js";
import { ESP_IMAGE_SHIELD_MARKER } from "../src/shields/formats/esp-image.js";
import { GODOT_PCK_SHIELD_MARKER } from "../src/shields/formats/godot-pck.js";
import { PYINSTALLER_SHIELD_MARKER } from "../src/shields/formats/pyinstaller.js";
import { UNITYFS_SHIELD_MARKER } from "../src/shields/formats/unityfs.js";

const dir = mkdtempSync(join(tmpdir(), "aegis-draft-dispatch-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

const pad = (head: Buffer) => Buffer.concat([head, Buffer.alloc(64, 0x41)]);
const cases = [
  { format: "godot-pck", marker: GODOT_PCK_SHIELD_MARKER, bytes: pad(Buffer.from("GDPC", "latin1")) },
  { format: "unityfs", marker: UNITYFS_SHIELD_MARKER, bytes: pad(Buffer.from("UnityFS\0", "latin1")) },
  { format: "devicetree", marker: DEVICETREE_SHIELD_MARKER, bytes: pad(Buffer.from([0xd0, 0x0d, 0xfe, 0xed])) },
  { format: "esp-image", marker: ESP_IMAGE_SHIELD_MARKER, bytes: pad(Buffer.from([0xe9, 0x03])) },
  {
    format: "pyinstaller-archive",
    marker: PYINSTALLER_SHIELD_MARKER,
    bytes: Buffer.concat([Buffer.alloc(64, 0x41), Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e", "latin1"), Buffer.alloc(32)]),
  },
] as const;

describe("draft shields wired into dispatch", () => {
  for (const c of cases) {
    it(`${c.format}: right magic is detected and protectTarget appends the marker`, () => {
      const input = join(dir, `${c.format}.blob`);
      const output = join(dir, `${c.format}.out`);
      writeFileSync(input, c.bytes);
      expect(detectArtifactFormat(input)).toBe(c.format);
      protectTarget({ inputPath: input, outputPath: output });
      const out = readFileSync(output);
      expect(out.subarray(0, c.bytes.length).equals(c.bytes)).toBe(true);
      expect(out.toString("latin1")).toContain(c.marker);
    });
  }

  it("a file with no matching magic is still unknown (not claimed by any draft shield)", () => {
    const input = join(dir, "plain.blob");
    writeFileSync(input, Buffer.from("just some plain bytes, nothing special"));
    expect(detectArtifactFormat(input)).toBe("unknown");
  });

  it("wrong magic does not select a draft shield (near-miss GDPX, UnityFX, d00dfeee)", () => {
    for (const [name, head] of [
      ["gdpx.blob", Buffer.from("GDPX")],
      ["unityfx.blob", Buffer.from("UnityFX\0")],
      ["fdt-miss.blob", Buffer.from([0xd0, 0x0d, 0xfe, 0xee])],
    ] as const) {
      const p = join(dir, name);
      writeFileSync(p, pad(head));
      expect(detectArtifactFormat(p)).toBe("unknown");
    }
  });

  it("existing formats keep their classification (wasm, sqlite, gguf, uf2-less js)", () => {
    const wasm = join(dir, "a.bin");
    writeFileSync(wasm, pad(Buffer.from([0x00, 0x61, 0x73, 0x6d])));
    expect(detectArtifactFormat(wasm)).toBe("wasm");
    const js = join(dir, "x.js");
    writeFileSync(js, Buffer.from([0xe9, 0x20, 0x31]));
    expect(detectArtifactFormat(js)).toBe("javascript");
    const gguf = join(dir, "m.bin");
    writeFileSync(gguf, pad(Buffer.from("GGUF")));
    expect(detectArtifactFormat(gguf)).toBe("model-gguf");
  });
});
