import { describe, expect, it } from "vitest";
import { detectDeviceTree, draftAnnotateDeviceTree } from "../src/shields/formats/devicetree.js";
import { detectEspImage, draftAnnotateEspImage } from "../src/shields/formats/esp-image.js";
import { detectGodotPck, draftAnnotateGodotPck } from "../src/shields/formats/godot-pck.js";
import { detectPyInstaller, draftAnnotatePyInstaller } from "../src/shields/formats/pyinstaller.js";
import { detectUnityFs, draftAnnotateUnityFs } from "../src/shields/formats/unityfs.js";

describe("draft format shields (docs/AEGIS-BUDGETS.md section 3, missing format families)", () => {
  it("godot-pck: detects GDPC magic and appends a marked trailer without mutating original bytes", () => {
    const original = Buffer.concat([Buffer.from([0x47, 0x44, 0x50, 0x43]), Buffer.from("rest-of-pack")]);
    expect(detectGodotPck(original)).toBe(true);
    expect(detectGodotPck(Buffer.from("not a pck"))).toBe(false);
    const annotated = draftAnnotateGodotPck(original);
    expect(annotated.subarray(0, original.length)).toEqual(original);
    expect(annotated.length).toBeGreaterThan(original.length);
  });

  it("unityfs: detects UnityFS signature and appends a marked trailer without mutating original bytes", () => {
    const original = Buffer.concat([Buffer.from("UnityFS\0", "latin1"), Buffer.from("rest-of-bundle")]);
    expect(detectUnityFs(original)).toBe(true);
    expect(detectUnityFs(Buffer.from("not a bundle"))).toBe(false);
    const annotated = draftAnnotateUnityFs(original);
    expect(annotated.subarray(0, original.length)).toEqual(original);
    expect(annotated.length).toBeGreaterThan(original.length);
  });

  it("pyinstaller: detects the CArchive cookie magic and appends a marked trailer", () => {
    const magic = Buffer.from("MEI\x0c\x0b\x0a\x0b\x0e", "latin1");
    const original = Buffer.concat([Buffer.from("junk-before"), magic, Buffer.from("junk-after")]);
    expect(detectPyInstaller(original)).toBe(true);
    expect(detectPyInstaller(Buffer.from("no cookie here"))).toBe(false);
    const annotated = draftAnnotatePyInstaller(original);
    expect(annotated.subarray(0, original.length)).toEqual(original);
    expect(annotated.length).toBeGreaterThan(original.length);
  });

  it("devicetree: detects the d00dfeed FDT magic and appends a marked trailer", () => {
    const original = Buffer.concat([Buffer.from([0xd0, 0x0d, 0xfe, 0xed]), Buffer.from("rest-of-dtb")]);
    expect(detectDeviceTree(original)).toBe(true);
    expect(detectDeviceTree(Buffer.from("not a dtb"))).toBe(false);
    const annotated = draftAnnotateDeviceTree(original);
    expect(annotated.subarray(0, original.length)).toEqual(original);
    expect(annotated.length).toBeGreaterThan(original.length);
  });

  it("esp-image: detects the 0xE9 header byte and appends a marked trailer", () => {
    const original = Buffer.concat([Buffer.from([0xe9]), Buffer.from("rest-of-flash-image")]);
    expect(detectEspImage(original)).toBe(true);
    expect(detectEspImage(Buffer.from([0x00, 0x01]))).toBe(false);
    const annotated = draftAnnotateEspImage(original);
    expect(annotated.subarray(0, original.length)).toEqual(original);
    expect(annotated.length).toBeGreaterThan(original.length);
  });
});
