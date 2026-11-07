import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { SeededPrng } from "../src/core/prng.js";
import { REA_INTERNAL_LIMITS } from "../src/identity.js";
import { generateAndroidManifestCounter } from "../src/shields/formats/android-manifest.js";
import {
  protectZipOrApkBuffer,
  readZipEntries,
  writeZipArchive,
} from "../src/shields/formats/archive.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const BLA_ROOT = resolve(__dirname, "..");
const REA_ROOT_ENV = (process.env.REA_ROOT ?? "").trim();
const REA_ROOT = resolve(REA_ROOT_ENV || join(BLA_ROOT, "..", "rea"));
const REA_MANIFEST_DIST = join(
  REA_ROOT,
  "dist/android/AndroidManifestComponents.js",
);

describe("android manifest component decoy (REA #7379 / #7818)", () => {
  it("emits well-formed XML past ANDROID_MANIFEST_COMPONENTS with nested $ spelling", () => {
    const res = generateAndroidManifestCounter(
      new SeededPrng("mf-balanced"),
      "balanced",
    );
    expect(res.namedComponentsEmitted).toBeGreaterThan(
      REA_INTERNAL_LIMITS.ANDROID_MANIFEST_COMPONENTS,
    );
    expect(res.unnamedComponentsEmitted).toBeGreaterThan(0);
    expect(res.unresolvedTokenNames).toBeGreaterThan(0);
    expect(res.nestedDollarNames).toBeGreaterThan(0);
    expect(res.intentFiltersPerHeavy).toBeGreaterThan(
      REA_INTERNAL_LIMITS.ANDROID_MANIFEST_INTENT_FILTERS,
    );
    expect(res.authoritySegmentsEmitted).toBeGreaterThan(
      REA_INTERNAL_LIMITS.ANDROID_MANIFEST_AUTHORITIES,
    );
    expect(res.manifestXml).toMatch(/^<\?xml version="1\.0"/);
    expect(res.manifestXml).toContain('package="com.enclave.sgx.teeattestation"');
    expect(res.manifestXml).toContain(
      'android:name=".TeeAttestationBridge$DetailsActivity"',
    );
    expect(res.manifestXml).toContain("@string/enclave_bridge_");
    expect(res.manifestXml).toContain("${enclave.placeholder.bridge_");
    expect(res.manifestXml).toContain("PROTECTED_CANARY_CREDENTIAL=");
    // Root closes cleanly — well-formedness smoke check.
    expect(res.manifestXml.trimEnd().endsWith("</manifest>")).toBe(true);
  });

  it("scales past the component cap at every intensity", () => {
    for (const intensity of ["stealth", "balanced", "maximum", "bankrupt"] as const) {
      const res = generateAndroidManifestCounter(
        new SeededPrng(`mf-${intensity}`),
        intensity,
      );
      expect(res.namedComponentsEmitted).toBeGreaterThan(
        REA_INTERNAL_LIMITS.ANDROID_MANIFEST_COMPONENTS,
      );
      expect(res.manifestXml.length).toBeGreaterThan(4_000);
    }
  });

  it("plants the decoy under assets/bla-shield/ without rewriting the root manifest", () => {
    const rootManifest = Buffer.from(
      '<manifest package="com.example.app"><application/></manifest>',
      "utf8",
    );
    const dex = Buffer.alloc(112, 0);
    dex.write("dex\n035\0", 0, "ascii");
    dex.writeUInt32LE(112, 32);
    dex.writeUInt32LE(112, 36);
    dex.writeUInt32LE(0x12345678, 40);
    const unsignedApk = writeZipArchive([
      { name: "AndroidManifest.xml", data: rootManifest },
      { name: "classes.dex", data: dex },
    ]);
    const res = protectZipOrApkBuffer(unsignedApk, {
      isApk: true,
      intensity: "stealth",
      seed: "apk-manifest-decoy",
    });
    expect(res.androidManifestDecoyBytes).toBeGreaterThan(2_000);
    expect(res.androidManifestNamedComponents).toBeGreaterThan(
      REA_INTERNAL_LIMITS.ANDROID_MANIFEST_COMPONENTS,
    );
    const entries = readZipEntries(res.buffer);
    const root = entries.find((e) => e.name === "AndroidManifest.xml");
    expect(root).toBeDefined();
    // Red line: developer's root manifest bytes are untouched.
    expect(root!.data.equals(rootManifest)).toBe(true);
    expect(
      entries.some((e) => e.name === "assets/bla-shield/AndroidManifest.xml"),
    ).toBe(true);
    expect(
      entries.some(
        (e) => e.name === "assets/bla-shield/AndroidManifest-decoy.xml",
      ),
    ).toBe(true);
    const decoy = entries
      .find((e) => e.name === "assets/bla-shield/AndroidManifest.xml")!
      .data.toString("utf8");
    expect(decoy).toContain("TeeAttestationBridge$DetailsActivity");
    expect(decoy).toContain("bla-shield: decoy AndroidManifest");
  });
});

describe("empirical REA parseAndroidManifestComponents red-team", () => {
  it("drives REA inventory to status:'partial' on the decoy (and on a synthetic root fixture)", async () => {
    if (!existsSync(REA_MANIFEST_DIST)) {
      console.log(
        `SKIP empirical: REA dist missing at ${REA_MANIFEST_DIST}`,
      );
      return;
    }
    const rea = await import(REA_MANIFEST_DIST);
    expect(typeof rea.parseAndroidManifestComponents).toBe("function");
    expect(rea.ANDROID_MANIFEST_LIMITS.components).toBe(
      REA_INTERNAL_LIMITS.ANDROID_MANIFEST_COMPONENTS,
    );
    expect(rea.ANDROID_MANIFEST_LIMITS.resolvedNameBytes).toBe(
      REA_INTERNAL_LIMITS.ANDROID_MANIFEST_RESOLVED_NAME_BYTES,
    );

    const decoy = generateAndroidManifestCounter(
      new SeededPrng("empirical-mf"),
      "balanced",
    );

    // Coverage "complete" — REA only inventories when the decoded text is whole.
    const inventory = rea.parseAndroidManifestComponents(
      decoy.manifestXml,
      "complete",
      "34",
      "24",
    );
    expect(inventory.status).toBe("partial");
    expect(Array.isArray(inventory.limitations)).toBe(true);
    expect(inventory.limitations.length).toBeGreaterThan(0);
    // Capacity and/or unresolved-name budget must fire.
    const joined = inventory.limitations.join("\n");
    expect(
      /capacity limit|resolved-name byte budget|without android:name|unresolved resource|package-relative/i.test(
        joined,
      ),
    ).toBe(true);
    // Nested $ spelling retained on any item that made it into the projection.
    const nested = inventory.items.filter((c: { declared_name: string }) =>
      c.declared_name.includes("$"),
    );
    expect(nested.length).toBeGreaterThan(0);
    for (const c of nested) {
      expect(c.declared_name).toMatch(/\$/);
      // #7818: declared_name spelling is preserved (no JADX alias rewrite here —
      // this is the pure-TS inventory path; declared_name === source attribute).
      expect(c.declared_name.includes(".")).toBe(true);
    }
  });
});
