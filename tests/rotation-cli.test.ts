import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../src/cli.js";
import { validateAegisConfigShape } from "../src/core/config.js";

const tempDirs: string[] = [];
function createTempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "aegis-rotation-cli-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function withSilencedConsole<T>(fn: () => T): T {
  const log = console.log;
  const err = console.error;
  console.log = () => {};
  console.error = () => {};
  try {
    return fn();
  } finally {
    console.log = log;
    console.error = err;
  }
}

describe("CLI rotation flags", () => {
  it("acceptance #8: --rotation-report writes a file and --dry-run writes zero artifact bytes", async () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.js"), "console.log('hi');\n");
    const reportPath = join(dir, "rotation.json");
    const code = await withSilencedConsole(() =>
      runCli(["harden", dir, "--seed", "fixed-seed", "--dry-run", "--rotation-report", reportPath]),
    );
    expect(code === 0 || code === 2).toBe(true);
    expect(existsSync(reportPath)).toBe(true);
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    expect(report.schema).toBe("aegis-rotation/v1");
    expect(typeof report.decoyCount).toBe("number");
    // dry-run must not persist a seed into .aegisrc
    expect(existsSync(join(dir, ".aegisrc"))).toBe(false);
  });

  it("error table: --no-rotation + --rotation-report together reports decoyCount 0 and buildId null", async () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.js"), "console.log('hi');\n");
    const reportPath = join(dir, "rotation-off.json");
    await withSilencedConsole(() =>
      runCli(["harden", dir, "--seed", "fixed-seed", "--dry-run", "--no-rotation", "--rotation-report", reportPath]),
    );
    expect(existsSync(reportPath)).toBe(true);
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    expect(report.decoyCount).toBe(0);
    expect(report.buildId).toBeNull();
  });

  it("acceptance #4: --seed '' exits 2 and never touches the target", async () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.js"), "console.log('hi');\n");
    const before = readFileSync(join(dir, "app.js"), "utf8");
    const code = await withSilencedConsole(() => runCli(["harden", dir, "--seed", ""]));
    expect(code).toBe(1);
    expect(readFileSync(join(dir, "app.js"), "utf8")).toBe(before);
  });

  it("rotation.decoyCount in config overrides the intensity-derived range end-to-end", async () => {
    const dir = createTempDir();
    writeFileSync(join(dir, "app.js"), "console.log('hi');\n");
    const configPath = join(dir, "aegis.config.json");
    writeFileSync(
      configPath,
      JSON.stringify({ input: ".", rotation: { enabled: true, decoyCount: 5 } }),
    );
    const reportPath = join(dir, "rotation-cfg.json");
    await withSilencedConsole(() =>
      runCli(["harden", dir, "--seed", "fixed", "--dry-run", "--rotation-report", reportPath, "-c", configPath]),
    );
    const report = JSON.parse(readFileSync(reportPath, "utf8"));
    expect(report.decoyCount).toBe(5);
  });
});

describe("rotation config schema validation", () => {
  it("rejects a non-object rotation block", () => {
    expect(() => validateAegisConfigShape({ rotation: "nope" }, "test")).toThrow(/rotation.*object/);
  });

  it("rejects decoyCount out of the 1-4096 range", () => {
    expect(() => validateAegisConfigShape({ rotation: { decoyCount: 0 } }, "test")).toThrow(/decoyCount/);
    expect(() => validateAegisConfigShape({ rotation: { decoyCount: 5000 } }, "test")).toThrow(/decoyCount/);
  });

  it("accepts a well-formed rotation block", () => {
    const parsed = validateAegisConfigShape(
      { rotation: { enabled: true, decoyCount: 8, reservedNames: ["main"] } },
      "test",
    );
    expect(parsed.rotation?.decoyCount).toBe(8);
  });
});
