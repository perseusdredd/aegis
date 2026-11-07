import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Mock node:readline/promises so the wizard's prompts are answered
// deterministically instead of actually reading from stdin.
const answers: string[] = [];
vi.mock("node:readline/promises", () => ({
  createInterface: () => ({
    question: vi.fn(async () => answers.shift() ?? ""),
    close: vi.fn(),
  }),
}));

describe("interactive wizard (zero-arg, TTY-only entry point)", () => {
  let dir: string;
  let originalIsTTY: boolean | undefined;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "aegis-wizard-test-"));
    writeFileSync(join(dir, "app.js"), "module.exports = () => 1;\n");
    originalIsTTY = process.stdin.isTTY;
    answers.length = 0;
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
    Object.defineProperty(process.stdin, "isTTY", {
      value: originalIsTTY,
      configurable: true,
    });
    vi.resetModules();
  });

  it("never triggers when stdin is not a TTY (argv-driven paths stay exactly as before)", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: undefined, configurable: true });
    const { runCli } = await import("../src/cli.js");
    // Zero args + non-TTY must fall back to help (exit 0), not the wizard.
    expect(await runCli([])).toBe(0);
  });

  it("prompts for a target and an intensity, then hardens that target", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
    answers.push(dir); // target path prompt
    answers.push("1"); // intensity choice: stealth
    const { runCli } = await import("../src/cli.js");
    const code = await runCli([]);
    expect(code).toBe(0);
  });

  it("re-prompts when the given target path does not exist", async () => {
    Object.defineProperty(process.stdin, "isTTY", { value: true, configurable: true });
    answers.push(join(dir, "does-not-exist"));
    answers.push(dir);
    answers.push(""); // default intensity (bankrupt)
    const { runCli } = await import("../src/cli.js");
    const code = await runCli([]);
    expect(code).toBe(0);
    expect(existsSync(dir)).toBe(true);
  });
});
