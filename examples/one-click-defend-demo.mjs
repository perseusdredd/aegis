#!/usr/bin/env node
/**
 * End-to-End One-Click Defense Demo (`defendTarget`)
 * Run after `npm run build`: `node examples/one-click-defend-demo.mjs`
 */
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { defendTarget } from "../dist/index.js";

const workDir = mkdtempSync(join(tmpdir(), "bla-demo-"));
try {
  const targetFile = join(workDir, "licensing-core.js");
  writeFileSync(
    targetFile,
    `export function verifyEnterpriseLicense(key) {
  return key.startsWith("ENT-2026-") && key.length === 28;
}\n`,
    "utf8",
  );

  const report = defendTarget({
    inputPath: targetFile,
    intensity: "bankrupt",
    emitManifest: true,
  });

  console.log("One-Click Defense Score:", report.verification.defenseScore);
  console.log("Token Amplification:", report.exhaustionSummary.tokenAmplificationFactor + "x");
  console.log("Decoy Procedures Injected:", report.deceptionSummary.decoyFunctionsInjected);
} finally {
  rmSync(workDir, { recursive: true, force: true });
}
