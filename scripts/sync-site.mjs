#!/usr/bin/env node
/**
 * Syncs ./website/* from qybaihe/bla to https://github.com/qybaihe/bla-site
 * Usage: npm run sync:site
 */
import { execSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const rootDir = path.resolve(__dirname, "..");
const websiteDir = path.join(rootDir, "website");
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "bla-site-sync-"));

try {
  console.log("Cloning qybaihe/bla-site...");
  execSync(`git clone --depth 1 https://github.com/qybaihe/bla-site.git "${tmpDir}"`, {
    stdio: "inherit",
  });

  // Copy all files from website/ to tmpDir
  fs.cpSync(websiteDir, tmpDir, { recursive: true, force: true });

  const status = execSync("git status --porcelain", { cwd: tmpDir, encoding: "utf8" }).trim();
  if (!status) {
    console.log("qybaihe/bla-site is already up to date with ./website.");
  } else {
    execSync("git add -A", { cwd: tmpDir, stdio: "inherit" });
    execSync('git commit -m "chore(site): sync website from qybaihe/bla"', {
      cwd: tmpDir,
      stdio: "inherit",
    });
    execSync("git push origin main", { cwd: tmpDir, stdio: "inherit" });
    console.log("Successfully synced ./website to https://github.com/qybaihe/bla-site");
  }
} finally {
  fs.rmSync(tmpDir, { recursive: true, force: true });
}
