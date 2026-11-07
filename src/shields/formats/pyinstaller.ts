/**
 * PyInstaller onefile/onedir bundle — DRAFT shield
 * (docs/AEGIS-BUDGETS.md section 3). Distinct from `python.ts` /
 * `python-pyc-weave.ts` / `python-ast-weave.ts`, which target raw
 * source/bytecode, not the PyInstaller CArchive container itself. REA has no
 * dedicated CArchive reader yet; minimal placeholder only.
 */

// PyInstaller's CArchive cookie magic, as embedded near EOF by the bootloader.
const PYINSTALLER_COOKIE_MAGIC = "MEI\x0c\x0b\x0a\x0b\x0e";

export const PYINSTALLER_SHIELD_MARKER = "[AEGIS-PYINSTALLER-DRAFT]";

/** True if the CArchive cookie magic appears anywhere in `bytes` (bounded scan). */
export function detectPyInstaller(bytes: Buffer, scanWindowBytes = 1_048_576): boolean {
  const magic = Buffer.from(PYINSTALLER_COOKIE_MAGIC, "latin1");
  const start = Math.max(0, bytes.length - scanWindowBytes);
  return bytes.indexOf(magic, start) !== -1;
}

/** Smallest-working-design decoy: append a tagged trailer, never mutate existing bytes. */
export function draftAnnotatePyInstaller(bytes: Buffer): Buffer {
  const trailer = Buffer.from(`\n${PYINSTALLER_SHIELD_MARKER}\n`, "utf8");
  return Buffer.concat([bytes, trailer]);
}
