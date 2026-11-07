/**
 * Godot PCK container — DRAFT shield (docs/AEGIS-BUDGETS.md section 3).
 *
 * REA has no dedicated Godot PCK reader yet; this is a minimal, intentionally
 * small-surface placeholder: detect the format and append a byte-exact,
 * self-describing decoy trailer. No real PCK resource-table rewriting is
 * attempted here (would be over-engineering for an as-yet-unexploited format
 * family) — widen this once a corresponding REA reader exists to target.
 */

const PCK_MAGIC = 0x43_50_44_47; // "GDPC" ASCII bytes read back as a little-endian u32 from offset 0

export const GODOT_PCK_SHIELD_MARKER = "[AEGIS-GODOT-PCK-DRAFT]";

/** True if `bytes` starts with Godot's `GDPC` pack magic. */
export function detectGodotPck(bytes: Buffer): boolean {
  if (bytes.length < 4) return false;
  return bytes.readUInt32LE(0) === PCK_MAGIC;
}

/**
 * Smallest-working-design decoy: append a tagged, clearly-marked trailer
 * after the artifact's real bytes. Never mutates existing bytes.
 */
export function draftAnnotateGodotPck(bytes: Buffer): Buffer {
  const trailer = Buffer.from(`\n${GODOT_PCK_SHIELD_MARKER}\n`, "utf8");
  return Buffer.concat([bytes, trailer]);
}
