/**
 * Flattened Device Tree blob (`.dtb`) — DRAFT shield
 * (docs/AEGIS-BUDGETS.md section 3). REA has no dedicated DTB reader yet;
 * minimal placeholder only — detect the `d00dfeed` big-endian magic and
 * append a marked, byte-exact trailer. No struct-block/string-block
 * rewriting is attempted (over-engineering for an unexploited format
 * family).
 */

const FDT_MAGIC = 0xd0_0d_fe_ed;

export const DEVICETREE_SHIELD_MARKER = "[AEGIS-DEVICETREE-DRAFT]";

/** True if `bytes` starts with the big-endian FDT magic (`d00dfeed`). */
export function detectDeviceTree(bytes: Buffer): boolean {
  if (bytes.length < 4) return false;
  return bytes.readUInt32BE(0) === FDT_MAGIC;
}

/** Smallest-working-design decoy: append a tagged trailer, never mutate existing bytes. */
export function draftAnnotateDeviceTree(bytes: Buffer): Buffer {
  const trailer = Buffer.from(`\n${DEVICETREE_SHIELD_MARKER}\n`, "utf8");
  return Buffer.concat([bytes, trailer]);
}
