/**
 * Unity `UnityFS` AssetBundle container — DRAFT shield
 * (docs/AEGIS-BUDGETS.md section 3). REA has no dedicated AssetBundle reader
 * yet; minimal placeholder only — detect + append a marked, byte-exact
 * trailer. No bundle block/asset rewriting is attempted (over-engineering
 * for an unexploited format family).
 */

const UNITYFS_SIGNATURE = "UnityFS\0";

export const UNITYFS_SHIELD_MARKER = "[AEGIS-UNITYFS-DRAFT]";

/** True if `bytes` starts with the `UnityFS\0` signature. */
export function detectUnityFs(bytes: Buffer): boolean {
  if (bytes.length < UNITYFS_SIGNATURE.length) return false;
  return bytes.subarray(0, UNITYFS_SIGNATURE.length).toString("latin1") === UNITYFS_SIGNATURE;
}

/** Smallest-working-design decoy: append a tagged trailer, never mutate existing bytes. */
export function draftAnnotateUnityFs(bytes: Buffer): Buffer {
  const trailer = Buffer.from(`\n${UNITYFS_SHIELD_MARKER}\n`, "utf8");
  return Buffer.concat([bytes, trailer]);
}
