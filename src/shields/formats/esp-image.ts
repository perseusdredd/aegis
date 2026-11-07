/**
 * ESP32/ESP8266 flash image (`.bin`, image header `e9`) — DRAFT shield
 * (docs/AEGIS-BUDGETS.md section 3). Distinct from `firmware-uf2.ts`, which
 * targets the UF2 drag-and-drop container, not a raw ESP flash dump. REA has
 * no dedicated ESP image reader yet; minimal placeholder only.
 */

const ESP_IMAGE_MAGIC_BYTE = 0xe9;

export const ESP_IMAGE_SHIELD_MARKER = "[AEGIS-ESP-IMAGE-DRAFT]";

/** True if `bytes` starts with the ESP image header magic byte (`0xE9`). */
export function detectEspImage(bytes: Buffer): boolean {
  if (bytes.length < 1) return false;
  return bytes[0] === ESP_IMAGE_MAGIC_BYTE;
}

/** Smallest-working-design decoy: append a tagged trailer, never mutate existing bytes. */
export function draftAnnotateEspImage(bytes: Buffer): Buffer {
  const trailer = Buffer.from(`\n${ESP_IMAGE_SHIELD_MARKER}\n`, "utf8");
  return Buffer.concat([bytes, trailer]);
}
