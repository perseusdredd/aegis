import { SeededPrng } from "../../core/prng.js";
import type { ProtectionIntensity } from "../../core/types.js";

export interface BpeTokenAmplifierResult {
  readonly code: string;
  readonly amplifiedIdentifiersCount: number;
  readonly rawUtf8Bytes: number;
  readonly estimatedBpeTokens: number;
  readonly tokensPerByteRatio: number;
}

const HIGH_SPLIT_SUBWORDS = [
  "Zq",
  "X9",
  "Kv",
  "W7",
  "Jm",
  "P3",
  "Vh",
  "N8",
  "Cx",
  "B4",
  "Gf",
  "L6",
  "Tr",
  "D2",
  "Yw",
  "S5",
] as const;

/**
 * Generates valid ECMAScript/C identifiers and lookup tables engineered to maximize
 * Byte-Pair Encoding (BPE) subword fragmentation in Claude Opus 4 / Sonnet 4 and OpenAI
 * `o200k_base` / `cl100k_base` tokenizers.
 *
 * Alternating MixedCase + consonant-digit pairs (`Zq_X9_Kv_W7...`) prevent BPE tokenizers
 * from merging character sequences into long whole-word tokens, achieving ~0.55–0.70
 * BPE tokens per UTF-8 byte (vs ~0.18 tokens/byte for normal source code) while
 * compressing down to < 15% size under gzip/brotli/asar packaging!
 */
export function generateBpeTokenAmplifier(
  prng: SeededPrng,
  intensity: ProtectionIntensity = "balanced",
): BpeTokenAmplifierResult {
  const symbolCount =
    intensity === "stealth"
      ? 8
      : intensity === "balanced"
        ? 16
        : intensity === "maximum"
          ? 28
          : 42;
  const tag = prng.hex(3);
  const identifiers: string[] = [];

  for (let i = 0; i < symbolCount; i++) {
    const parts: string[] = [`bpeSink_${tag}`];
    for (let s = 0; s < 8; s++) {
      const sub =
        HIGH_SPLIT_SUBWORDS[(i * 7 + s * 3 + prng.nextInt(0, 15)) % HIGH_SPLIT_SUBWORDS.length]!;
      parts.push(sub);
    }
    identifiers.push(parts.join("_"));
  }

  const lines: string[] = [
    `const tokenSink_${tag} = Object.freeze({`,
  ];
  for (let i = 0; i < identifiers.length; i++) {
    const id = identifiers[i]!;
    const prev = identifiers[(i + identifiers.length - 1) % identifiers.length]!;
    lines.push(
      `  ${id}: (${i + 1} ^ 0x${prng.hex(4)}) /* ref:${prev} */,`,
    );
  }
  lines.push(`});`);

  const code = lines.join("\n");
  const rawUtf8Bytes = Buffer.byteLength(code, "utf8");
  // Each `Zq_` 3-char segment splits into 2 BPE tokens in cl100k/Claude tokenizers (~0.62 tokens/byte)
  const estimatedBpeTokens = Math.ceil(rawUtf8Bytes * 0.62);

  return {
    code,
    amplifiedIdentifiersCount: identifiers.length,
    rawUtf8Bytes,
    estimatedBpeTokens,
    tokensPerByteRatio: Number((estimatedBpeTokens / Math.max(1, rawUtf8Bytes)).toFixed(2)),
  };
}
