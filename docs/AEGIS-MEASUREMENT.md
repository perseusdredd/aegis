# AEGIS — Measurement sütunu (tasarım spec)

Durum: tasarım. Kod yazılmadı. Var olan dosyalar değiştirilmedi.
Hedef: AEGIS'in iddia ettiği bütçe ihlallerini **gerçek REA koduna** karşı ölçen tek komut. Ölçüm, iddia ile ampirik sonucu yan yana koyar ve sapmayı sayı olarak verir.

## 0. Bugünkü durum (okunan kod)

Var:
- `scripts/redteam/run.mjs` — 13 format için "önce/sonra" ampirik koşucu; `docs/redteam/empirical-rea-validation.{md,json}` yazar; REA dist yoksa `status: "unverified"` + exit 0.
- `scripts/redteam/lib/probes.mjs` — gerçek REA parserlarını `dist/` üzerinden yükler (`probeWasm`, `probeSqlite`, `probeGo`, ...).
- `scripts/redteam/lib/samples.mjs` — örnek matrisi; `buildSampleMatrix()` `{aegis, intensity, seed, samples}` döner, seed sabit `"aegis-redteam-empirical-v1"`.
- `scripts/redteam/lib/report.mjs` — `buildReportDocument()`, `writeReports()`.
- `src/engine/rea-observability.ts` — `resolveReaRoot()`, `reaCheckoutPresent()`, `reaDistReady()`, `getRedteamReport({execute})`, `ReaObservabilityStatus = pass|fail|unverified|available`.
- `src/engine/verifier.ts:112-115` — savunma skoru formülü: `min(100, (passed/checks)*70 + max(0, 100-exposureScore)*0.3)`.

Eksik olan (bu spec'in eklediği; bugün kodda **yok**):
- CLI `measure` komutu — yok, eklenecek.
- `src/engine/measurement-runner.ts` — yok, eklenecek.
- Sapma (deviation) hesabı ve eşik kapısı — yok, eklenecek (`report.mjs` yalnızca AGREE/DIVERGE metni üretiyor, sayı yok).
- `AEGIS_MEASURE_OUT_DIR` ve `--out` ile çıktı yönlendirme — yok, eklenecek.

Yeniden kullanılacak: `lib/probes.mjs`, `lib/samples.mjs`, `reaDistReady()`. Yeniden yazılmayacak.

## 1. Komut arayüzü

```
aegis measure [--format <f>]... [--seed <s>] [--intensity <p>]
              [--out <dir>] [--json] [--timeout-ms <n>] [--fail-on-diverge]
```

| Bayrak | Anlam | Varsayılan |
|---|---|---|
| `--format <f>` | Yalnızca bu formatı koş (tekrarlanabilir). Geçerli değerler `run.mjs`'deki 13 anahtar. | tümü |
| `--seed <s>` | Build seed'i; `rotation` spec'indeki çözümleyici ile aynı öncelik. | `resolveRotationSeed()` |
| `--intensity <p>` | `stealth\|balanced\|maximum\|bankrupt` — mevcut doğrulama kullanılır. | `bankrupt` |
| `--out <dir>` | Çıktı dizini. | `docs/measure` |
| `--timeout-ms <n>` | Format başına sert süre sınırı. | 120000 |
| `--json` | stdout'a yalnız JSON özet satırı. | kapalı |
| `--fail-on-diverge` | Sapma varsa exit 2. Yoksa exit 0. | kapalı |

Çıkış kodları: `0` başarı, `1` koşu hatası (REA/örnek üretimi), `2` eşik veya sapma kapısı, `3` REA hazır değil (atlandı).
`--format` bilinmeyen anahtar → exit 2 + geçerli liste.

## 2. Toplanan metrikler

Her format için ayrı kayıt:

- `format` — ölçülen analizör anahtarı.
- `status` — `measured` | `skipped` | `failed`.
- `durationMs` — gerçek duvar saati; `--timeout-ms` aşılırsa `timeout: true`.
- `beforeBudgetHit` / `afterBudgetHit` — boolean.
- `afterBudgetName` — hangi REA limiti tetiklendi (`MAX_POOL_URIS`, `MODEL_METADATA_NESTING`, ...).
- `estimatedTrip` — AEGIS'in `sampleMeta` iddiası (boolean veya null = iddia yok).
- `deviation` — `afterBudgetHit === estimatedTrip` ise `0`; değilse `1` (yön bilgisi `deviationKind: "overclaim" | "underclaim"`).
- `inputBytesBefore` / `inputBytesAfter` — büyüme oranı `growthRatio` türetilir, ham bayt da saklanır.
- `errorName` / `errorMessage` — REA hata sınıfı; `metrics` — analizöre özgü ek alanlar (`packageUriCount`, `tsharkJsonBytes`, `headerBytes`, ...).

Toplamda: `formatCoverage` (ölçülen / seçilen), `passed`, `remaining`, `divergences`, `overclaims`, `underclaims`, `totalDurationMs`, `medianDurationMs`.

## 3. Çıktı formatı

İki dosya, `--out` altında: `measure-<stamp>.json` ve `measure-<stamp>.md`.

JSON (`aegis-measure/v1`):

```json
{
  "schema": "aegis-measure/v1",
  "generatedAt": "2026-11-07T13:55:00Z",
  "aegisVersion": "3.0.1",
  "rea": { "root": "C:/Users/numan/aresearch/rea", "commit": "<git rev-parse>", "distReady": true },
  "run": { "seed": "aegis-…", "intensity": "bankrupt", "nodeVersion": "v24.19.0" },
  "summary": {
    "selected": 13, "measured": 12, "skipped": 1,
    "passed": 11, "remaining": 1,
    "divergences": 1, "overclaims": 1, "underclaims": 0,
    "formatCoverage": 0.923,
    "totalDurationMs": 184230, "medianDurationMs": 9100,
    "verdict": "fail"
  },
  "formats": [ { "format": "wasm_module", "status": "measured", "durationMs": 12110,
                 "afterBudgetHit": true, "afterBudgetName": "WASM_INTERFACE_REPRESENTATION_BYTES",
                 "estimatedTrip": true, "deviation": 0, "deviationKind": null,
                 "inputBytesBefore": 1048576, "inputBytesAfter": 4194304,
                 "errorName": null, "errorMessage": null, "metrics": {} } ],
  "skips": [ { "format": "pcap_capture", "reason": "tshark-unavailable" } ]
}
```

İnsan okur özet (`measure-<stamp>.md`) sırası: tek satır hüküm (kapsama + sapma sayısı), sapma tablosu, atlananlar ve nedenleri, süre tablosu, ortam künyesi (REA commit, node, seed). En fazla 40 satır; üstü kesilir ve `truncated: true` yazılır.

## 4. Eşik ve başarı tanımı

- `formatCoverage` ≥ **0.85** (13 formatın en az 12'si ölçülmüş; 11/13 = 0.846 eşiğin altındadır).
- `divergences` == 0.
- `beforeBudgetHit` hiçbir formatta `true` olmamalı (sertleştirilmemiş örnek bütçeyi aşmamalı).
- `totalDurationMs` ≤ 600000.
- `verdict`: hepsi sağlanırsa `"pass"`, kapsama veya süre düşerse `"inconclusive"`, sapma veya before-hit varsa `"fail"`.

`"pass"` dışı hüküm asla başarı sayılmaz; `inconclusive` için exit 0 (bilgi), `fail` için exit 0 (varsayılan) veya 2 (`--fail-on-diverge`).

## 5. REA kurulumu varsayımları

- REA kök dizini: `--rea-root` > `REA_ROOT` env > `<aegis paket kökü>/../rea` (`resolveReaRoot()` mevcut davranışı).
- `rea/src` **ve** `rea/dist/go/GoBinaryImage.js` mevcut olmalı (`reaCheckoutPresent` + `reaDistReady`).
- `dist/` derlenmiş olmalı; koşucu `tsc` çalıştırmaz, hazır değilse `skip`.
- Node sürümü REA SQLite capability gate'i için ≥ 24.15; altındaysa `sqlite_db` → `skipped` (`capability-gated`), diğerleri koşar.
- `tshark` PATH'te yoksa `pcap_capture` → `skipped` (`tshark-unavailable`).
- REA commit'i `git -C <rea> rev-parse --short HEAD` ile alınır; git yoksa `null`, ölçüm durmaz.

## 6. Hata ve atlandı durumları

| Durum | `status` | Etki |
|---|---|---|
| REA kökü yok / `dist` yok | koşu durur | exit 3, `verdict` yok, dosya yazılmaz |
| Format örneği üretilemedi | `failed`, `errorName` dolu | kapsamadan düşer |
| REA parserı beklenmedik hata fırlattı | `failed` | kapsamadan düşer |
| `--timeout-ms` aşıldı | `failed`, `timeout: true` | kapsamadan düşer |
| Analizör yeteneği yok (`sqlite` < Node 24.15, `tshark` yok) | `skipped` | kapsamadan düşer, neden `skips[]` |
| Aynı anda ikinci koşu | ikinci koşu exit 1, `measure-lock` dosyası | — |

Atlanan her format `skips[]` içinde nedeniyle birlikte görünür; sessiz atlama yok. `skipped` sayısı kapsamaya yansır, bu yüzden "her şey atlandı" durumu `inconclusive` olur, `pass` olmaz.

## 7. Kabul kriterleri

1. `aegis measure --format wasm_module` tek formatı koşar, `summary.selected == 1` olur.
2. `aegis measure --format yok-boyle` exit 2 verir ve geçerli formatları listeler.
3. REA `dist` silinmişken `aegis measure` exit 3 verir, `docs/measure` altına yeni dosya yazmaz.
4. Aynı seed ile iki koşu aynı `formats[].afterBudgetHit` değerlerini üretir (süreler hariç).
5. Üretilen JSON `aegis-measure/v1` şemasına uyar; `summary.measured + summary.skipped == summary.selected`.
6. Bilerek bozulmuş bir iddia (ör. wasm decoy sayısı düşürülmüş) `deviation: 1`, `deviationKind: "overclaim"` ve `verdict: "fail"` üretir.
7. `verdict: "fail"` iken `--fail-on-diverge` exit 2, bayraksız exit 0 verir.
8. Atlanan format olduğunda `skips[]` dolu olur ve `formatCoverage` düşer.
9. Özet markdown 40 satırı aşmaz, aştığında `truncated: true` yazar.
10. `--json` verildiğinde stdout'ta tek satır JSON olur, markdown yolu `stderr`'e gider.

## 8. Sınırlar

- Ölçüm yalnızca `scripts/redteam` matrisinin kapsadığı 13 formatı ölçer; matriste örneği olmayan format "kapsam dışı"dır ve `skips[]`'e `no-sample` olarak yazılır.
- `gpu_ptx` yalnız metin taramasıyla doğrulanır; fatbin/SPIR-V nesne çözümü ölçülmüş sayılmaz, `metrics.nativeDecode: false` ile işaretlenir.
- Ölçüm, üretim artifact'ını değiştirmez; yalnız `docs/measure` altına yazar.
