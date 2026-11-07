# AEGIS — Rotation sütunu (tasarım spec)

Durum: tasarım. Kod yazılmadı. Var olan dosyalar değiştirilmedi.
Hedef: her build'de seed ve decoy kadrosu değişsin; aynı seed verildiğinde çıktı bit-bit aynı kalsın.

## 0. Bugünkü durum (okunan kod)

- `src/core/prng.ts` — `SeededPrng` (SplitMix32), `deriveSeedLabel(rootSeed, label)` (HMAC-SHA256), `SeededPrng.derive(label)`. Determinizm altyapısı **var**.
- `src/core/config.ts:resolveProjectSeed()` — öncelik: açık `--seed` > config'teki kullanılabilir seed > `generateProjectSeed()` ile üretip `.aegisrc`'ye yaz.
- `src/core/config.ts:LEGACY_FIXED_SEEDS` — `aegis-project-seed-v1`, `aegis-shield-seed-v1`, `aegis-js-shield-v1` sabitleri "parmak izi" sayılıp yeniden kullanılmıyor.
- `src/cli.ts:296` — `--seed` flag'i doğrulanıyor (boş değer `argErrors`'a düşüyor).
- `scripts/redteam/lib/samples.mjs:200` — red-team matrisi hâlâ sabit `"aegis-redteam-empirical-v1"` kullanıyor.

Eksik olan (bu spec'in eklediği; bugün kodda **yok**):
- Ortam değişkeni ile seed girişi (`AEGIS_SEED`) — yok, eklenecek.
- Build kimliğinden türetilmiş alt-seed — yok, eklenecek.
- Decoy rotasyon planlayıcısı — yok, eklenecek.
- `--rotation-report` flag'i ve `rotation` config bloğu — yok, eklenecek.

## 1. Yeni modül

Dosya: `src/core/rotation.ts` (yeni).
Tek sorumluluk: kök seed + build kimliğinden deterministik bir **rotasyon planı** üretmek. Şifreleme yok, sadece türetme.

Dışa açılan yüzey (imza düzeyinde):

```ts
export const ROTATION_SCHEMA = "aegis-rotation/v1";

export type RotationSeedSource = "cli" | "env" | "config" | "generated";

export interface RotationSeedInput {
  readonly cwd: string;
  readonly cliSeed?: string;
  readonly env?: NodeJS.ProcessEnv;
  readonly configPath?: string;
  /** Dry-run'da diske yazma. */
  readonly persist?: boolean;
}

export interface RotationSeed {
  readonly rootSeed: string;
  readonly source: RotationSeedSource;
  readonly persistedTo: string | null;
}

/** Öncelik sırasına göre kök seed'i çözer; hiçbiri yoksa üretir. */
export function resolveRotationSeed(input: RotationSeedInput): RotationSeed;

/** Build kimliği: hedef yolun normalize hali + içerik SHA-256'sının ilk 16 hex'i. */
export function deriveBuildId(targetPath: string, contentDigest: string): string;

/**
 * Build'e özel alt-seed. Aynı (rootSeed, buildId) -> aynı alt-seed.
 * Farklı build'ler PRNG durumunu paylaşmaz (HMAC ile ayrık substream).
 */
export function deriveBuildSeed(rootSeed: string, buildId: string): string;

export interface DecoySpec {
  readonly minCount: number;
  readonly maxCount: number;
  /** Aynı isim iki kez üretilirse atılmaz, reddedilir. */
  readonly reservedNames?: readonly string[];
}

export interface DecoyPlan {
  readonly buildId: string;
  readonly buildSeed: string;
  readonly decoyNames: readonly string[];
  readonly coefficients: readonly number[];
}

/** Decoy kadrosunu alt-seed'den üretir. Girdi aynıysa çıktı aynıdır. */
export function planDecoyRotation(buildSeed: string, spec: DecoySpec): DecoyPlan;
```

`planDecoyRotation` içinde `new SeededPrng(buildSeed)` kurulur; isimler `prng.identifier()` ile üretilir (gerçekçi kelime dağarcığı, `_aegis` öneki basılmaz), katsayılar `prng.nextInt(-2**31, 2**31-1)`.

## 2. Seed nereden geliyor (öncelik sırası)

1. `--seed <değer>` — CLI, en yüksek öncelik. Boş/whitespace → `--seed requires a non-empty value` hatası (mevcut davranış korunur).
2. `AEGIS_SEED` ortam değişkeni (yeni). Boş sayılır ve atlanır; `LEGACY_FIXED_SEEDS` üyesi ise **uyarı** basılır ama yine kullanılır.
3. Config dosyası (`aegis.config.json` / `.aegisrc` / `package.json#aegis`) içindeki `seed` — `LEGACY_FIXED_SEEDS` üyesi ise yok sayılır (mevcut `isUsableSeed` davranışı).
4. Hiçbiri yoksa `generateProjectSeed()` ile üretilir ve config'e yazılır (`persist !== false` ise).

`--dry-run` verildiğinde üretilen seed diske yazılmaz; sadece rapor satırında görünür (mevcut `cli.ts:472` davranışıyla aynı).

Build seed'i asla doğrudan kullanılmaz: her zaman `deriveBuildSeed(rootSeed, buildId)` üzerinden gidilir, böylece iki farklı artifact aynı decoy kadrosunu almaz.

## 3. Decoy üretim kuralı

- Kadro boyu: `intensity` ile ölçeklenir — `stealth` 2–4, `balanced` 6–12, `maximum` 16–32, `bankrupt` 48–96 (`DecoySpec.minCount/maxCount`).
- Her decoy adı `reservedNames` içindekilerle çakışmayacak şekilde üretilir; çakışma olursa aynı PRNG'den yeniden çekilir, en fazla 32 denemeden sonra hata.
- Katsayılar decoy sayısıyla **birebir** aynı uzunlukta; her decoy'un bir katsayısı vardır, eşleşme sırayla yapılır.
- Decoy adları artifact içine yazılırken `buildId` sırasına göre karıştırılır (`prng.shuffle`), böylece art arda gelen build'lerde konum da değişir.
- Sabit metin (magic byte, sabit tablo) decoy üretmez; yalnızca isim, katsayı, dolgu uzunluğu döner.

## 4. Determinizm garantisi

Sözleşme: **aynı `rootSeed` + aynı girdi baytları ⇒ bit-bit aynı çıktı.**

- PRNG yalnızca `SeededPrng`'dir; `Math.random()`, `Date.now()`, `crypto.randomUUID()` çıktıya karışmaz.
- Her build kendi substream'ini alır (`deriveBuildSeed` → HMAC-SHA256), üst akıştan çekim yapmaz; bu yüzden bir artifact'ın eklenmesi diğerlerinin çıktısını kaydırmaz.
- Alt-seed'ler `label` olarak `buildId` kullanır; `deriveSeedLabel` boş label'da hata verir (mevcut davranış).
- Doğrulama testi: aynı girdi iki kez korunduğunda SHA-256 özetleri eşit; farklı iki seed ile özetler farklı.

## 5. CLI

Mevcut: `--seed <seed>`, `--dry-run`, `--json`, `--intensity <preset>`.
Eklenecek:

```
--rotation-report <path>   Rotasyon planını JSON olarak bu yola yaz (yeni)
--no-rotation              Rotasyonu kapat; kök seed tek başına kullanılır (yeni)
```

Yeni komut yok; `harden`, `defend`, `protect` mevcut komutlarına bağlanır.
`--json` verildiğinde stdout'a `{"schema":"aegis-rotation/v1","buildId":...,"seedSource":"cli|env|config|generated","decoyCount":N}` satırı düşer; seed'in kendisi `--json` çıktısında **yazılmaz**, sadece `--rotation-report` dosyasında görünür.

## 6. Config şeması

`AegisProjectConfig`'e eklenecek (yeni alan, mevcut alanlar değişmez):

```json
{
  "rotation": {
    "enabled": true,
    "decoyCount": 48,
    "reservedNames": ["main", "init"]
  }
}
```

- `rotation` yoksa `enabled: true`, `decoyCount: null` (intensity'den türetilir) varsayılır.
- `decoyCount` verilirse intensity ölçeğini **ez**er ve `minCount = maxCount = decoyCount` olur.
- Şema doğrulaması `validateAegisConfigShape` içinde: `rotation` nesne değilse veya `decoyCount` 1–4096 dışındaysa `Invalid AEGIS config at <source>: ...` fırlatılır — sessiz geri düşme yok.

## 7. Hata durumları

| Durum | Davranış |
|---|---|
| `--seed` boş / sadece boşluk | `argErrors`, exit 2, dosya yazılmaz |
| `AEGIS_SEED` boş | sessizce atlanır, sonraki kaynağa geçilir |
| Seed `LEGACY_FIXED_SEEDS` üyesi ve kaynak env/config | stderr'e `warning: legacy fixed seed, per-build rotation weak` |
| `decoyCount` aralık dışı | config doğrulama hatası, exit 2 |
| Decoy adı 32 denemede tekil olamadı | `RotationVocabularyExhausted`, exit 1 |
| Hedef okunamıyor (digest alınamıyor) | `RotationTargetUnreadable`, exit 1 |
| `--no-rotation` + `--rotation-report` birlikte | rapor yazılır, `decoyCount: 0`, `buildId: null` |

Hiçbir hata "yarım artifact" bırakmaz: yazma işlemi plan tamamlandıktan sonra başlar.

## 8. Kabul kriterleri

1. `aegis harden . --seed A --dry-run` iki kez koşulduğunda üretilen plan JSON'ları birebir aynıdır.
2. Aynı proje, `--seed A` ve `--seed B` ile korunduğunda decoy ad kümeleri kesişmez (en az %90 farklı).
3. Aynı seed, iki farklı artifact → iki farklı `buildId` ve ayrık decoy kadrosu; birinin yeniden korunması diğerinin çıktısını değiştirmez.
4. `--seed ""` exit 2 verir ve artifact'a dokunmaz.
5. `seed` alanı olmayan projede ilk koşu `generated` kaynağı raporlar ve `.aegisrc`'ye seed yazar; ikinci koşu `config` kaynağı raporlar ve aynı çıktıyı üretir.
6. `AEGIS_SEED=x` verilip `--seed y` de verildiğinde kaynak `cli` raporlanır.
7. `rotation.decoyCount = 8` iken plan tam olarak 8 decoy üretir.
8. `--rotation-report out.json` dosyayı yazar; `--dry-run` ile birlikte artifact'a hiç bayt yazılmaz.
