# CLI & MCP Reference (`aegis-agents`)

For coding agents, the **[`aegis-counter-rea` skill](../.agents/skills/aegis-counter-rea/SKILL.md)** is the primary one-click harden guide; this page indexes the CLI/MCP execution surface.

## CLI Commands

| Command | Description |
| :--- | :--- |
| `npx aegis-agents setup` | Auto-registers the `aegis` MCP server and `aegis-counter-rea` skill with Claude Code, Cursor, Codex, Windsurf, Gemini CLI, and Antigravity. |
| `npx aegis-agents harden .` | **Default one-command UX**: auto-discover build outputs and run audit → protect → verify (bankrupt). Prefer over `defend` when you have a project directory. Agent guide: [`aegis-counter-rea` skill](../.agents/skills/aegis-counter-rea/SKILL.md). |
| `npx aegis-agents lint .` | **Unified packaging-footgun scan** (`aegis-packaging-gates/v1`): all R1–R7 refuse lints + lanes/panel. Exit 2 when bankrupt would refuse. Writes nothing. |
| `npx aegis-agents defend <target> [--manifest] [--sign-manifest --manifest-key <pem>] [--llm-directives] [--weave-decoys]` | **5-stage pipeline** on a known path: `inspect-release` → `audit` → `protect` → `verify` → optional `.aegis-manifest.json` (opt-in; unsigned unless `--sign-manifest` is set). Risky LLM directive layers stay off unless `--llm-directives`. Structural weave decoys stay off unless `--weave-decoys`. |
| `npx aegis-agents harden . [--weave-decoys]` | Same as `harden` with opt-in structural weave (`weave_decoys`). |
| `npx aegis-agents inspect-release <target>` | Read-only local scan for embedded `.map` (`sourcesContent`) and sourceMappingURL references. |
| `npx aegis-agents audit <target>` | Pre-flight 16-vector REA vulnerability & token-cost audit. |
| `npx aegis-agents protect <target> [-o <out>] [--weave-decoys]` | Injects AEGIS's Resource-Exhaustion and Model-Misjudgment shield (`stealth`, `balanced`, `maximum`, `bankrupt`). Opt-in `--weave-decoys` for structural Python customer-def weave. |
| `npx aegis-agents verify <target> [original]` | Verifies Counter-REA invariants and calculates token/cost amplification. |
| `npx aegis-agents benchmark` | Runs the 8-target Counter-REA Showcase Benchmark suite. |
| `npx aegis-agents emit-headers --lang <c\|rust\|go>` | Emits compile-time native defense headers (`aegis_shield.h`, `aegis_shield.rs`, `aegis_shield.go`). |
| `npx aegis-agents doctor` | Checks readiness of all AEGIS protection engines and agent MCP registrations. |

### Signed manifests (ed25519)

`.aegis-manifest.json` is unsigned by default. To sign it:

```bash
aegis defend ./dist --manifest --sign-manifest --manifest-key ./release-key.pem
```

The manifest keeps the plain JSON payload and adds a `signature` object with
`algorithm: "ed25519"`, the SPKI public key, and a base64 signature over the
payload JSON (the `signature` field is excluded). `attestationKind` is
`"unsigned"` or `"ed25519"`, so consumers can tell whether a signature exists.

Verify with the library:

```ts
import { readFileSync } from "node:fs";
import { verifyManifestSignature } from "aegis-agents";

const manifest = JSON.parse(readFileSync(".aegis-manifest.json", "utf8"));
// Without a pinned key this only proves the payload matches the embedded key.
verifyManifestSignature(manifest);
```

Signing fails closed: `--sign-manifest` without `--manifest-key`, a missing key
file, or a key path without `--manifest` is an error, never a silently unsigned
manifest.

## MCP Tools (`aegis` Server)

- `aegis_harden`: Preferred one-sentence harden of a project directory (`directory`, `intensity`, `emit_manifest` default false, `llm_directives` default false, `weave_decoys` default false, `self_seal` default false, `wasm_preserve_exports`, `allow_lane_independent`, `allow_plaintext_seal`, `allow_wasm_clear_params`, `allow_stable_panel_derive`, `seed`, `dry_run` default false, `max_artifacts` default 64, `confirm_overwrite` default false, `output_directory` optional). The report carries `dryRun`, `truncated`, `maxArtifacts`, `wouldOverwrite`, and `outputDirectory`.
- `aegis_discover`: Read-only inventory using the same discovery as `aegis_harden` (`directory`, `max_artifacts`, `offset`) → `{ directory, artifacts[{path, relativePath, format}], truncated, maxArtifacts, offset, nextOffset? }`. When `truncated`, pass `nextOffset` as the next `offset` to page 64+ trees without losing the tail. Writes nothing.
- `aegis_defend`: Full Counter-REA pipeline on a known path (`input_path`, `output_path`, `intensity`, `emit_manifest` default false, `llm_directives` default false, `weave_decoys` default false, `self_seal` default false, `wasm_preserve_exports`, `allow_lane_independent`, `allow_plaintext_seal`, `seed`, `in_place` default false, `confirm_overwrite` default false).
- `aegis_audit`: Pre-flight REA exposure and token-economics audit (`path`).
- `aegis_protect`: Granular shield injection (`input_path`, `output_path`, `intensity`, `seed`, `llm_directives` default false, `weave_decoys` default false, `self_seal` default false, `wasm_preserve_exports`, `allow_lane_independent`, `allow_plaintext_seal`, `in_place` default false, `honey_source_maps` default true, `confirm_overwrite` default false).
- `aegis_verify`: Counter-REA invariant verification (`target_path`, `original_path`, optional honesty metadata `self_seal_enabled` / `wasm_export_rename_applied` / `numeric_template_leak_known` so `defenseScore` soft-caps match what protect actually ran; optional `summary_path` / `run_id` to correlate with a prior harden summary).
- `aegis_lint`: **DEFAULT** packaging-footgun project scan (`directory`, `intensity`, allow_* flags) → `aegis-packaging-gates/v1` (findings + blocking + honestyNote). Prefer over calling eight separate lints. Same engines as CLI `aegis lint`.
- `aegis_lint_lanes`: Read-only lane-independence footgun lint (`path`) — same engine as CLI `aegis lint-lanes`.
- `aegis_lint_seal`: Read-only seal-commitment lint (`path`) — plaintext / reversible seal sidecars; same engine as CLI `aegis lint-seal`.
- `aegis_lint_wasm_params`: Read-only WASM clear param/cipher carrier lint (`path`) — `R3PARM`/`R3CIPH`/`R2SEAL`-class; same engine as CLI `aegis lint-wasm-params`.
- `aegis_lint_panel_derive`: Read-only panel-derive ABI lint (`path`) — stable `__vaultPanelDerive_*` / `deriveLocal` / `panelTokenSha256` oracle; same engine as CLI `aegis lint-panel-derive`.
- `aegis_lint_js_aes_unwrap`: Read-only JS AES wrap-key unwrap lint (`path`) — wrap-key + create*iv + fixed hdr; same engine as CLI `aegis lint-js-aes-unwrap`. Gate only — not white-box AES.
- `aegis_lint_js_wasm_hydrate_dump`: Read-only JS←WASM hydrate param-dump lint (`path`) — memory.buffer + salt/rounds/cipher after hydrate; same engine as CLI `aegis lint-js-wasm-hydrate-dump`. Prefer in-WASM ARX+certify.
- `aegis_lint_wasm_xor_mask_sidecar`: Read-only WASM XOR-mask sidecar lint (`path`) — masked entitlement pack beside plaintext 32-byte mask in WASM data; bankrupt refuses unless `allow_wasm_xor_mask_sidecar`, `allow_wasm_seal_xor_known_plaintext`.
- `aegis_lint_wasm_seal_xor_known_plaintext`: Read-only seal.revision XOR known-plaintext lint (`path`, optional `seal_path`) — bankrupt refuses unless `allow_wasm_seal_xor_known_plaintext`.
- `aegis_run_lookup`: Read-only harden-run correlation (`summary_path`, optional `run_id`). Summaries are **unsigned**; missing/mismatched id is an error.
- `aegis_rea_drift`: Thin wrapper over `npm run verify:rea` / `scripts/verify-rea-constants.mjs`. Absent sibling REA → `status: unverified` (not red-team evidence).
- `aegis_redteam_report`: Read (or `execute:true` re-run) `docs/redteam/empirical-rea-validation.json`. On-disk read → `status: available` (not a live REA verdict); `execute:true` → `pass`/`fail`; missing report / unready REA → `status: unverified`.
- `aegis_benchmark`: Runs the 8-target showcase benchmark suite.
- `aegis_emit_headers`: Generates C/C++, Rust, or Go defense headers (`language`, `intensity`).
- `aegis_bind_scope`: Optional honest code-lock — write public `bind-scope.json` (domains / validFrom / validUntil) and inject `AEGIS_BIND_SCOPE_CHECK` into the license entry. Default OFF; never a covert backdoor.
- `aegis_lint_bind_scope`: Read-only lint for `aegis-bind-scope/v1` (refuses non-public / hidden fields / missing runtime check).
- `aegis_doctor`: Diagnostics for AEGIS engines and agent client registrations; also reports `skillMissingFiles` / `skillModifiedFiles` (format appendices under `references/` included).
- `aegis_weave_plan`: Read-only weave-decoy planner (`path`, optional `max_targets`) → `aegis-weave-plan/v1` JSON (defensive theory checklist + AST `surgicalWorkorder` with `entryFunctions`, `sharedStateSlots`, `branchCandidates`, and `agentRewriteRecipe`; no crack/RE).
- `aegis_verify_weave`: Read-only structural weave verifier (`path`, optional `max_targets`) → `aegis-weave-verify/v1` JSON (`overallPassed`, `weaveScore`, per-file 6-check verification, and actionable `agentActions` for autonomous Agent self-repair).

### Write safety (dry-run, confirmation, receipts)

- `aegis_harden` with `dry_run: true` (CLI `aegis harden . --dry-run`) discovers targets and plans outputs with **zero bytes written** (no `.aegis-hardened/`, no summary, no `.aegisrc` seed). Dry-run sets `overallSuccess: false` — it never claims a successful harden.
- Discovery is capped (`max_artifacts`, default 64); when more targets exist the result sets `truncated: true` and `nextOffset` instead of silently dropping them — page with `offset` until `truncated` is false.
- `aegis_harden` / `aegis_defend` / `aegis_protect` refuse to overwrite an existing output file unless `confirm_overwrite: true`. A refusal is `isError: true` with `{ status: "confirmation_required", wouldOverwrite: [...], wrote: [] }`; nothing is written.
- Successful `aegis_harden` / `aegis_defend` / `aegis_protect` writes add `writeReceipt: { status: "written", wrote, overwrote, confirmed }` (`aegis_harden` dry-run omits it).
- `in_place: true` (MCP) / `--in-place` (CLI) plans the output as the input path; because that path already exists, `confirm_overwrite: true` is required on MCP or the call is refused with `confirmation_required`.

`weave_decoys: true` activates structural Python customer-def weave (shared-slot touch + opaque-false decoy calls) after the #51 tarpit; when false, Python stays warm-init-only. JS AST weave remains always-on.

Project config parity: set `"weaveDecoys": true` in `.aegisrc` / `aegis.config.json` (schema `aegis.config.v1.json`) to enable the same flag without repeating `--weave-decoys` / MCP `weave_decoys` on every invoke. CLI/MCP flags still OR with the config value.

Opt-in **self-seal** (issue #40.5): CLI `--self-seal`, MCP `self_seal`, `.aegisrc` `"selfSeal": true`. Injects a Node self-integrity preamble (module + optional sibling paths + env fingerprint) and folds the digest into the opaque-predicate seed for JS/Node targets.
WASM public ABI preserve list (issue #40.3 / red-blue round-1): CLI `--wasm-preserve-exports a,b`, MCP `wasm_preserve_exports`, `.aegisrc` `"wasmPreserveExports": ["a","b"]`. At `maximum`/`bankrupt`, **every** non-listed export is renamed by default — keeping `mix`/`seal`-style names requires an explicit list.

Heuristic **lane-independence lint** (issue #40.1 / red-blue round-1): CLI `aegis lint-lanes <file>` and MCP `aegis_lint_lanes` emit severity **error** when gate code looks like independent per-lane checks. Harden/defend/protect **refuse** unless CLI `--allow-lane-independent` / MCP `allow_lane_independent` / `.aegisrc` `"allowLaneIndependentGates": true`. Prefer whole-key chained mixing.

Heuristic **seal-commitment lint** (red-blue round-2): CLI `aegis lint-seal <file>` and MCP `aegis_lint_seal` flag plaintext seal/entitlement JSON and reversible public commitments (`scheduleSalt`+`rounds`+`revision` without a one-way algorithm). Severity **error** findings make **bankrupt** harden/protect **refuse** unless CLI `--allow-plaintext-seal` / MCP `allow_plaintext_seal` / `.aegisrc` `"allowPlaintextSeal": true`. One-way SHA-256/HMAC digests pass. Full seal-encrypt/bind remains a follow-up; refusal closes the round-2 footgun by default.

### MCP Resources

- `aegis://directives/weave-decoy` — weave-decoy theory + executor checklist (Markdown).
- `aegis://docs/weave-decoy-mcp` — same directives payload (doc pointer URI).

See [`weave-decoy-mcp.md`](./weave-decoy-mcp.md).
