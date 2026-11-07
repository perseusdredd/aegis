<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-banner-dark.png">
  <img src="docs/assets/logo-banner.png" alt="AEGIS: Blind LLM Agents" width="420">
</picture>

### Rotate -> Deepen -> Measure

AEGIS is a build-time defence layer for software you ship: it makes release artefacts expensive for an AI reverse-engineering agent (REA) to read, while runtime behaviour stays equivalent.

[![npm version](https://img.shields.io/badge/npm-aegis--agents-2563eb?style=flat-square&logo=npm)](https://www.npmjs.com/package/aegis-agents)
[![Node.js](https://img.shields.io/badge/Node.js-%5E22.23.4%7C%7C_24.x-0284c7?style=flat-square&logo=nodedotjs&logoColor=white)](#requirements)
[![MIT license](https://img.shields.io/badge/license-MIT-38bdf8?style=flat-square)](LICENSE)


## What it does

| Layer | What it does |
| --- | --- |
| **Rotate** | Picks decoys deterministically per build from a seed, so a rebuild is reproducible and two builds never share one layout. The plan can be written out with `--rotation-report`. |
| **Deepen** | Pushes each format past its recorded cost budget: header rows, nesting depth, interface inventories, PCAP JSON, fuse sentinels, model JSON. |
| **Measure** | Runs REA probes against the build and diffes the result against the recorded budget. Deviation is reported, never assumed. |

Each layer has a spec with the exact limits it targets: [rotation](docs/AEGIS-ROTATION.md), [budgets](docs/AEGIS-BUDGETS.md), [measurement](docs/AEGIS-MEASUREMENT.md).

## Benchmark

`node dist/cli.js benchmark` runs the 14-target Counter-REA showcase and reports estimated REA reconstruction cost before and after AEGIS, at identical runtime behaviour:

| Target | Before (score / cost) | After (score / cost) | Token mult | Runtime |
| --- | --- | --- | --- | --- |
| DX-Ball Sound-Pan Calculation | 84/100, $0.20 | 2/100, $236.47 | 3150.8x | EXACT |
| Notion Electron Clipboard Bridge (.asar) | 98/100, $0.34 | 2/100, $358.64 | 2532.3x | EXACT |
| Enterprise License & Crypto Validator | 87/100, $0.20 | 2/100, $241.51 | 3220.8x | EXACT |
| WebAssembly Crypto Kernel (.wasm) | 81/100, $0.20 | 6/100, $30.23 | 381.5x | EXACT |
| Native ELF64 Rust/Go/Electron/Dart Binary | 81/100, $0.73 | 2/100, $60.03 | 105.6x | EXACT |
| Local SQLite Entitlement Database (.sqlite) | 81/100, $0.29 | 7/100, $28.39 | 162.1x | EXACT |
| Proprietary Edge AI Model (.safetensors) | 81/100, $0.20 | 6/100, $29.90 | 376.8x | EXACT |
| Android Dalvik Bytecode (classes.dex) | 81/100, $0.34 | 7/100, $45.13 | 313.4x | EXACT |
| Apple Bundle PropertyList (Info.plist) | 81/100, $0.26 | 9/100, $22.96 | 211.8x | EXACT |
| .NET Managed CLR Assembly (.dll) | 81/100, $0.34 | 6/100, $39.97 | 274.9x | EXACT |
| Erlang/OTP BEAM Module (.beam) | 81/100, $0.34 | 5/100, $62.08 | 433.2x | EXACT |
| EVM Contract Bytecode (Solidity metadata) | 81/100, $0.26 | 6/100, $29.40 | 276.3x | EXACT |
| libpcap Network Capture (.pcap) | 81/100, $0.20 | 8/100, $26.58 | 333.2x | EXACT |
| NVIDIA PTX Text Module (.ptx) | 81/100, $0.20 | 6/100, $39.56 | 504.0x | EXACT |

**Aggregate:** token 641.0x, cost 305.1x across all 14 targets (estimated reconstruction cost, Claude Opus 4 pricing). "Runtime: EXACT" means the protected artefact behaves identically to the original. These are AEGIS's own token-cost estimates, not a live LLM run — see [Measurement](#measurement) below for the empirical check against real REA probes.

## Requirements

- Node.js `^22.23.4` or `>=24.0.0` (REA red-team probes need `zlib.zstd*` on 22.23+)
- Optional: `wabt` and `tshark` on `PATH` for WASM and PCAP coverage

There is no global `aegis` binary to rely on. Use one of these two forms:

- `npx aegis-agents <command>` — published package
- `node dist/cli.js <command>` — local build

On Windows use `npm.cmd` for scripts, since `npm.ps1` is blocked by the default execution policy.

## Install

```bash
git clone https://github.com/perseusdredd/aegis.git
cd aegis
npm install
npm.cmd run build
```

## Usage

Register the MCP server and skill with your coding agent, then run the default one-command pass:

```bash
npx aegis-agents setup -y
npx aegis-agents harden .
# or tell your agent: "Harden my software against REA"
```

`harden` auto-discovers build outputs (`dist/`, `build/`, `.asar`, `.wasm`, `.sqlite`, `models/` ...) and runs `audit` -> `protect` -> `verify` at `bankrupt` intensity.

> On Windows PowerShell, `npx` may be blocked by script execution policy. Use `npx.cmd` instead (e.g. `npx.cmd aegis-agents setup -y`).

Step by step, when you know the target:

```bash
npx aegis-agents audit dist            # read-only exposure scan
node dist/cli.js protect dist          # inject shields (writes alongside, or --in-place)
node dist/cli.js verify dist           # check invariants survived
node dist/cli.js defend app.asar       # full pipeline in one call
node dist/cli.js measure app.wasm      # measure one artefact against REA
```

Report a rotation plan and the emitted manifest:

```bash
node dist/cli.js protect dist --intensity balanced --seed my-seed --rotation-report aegis-rotation/v1.json
node dist/cli.js protect dist --manifest --sign-manifest --manifest-key private.pem
node dist/cli.js verify-manifest dist/.aegis-manifest.json --public-key public.pem
```

Intensity presets: `stealth`, `balanced`, `maximum`, `bankrupt` (default for `harden`/`defend` is `bankrupt`, `protect` is `balanced`). `--fail-under <n>` turns a weak score into exit 2 for CI.

## Measurement

`measure` compares a protected artefact against the live REA probes:

```bash
node dist/cli.js measure dist/app.wasm --format wasm --json --out docs/measure
```

| Format | Budget target | Observed | Verdict |
| --- | --- | --- | --- |
| `go_buildinfo` | MAX_BUILD_INFO_BYTES | 2 ms | trip, 0 deviation |
| `erlang_beam` | max_chunks | 0 ms | trip, 0 deviation |
| `wasm_module` | WASM_INTERFACE_REPRESENTATION_BYTES | 6 ms | trip, 0 deviation |
| `javascript` | alias+getter+primitive byte budgets | 1108 ms | trip, 0 deviation |

Real run, 2026-11-07, AEGIS `8cd5447` against REA `c5301e6`: 13/13 formats measured, 0 remaining, 0 deviations, verdict pass, 4349 ms total. Full table in [docs/MEASURE-RESULT.md](docs/MEASURE-RESULT.md). See [docs/AEGIS-MEASUREMENT.md](docs/AEGIS-MEASUREMENT.md) for flags and report layout.


## Limits

- Draft shields (LLM directives, weave decoys, self-seal, sidecar entangle, Godot PCK, UnityFS, PyInstaller, device tree, ESP images) are opt-in and experimental; the newest five are wired into dispatch and tested on magic bytes only, not on real-world binaries.
- The measurement set is a fixed 13-format list, not a general REA score.
- Firmware, JADX/APK resign, GPU fatbins and Frida live sessions are designed for but not all wired end to end.
- Verify always runs after protect; a shield that breaks runtime is a regression, not a win.

## Tests

```bash
npm.cmd run build
npm.cmd test
```

Tests need the sibling `rea` checkout next to this repo; without it one test is skipped.

## License

MIT. AEGIS is a fork of BLA; the original BLA copyright line is retained in [LICENSE](LICENSE).
