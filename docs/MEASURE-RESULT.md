# Measurement result

Real run of `aegis measure` against the sibling REA checkout (output copied from the run, not edited).

- Date: 2026-11-07T14:51:42.527Z
- AEGIS commit: 8cd5447
- REA commit: c5301e6
- Node: v24.19.0, seed: aegis-redteam-empirical-v1
- Passed / remaining: 13 / 0 (selected 13, measured 13, skipped 0)
- Format coverage: 100.0%
- Duration: total 4349 ms, median 9 ms
- Budget deviations: 0 (overclaims 0, underclaims 0)
- Verdict: **pass**

| format | status | ms | REA budget tripped | AEGIS claimed trip | deviation |
|---|---|---|---|---|---|
| go_buildinfo | measured | 2 | MAX_BUILD_INFO_BYTES | true | 0 |
| flutter_pool | measured | 8 | MAX_POOL_URIS|MAX_POOL_TOKENS | no claim | n/a |
| erlang_beam | measured | 0 | max_chunks | true | 0 |
| evm_bytecode | measured | 3 | EVM_INTERFACE_LIMITS.inputBytes (approach) | true | 0 |
| pcap_capture | measured | 658 | TSHARK_JSON_MAX_BYTES | true | 0 |
| safetensors | measured | 9 | MODEL_JSON_NESTING | true | 0 |
| gguf | measured | 6 | MODEL_METADATA_NESTING | true | 0 |
| gpu_ptx | measured | 12 | GPU_REPORT_BYTES | no claim | n/a |
| electron_asar | measured | 19 | DEFAULT_ASAR_MAX_HEADER_BYTES | true | 0 |
| wasm_module | measured | 6 | WASM_INTERFACE_REPRESENTATION_BYTES | true | 0 |
| sqlite_db | measured | 16 | SqliteColumnEvaluationFailure | no claim | n/a |
| electron_fuses | measured | 2502 | ELECTRON_FUSE_LIMITS.maximumSentinelsPerSlice | true | 0 |
| javascript | measured | 1108 | alias-selections+getter-expansion+primitive-bytes+primitive-candidates | true | 0 |

## Notes

- 3 formats (flutter_pool, gpu_ptx, sqlite_db) carry no AEGIS trip claim, so no deviation is computed for them; REA did trip a budget on all three.
- An earlier run of the same command reported 7/13 measured and verdict inconclusive. Cause: the runner counted REA budget-trip errors as failed probes. Fixed in 8cd5447; the numbers above are from the fixed build.
- `--intensity` is recorded in the report but the sample matrix in scripts/redteam/lib/samples.mjs uses its own fixed intensity, so it does not change the samples.
