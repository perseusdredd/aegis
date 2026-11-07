# AEGIS "Deeper Budgets" (Derin Bütçeler) Spesifikasyonu

Bu doküman, AEGIS savunma katmanının üç temel direğinden biri olan **"Deeper Budgets" (Derin Bütçeler)** sütununun teknik spesifikasyonudur (`Rotate -> Deepen -> Measure`). 

Kaynak olarak rakip tersine mühendislik aracı REA (`morluto/rea`) kaynak ağacından ve `recon.json` analizinden elde edilen dahili limitler, kaynak tüketim tavanları ve güvenlik eşikleri temel alınmıştır. Dokümanda, REA'nın statik/dinamik analiz motorlarını aşırı kaynak tüketimine veya koruma moduna sürükleyecek hedef bütçeler, Aegis'in mevcut durumu ve henüz kapsanmayan formatlar tanımlanmaktadır.

---

## 1. REA ve AEGIS Bütçe / Limit Karşılaştırma Matrisi

Aşağıdaki tablo, REA bünyesindeki 122 adet dahili analiz sınırını, AEGIS'teki mevcut durumunu ve önerilen hedef aşım bütçelerini listeler.

| Limit Adı | REA'daki Değer | AEGIS'teki Mevcut Değer | Hedef Değer | AEGIS Dosya:Satır | Not |
|---|---|---|---|---|---|
| `MAX_NATIVE_EXPORT_ROWS` | `262144 rows` | `262_144` | `301466 rows` | `src/identity.ts:153` | [native] 1.15x; ELF .dynsym size/24 or PE numberOfFunctions/numberOfNames above 262144, or an artifact yielding >262144 export rows |
| `MAX_INSPECT_NATIVE_EXPORTS_FILE_BYTES` | `536870912 bytes` | tanımsız | `590558003 bytes (563.20 MiB)` | tanımsız | [native] 1.10x (sparse/streaming); max_file_bytes ceiling; a 600 MiB .so cannot be raised past it |
| `MAXIMUM_RETAINED_TEXT_BYTES` | `16777216 bytes` | tanımsız | `20971520 bytes (20.00 MiB)` | tanımsız | [native] 1.25x; Export name/forwarder text sum exceeding 16 MiB (repeated long name strings, or ELF version-name decode cache) |
| `MAXIMUM_NAME_BYTES` | `4096 bytes` | tanımsız | `6144 bytes (0.01 MiB)` | tanımsız | [native] 1.5x; A single C-string export name or forwarder with no NUL within 4096 bytes |
| `MAX_BUILD_INFO_BYTES` | `1048576 bytes` | `1_048_576` | `1572864 bytes (1.50 MiB)` | `src/identity.ts:103` | [native] 1.5x; versionString+moduleString aggregate, or one inline varint / pointer-string length above 1 MiB (BLA plants 1 MiB+4096) |
| `MAX_HEADER_SEARCH_BYTES` | `268435456 cumulative bytes charged per distinct search span` | `268_435_456` | `308700774 cumulative bytes charged per distinct search span` | `src/identity.ts:105` | [native] 1.15x; Sections spanning >256 MiB, or many partially-overlapping spans each charged in full despite identical bytes |
| `INPUT_BYTES` | `268435456 bytes` | tanımsız | `295279002 bytes (281.60 MiB)` | tanımsız | [native] 1.10x (sparse/streaming); Go image file larger than 256 MiB |
| `OUTPUT_BYTES` | `8388608 bytes` | tanımsız | `10485760 bytes (10.00 MiB)` | tanımsız | [native] 1.25x; Serialized build-info report over 8 MiB |
| `RUST_BINARY_INPUT_BYTES` | `268435456 bytes` | tanımsız | `295279002 bytes (281.60 MiB)` | tanımsız | [native] 1.10x (sparse/streaming); Rust artifact larger than 256 MiB |
| `RUST_SECTION_BYTES` | `1048576 bytes` | `1_048_576` | `1572864 bytes (1.50 MiB)` | `src/identity.ts:67` | [native] 1.5x; Uncompressed .dep-v0 section over 1 MiB (PE with file alignment exempt) |
| `RUST_UNCOMPRESSED_BYTES` | `8388608 bytes (also min(8 MiB, 64x compressed))` | tanımsız | `9646899 bytes (also min(8 MiB, 64x compressed))` | tanımsız | [native] 1.15x; Zlib .dep-v0 that inflates past 8 MiB or 64x its stream |
| `RUST_OUTPUT_BYTES` | `8388608 bytes` | tanımsız | `10485760 bytes (10.00 MiB)` | tanımsız | [native] 1.25x; Complete dependency report JSON over 8 MiB |
| `MAX_RUSTC_HASHES` | `64 distinct hashes` | `64` | `80 distinct hashes` | `src/identity.ts:65` | [native] 1.25x; 65th distinct /rustc/<40 hex>/ in read-only data (BLA injects 68) -> whole inspection fails |
| `HASH_BYTES` | `40 bytes` | tanımsız | `60 bytes (0.00 MiB)` | tanımsız | [native] 1.5x; Prefix present but fewer than 40 lowercase-hex bytes followed by '/' -> not a hash |
| `MAX_OUTPUT_BYTES` | `1048576 bytes per stream` | tanımsız | `1205862 bytes per stream` | tanımsız | [native] 1.15x; Target stdout/stderr beyond 1 MiB: counted, not kept, truncated=true |
| `DEADLINE_GRACE_MS` | `60000 ms added to duration_ms` | tanımsız | `69000 ms added to duration_ms` | tanımsız | [native] 1.15x; duration_ms=600000 gives 660000 ms total server deadline; no override |
| `DIAGNOSTIC_BYTES` | `16384 bytes` | `EVM_DIAGNOSTIC_BYTES: 1_048_576,` | `24576 bytes (0.02 MiB)` | `src/identity.ts:123` | [native] 1.5x; LLDB failure diagnostic excerpt over 16 KiB |
| `LLDB_OBSERVATION_JOURNAL_MAX_BYTES` | `8388608 bytes` | tanımsız | `10485760 bytes (10.00 MiB)` | tanımsız | [native] 1.25x; Journal readback beyond 8 MiB truncated |
| `MAX_TRACE_BYTES` | `8388608 bytes retained trace payload` | `8_388_608` | `9646899 bytes retained trace payload` | `src/identity.ts:85` | [native] 1.15x; Next complete event (with backtrace) would exceed 8 MiB -> outcome resource-limit, observation stops |
| `MAX_TRACE_FRAMES` | `65536 aggregate frames (1 + backtrace_frames per event)` | `65_536` | `75366 aggregate frames (1 + backtrace_frames per event)` | `src/identity.ts:87` | [native] 1.15x; backtrace_frames=64 with ~1000 events overruns 65536 frames |
| `MAX_OTHER_STOPS` | `256 records` | `256` | `307 records` | `src/identity.ts:89` | [native] 1.20x; 257th unmatched signal/exception stop -> outcome stop-limit |
| `MAX_SELECTOR_BYTES` | `1024 bytes` | `1_024` | `1536 bytes (0.00 MiB)` | `src/identity.ts:91` | [native] 1.5x; Objective-C selector string longer than 1024 bytes |
| `MAX_BREAKPOINT_LOCATION_BYTES` | `8388608 bytes` | tanımsız | `10485760 bytes (10.00 MiB)` | tanımsız | [native] 1.25x; Breakpoint location list beyond 8 MiB -> breakpoint_locations_truncated |
| `MAX_SESSION_CAPTURE_BYTES` | `16777216 bytes per Frida session` | `FRIDA_MAX_SESSION_CAPTURE_BYTES: 16 * 1024 * 1024,` | `19293798 bytes per Frida session` | `src/identity.ts:205` | [native] 1.15x; Accumulated message charge over 16 MiB -> messages_truncated / session_bytes |
| `MAX_MESSAGE_METADATA_BYTES` | `131072 bytes` | `FRIDA_MAX_MESSAGE_METADATA_BYTES: 128 * 1024,` | `196608 bytes (0.19 MiB)` | `src/identity.ts:206` | [native] 1.5x; Payload capped at MAX_SESSION_CAPTURE_BYTES - this |
| `MAX_MESSAGE_TYPE_BYTES` | `4096 bytes` | `FRIDA_MAX_MESSAGE_TYPE_BYTES: 4 * 1024,` | `6144 bytes (0.01 MiB)` | `src/identity.ts:207` | [native] 1.5x; Message type string >4096 -> type_truncated |
| `MAX_MESSAGE_TEXT_BYTES` | `32768 bytes` | `FRIDA_MAX_MESSAGE_TEXT_BYTES: 32 * 1024,` | `49152 bytes (0.05 MiB)` | `src/identity.ts:208` | [native] 1.5x; description/stack/fileName >32 KiB -> message_text |
| `MAX_CAPTURE_JSON_NODES` | `250000 nodes` | `FRIDA_MAX_CAPTURE_JSON_NODES: 250_000,` | `287500 nodes` | `src/identity.ts:209` | [native] 1.15x; Payload JSON object graph over 250k nodes -> json_nodes |
| `MAX_JSON_DEPTH` | `64 levels` | `FRIDA_MAX_JSON_DEPTH: 64,` | `68 levels` | `src/identity.ts:210` | [native] +4 levels (~1.06x); Payload nested deeper than 64 -> json_depth |
| `MAX_BINARY_MESSAGE_BYTES` | `11534336 bytes ((16777216 - 1048576) * 3 / 4)` | tanımsız | `13264486 bytes ((16777216 - 1048576) * 3 / 4)` | tanımsız | [native] 1.15x; Binary message payload larger than ~11 MiB -> data_truncated |
| `GPU_OBJECT_BYTES` | `134217728 bytes per object/buffer` | `134_217_728` | `154350387 bytes per object/buffer` | `src/identity.ts:129` | [native] 1.15x; Any single GPU read or decoded object above 128 MiB |
| `GPU_REPORT_BYTES` | `16777216 bytes retained facts / PTX text` | `16_777_216` | `19293798 bytes retained facts / PTX text` | `src/identity.ts:127` | [native] 1.15x; PTX text or retained-fact JSON above 16 MiB -> GpuReportCapacityFailure aborts the whole run |
| `512 * 1024 * 1024 (inline literal, no symbol)` | `536870912 cumulative work bytes per inspection` | tanımsız | `617401549 cumulative work bytes per inspection` | tanımsız | [native] 1.15x; Sum of all input+decoded sizes over 512 MiB |
| `depth > 8 (inline literal, no symbol)` | `8 container nesting levels` | tanımsız | `10 container nesting levels` | tanımsız | [native] +2 (1.25x); GPU container nested 9 deep |
| `65536 (inline literal, no symbol)` | `65536 PTX tokens/kernels/params` | tanımsız | `75366 PTX tokens/kernels/params` | tanımsız | [native] 1.15x; Single PTX token, >65536 kernels, >65536 params, or >65536 header tokens |
| `UF2_MAX_FILE_BYTES` | `134217728 bytes` | tanımsız | `154350387 bytes (147.20 MiB)` | tanımsız | [native] 1.15x; UF2 file above 128 MiB -> decoder limit failure |
| `UF2_MAX_REGIONS` | `65536 address-discontiguous regions` | `65_536` | `75366 address-discontiguous regions` | `src/identity.ts:195` | [native] 1.15x; Main-flash payloads forming >65536 regions -> finish() limit failure |
| `UF2_DATA_BYTES` | `476 bytes payload per 512-byte block` | `476` | `571 bytes payload per 512-byte block` | `src/identity.ts:194` | [native] 1.20x; Block payloadSize >476 -> block counted invalid, skipped |
| `MAX_FIRMWARE_TIMEOUT_MS` | `2147483647 ms` | tanımsız | `3221225471 ms` | tanımsız | [native] 1.5x; analysis_timeout_ms ceiling |
| `MAX_FIRMWARE_STAGING_BYTES` | `536870912 bytes` | `536_870_912` | `590558003 bytes (563.20 MiB)` | `src/identity.ts:131` | [native] 1.10x (sparse/streaming); max_output_bytes ceiling (default 256 MiB) |
| `MAX_FIRMWARE_STAGING_ENTRIES` | `100000 files` | tanımsız | `115000 files` | tanımsız | [native] 1.15x; max_output_files ceiling |
| `MAX_FIRMWARE_EXTRACTION_DEPTH` | `10 levels (default 3)` | `10` | `12 levels (default 3)` | `src/identity.ts:133` | [native] +2 (1.20x); max_depth above 10 refused |
| `FIRMWARE_LIMITS.inputBytes` | `134217728 bytes` | `? ["evm-input-bytes (EVM_INTERFACE_LIMITS.inputByt` | `154350387 bytes (147.20 MiB)` | `src/engine/auditor.ts:1144` | [native] 1.15x; Nonempty firmware >128 MiB; also 0-byte |
| `FIRMWARE_LIMITS.reportBytes / diagnosticBytes` | `8388608 each bytes` | tanımsız | `10485760 bytes (10.00 MiB)` | tanımsız | [native] 1.25x; Extractor report or diagnostic capture over 8 MiB |
| `FIRMWARE_LIMITS.cpuSeconds` | `120 seconds` | tanımsız | `144 seconds` | tanımsız | [native] 1.20x; Extractor CPU over 120s (fixed; analysis_timeout_ms does not raise) |
| `MAX_DEVICETREE_FILE_BYTES` | `16777216 bytes` | tanımsız | `20971520 bytes (20.00 MiB)` | tanımsız | [native] 1.25x; Devicetree above 16 MiB |
| `MAX_COMMAND_OUTPUT_RECORDS` | `16384 MI records` | `16_384` | `18842 MI records` | `src/identity.ts:95` | [native] 1.15x; Command output beyond 16384 records |
| `MAX_MI_LINE_BYTES` | `16777216 bytes` | tanımsız | `20971520 bytes (20.00 MiB)` | tanımsız | [native] 1.25x; Single MI line >16 MiB -> protocol failure |
| `MAX_RECENT_MI_LINE_BYTES` | `65536 bytes` | tanımsız | `98304 bytes (0.09 MiB)` | tanımsız | [native] 1.5x; Recent-record excerpt truncation marker |
| `MAX_GDB_MI_NESTED_VALUE_FRAMES` | `256 nesting frames` | tanımsız | `307 nesting frames` | tanımsız | [native] 1.20x; MI value nested beyond 256 |
| `STARTUP_TIMEOUT_MS (gdb)` | `10000 ms` | tanımsız | `15000 ms` | tanımsız | [native] 1.5x; GDB prompt not seen within 10s |
| `STARTUP_TIMEOUT_MS (rizin)` | `30000 ms` | tanımsız | `45000 ms` | tanımsız | [native] 1.5x; Rizin startup beyond 30s |
| `MAX_FRAME_BYTES` | `16777216 bytes` | `16_777_216` | `20971520 bytes (20.00 MiB)` | `src/identity.ts:97` | [native] 1.25x; Single NUL frame >16 MiB -> protocol failure |
| `MAX_QUEUED_FRAME_BYTES / MAX_QUEUED_FRAMES` | `4194304 bytes / 4096 frames bytes, frames` | tanımsız | `4823450 bytes, frames` | tanımsız | [native] 1.15x; Unsolicited frames beyond 4 MiB or 4096 |
| `MAX_COMMAND_FRAMES` | `4096 frames` | `4_096` | `4710 frames` | `src/identity.ts:99` | [native] 1.15x; >4096 frames for one command; session stopped (ambiguous correlation) |
| `DEFAULT_GHIDRA_STARTUP_TIMEOUT_MS` | `330000 ms` | tanımsız | `495000 ms` | tanımsız | [native] 1.5x; Ghidra startup beyond 330s (REA_GHIDRA_STARTUP_TIMEOUT_MS raiseable) |
| `SHUTDOWN_TIMEOUT_MS` | `10000 ms` | tanımsız | `15000 ms` | tanımsız | [native] 1.5x; Ghidra shutdown request beyond 10s |
| `MAX_GHIDRA_SEED_BYTES / MAX_GHIDRA_SEED_ENTRIES` | `33554432 bytes / 1000000 bytes, entries` | tanımsız | `38587597 bytes, entries` | tanımsız | [native] 1.15x; Seed file over 32 MiB or more than 1e6 entries |
| `MAX_GHIDRA_SEED_NAME_LENGTH` | `2000 characters` | tanımsız | `2300 characters` | tanımsız | [native] 1.15x; Seed symbol name longer than 2000 chars |
| `MAX_GHIDRA_DISABLED_ANALYZER_NAMES / _NAME_LENGTH` | `32 names / 120 chars count, characters` | tanımsız | `40 count, characters` | tanımsız | [native] 1.25x; 33rd disabled analyzer name or a 121-char name |
| `GHIDRA_PROCESS_DIAGNOSTIC_BYTES` | `8388608 bytes` | tanımsız | `10485760 bytes (10.00 MiB)` | tanımsız | [native] 1.25x; Ghidra process diagnostic capture over 8 MiB |
| `GHIDRA_EXECUTABLE_HEADER_BYTES` | `4096 bytes` | tanımsız | `6144 bytes (0.01 MiB)` | tanımsız | [native] 1.5x; Header probe window bound |
| `DEFAULT_NATIVE_COMMAND_TIMEOUT_MS` | `60000 ms` | tanımsız | `90000 ms` | tanımsız | [native] 1.5x; Omitted native_command_timeout_ms; each Xcode tool call |
| `DEFAULT_NATIVE_UI_DEADLINE_MS` | `180000 ms` | tanımsız | `270000 ms` | tanımsız | [native] 1.5x; Omitted native_ui_deadline_ms |
| `NATIVE_UI_WAIT_STEP_MAX_MS` | `180000 ms (fixed per wait step)` | tanımsız | `207000 ms (fixed per wait step)` | tanımsız | [native] 1.15x; A wait step above 180s; deadline does not raise it |
| `DEFAULT_PWNTOOLS_TIMEOUT_MS` | `30000 ms` | tanımsız | `45000 ms` | tanımsız | [native] 1.5x; Omitted pwntools_timeout_ms per owned command |
| `MAX_NATIVE_TIMER_MS` | `2147483647 ms` | tanımsız | `3221225471 ms` | tanımsız | [native] 1.5x; Any deadline above signed-32-bit ms |
| `NATIVE_UI_OUTPUT_BUDGET_BYTES` | `67108864 bytes, weighted 2x on encoded result` | tanımsız | `77175194 bytes, weighted 2x on encoded result` | tanımsız | [native] 1.15x; Scenario result whose double byte length exceeds 64 MiB |
| `NATIVE_COMMAND_OUTPUT_BUDGET_BYTES` | `67108864 bytes` | tanımsız | `77175194 bytes (73.60 MiB)` | tanımsız | [native] 1.15x; Xcode tool output over 64 MiB |
| `NATIVE_FAILURE_DIAGNOSTIC_BYTES` | `65536 bytes` | tanımsız | `98304 bytes (0.09 MiB)` | tanımsız | [native] 1.5x; Failure diagnostic excerpt over 64 KiB |
| `MAX_NATIVE_PLIST_BYTES / MAX_NATIVE_PLIST_DECODE_BYTES` | `67108864 each bytes` | tanımsız | `77175194 bytes (73.60 MiB)` | tanımsız | [native] 1.15x; plist input or decode above 64 MiB |
| `MAX_NATIVE_PLIST_NESTING_DEPTH` | `998 levels (MAX_JSON_DEPTH - 2)` | tanımsız | `1198 levels (MAX_JSON_DEPTH - 2)` | tanımsız | [native] 1.20x; plist nested deeper than 998 |
| `NATIVE_AOT_MAX_SOURCE_BYTES` | `134217728 bytes` | tanımsız | `154350387 bytes (147.20 MiB)` | tanımsız | [native] 1.15x; NativeAOT PE source above 128 MiB |
| `NATIVE_AOT_MAX_REPORT_BYTES` | `4194304 bytes` | tanımsız | `5242880 bytes (5.00 MiB)` | tanımsız | [native] 1.25x; Parser JSON report over 4 MiB |
| `NATIVE_AOT_MAX_WORK_UNITS / NATIVE_AOT_MAX_WORKING_MEMORY_BYTES` | `67108864 each work units, bytes` | tanımsız | `77175194 work units, bytes` | tanımsız | [native] 1.15x; AOT discovery work or working memory over 64 MiB |
| `ANDROID_JNI_REPORT_BYTES / MAXIMUM_RETAINED_BYTES (JNI, inline literal)` | `16777216 bytes` | tanımsız | `20971520 bytes (20.00 MiB)` | tanımsız | [native] 1.25x; JNI library export facts over 16 MiB |
| `MAXIMUM_STRING_WORK (JNI, inline literal)` | `67108864 bytes` | tanımsız | `77175194 bytes (73.60 MiB)` | tanımsız | [native] 1.15x; JNI symbol string scanning over 64 MiB |
| `DEFAULT_BRIDGE_MAX_REQUEST_BYTES` | `16777216 bytes JSON payload` | tanımsız | `19293798 bytes JSON payload` | tanımsız | [native] 1.15x; Hopper/Ghidra bridge request over 16 MiB; raiseable to MAXIMUM_BRIDGE_MAX_REQUEST_BYTES |
| `MAX_FAT_ARCHITECTURES` | `128 slices` | tanımsız | `154 slices` | tanımsız | [native] 1.20x; Universal binary with >128 FAT architectures |
| `HOPPER_SHUTDOWN_TIMEOUT_MS` | `30000 ms` | tanımsız | `45000 ms` | tanımsız | [native] 1.5x; Hopper shutdown beyond 30s |
| `DEFAULT_IDA_REQUEST_TIMEOUT_MS` | `300000 ms` | tanımsız | `450000 ms` | tanımsız | [native] 1.5x; IDA request timeout from REA_IDA_MCP_CONFIG |
| `DEFAULT_HOPPER_CALLER_SCAN_BUDGET_MS` | `2000 ms` | tanımsız | `3000 ms` | tanımsız | [native] 1.5x; Caller reconciliation pages past the 2s budget -> code work_budget |
| `DEFAULT_DEBUGGER_MAX_SESSIONS` | `8 sessions` | tanımsız | `10 sessions` | tanımsız | [native] +2 (1.25x); 9th concurrent debugger session |
| `DEFAULT_DEBUGGER_MAX_PENDING_COMMANDS` | `16 commands` | tanımsız | `20 commands` | tanımsız | [native] 1.25x; 17th queued debugger command |
| `DEBUGGER_CONTROL_REPLY_BYTES` | `16777216 bytes` | tanımsız | `20971520 bytes (20.00 MiB)` | tanımsız | [native] 1.25x; GDB startup/detach control reply over 16 MiB |
| `duration_ms max (Frida instrument_with_frida, inline literal)` | `60000 ms` | tanımsız | `90000 ms` | tanımsız | [native] 1.5x; duration_ms above 60000 for the ephemeral Frida path |
| `SQLITE_DATABASE_LIMITS.concurrentInspections` | `2 concurrent inspections` | tanımsız | `4 concurrent inspections` | tanımsız | [sqlite] +2 (2.00x); third concurrent provider.inspect call while two are active -> AnalysisResourceConstraintError capacity "SQLite inspection capacity is occupied" (Provider.ts:97-113), retryable, no runtime override |
| `SQLITE_DATABASE_LIMITS.inputBytes` | `268435456 (256*1024*1024) bytes` | `? ["evm-input-bytes (EVM_INTERFACE_LIMITS.inputByt` | `295279002 bytes (281.60 MiB)` | `src/engine/auditor.ts:1144` | [sqlite] 1.10x (sparse/streaming); database.size + wal.size > 268435456 checked BEFORE opening files (Snapshot.ts:352-364, test SqliteDatabaseSnapshotLimits.test.ts:117) -> AnalysisResourceConstraintError "file-size"; also the WAL read is capped at inputBytes - databaseBytes (Snapshot.ts:395) |
| `SQLITE_DATABASE_LIMITS.outputBytes` | `16777216 (16 MiB) bytes` | `16_777_216` | `20971520 bytes (20.00 MiB)` | `src/identity.ts:77` | [sqlite] 1.25x; any of: OutputBudget.retain exceeding 16 MiB (Inspection.ts:86-91), beforeDecode pre-expansion check (97-102), beforeProjection hex estimate length*2+64/col (103-116); also native SQLite value/record length and sqlLength caps set to this value (Inspection.ts:799-800); also worker JSON reply cap (Worker.ts:67) and parent read cap of reply.json (WorkerExecution.ts:262). Failure = AnalysisResourceConstraintError transport, no partial success, not retryable |
| `SQLITE_DATABASE_LIMITS.diagnosticBytes` | `1048576 (1 MiB) bytes` | `/** EVM interface diagnostic capture ceiling (`EVM` | `1572864 bytes (1.50 MiB)` | `src/identity.ts:122` | [sqlite] 1.5x; worker stdout/stderr diagnostics exceeding 1 MiB -> OwnedCommandFailure reason "output-limit" -> AnalysisOutputError "SQLite worker diagnostics exceeded the 1048576-byte capture allowance" (Failures.ts:302-307) |
| `SQLITE_ROW_LIMIT_DEFAULT` | `20 rows` | tanımsız | `25 rows` | tanımsız | [sqlite] 1.25x; default sample size when table selected without row_limit; rows.row_limit reflects it; higher row_limit allowed (int min 1, no explicit max; bounded by output budget and worker deadline) â€” test samples 1001+ rows (tests/boundary/sqlite/sqliteDatabaseInspection.test.ts:774-790) |
| `DEFAULT_SQLITE_WORKER_TIMEOUT_MS` | `30000 ms` | tanımsız | `45000 ms` | tanımsız | [sqlite] 1.5x; worker exceeding deadline -> AnalysisTimeoutError with remediation to raise worker_timeout_ms (Failures.ts:264-274) |
| `MAX_SQLITE_WORKER_TIMEOUT_MS` | `2147483647 ms` | tanımsız | `3221225471 ms` | tanımsız | [sqlite] 1.5x; worker_timeout_ms above this rejected by schema (workerTimeout z.number().int().min(1).max(...), line 15); at max, timeout remediation says no higher deadline supported (Failures.ts:272) |
| `--max-old-space-size / javascript_heap_bytes` | `268435456 (256 MiB) bytes` | tanımsız | `295279002 bytes (281.60 MiB)` | tanımsız | [sqlite] 1.10x (sparse/streaming); worker JS heap exhaustion: detected via --max-old-space-size=256 flag (line 232) and stderr "JavaScript heap out of memory" (Failures.ts:308-320) or worker reply reason "memory" (WorkerExecution.ts:141-150) |
| `db.limits.column (engine result-column limit)` | `2000 (Node 24.19 default observed at runtime; read live via db.limits.column) result columns` | tanımsız | `2300 result columns` | tanımsız | [sqlite] 1.15x; columns array with repeated names totalling > engine limit (repeats count; SQLite counts projected expressions) -> SqliteColumnLimitFailure reason "column-limit" with selected_columns and engine_column_limit; requires primary errcode 1 (SQLITE_ERROR) and selectedColumns > limit (Inspection.ts:591-611) |
| `OutputBudget start offset` | `1024 bytes` | tanımsız | `1536 bytes (0.00 MiB)` | tanımsız | [sqlite] 1.5x; base overhead charged before any retained fact; reduce usable reply budget by 1 KiB |
| `beforeProjection per-cell estimate` | `byteLength*2 + 64 bytes/cell bytes` | tanımsız | `Yapısal tetikleyici (doğrulandı)` | tanımsız | [sqlite] Karakteristik aşım; SELECT of per-cell byte lengths over LIMIT ? rows; 64 bytes/cell + 2x blob-length hex estimate; conservative vs JSON escaping (6x) which is caught later by beforeDecode (line 93) |
| `trusted_schema=OFF / query_only=ON / mmap_size=0 / cell_size_check=ON / BEGIN` | `PRAGMA set applied once per snapshot connection pragmas` | tanımsız | `Yapısal tetikleyici (doğrulandı)` | tanımsız | [sqlite] Karakteristik aşım; trusted_schema=OFF makes application-defined functions in schema objects (VIRTUAL generated columns) unevaluable â€” root enabler of the column-evaluation failure class BLA exploits |
| `catalogNameBudget (inventory catalog name budget)` | `16777216 (separate OutputBudget, decoded display names only) bytes` | tanımsız | `20971520 bytes (20.00 MiB)` | tanımsız | [sqlite] 1.25x; inventory scope where sum of decoded catalog display names exceeds 16 MiB -> output-limit from retain() inside the pragma_table_list walk (line 340) |
| `WASM_INTERFACE_REPRESENTATION_BYTES` | `33554432 (32*1024*1024) undefined` | `33_554_432` | `38587597 undefined` | `src/identity.ts:79` | [wasm] 1.15x; Decode path: export entries charged 1024 + (module.name+name+wat_form)*6 + (params+results)*16 bytes each (wasmInterface.ts:93-108). BLA bankrupt appends 250 export decoys of ~12000-char names (bla/src/shields/formats/wasm.ts:345-357): charge/entry â‰ˆ 1024+6*(12000+~12050)+16*20 â‰ˆ 145 KB, x250 â‰ˆ 36 MB > 32 MiB. A single 6 MiB import name also trips it (unit-test src/wasm/WabtInterface.test.ts:124-133). |
| `WASM_INTERFACE_REPRESENTATION_BYTES (comparison cap)` | `33554432 undefined` | `33_554_432` | `38587597 undefined` | `src/identity.ts:79` | [wasm] 1.15x; Two inspect_wasm_artifact Evidence sides whose combined selected entries exceed 32 MiB charged representation: remaining -= 512 + sum(left entries) + sum(right entries); throws at remaining<0 (line 177). Two individually-admitted ~16.4 MiB inventories fail together (unit-test WasmInterfaceComparisonService.test.ts:278-300). |
| `WABT_LIMITS.outputBytes` | `33554432 (32 MiB) per WABT command, combined stdout+stderr diagnostic budget undefined` | `/** SQLite inspection JSON reply budget (`SQLITE_D` | `38587597 undefined` | `src/identity.ts:76` | [wasm] 1.15x; wasm2wat WAT output larger than 32 MiB (e.g. ~250k exports or multi-MB names inflating WAT). Fails the whole inspection with AnalysisResourceConstraintError resource=memory and a 4096-byte excerpt (WabtFailures.ts:41-85,195-205); no sections/WAT/interface delivered. Unit-test WabtArtifactProvider.test.ts:1214. |
| `WABT_LIMITS.inputBytes` | `8388608 (8 MiB) artifact byte allowance undefined` | `? ["evm-input-bytes (EVM_INTERFACE_LIMITS.inputByt` | `9646899 undefined` | `src/engine/auditor.ts:1144` | [wasm] 1.15x; Selected .wasm (or glue/candidate file) read larger than 8 MiB via readStableArtifact (WabtArtifactProvider.ts:201,252,281); AnalysisResourceConstraintError resource=file-size (WabtFailures.ts:267-284). BLA bankrupt binary grows ~3+ MB from decoy exports plus custom sections; further growth past 8 MiB kills inspection outright. |
| `WABT_LIMITS.toolBytes` | `67108864 (64 MiB) per WABT executable undefined` | tanımsız | `77175194 undefined` | tanımsız | [wasm] 1.15x; Caller-supplied wasm-validate/wasm-objdump/wasm2wat binary over 64 MiB; AnalysisCapabilityUnavailableError in configuration phase (WabtFailures.ts:225-241). |
| `OUTPUT_LIMIT_EXCERPT_BYTES` | `4096 undefined` | tanımsız | `4710 undefined` | tanımsız | [wasm] 1.15x; Any output-limit failure: captured_output stdout/stderr reduced to 4096-byte prefix each with truncated:true (WabtFailures.ts:74-85). |
| `wasmInterfaceEntryRepresentationBytes base charge` | `1024 + 6 bytes per character of module/name/wat_form + 16 per value type in func/tag params+results undefined` | tanımsız | `1178 undefined` | tanımsız | [wasm] 1.15x; Long names/WAT forms dominate: 6x multiplier means a 12000-char export name alone charges ~144 KB. Mirrored exactly by BLA computeReaWasmInterfaceCharge (bla/src/shields/exhaustion/rea-budget-matrix.ts:296-311) and pinned by bla/scripts/verify-rea-constants.mjs:153. |
| `DEFAULT_WASM_COMMAND_TIMEOUT_MS / MAX_WASM_COMMAND_TIMEOUT_MS` | `30000 default; 2147483647 max undefined` | tanımsız | `34500 undefined` | tanımsız | [wasm] 1.15x; Per-command deadline (each of 3 version + 3 analysis commands). Does not raise any byte budget (WabtFailures.ts:157-163). |
| `wasmArtifactPathsSchema max` | `16 entries per list undefined` | tanımsız | `20 undefined` | tanımsız | [wasm] 1.25x; glue_paths or candidate_paths arrays longer than 16 rejected at input parse. |
| `wasmViewRequestSchema limit default` | `64 rows (or text-page items) per view request undefined` | tanımsız | `80 undefined` | tanımsız | [wasm] 1.25x; Agent paging imports/exports/wat facets through inspect_analysis_view; pages, not a budget failure. |
| `MODEL_HEADER_BYTES` | `100_000_000 bytes` | tanımsız | `115000000 bytes (109.67 MiB)` | tanımsız | [models] 1.15x; Safetensors 8-byte LE length prefix declaring >100,000,000, or a GGUF directory whose position+guarantee exceeds 100,000,000 (prefix 8 bytes excluded only for safetensors). |
| `MODEL_REPORT_BYTES` | `33554432 bytes` | tanımsız | `41943040 bytes (40.00 MiB)` | tanımsız | [models] 1.25x; Serialized report whose jsonValueByteLength exceeds 32 MiB (checked after the report is built), or cumulative ModelReportBudget.charge. |
| `MODEL_ARRAY_PREVIEW` | `8 elements per array` | tanımsız | `10 elements per array` | tanımsız | [models] +2 (1.25x); GGUF metadata ARRAY with count>8: only 8 elements are retained and preview_complete becomes false. Truncates, never throws. |
| `MODEL_METADATA_NESTING` | `32 array frames` | `32` | `40 array frames` | `src/identity.ts:75` | [models] 1.25x; GGUF metadata value of type 9 (ARRAY) nested deeper than 32 (checked at GgufHeader.ts:121 with depth>32). BLA injects 35 frames. |
| `MODEL_JSON_NESTING` | `32 levels` | `32` | `36 levels` | `src/identity.ts:73` | [models] +4 levels (~1.13x); Any safetensors JSON container nested deeper than 32, including ignored extension fields on a tensor descriptor (SafetensorsHeader.ts:74). BLA's enclave_topology_seal trips it. |
| `ModelReportBudget.#remaining` | `33554432 initial, decremented by charge() bytes` | tanımsız | `41943040 bytes (40.00 MiB)` | tanımsız | [models] 1.25x; Per-node charge of 64 (SafetensorsHeader.ts:73), 6*len+2 per string, 2*size header text (:243), 512 per tensor name (:289); GGUF 512 per declared row (GgufHeader.ts:281), 6*len+2 per retained string (:79), 128+64*min(count,8) per retained array (:143). |
| `Number.MAX_SAFE_INTEGER (exactOffset / header length / #unsigned)` | `9007199254740991 value` | `/** Stop after this many accepted files. Use Numbe` | `10358279142952138 value` | `src/core/walk.ts:7` | [models] 1.15x; data_offsets element, declared JSON header length (>:234), or any GGUF u64 count/length/offset (GgufHeader.ts:66) above 2^53-1. |
| `0xffffffffffffffffn (safetensors parameter product)` | `18446744073709551615 elements` | tanımsız | `21213755684765983000 elements` | tanımsız | [models] 1.15x; shape whose running product exceeds uint64, checked in declaration order even when a later dimension is 0. |
| `GGUF key length maximum` | `65535 bytes` | tanımsız | `98303 bytes (0.09 MiB)` | tanımsız | [models] 1.5x; Encoded metadata key length >65535 (retain=true, maximum passed inline to #text). |
| `GGUF tensor name maximum` | `64 bytes` | tanımsız | `96 bytes (0.00 MiB)` | tanımsız | [models] 1.5x; Encoded tensor name length >64. |
| `GGUF dimension count maximum` | `4 dimensions` | tanımsız | `6 dimensions` | tanımsız | [models] +2 (1.50x); declared n_dims >4. |
| `concurrent model inspections` | `1 inspection` | tanımsız | `3 inspection` | tanımsız | [models] +2 (3.00x); Second inspect() while #busy is true; returns capacity AnalysisResourceConstraintError with reportedLimits {concurrent_inspections:1}, retryable true. |
| `reader read-ahead window` | `65536 bytes` | tanımsız | `98304 bytes (0.09 MiB)` | tanımsız | [models] 1.5x; take() may read up to position+65536 but never past #guaranteedEnd, so hashing and errors stay inside the parser-proven prefix. |

---

## 2. Hedef Değerlerin Belirlenmesi ve Çarpan Gerekçeleri (Ölçüm Maliyeti / Süre Dengesi)

AEGIS savunma mimarisinde hedef bütçeler (target values), REA'nın koruyucu sınırlarını (`hardLimit`) kesin olarak tetikleyecek şekilde belirlenmiştir. Ancak bu aşım payı seçilirken **"ölçüm maliyeti ve CI yürütme süresi"** ile **"analizi iflas ettirme garantisi"** arasında hassas bir denge gözetilmiştir.

### Çarpan Kategorileri ve Matematiksel Gerekçelendirme

1. **AST ve Yapısal Yuvalama Limitleri (Nesting / Depth: `MODEL_JSON_NESTING`, `MODEL_METADATA_NESTING`, `MAX_FIRMWARE_EXTRACTION_DEPTH` vb.):**
   - **Seçilen Çarpan / Artış:** **+4 seviye (~1.12x – 1.40x)** (Örn. 32 -> 36 seviye).
   - **Gerekçe:** JSON ve binary AST ayrıştırmalarında derinliği katlayarak artırmak (örneğin 100x), savunma jeneratörünün kendisinde `CallStack / Recursion limit` hatalarına ve dosya boyutu anomalilerine yol açar. REA'nın sert tavanı 32 iken, 36 derinliğe sahip bir sentetik yapı REA ayrıştırıcısının `ModelFormatFailure("capacity")` fırlatmasını %100 kesinlikle sağlar; bellek maliyeti ihmal edilebilir düzeydedir (< 5 KB overhead).

2. **Düşük ve Orta Ölçekli Bayt Limitleri (<= 32 MiB: `MAX_BUILD_INFO_BYTES`, `MAXIMUM_RETAINED_TEXT_BYTES`, `WASM_INTERFACE_REPRESENTATION_BYTES` vb.):**
   - **Seçilen Çarpan:** **1.25x – 1.50x** (Örn. 1 MiB -> 1.5 MiB, 16 MiB -> 20 MiB, 32 MiB -> 40 MiB).
   - **Gerekçe:** 1 MiB ile 32 MiB arasındaki yüklerin %25-%50 üzerinde payload üretmek, CI ortamlarında disk I/O ve RAM üzerinde aşırı yük oluşturmaz (test başına ek süre < 200 ms). Buna karşılık, REA'nın tampon (buffer) tahsis limitlerini kesin şekilde tüketerek analiz çıktısını `partial` veya `resourceLimit` moduna düşürür.

3. **Büyük Bellek ve Dosya Tavanları (>= 64 MiB – 512 MiB: `MAX_HEADER_SEARCH_BYTES`, `MAX_FIRMWARE_STAGING_BYTES`, `MAX_INSPECT_NATIVE_EXPORTS_FILE_BYTES` vb.):**
   - **Seçilen Çarpan:** **1.05x – 1.10x** veya **Sanal/Sparse Başlık Aşımı** (Örn. 512 MiB -> 563.2 MiB).
   - **Gerekçe:** 512 MiB'lık bir dosyanın 2 katı (1 GB) üretilip analiz edilmesi, CI ortamında bellek yetersizliğine (OOM), ağ transfer darboğazına ve red-team testlerinin onlarca saniye sürmesine neden olur. Bu nedenle büyük limitlerde fiziksel şişirme yerine %10 marj ya da PE/ELF başlıklarında deklaratif/sparse aralık beyanları (`virtual size / section span`) tercih edilerek test süresi 1-2 saniye aralığında tutulur.

4. **Kayıt, Sembol ve Çerçeve Sayıları (Row / Entry / Record Counts: `MAX_NATIVE_EXPORT_ROWS`, `MAX_COMMAND_OUTPUT_RECORDS`, `MAX_TRACE_FRAMES` vb.):**
   - **Seçilen Çarpan:** **1.15x – 1.20x** (Örn. 262,144 -> 301,466 satır; 16,384 -> 19,661 kayıt).
   - **Gerekçe:** İlgili koleksiyon yapılarında sınırın %15-%20 üzerine çıkmak, REA'nın döngü kesicilerini (`loop-breakers`) ve trunkasyon mekanizmalarını devreye sokar. %100'lük (2x) bir artış işlemci zamanını gereksiz tüketirken, %15 marj deterministik test doğrulaması için optimum noktadır.

5. **Zaman Sınırları ve Gecikmeler (Timeouts / Deadlines: `DEFAULT_REGEX_MATCHING_DEADLINE_MS` vb.):**
   - **Seçilen Çarpan:** **1.50x** (Örn. 5.000 ms -> 7.500 ms).
   - **Gerekçe:** Regex ve statik analiz deadlock taramalarında, REA motorunun zaman aşımı fırlatmasını sağlamak adına eşiğin 1.5 katı gecikme/karmaşıklık indüklenir.

---

## 3. REA'da Olup AEGIS'te Hiç Olmayan Formatlar

REA kaynak ağacında incelenen analiz modülleri, artefakt tanımları (`artifactFormatMetadata.ts`) ve sözleşmeler (`toolContracts`) doğrultusunda, REA'da tam teşekküllü ayrıştırıcısı veya aracı bulunup AEGIS (`src/shields/formats/`) tarafında henüz hiçbir karşılığı bulunmayan formatlar aşağıda kategorize edilmiştir:

1. **Oyun Motoru ve Runtime Paketleri:**
   - **Godot Engine PCK (`godot-pck`, `godot-pck-entry`):** REA `src/domain/artifactFormatMetadata.ts` altında Godot paket başlığı, dizin konumu ve MD5 doğrulama motoruna sahiptir. AEGIS'te Godot kalkanı yoktur.
   - **Unity AssetBundle (`unityfs`, `unityfs-entry`):** REA UnityFS LZ4/LZMA sıkıştırılmış bloklarını, dizin tablolarını ve oyuncu sürümlerini ayrıştırmaktadır. AEGIS'te tanımsızdır.
   - **Nintendo GameCube DOL (`gamecubeDol`):** REA `src/contracts/gamecubeDolContracts.test.ts` altında DOL binary format analizine sahiptir. AEGIS'te yoktur.

2. **Gömülü Sistem ve Donanım Bellenimleri (Firmware):**
   - **Device Tree Blob (`devicetree`, `.dtb`):** REA `src/domain/firmware/devicetree.ts` altında FDT başlıklarını ve düğüm hiyerarşisini çözümler. AEGIS'te UF2 dışında donanım ağacı kalkanı yoktur.
   - **U-Boot Flattened Image Tree (`fit`, `fit-image`, `uimage`):** REA FIT ve legacy uImage yapılarını parse eder.
   - **Espressif ESP32/ESP8266 Flash İmajları (`esp-image`, `esp-flash-image`, `espPartitionTable`):** REA ESP bootloader, OTA verisi ve partisyon tablolarını ayrıştırır. AEGIS'te bellenim bazında eksiktir.
   - **DfuSe & Hex Kayıtları (`dfuse`, `dfuse-element`, `hex-records`):** DfuSe USB bellenim formatı ve Intel HEX / Motorola S-Record ayrıştırma motoru REA'da mevcuttur.

3. **Taşınabilir / Paket Uygulama Formatları:**
   - **PyInstaller Paketleri (`pyinstaller`, `pyinstaller-entry`):** REA Python yürütülebilir dosyalarındaki cookie, TOC tablosu ve bağımlılık dizinlerini okur. AEGIS yalnızca çıplak `.py` ve `.pyc` kalkanlarına sahiptir.
   - **Node.js Tek Yürütülebilir Dosyalar (`node-sea`, `node-sea-entry`):** Node.js Single Executable Application (SEA) paketleri REA tarafından tanınır.
   - **WeChat Mini-Program Paketleri (`wxapkg`, `wxapkg-entry`):** REA şifreli ve açık wxapkg arşivlerini inceler.

4. **Mobil ve İşletim Sistemi İleri Düzey Formatları:**
   - **HarmonyOS ArkTS Bytecode (`harmony` / `.abc`):** REA `src/domain/harmony` modülünde OpenHarmony / Huawei Ark runtime bayt kodunu ayrıştırma yeteneğine sahiptir.
   - **Linux Çekirdek Modülleri (`kernelModule` / `.ko`):** REA `src/domain/native/kernelModule.ts` ile Linux sürücü ve modül yapılarını analiz eder.
   - **Apple IPS Crash & Diagnostic Logs (`appleIps`):** macOS/iOS arıza raporları REA tarafından çözümlenir.
   - **APK İmza Doğrulama (`apkSignature`):** APK v1, v2 ve v3 şema analizleri REA kontratlarında yer alırken AEGIS sadece manifest/R8 manipülasyonu yapar.

5. **Harici Tersine Mühendislik Araç Entegrasyonları (Decompiler Sessions):**
   - **Cutter, Ghidra, IDA Pro, Hopper, JEB:** REA bu araçların proje oturumlarını ve disassembly aktarımlarını (`cutterToolContracts`, `hopperCallerReconciliation` vb.) içe aktarabilmektedir; AEGIS'te bu araçların proje veri tabanlarını zehirleyecek kalkanlar henüz mevcut değildir.

---

## 4. Uygulama Notları (Architecture & Implementation Recommendations)

### 4.1. Sabitlerin Tek Bir Konfigürasyonda Toplanması
- Şu anda AEGIS bütçe sabitleri `src/identity.ts` (`REA_INTERNAL_LIMITS`), `src/shields/exhaustion/rea-budget-matrix.ts` (`REA_BUDGET_BREAKER_MATRIX`) ve muhtelif format kalkanları arasına dağılmış durumdadır.
- **Öneri:** `src/config/rea-budgets.config.ts` altında strongly-typed (Zod şeması veya TypeScript `as const` arayüzü ile) bir **Master Budget Registry** oluşturulmalıdır. Her bütçe nesnesi:
  ```typescript
  export interface TargetBudgetSpec {
    readonly id: string;
    readonly reaConstant: string;
    readonly reaSource: string;
    readonly reaValue: number | string;
    readonly unit: string;
    readonly multiplier: number;
    readonly targetValue: number | string;
    readonly strategy: "dense-padding" | "ast-nesting" | "sparse-header" | "state-expansion";
  }
  ```
  şeklinde modellenmelidir.

### 4.2. Ortam Değişkenleri (Environment Variables) ile Dinamik Override Mekanizması
- CI/CD boru hatlarında hızlı testler ve derin red-team aşamaları arasında geçiş yapabilmek için bütçeler harici değişkenlerle ezilebilir (`override`) olmalıdır:
  - `AEGIS_BUDGET_INTENSITY`: `stealth` | `balanced` | `maximum` | `bankrupt` (mevcut enum tüm kalkanlara genişletilmelidir).
  - `AEGIS_BUDGET_SCALE`: Tüm sayısal çarpanlara uygulanacak global katsayı (örn. `AEGIS_BUDGET_SCALE=1.0` varsayılan; CI için `0.5`, ağır stres testi için `2.0`).
  - `AEGIS_OVERRIDE_<CONSTANT_NAME>`: Belirli bir bütçeyi manuel ezme (Örn: `AEGIS_OVERRIDE_MODEL_MAX_JSON_NESTING=40`).

### 4.3. Gerekli Test Aşamaları ve Test Piramidi
Bu sütunun hayata geçirilmesi için dört aşamalı bir doğrulama testi mimarisi şarttır:
1. **Drift Doğrulama Testi (`npm run verify:rea:budgets`):**
   - `scripts/verify-rea-constants.mjs` scripti genişletilerek 122 limitin tamamının REA klonundaki güncel değerlerle birebir örtüştüğü AST seviyesinde denetlenmelidir. REA'da bir limit değiştiğinde CI derhal alarm vermelidir.
2. **Kalkan Üretim ve Boyut Doğrulama Testi (Unit / Emitter Tests):**
   - Her format kalkanının ürettiği sahte/tuzak artefaktın hedef bütçeyi aştığı (`artifact.size >= targetValue` veya `tree.depth >= targetDepth`) izole birim testlerle (`vitest`) ölçülmelidir.
3. **Gerçek REA Entegrasyon Red-Team Testi (`npm run redteam:rea`):**
   - Kalkanlar tarafından üretilen artefaktlar gerçek in-process REA analiz motoruna beslenmelidir.
   - REA'nın kesin olarak `capacity`, `resourceLimit`, `AnalysisResourceConstraintError` veya `status: "partial"` hatası ürettiği doğrulanmalıdır; REA analizi asla sessizce veya `status: "ok"` ile tamamlanmamalıdır.
4. **CI Kaynak ve Süre Tavanı Regresyon Testi:**
   - Savunma üretiminin CI ortamında 5 saniyeden uzun sürmediği ve bellek kullanımının 512 MB RSS tavanını aşmadığı benchmark testleri ile tescillenmelidir.

---

## 5. Kabul Kriterleri (Ölçülebilir Cümleler)

Aşağıdaki ölçülebilir kriterler sağlanmadan "Deeper Budgets" sütunu tamamlanmış kabul edilmez:

1. **Limit Kapsama Oranı:** Tabloda yer alan 122 REA bütçesinin en az 100 adedi (%82+) AEGIS merkezi konfigürasyonunda tanımlanmış ve kalkan stratejileriyle ilişkilendirilmiş olacaktır.
2. **Drift Sıfır Hata:** `node scripts/verify-rea-constants.mjs` komutu çalıştırıldığında 122 bütçe için 0 hata (`0 FAIL`) verecektir.
3. **Hedef Aşım Garantisi:** AEGIS `bankrupt` modunda çalıştırıldığında, üretilen tüm korumalı artefaktlar ilgili REA limitini en az %10 (>= 1.10x) oranında aşacaktır.
4. **REA Kırılma Doğrulaması:** `npm run redteam:rea` testi icra edildiğinde, hedeflenen tüm kalkanlar REA üzerinde ölçülebilir bir kaynak yetersizliği (`ResourceLimit`, `Truncation` veya `CapacityError`) tetikleyecek, hiçbir korumalı artefakt REA tarafından tam başarıyla (`complete / ok`) ayrıştırılamayacaktır.
5. **CI Süre Tavanı:** 122 bütçelik test paketinin tamamı yerel ve GitHub Actions CI ortamlarında toplam 60 saniyenin altında hatasız tamamlanacaktır.
6. **Eksik Format İlerlemesi:** REA'da olup AEGIS'te bulunmayan 5 ana format grubu (Godot PCK, UnityFS, PyInstaller, DeviceTree, ESP Flash) için format kalkanı taslakları `src/shields/formats/` altına eklenmiş olacaktır.
