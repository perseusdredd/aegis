# Security Policy

## Scope

AEGIS (`aegis-shield`) is a defensive software-protection toolkit. We take the functional integrity and safety of protected artifacts seriously.

## Reporting a Vulnerability

If you discover:
1. A bug where `aegis protect` alters the runtime behavior or output of a valid target program,
2. A vulnerability in AEGIS's `.asar`, `.wasm`, `.pyc`, ELF/Mach-O/PE, or ZIP parsers, or
3. A bypass where an automated reverse-engineering agent recovers literal secrets without hitting AEGIS's resource-limit tripwires,

please open a GitHub issue or security advisory on the repository with a minimal reproducible example.
