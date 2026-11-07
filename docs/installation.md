# Installation & Setup Guide

**AEGIS (`aegis-agents` — Blind LLM Agents)** is distributed as a zero-config Node.js CLI and MCP server that runs anywhere Node.js `^22.23.4 || >=24.0.0` is installed (matches `package.json` `engines`).

---

## 1. Quick Start (`npx`)

Run AEGIS directly without installing anything globally:

```bash
# 1. Register AEGIS MCP Server + Skill into Claude Code, Cursor, Codex, Windsurf, Gemini CLI, etc.
npx aegis-agents setup

# 2. Check your environment and configured AI clients
npx aegis-agents doctor

# 3. Audit an artifact for REA exposure before release
npx aegis-agents audit ./dist/app.js

# 4. Protect the artifact with AEGIS's three-stage shield
npx aegis-agents protect ./dist/app.js --mode bankrupt

# 5. Verify functional preservation and REA analyzer degradation
npx aegis-agents verify ./dist/app.js ./dist/app.aegis.js
```

---

## 2. Global or Project-Local Installation

### Install as a Dev Dependency (Recommended for CI/CD Release Pipelines)

```bash
npm install --save-dev aegis-agents
# or
pnpm add -D aegis-agents
# or
bun add -d aegis-agents
```

Then add a post-build protection script to your `package.json`:

```json
{
  "scripts": {
    "build": "vite build",
    "postbuild": "aegis protect ./dist/assets/index.js --in-place --mode bankrupt --emit-sourcemap"
  }
}
```

### Install Globally

```bash
npm install -g aegis-agents

# Both `aegis` and `aegis-agents` binaries are registered:
aegis --version
aegis-agents doctor
```

---

## 3. Registering AEGIS in Coding Agents (`aegis setup`)

Just like `npx reverse-engineer-anything setup`, `npx aegis-agents setup` auto-discovers installed AI coding agents on your machine and registers:

1. **The `aegis` MCP stdio server** (`aegis_audit`, `aegis_protect`, `aegis_verify`, `aegis_benchmark`, `aegis_emit_headers`, `aegis_doctor`)
2. **The `aegis-counter-rea` skill** (`SKILL.md` + Counter-REA Matrix)

### Supported Clients

| Client ID | Name | Config Location | Skill Location |
| :--- | :--- | :--- | :--- |
| `claude-code` | Claude Code | `~/.claude.json` | `~/.claude/skills/aegis-counter-rea` |
| `cursor` | Cursor | `~/.cursor/mcp.json` | `~/.cursor/skills/aegis-counter-rea` |
| `codex` | OpenAI Codex | `~/.codex/config.toml` | `~/.codex/skills/aegis-counter-rea` |
| `windsurf` | Windsurf | `~/.codeium/windsurf/mcp_config.json` | `~/.codeium/windsurf/skills/aegis-counter-rea` |
| `gemini` | Gemini CLI | `~/.gemini/settings.json` | `~/.gemini/skills/aegis-counter-rea` |
| `opencode` | OpenCode | `~/.config/opencode/opencode.json` | `~/.config/opencode/skills/aegis-counter-rea` |

### Target Specific Clients

```bash
npx aegis-agents setup --client claude-code,cursor
```

### Uninstall

To cleanly remove AEGIS from all agent configuration files and delete installed skill folders:

```bash
npx aegis-agents uninstall
```

---

## 4. Compile-Time Header Integration (C / C++ / Rust / Go)

If you are shipping a native binary compiled with `clang`, `gcc`, `rustc`, or `go build`, you can embed AEGIS's compile-time counters directly into `.rodata` before linking:

```bash
npx aegis-agents emit-headers ./include/shield --seed my-release-v1
```

- **C / C++**: `#include "aegis_shield.h"` and call `AEGIS_ANCHOR_SHIELD();` inside `main()`.
- **Rust**: `mod aegis_shield;` and call `aegis_shield::anchor_shield();` inside `fn main()`.
- **Go**: Include `aegis_shield.go` in your package and call `AnchorAegisShield()` inside `func main()`.
