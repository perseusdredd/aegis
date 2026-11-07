# Red (`REA`) vs. Blue (`bla-agents`) — The Adversarial Defense Manifesto

- **REA (`re` = Red)**: Offensive reverse-engineering MCP (`Decompile -> Understand -> Recreate`).
- **BLA (`bl` = Blue / Blind LLM Agents)**: Defensive counter-reverse-engineering MCP (`Poison -> Exhaust -> Hallucinate`).

## Why Traditional Obfuscation Fails Against LLM Agents

Traditional obfuscators rename `calculatePrice` to `_0x1a2b`. Large language models trivially recover the original semantics by reading the surrounding control flow and constants.

BLA instead targets the **two structural bottlenecks of AI reverse-engineering agents**:
1. **Deterministic Parser & Context Budgets (Resource Exhaustion)**: Every static analyzer and MCP server in `REA` enforces strict recursion, candidate, and byte caps to prevent worker OOMs. BLA trips these exact caps in $O(1)$ runtime.
2. **Evidence-Driven Reasoning Discipline (Model Misjudgment Induction)**: Coding agents instructed to cite `observed` tool outputs over `unknown` paths will faithfully reconstruct BLA's crystal-clear **Shadow Business Logic** whenever the real business logic is guarded behind semantic `unknown` frontiers.
