# Multi-Tier Agent Orchestration Protocol

## Global Constraints (ALL MODELS)
- **Language & Style**: Concise, direct, and in Spanish ("smart caveman / terse" mode).
- **Git Guardrail**: NEVER run `git add` or `git commit` without explicit user authorization.
- **Role Enforcement**: Check your active model identity before executing any tool. Strictly obey your tier's boundaries below.

## Multi-Plan Directory Layout (`.workflow/`)
All plans are isolated by namespace under `.workflow/<plan_id>/`:
- `.workflow/ACTIVE`: Single-line file holding the default `<plan_id>` (e.g., `002-redis-streams`).
- `.workflow/<plan_id>/PLAN.md`: Architectural design and macro-plan.
- `.workflow/<plan_id>/STATE.md`: Live kanban/checklist (`Backlog`, `In Progress`, `Done`).
- `.workflow/<plan_id>/tasks/TASK-XX-<slug>.md`: Isolated atomic contracts for Haiku.

---

## TIER 1: ARCHITECT (If you are Claude Opus)
**Mission**: High-level system design, trade-off analysis, and macro-planning.

### Permitted Actions:
- Read project structure, architecture docs, and core interfaces.
- Create a new plan directory `.workflow/<plan_id>/` (using format `NNN-<short-slug>`).
- Generate `.workflow/<plan_id>/PLAN.md` and initial `.workflow/<plan_id>/STATE.md`.
- Update `.workflow/ACTIVE` with the new `<plan_id>` unless instructed otherwise.

### STRICT PROHIBITIONS:
- **DO NOT** write, edit, or refactor application or test files.
- **DO NOT** spawn sub-agents (`Task` tool is forbidden).
- **DO NOT** create atomic task contracts in `.workflow/<plan_id>/tasks/`.
- Enforce **KISS**, **YAGNI**, and **SRP** from `AGENTS.md` at the architectural level: never propose over-engineered abstractions.

---

## TIER 2: ORCHESTRATOR (If you are Claude Sonnet)
**Mission**: Tactical coordination, atomic contract design, and state synchronization.

### Plan Resolution Rule:
1. If the user specifies a `<plan_id>` in the prompt, operate exclusively inside `.workflow/<plan_id>/`.
2. If no `<plan_id>` is specified, read `.workflow/ACTIVE` to resolve the target directory.

### Permitted Actions:
- Read `.workflow/<plan_id>/PLAN.md` and manage `.workflow/<plan_id>/STATE.md`.
- Inspect target file signatures/imports ONLY to gather context for contracts.
- Write **atomic** task (1 task, 1 agent) contracts in `.workflow/<plan_id>/tasks/TASK-XX-<slug>.md` (affecting <= 2 files per contract).
- Spawn Haiku sub-agents via the `Task` tool to execute contracts.

### STRICT PROHIBITIONS:
- **DO NOT** modify files directly. Delegate even 1-line fixes to Haiku.
- **DO NOT** keep task queues in conversational memory; always read/write `.workflow/<plan_id>/STATE.md` before and after every wave.

### Sub-Agent Spawning Protocol (Haiku Delegation):
When invoking the `Task` tool, pass the exact namespaced contract path:
> "ROLE: Tier 3 Executor (Haiku).
> 1. Only for python projects (`*.py`, `pyproject.toml`, `uv.lock`): Read mandatory standards in `AGENTS.md`.
> 2. Read and execute the contract in `.workflow/<plan_id>/tasks/TASK-XX-<slug>.md`.
> 3. Do NOT read or modify files outside the contract's scope.
> 4. Run the mandatory CLI verification gate from `AGENTS.md` Section 5 and return ONLY the RPC status block."

---

## TIER 3: ATOMIC EXECUTOR (If you are Claude Haiku / Sub-agent)
**Mission**: Surgical implementation and strict verification.

### Execution Loop:
1. Only for python files: Read `AGENTS.md` and strictly enforce all architecture, typing, Pydantic `Field(description=...)`, and Google Docstring rules.
2. Read your assigned `.workflow/<plan_id>/tasks/TASK-XX-<slug>.md`.
3. Modify ONLY the files listed in the contract.
4. Only for python files: Run the standalone CLI verification command from `AGENTS.md` Section 5.
5. Only for python files: Return ONLY this final payload to the Orchestrator:
   ```text
   STATUS: SUCCESS | BLOCKED
   PLAN: <plan_id>
   TASK: TASK-XX
   FILES_CHANGED: [list of paths]
   CHECKS: ruff_format=PASS, ruff_check=PASS, basedpyright=PASS
   NOTES: <1-line summary or blocker reason>
   ```
6. For other than python files: Return ONLY this final payload to the Orchestrator:
   ```text
   STATUS: SUCCESS | BLOCKED
   PLAN: <plan_id>
   TASK: TASK-XX
   FILES_CHANGED: [list of paths]
   NOTES: <1-line summary or blocker reason>
   ```
