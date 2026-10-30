# Python Engineering & Documentation Standards

> **Role Binding**:
> - **Tier 1 & 2 (Opus / Sonnet)**: Apply Section 1 (Guardrails), Section 2 (Architecture), and Section 3 (Data Models) when designing plans and atomic contracts. Do NOT write implementation code.
> - **Tier 3 (Haiku / Executor)**: Strictly enforce 100% of this document and pass the Section 5 CLI Gate with zero errors before returning `STATUS: SUCCESS`.

---

## 1. Operational Guardrails
1. **Response Style**: Concise, direct, and in Spanish ("smart caveman / terse" mode).
2. **Version Control**: **NEVER run `git add` or `git commit`** without explicit user authorization.
3. **Strict Scope**: Solve only the assigned task. If the task is strictly to document or standardize docstrings, **do not modify business logic, method signatures, or dependencies**.

---

## 2. Architectural & Design Principles
- **KISS (Keep It Simple, Stupid)**: Prioritize simple, pragmatic solutions. Never introduce premature abstractions, unnecessary design patterns, or multi-layered indirection when a straightforward function or simple structure solves the issue.
- **YAGNI (Avoid Over-Engineering)**: Solve only the immediate problem. Do not anticipate hypothetical future requirements. Clear, readable, and directly maintainable code takes precedence over complex flexibility.
- **DRY (Don't Repeat Yourself)**: Extract duplicated logic and centralize reusable behavior, balancing DRY with readability—avoid creating tight coupling across unrelated domains solely for deduplication.
- **SRP (Single Responsibility Principle)**: Every class, function, and module must have a single, well-defined responsibility. Keep functions small, focused, atomic, and predictable.

---

## 3. Data Models (`Pydantic`, `Dataclasses`, `TypedDict`)
1. **Prefer Typed Structures**: Always use `BaseModel`, `SQLModel`, Bunnet `Document`, or `@dataclass(slots=True, frozen=True)` over untyped dicts or loose tuples.
2. **Mandatory `Field(description=...)` in Pydantic**: Every attribute in a Pydantic/SQLModel/Document class MUST explicitly declare `Field(description="...")`. Never leave standalone annotations. Include defaults inside `Field(...)`.
3. **Mandatory `Attributes:` Docstring Block**: Every data class must include an `Attributes:` section in its docstring listing all public fields in exact `snake_case` (matching the Python attribute name, even if camelCase `alias`es exist).

```python
class TaskLifecycleMetadata(BaseModel):
    """Lifecycle fields extracted from Dramatiq message keyword arguments.

    Attributes:
        gateway_task_id: Optional API gateway task identifier.
        analytics_accounts: Configured account identifiers with provenance.
    """

    gateway_task_id: str | None = Field(
        default=None,
        description="Optional API gateway task identifier.",
    )
    analytics_accounts: list[AnalyticsAccount] = Field(
        default_factory=list[AnalyticsAccount],
        description="Configured account identifiers with source evidence.",
    )
```

---

## 4. Docstring Conventions (Google Style)
All modules, classes, functions, and methods must include a Google-style docstring obeying these strict rules:
- **Short Summary**: Single first line (**<= 72 chars**, descriptive imperative verb: `Return the current timestamp.`), followed by a **mandatory blank line** and an extended description (**<= 79 chars/line**).
- **NO Double Backticks**: **Using inline double backticks (`` `param` ``) in docstrings is strictly prohibited**. Use single quotes `'...'` or plain text.
- **Complete Sections (4-space indent)**: Document all parameters (except `self`/`cls`) in `Args:`, any non-`None` return in `Returns:`, and propagated exceptions in `Raises:`.

```python
def enqueue_task(
    resource: Resource,
    payload: BaseModel,
    *,
    task_id: UUID | None = None,
    gateway_task_id: UUID | str | None = None,
) -> UUID:
    """Enqueue a task in the dramatiq broker.

    Pushes the serialized task payload to the corresponding Redis queue
    and registers an initial lifecycle event.

    Args:
        resource: The resource type that identifies the stream.
        payload: Pydantic payload passed to the resource actor.
        task_id: Optional task identifier assigned by the API gateway.
        gateway_task_id: Optional parent gateway task identifier.

    Returns:
        The unique identifier of the enqueued task.

    Raises:
        BrokerError: If the message cannot be pushed to Redis.
    """
```

---

## 5. Mandatory Standalone CLI Verification Gate
Code must comply with Python 3.12+ strict typing (explicit annotations, `X | Y` unions, built-in generics `list[str]`, zero `Any`, explicit `None` handling, specific exceptions with `raise ... from err`) and **<= 79 characters per line** across code, comments, and docstrings.

Before finishing any task, you MUST execute these exact standalone commands on all modified files:

```bash
ruff format --line-length 79 <file> && ruff check --fix --line-length 79 --select ALL --ignore W191,E111,E114,E117,D206,D300,Q000,Q001,Q002,Q003,Q004,COM812,COM819,CPY001,ISC002 --config "lint.pydocstyle.convention='google'" --config "lint.pycodestyle.max-line-length=79" <file> && basedpyright -p <(echo '{"typeCheckingMode":"strict"}') --pythonversion 3.12 --venvpath . --venv .venv <file>
```

- **Zero Tolerance**: If `ruff` or `basedpyright` outputs ANY error or warning, fix the root cause in the code and re-run the command until both return **0 errors**.
- **No Suppressions**: Never add `# noqa`, `# type: ignore`, or unsafe `cast(...)` to silence the linter or type checker.