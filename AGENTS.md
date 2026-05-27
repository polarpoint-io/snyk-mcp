# AGENTS.md — Guidance for AI coding agents

This document provides guidance for AI agents (Claude Code, Cursor, Copilot, etc.) working on the `pysnyk-mcp` codebase.

## Project structure

```
snyk-mcp/
├── src/pysnyk_mcp/
│   ├── __init__.py         # package version
│   ├── client.py           # SnykClient factory (lru_cache, env vars)
│   └── server.py           # all FastMCP tools + main() entrypoint
├── tests/
│   └── test_tools.py       # unit tests with mocked SnykClient
├── pyproject.toml          # build config
├── Dockerfile              # container image
├── Makefile                # dev shortcuts
├── README.md               # user-facing docs
├── CLAUDE.md               # developer context
└── AGENTS.md               # this file
```

## Key design decisions

1. **No live API calls in tests** — All tests mock `get_client()`. Never add tests that require a real `SNYK_TOKEN`.
2. **Sync tools** — pysnyk is synchronous. All tools use plain `def`, not `async def`. FastMCP handles sync tools fine.
3. **`_safe_call()` is mandatory** — Every tool must wrap its logic in `_safe_call(_run)`. This ensures exceptions surface as `{"error": ..., "message": ...}` dicts.
4. **`_jsonable()` for all outputs** — pysnyk objects are dataclasses. Always convert with `_jsonable()` before returning.
5. **No destructive tools** — `project.delete()`, `project.move()`, `org.invite()` are intentionally not exposed.

## Adding a tool

```python
@mcp.tool()
def snyk_my_new_tool(org_id: str, some_param: str) -> dict:
    """One-line description for the LLM.

    Longer explanation of what this does and when to use it.

    Args:
        org_id: The Snyk organization UUID.
        some_param: What this parameter does.
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        result = org.some_manager.all()
        return {"count": len(result), "items": _jsonable(result)}

    return _safe_call(_run)
```

Then add a corresponding test in `tests/test_tools.py` following the existing pattern.

## Linting

```bash
make lint     # ruff check src tests
make format   # ruff check --fix src tests
```

## Testing

```bash
make test     # pytest -q
```

Tests must pass before any PR is merged. Do not mark a task complete if tests are failing.

## Release process

1. Update `version` in `pyproject.toml` and `src/pysnyk_mcp/__init__.py`
2. Update `CHANGELOG.md`
3. Tag the commit: `git tag v1.x.x && git push --tags`
4. The CI workflow builds and pushes the Docker image
