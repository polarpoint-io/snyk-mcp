# CLAUDE.md — pysnyk-mcp

## Project overview

`pysnyk-mcp` is an MCP (Model Context Protocol) server that exposes Snyk's developer security platform to LLM clients via the [pysnyk](https://github.com/snyk-labs/pysnyk) SDK. It follows the same structure as [tenable-mcp](https://github.com/polarpoint-io/tenable-mcp).

## Key files

| File | Purpose |
|---|---|
| `src/pysnyk_mcp/server.py` | All MCP tools (FastMCP) |
| `src/pysnyk_mcp/client.py` | Lazy SnykClient factory |
| `tests/test_tools.py` | Mocked-client unit tests |
| `pyproject.toml` | Build config and dependencies |
| `Dockerfile` | Container image |
| `Makefile` | Developer shortcuts |

## Architecture

- **Transport**: stdio (default) or SSE/HTTP, controlled by `TRANSPORT` env var
- **Auth**: Single `SNYK_TOKEN` env var
- **Client**: `pysnyk.SnykClient` (synchronous), cached via `@lru_cache`
- **Error handling**: All tools use `_safe_call()` to catch exceptions and return `{"error": ..., "message": ...}` dicts

## Common commands

```bash
make dev        # install with dev extras
make test       # run pytest
make lint       # ruff check
make run        # start stdio server
make run-http   # start HTTP/SSE server on :8000
```

## Adding a new tool

1. Add a `@mcp.tool()` function in `server.py`
2. Wrap the pysnyk call in `_run()` and pass it to `_safe_call(_run)`
3. Use `_jsonable()` to convert pysnyk objects to JSON
4. Add a test in `tests/test_tools.py` with a mocked client

## pysnyk API patterns

```python
# Organizations
client.organizations.all()
client.organizations.get(org_id)

# Projects
org.projects.all()
org.projects.get(project_id)

# Issues
project.issueset_aggregated.filter(severities=["high"], types=["vuln"])
project.vulnerabilities  # list of Vulnerability objects

# Package testing
org.test_npm(name, version)
org.test_python(name, version)
org.test_maven(group_id, artifact_id, version)
org.test_rubygem(name, version)

# Raw HTTP (REST/v3 API)
client.get("user/me")
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `SNYK_TOKEN` | Yes | Snyk API token |
| `SNYK_API_URL` | No | Override API URL |
| `TRANSPORT` | No | `stdio` or `http` |
| `HTTP_HOST` | No | Bind host for HTTP mode |
| `HTTP_PORT` | No | Bind port for HTTP mode |
| `LOG_LEVEL` | No | Python log level |
