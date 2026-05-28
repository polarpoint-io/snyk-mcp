# snyk-mcp

A Model Context Protocol (MCP) server that exposes [Snyk](https://snyk.io) to LLM clients (Claude Desktop, Claude Code, Cursor, VS Code, etc.) via the official [pysnyk](https://github.com/snyk-labs/pysnyk) SDK.

Ask an LLM things like "which of our npm projects have critical vulnerabilities?", "show me all CVEs in our nginx container image", or "test the latest version of lodash for known CVEs" — and the LLM answers by calling Snyk directly through this server.

> **uvx**: `uvx pysnyk-mcp` &nbsp;·&nbsp; **PyPI**: `pip install pysnyk-mcp` &nbsp;·&nbsp; **Image**: `ghcr.io/polarpoint-io/snyk-mcp:latest` &nbsp;·&nbsp; **Repo**: <https://github.com/polarpoint-io/snyk-mcp>

## Table of contents

- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Client integrations](#client-integrations)
- [Tool reference](#tool-reference)
- [Example prompts](#example-prompts)
- [Running from source](#running-from-source)
- [Development](#development)
- [Publishing](#publishing)
- [Security notes](#security-notes)


## Quick start

### 1. uvx (recommended — zero install)

[uv](https://docs.astral.sh/uv/) runs the server directly from PyPI with no prior installation step.

```bash
# Install uv once (if you don't have it)
curl -LsSf https://astral.sh/uv/install.sh | sh

export SNYK_TOKEN=your_snyk_api_token
uvx pysnyk-mcp                                          # stdio
TRANSPORT=http HTTP_PORT=8000 uvx pysnyk-mcp            # HTTP/SSE
```

### 2. pip

```bash
pip install pysnyk-mcp
export SNYK_TOKEN=your_snyk_api_token

pysnyk-mcp                                    # stdio
TRANSPORT=http HTTP_PORT=8000 pysnyk-mcp      # HTTP/SSE
```

### 3. Docker (stdio — launched by your MCP client)

```bash
docker pull ghcr.io/polarpoint-io/snyk-mcp:latest

docker run --rm -i \
  -e SNYK_TOKEN=your_snyk_api_token \
  ghcr.io/polarpoint-io/snyk-mcp:latest
```

### 4. Docker (HTTP/SSE — standalone service)

```bash
docker run --rm \
  -p 8000:8000 \
  -e SNYK_TOKEN=your_snyk_api_token \
  -e TRANSPORT=http \
  ghcr.io/polarpoint-io/snyk-mcp:latest
# SSE endpoint: http://localhost:8000/sse
```

Get your token from: **Snyk → Account Settings → Auth Token** at <https://app.snyk.io/account>.


## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `SNYK_TOKEN` | yes | — | Snyk API token |
| `SNYK_API_URL` | no | `https://api.snyk.io/v1` | Override API base URL |
| `TRANSPORT` | no | `stdio` | `stdio` or `http` |
| `HTTP_HOST` | no | `0.0.0.0` | Bind host (HTTP mode) |
| `HTTP_PORT` | no | `8000` | Bind port (HTTP mode) |
| `LOG_LEVEL` | no | `INFO` | Python log level |

See [`.env.example`](.env.example) for a copy-pasteable template.


## Client integrations

Each client supports three options — **uvx** (recommended, zero install), **pip**, or **Docker**.

---

### Claude Desktop

Edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows).

**uvx (recommended)**
```json
{
  "mcpServers": {
    "snyk": {
      "command": "uvx",
      "args": ["pysnyk-mcp"],
      "env": {
        "SNYK_TOKEN": "your_snyk_api_token"
      }
    }
  }
}
```

**pip**
```json
{
  "mcpServers": {
    "snyk": {
      "command": "pysnyk-mcp",
      "env": {
        "SNYK_TOKEN": "your_snyk_api_token"
      }
    }
  }
}
```

**Docker**
```json
{
  "mcpServers": {
    "snyk": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "SNYK_TOKEN",
        "ghcr.io/polarpoint-io/snyk-mcp:latest"
      ],
      "env": {
        "SNYK_TOKEN": "your_snyk_api_token"
      }
    }
  }
}
```

Restart Claude Desktop after editing. You should see a hammer icon in the chat confirming the `snyk` server is connected with all 21 tools available.

---

### Claude Code

**uvx (recommended)**
```bash
claude mcp add snyk -- uvx pysnyk-mcp
export SNYK_TOKEN=your_snyk_api_token
```

**pip**
```bash
pip install pysnyk-mcp

claude mcp add snyk -- pysnyk-mcp
export SNYK_TOKEN=your_snyk_api_token
```

**Docker**
```bash
claude mcp add snyk -- docker run --rm -i \
  -e SNYK_TOKEN \
  ghcr.io/polarpoint-io/snyk-mcp:latest

export SNYK_TOKEN=your_snyk_api_token
```

---

### Cursor

Edit `~/.cursor/mcp.json`:

**uvx (recommended)**
```json
{
  "mcpServers": {
    "snyk": {
      "command": "uvx",
      "args": ["pysnyk-mcp"],
      "env": {
        "SNYK_TOKEN": "your_snyk_api_token"
      }
    }
  }
}
```

**pip**
```json
{
  "mcpServers": {
    "snyk": {
      "command": "pysnyk-mcp",
      "env": {
        "SNYK_TOKEN": "your_snyk_api_token"
      }
    }
  }
}
```

**Docker**
```json
{
  "mcpServers": {
    "snyk": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "-e", "SNYK_TOKEN",
               "ghcr.io/polarpoint-io/snyk-mcp:latest"],
      "env": { "SNYK_TOKEN": "your_snyk_api_token" }
    }
  }
}
```

---

### VS Code (Continue)

Edit `~/.continue/config.json`:

**uvx (recommended)**
```json
{
  "mcpServers": [{
    "name": "snyk",
    "command": "uvx",
    "args": ["pysnyk-mcp"],
    "env": { "SNYK_TOKEN": "your_snyk_api_token" }
  }]
}
```

**pip**
```json
{
  "mcpServers": [{
    "name": "snyk",
    "command": "pysnyk-mcp",
    "env": { "SNYK_TOKEN": "your_snyk_api_token" }
  }]
}
```

**Docker**
```json
{
  "mcpServers": [{
    "name": "snyk",
    "command": "docker",
    "args": ["run", "--rm", "-i", "-e", "SNYK_TOKEN",
             "ghcr.io/polarpoint-io/snyk-mcp:latest"],
    "env": { "SNYK_TOKEN": "your_snyk_api_token" }
  }]
}
```

---

### HTTP / SSE (remote or shared server)

If you prefer to run the server as a persistent HTTP service rather than a subprocess:

```bash
# uvx
SNYK_TOKEN=your_token TRANSPORT=http HTTP_PORT=8000 uvx pysnyk-mcp

# pip
pip install pysnyk-mcp
SNYK_TOKEN=your_token TRANSPORT=http HTTP_PORT=8000 pysnyk-mcp

# Docker
docker run --rm -p 8000:8000 \
  -e SNYK_TOKEN=your_snyk_api_token \
  -e TRANSPORT=http \
  ghcr.io/polarpoint-io/snyk-mcp:latest
```

Then point your MCP client at `http://localhost:8000/sse`.


## Tool reference

The server exposes **21 tools** grouped by capability. All return JSON. Errors from the Snyk API are caught and returned as `{"error": "...", "message": "..."}` so the LLM can handle them gracefully.

### Organizations

| Tool | Description |
|---|---|
| `snyk_list_organizations` | List all orgs the token has access to |
| `snyk_get_organization` | Get details for a single org by ID |

### Projects

| Tool | Description |
|---|---|
| `snyk_list_projects` | List projects (filter by org, name, or origin) |
| `snyk_get_project` | Full details for a single project |
| `snyk_get_project_dependency_graph` | Full dependency tree for a project |

### Issues & Vulnerabilities

| Tool | Description |
|---|---|
| `snyk_list_project_vulnerabilities` | Open vulnerabilities with optional severity filter |
| `snyk_list_aggregated_issues` | Deduplicated issues with fix info (recommended) |

### CVEs

| Tool | Description |
|---|---|
| `snyk_list_project_cves` | Flat CVE list (CVE ID, CVSS score, package, upgrade path) for any project, sorted by severity |
| `snyk_list_container_projects` | Discover container image projects in an org (Docker Hub, ECR, ACR, GCR, Quay, Harbor, …) |
| `snyk_list_container_image_cves` | CVEs for a specific container image project |

### Dependencies & Licenses

| Tool | Description |
|---|---|
| `snyk_list_dependencies` | Packages in use (org-wide or per project) |
| `snyk_list_org_licenses` | Licenses across an org — compliance audit |
| `snyk_list_project_licenses` | Licenses for a specific project |

### Members

| Tool | Description |
|---|---|
| `snyk_list_members` | Members of a Snyk organization |

### Integrations

| Tool | Description |
|---|---|
| `snyk_list_integrations` | Active integrations (GitHub, Docker Hub, npm, etc.) |

### Package Testing

| Tool | Description |
|---|---|
| `snyk_test_npm_package` | Test an npm package for known vulnerabilities |
| `snyk_test_python_package` | Test a PyPI package for known vulnerabilities |
| `snyk_test_maven_package` | Test a Maven artifact for known vulnerabilities |
| `snyk_test_rubygem_package` | Test a Ruby gem for known vulnerabilities |

### Tags

| Tool | Description |
|---|---|
| `snyk_list_project_tags` | Tags applied to a project (key/value pairs) |

### User / Health

| Tool | Description |
|---|---|
| `snyk_get_user_info` | Authenticated user details — useful as a connectivity check |


## Example prompts

> **Security triage:** "List all projects with critical vulnerabilities in our main org."
>
> **Package audit:** "Is the version of Flask we're using (2.3.0) affected by any known CVEs?"
>
> **CVE report:** "Give me all critical and high CVEs in the payment-service project with their CVSS scores and upgrade paths."
>
> **Container audit:** "List all our container image projects and show me any critical CVEs in the nginx image."
>
> **Log4Shell check:** "Do any of our container images have CVE-2021-44228?"
>
> **License compliance:** "Show me all high-severity license issues across our organization."
>
> **Maven check:** "Test log4j-core 2.14.1 — is it affected by Log4Shell?"
>
> **Inventory:** "How many projects do we have per origin (github, cli, docker)?"
>
> **Member audit:** "Who are the admins in our Snyk org?"


## Running from source

```bash
git clone git@github.com:polarpoint-io/snyk-mcp.git
cd snyk-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]

export SNYK_TOKEN=...

pysnyk-mcp                                    # stdio
TRANSPORT=http HTTP_PORT=8000 pysnyk-mcp      # HTTP/SSE
```

Or via the Makefile:

```bash
make dev       # install with dev extras
make test      # pytest
make lint      # ruff check
make run       # stdio
make run-http  # HTTP/SSE on :8000
make docker    # build the image locally
```


## Development

```bash
make dev
make test
make lint
```

Adding a new tool:

1. Add a `@mcp.tool()` function in `src/pysnyk_mcp/server.py`, wrapping the pysnyk call in a `_run()` closure.
2. Pass `_run` to `_safe_call()` to ensure exceptions return cleanly as `{"error": ..., "message": ...}`.
3. Add a mocked-client test in `tests/test_tools.py`.

See [`AGENTS.md`](AGENTS.md) for deeper contribution guidance.


## Publishing

Releases are fully automated via [semantic-release](https://semantic-release.gitbook.io/) — no manual tagging needed.

### How it works

Every push to `main` runs the CI pipeline:

1. **Test** — lint (`ruff`) + pytest across Python 3.10 / 3.11 / 3.12
2. **Docker** — builds and pushes the image to GHCR (multi-arch `amd64`/`arm64`)
3. **Release** — semantic-release analyses conventional commits, bumps the version, updates `CHANGELOG.md`, publishes to PyPI, and creates a GitHub Release

A release only happens when commits contain a `feat:`, `fix:`, or breaking-change — `chore:`, `docs:`, `ci:` commits don't trigger one.

### Docker image tags

| Tag | When pushed |
|---|---|
| `latest` | Every merge to `main` |
| `sha-<short>` | Every merge to `main` |
| `1.2.3` / `1.2` | On a semantic-release version bump |

### Required GitHub secrets

| Secret | Description |
|---|---|
| `POL_GH_TOKEN` | Personal access token with `repo` + `write:packages` scope |
| `PYPI_TOKEN` | PyPI API token for the `pysnyk-mcp` project |

Add both at: **GitHub repo → Settings → Secrets and variables → Actions**.

### Commit conventions

```
feat: add new tool          → minor version bump (0.x.0)
fix: correct response shape → patch bump        (0.0.x)
feat!: breaking change      → major bump        (x.0.0)
chore/docs/ci/test          → no release
```


## Security notes

- The container runs as a non-root user (`uid 10001`).
- `SNYK_TOKEN` is read from env vars only — never written to disk.
- Destructive operations (`project.delete()`, `project.move()`) are deliberately **not** exposed.
- If you add write tools, guard them behind a separate env flag (e.g. `SNYK_ENABLE_WRITE=1`).


## License

MIT — see [LICENSE](LICENSE).
