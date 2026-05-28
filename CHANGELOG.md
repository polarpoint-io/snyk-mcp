# [1.1.0](https://github.com/polarpoint-io/snyk-mcp/compare/v1.0.0...v1.1.0) (2026-05-28)


### Features

* make org_id optional — auto-discover orgs across all tools ([3604805](https://github.com/polarpoint-io/snyk-mcp/commit/3604805abdff11745ff9bde841be41368a6c7573))

# 1.0.0 (2026-05-27)


### Bug Fixes

* remove unused pytest import (ruff F401) ([4c69fa0](https://github.com/polarpoint-io/snyk-mcp/commit/4c69fa07aae78d21b57003b6814b52b58fd5d3fa))


### Features

* initial release of pysnyk-mcp v1.0.0 ([179876c](https://github.com/polarpoint-io/snyk-mcp/commit/179876c4fbb97bbc756cc8273cc3492a3a656fea))

# Changelog

All notable changes to `pysnyk-mcp` will be documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-05-27

### Added

- Initial release
- 20 MCP tools covering Snyk organizations, projects, issues, CVEs, dependencies, licenses, members, integrations, package testing, tags, and container images
- `snyk_list_project_cves` — extract CVE IDs from project vulnerabilities, sorted by severity
- `snyk_list_container_projects` — discover container image projects (Docker Hub, ECR, ACR, GCR, Quay, Harbor, etc.)
- `snyk_list_container_image_cves` — CVEs for a specific container image project
- stdio and HTTP/SSE transport modes
- Docker image published to `ghcr.io/polarpoint-io/snyk-mcp`
- PyPI package `pysnyk-mcp`
