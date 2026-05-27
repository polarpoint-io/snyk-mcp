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
