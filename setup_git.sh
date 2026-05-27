#!/usr/bin/env bash
# setup_git.sh — initialise git and push snyk-mcp to GitHub
# Run once from the project root: bash setup_git.sh
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
REMOTE="git@github.com:polarpoint-io/snyk-mcp.git"

echo "==> Project: $PROJECT_DIR"
cd "$PROJECT_DIR"

# Clean up any stale lock files from prior attempts
rm -f .git/index.lock 2>/dev/null || true

# Init (safe to re-run)
if [ ! -d .git ]; then
  git init
fi

git config user.name  "Surj Bains"
git config user.email "surj@polarpoint.io"
git branch -M main 2>/dev/null || true

git add -A

# Only commit if there is something staged
if ! git diff --cached --quiet; then
  git commit -m "feat: initial release of pysnyk-mcp v1.0.0

- 20 MCP tools: orgs, projects, vulnerabilities, CVEs,
  dependencies, licenses, members, integrations, package
  testing, tags, and container image CVEs
- snyk_list_project_cves: flat CVE list sorted by severity
- snyk_list_container_projects: Docker Hub, ECR, ACR, GCR, Quay...
- snyk_list_container_image_cves: CVEs scoped to container projects
- stdio and HTTP/SSE transports (Dockerfile + docker-compose)
- GitHub Actions CI + release workflow (PyPI OIDC + GHCR multi-arch)
- 28 unit tests, all passing"
else
  echo "==> Nothing new to commit (already up to date)"
fi

# Add remote (ignore error if it already exists)
git remote add origin "$REMOTE" 2>/dev/null \
  || git remote set-url origin "$REMOTE"

echo ""
echo "==> Pushing to $REMOTE ..."
git push -u origin main

echo ""
echo "✅  Done. Visit https://github.com/polarpoint-io/snyk-mcp"
