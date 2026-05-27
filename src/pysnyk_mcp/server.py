"""FastMCP server exposing Snyk via pysnyk.

Tools provided:
    Organizations:
        - snyk_list_organizations
        - snyk_get_organization

    Projects:
        - snyk_list_projects
        - snyk_get_project
        - snyk_get_project_dependency_graph

    Issues / Vulnerabilities:
        - snyk_list_project_vulnerabilities
        - snyk_list_aggregated_issues

    CVEs:
        - snyk_list_project_cves
        - snyk_list_container_projects
        - snyk_list_container_image_cves

    Dependencies & Licenses:
        - snyk_list_dependencies
        - snyk_list_org_licenses
        - snyk_list_project_licenses

    Members:
        - snyk_list_members

    Integrations:
        - snyk_list_integrations

    Package Testing:
        - snyk_test_npm_package
        - snyk_test_python_package
        - snyk_test_maven_package
        - snyk_test_rubygem_package

    Tags:
        - snyk_list_project_tags

    User / Health:
        - snyk_get_user_info

Transport selection (env vars):
    TRANSPORT=stdio (default)   - MCP stdio transport
    TRANSPORT=http              - SSE/HTTP transport on HTTP_HOST:HTTP_PORT
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import fields as dataclass_fields
from typing import Any

from mcp.server.fastmcp import FastMCP

from .client import SnykConfigError, get_client

logger = logging.getLogger("pysnyk_mcp")

mcp = FastMCP(
    name="pysnyk-mcp",
    instructions=(
        "Query Snyk for organizations, projects, vulnerabilities, and dependencies. "
        "Requires SNYK_TOKEN env var set to your Snyk API token."
    ),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_call(fn, *args, **kwargs) -> Any:
    """Wrap pysnyk calls so credential errors surface cleanly to the LLM."""
    try:
        return fn(*args, **kwargs)
    except SnykConfigError as exc:
        return {"error": "configuration", "message": str(exc)}
    except Exception as exc:  # noqa: BLE001 - surface all upstream errors
        logger.exception("Snyk API call failed")
        return {"error": exc.__class__.__name__, "message": str(exc)}


def _to_dict(obj: Any) -> Any:
    """Recursively convert pysnyk dataclass objects to JSON-safe dicts.

    Skips 'client' and 'organization' fields to avoid circular references.
    """
    _SKIP_FIELDS = {"client", "organization"}

    if obj is None:
        return None
    if isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, list):
        return [_to_dict(item) for item in obj]
    if isinstance(obj, dict):
        return {k: _to_dict(v) for k, v in obj.items()}
    # pysnyk models are dataclasses
    if hasattr(obj, "__dataclass_fields__"):
        result: dict[str, Any] = {}
        for f in dataclass_fields(obj):
            if f.name in _SKIP_FIELDS:
                continue
            result[f.name] = _to_dict(getattr(obj, f.name, None))
        return result
    # Last resort: try JSON round-trip, fall back to str
    try:
        json.dumps(obj)
        return obj
    except TypeError:
        return str(obj)


def _jsonable(obj: Any) -> Any:
    """Ensure obj is JSON-serialisable (used for final output)."""
    return json.loads(json.dumps(_to_dict(obj), default=str))


# ---------------------------------------------------------------------------
# Organizations
# ---------------------------------------------------------------------------

@mcp.tool()
def snyk_list_organizations() -> dict:
    """List all Snyk organizations the API token has access to.

    Returns organization IDs, names, slugs, URLs, and group membership.
    Use the returned organization IDs with other tools to scope operations.
    """
    def _run() -> dict:
        client = get_client()
        orgs = client.organizations.all()
        return {"count": len(orgs), "organizations": _jsonable(orgs)}

    return _safe_call(_run)


@mcp.tool()
def snyk_get_organization(org_id: str) -> dict:
    """Get details for a single Snyk organization by ID.

    Args:
        org_id: The Snyk organization UUID (e.g. 'df734bed-d75c-4f11-bb47-1d119913bcc7').
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        return _jsonable(org)

    return _safe_call(_run)


# ---------------------------------------------------------------------------
# Projects
# ---------------------------------------------------------------------------

@mcp.tool()
def snyk_list_projects(
    org_id: str | None = None,
    name_filter: str | None = None,
    origin_filter: str | None = None,
    limit: int = 100,
) -> dict:
    """List Snyk projects, optionally scoped to one organization.

    Args:
        org_id: Restrict to projects in this organization. If omitted, returns
                projects across all organizations (may be slow for large accounts).
        name_filter: Substring filter on project name (case-sensitive).
        origin_filter: Filter by origin, e.g. 'github', 'cli', 'docker'.
        limit: Maximum projects to return (default 100).
    """
    def _run() -> dict:
        client = get_client()

        if org_id:
            org = client.organizations.get(org_id)
            projects = org.projects.all()
        else:
            projects = client.projects.all()

        # Apply optional filters
        if name_filter:
            projects = [p for p in projects if name_filter in p.name]
        if origin_filter:
            projects = [p for p in projects if p.origin == origin_filter]

        projects = projects[:limit]
        return {"count": len(projects), "projects": _jsonable(projects)}

    return _safe_call(_run)


@mcp.tool()
def snyk_get_project(org_id: str, project_id: str) -> dict:
    """Get full details for a single Snyk project.

    Args:
        org_id: The Snyk organization UUID that owns this project.
        project_id: The Snyk project UUID.
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        project = org.projects.get(project_id)
        return _jsonable(project)

    return _safe_call(_run)


@mcp.tool()
def snyk_get_project_dependency_graph(org_id: str, project_id: str) -> dict:
    """Return the full dependency graph for a Snyk project.

    The graph shows the complete tree of package dependencies including
    transitive deps, their versions, and the dependency relationships.

    Args:
        org_id: The Snyk organization UUID.
        project_id: The Snyk project UUID.
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        project = org.projects.get(project_id)
        graph = project.dependency_graph
        return _jsonable(graph)

    return _safe_call(_run)


# ---------------------------------------------------------------------------
# Issues / Vulnerabilities
# ---------------------------------------------------------------------------

@mcp.tool()
def snyk_list_project_vulnerabilities(
    org_id: str,
    project_id: str,
    severity_filter: list[str] | None = None,
    limit: int = 100,
) -> dict:
    """List vulnerabilities found in a Snyk project.

    Returns open, non-ignored vulnerabilities with full details including
    CVSS scores, CVE identifiers, upgrade/patch paths, and severity.

    Args:
        org_id: The Snyk organization UUID.
        project_id: The Snyk project UUID.
        severity_filter: Optionally restrict to severities, e.g. ['critical', 'high'].
        limit: Maximum vulnerabilities to return (default 100).
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        project = org.projects.get(project_id)
        vulns = project.vulnerabilities

        if severity_filter:
            vulns = [v for v in vulns if v.severity in severity_filter]

        vulns = vulns[:limit]

        summary = {
            "critical": sum(1 for v in vulns if v.severity == "critical"),
            "high": sum(1 for v in vulns if v.severity == "high"),
            "medium": sum(1 for v in vulns if v.severity == "medium"),
            "low": sum(1 for v in vulns if v.severity == "low"),
        }

        return {
            "count": len(vulns),
            "summary": summary,
            "vulnerabilities": _jsonable(vulns),
        }

    return _safe_call(_run)


@mcp.tool()
def snyk_list_aggregated_issues(
    org_id: str,
    project_id: str,
    severity_filter: list[str] | None = None,
    issue_type: str | None = None,
    ignored: bool = False,
    patched: bool = False,
    limit: int = 100,
) -> dict:
    """List aggregated issues for a Snyk project (recommended over raw vulnerabilities).

    Returns deduplicated issues grouped by vulnerability ID, with fix information
    and whether they are ignored or patched. Supports both 'vuln' and 'license' types.

    Args:
        org_id: The Snyk organization UUID.
        project_id: The Snyk project UUID.
        severity_filter: Filter by severity list, e.g. ['critical', 'high'].
        issue_type: Filter by type: 'vuln' or 'license'. If omitted, returns both.
        ignored: Include ignored issues (default False).
        patched: Include patched issues (default False).
        limit: Maximum issues to return (default 100).
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        project = org.projects.get(project_id)

        filter_kwargs: dict[str, Any] = {
            "ignored": ignored,
            "patched": patched,
        }
        if severity_filter:
            filter_kwargs["severities"] = severity_filter
        if issue_type:
            filter_kwargs["types"] = [issue_type]
        else:
            filter_kwargs["types"] = ["vuln", "license"]

        result = project.issueset_aggregated.filter(**filter_kwargs)
        issues = result.issues[:limit]

        summary = {
            "critical": sum(1 for i in issues if i.issueData.severity == "critical"),
            "high": sum(1 for i in issues if i.issueData.severity == "high"),
            "medium": sum(1 for i in issues if i.issueData.severity == "medium"),
            "low": sum(1 for i in issues if i.issueData.severity == "low"),
        }

        return {
            "count": len(issues),
            "summary": summary,
            "issues": _jsonable(issues),
        }

    return _safe_call(_run)


# ---------------------------------------------------------------------------
# CVEs
# ---------------------------------------------------------------------------

# Container image origins and types recognised by Snyk
_CONTAINER_ORIGINS = frozenset(
    {"docker-hub", "acr", "ecr", "gcr", "digitalocean-cr", "gitlab-cr",
     "harbor-cr", "nexus-cr", "quay-io", "artifactory-cr"}
)
_CONTAINER_TYPES = frozenset({"dockerimage"})


def _extract_cves(vulns: list) -> list[dict]:
    """Extract a flat, deduplicated CVE list from a list of Vulnerability objects."""
    seen: set[str] = set()
    cve_rows: list[dict] = []

    for v in vulns:
        identifiers = getattr(v, "identifiers", None) or {}
        cve_ids: list[str] = identifiers.get("CVE", []) if isinstance(identifiers, dict) else []

        if not cve_ids:
            # Still include the finding keyed by Snyk ID so nothing is dropped
            cve_ids = [getattr(v, "id", "UNKNOWN")]

        for cve_id in cve_ids:
            key = f"{cve_id}::{getattr(v, 'package', '')}::{getattr(v, 'version', '')}"
            if key in seen:
                continue
            seen.add(key)
            cve_rows.append(
                {
                    "cve": cve_id,
                    "snyk_id": getattr(v, "id", None),
                    "title": getattr(v, "title", None),
                    "severity": getattr(v, "severity", None),
                    "cvss_score": getattr(v, "cvssScore", None),
                    "cvss_v3": getattr(v, "CVSSv3", None),
                    "package": getattr(v, "package", None),
                    "version": getattr(v, "version", None),
                    "is_upgradable": getattr(v, "isUpgradable", None),
                    "upgrade_path": getattr(v, "upgradePath", []),
                    "disclosure_time": getattr(v, "disclosureTime", None),
                    "publication_time": getattr(v, "publicationTime", None),
                    "exploit_maturity": getattr(v, "exploitMaturity", None),
                    "url": getattr(v, "url", None),
                }
            )

    return cve_rows


@mcp.tool()
def snyk_list_project_cves(
    org_id: str,
    project_id: str,
    severity_filter: list[str] | None = None,
    limit: int = 200,
) -> dict:
    """List CVE identifiers found in a Snyk project, with severity and fix info.

    Extracts CVE IDs from vulnerability identifiers and returns a flat, deduplicated
    list sorted by severity. Each row includes the CVE ID, CVSS score, affected
    package/version, upgrade path, and a link to the Snyk advisory.

    Args:
        org_id: The Snyk organization UUID.
        project_id: The Snyk project UUID.
        severity_filter: Only return CVEs at these severities, e.g. ['critical', 'high'].
        limit: Maximum CVE rows to return (default 200).
    """
    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        project = org.projects.get(project_id)
        vulns = project.vulnerabilities

        if severity_filter:
            vulns = [v for v in vulns if v.severity in severity_filter]

        cves = _extract_cves(vulns)
        cves.sort(key=lambda r: _SEVERITY_ORDER.get(r["severity"] or "", 99))
        cves = cves[:limit]

        summary = {
            "critical": sum(1 for c in cves if c["severity"] == "critical"),
            "high": sum(1 for c in cves if c["severity"] == "high"),
            "medium": sum(1 for c in cves if c["severity"] == "medium"),
            "low": sum(1 for c in cves if c["severity"] == "low"),
        }

        return {
            "org_id": org_id,
            "project_id": project_id,
            "count": len(cves),
            "summary": summary,
            "cves": cves,
        }

    return _safe_call(_run)


@mcp.tool()
def snyk_list_container_projects(
    org_id: str,
    limit: int = 100,
) -> dict:
    """List container image projects monitored in a Snyk organization.

    Filters projects to those with a container origin (Docker Hub, ACR, ECR, GCR,
    Quay, Harbor, etc.) or type 'dockerimage'. Returns project name, ID, origin,
    image details, and current issue counts by severity.

    Args:
        org_id: The Snyk organization UUID.
        limit: Maximum container projects to return (default 100).
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        all_projects = org.projects.all()

        container_projects = [
            p for p in all_projects
            if getattr(p, "origin", "") in _CONTAINER_ORIGINS
            or getattr(p, "type", "") in _CONTAINER_TYPES
        ][:limit]

        rows = []
        for p in container_projects:
            counts = getattr(p, "issueCountsBySeverity", None)
            rows.append(
                {
                    "id": p.id,
                    "name": p.name,
                    "origin": getattr(p, "origin", None),
                    "type": getattr(p, "type", None),
                    "is_monitored": getattr(p, "isMonitored", None),
                    "last_tested": getattr(p, "lastTestedDate", None),
                    "remote_repo_url": getattr(p, "remoteRepoUrl", None),
                    "issue_counts": {
                        "critical": getattr(counts, "critical", 0),
                        "high": getattr(counts, "high", 0),
                        "medium": getattr(counts, "medium", 0),
                        "low": getattr(counts, "low", 0),
                    } if counts else None,
                }
            )

        return {
            "org_id": org_id,
            "count": len(rows),
            "container_projects": rows,
        }

    return _safe_call(_run)


@mcp.tool()
def snyk_list_container_image_cves(
    org_id: str,
    project_id: str,
    severity_filter: list[str] | None = None,
    limit: int = 200,
) -> dict:
    """List CVEs found in a Snyk container image project.

    Identical to snyk_list_project_cves but validates that the project is a
    container image type before querying, and includes the image name/tag in
    the response for easier identification.

    Use snyk_list_container_projects first to find container project IDs.

    Args:
        org_id: The Snyk organization UUID.
        project_id: The Snyk project UUID (must be a container image project).
        severity_filter: Only return CVEs at these severities, e.g. ['critical', 'high'].
        limit: Maximum CVE rows to return (default 200).
    """
    _SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        project = org.projects.get(project_id)

        origin = getattr(project, "origin", "")
        proj_type = getattr(project, "type", "")
        is_container = origin in _CONTAINER_ORIGINS or proj_type in _CONTAINER_TYPES

        if not is_container:
            return {
                "error": "not_a_container_project",
                "message": (
                    f"Project '{project.name}' has origin='{origin}' type='{proj_type}'. "
                    "Use snyk_list_container_projects to find container image project IDs."
                ),
            }

        vulns = project.vulnerabilities
        if severity_filter:
            vulns = [v for v in vulns if v.severity in severity_filter]

        cves = _extract_cves(vulns)
        cves.sort(key=lambda r: _SEVERITY_ORDER.get(r["severity"] or "", 99))
        cves = cves[:limit]

        summary = {
            "critical": sum(1 for c in cves if c["severity"] == "critical"),
            "high": sum(1 for c in cves if c["severity"] == "high"),
            "medium": sum(1 for c in cves if c["severity"] == "medium"),
            "low": sum(1 for c in cves if c["severity"] == "low"),
        }

        return {
            "org_id": org_id,
            "project_id": project_id,
            "image_name": project.name,
            "origin": origin,
            "count": len(cves),
            "summary": summary,
            "cves": cves,
        }

    return _safe_call(_run)


# ---------------------------------------------------------------------------
# Dependencies & Licenses
# ---------------------------------------------------------------------------

@mcp.tool()
def snyk_list_dependencies(
    org_id: str,
    project_id: str | None = None,
    limit: int = 100,
) -> dict:
    """List package dependencies for an organization or a specific project.

    Returns package names, versions, licenses, and whether any versions have issues.

    Args:
        org_id: The Snyk organization UUID.
        project_id: Optional project UUID to narrow results to one project.
        limit: Maximum dependencies to return (default 100).
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)

        if project_id:
            project = org.projects.get(project_id)
            deps = project.dependencies.all()
        else:
            deps = org.dependencies.all()

        deps = deps[:limit]
        return {"count": len(deps), "dependencies": _jsonable(deps)}

    return _safe_call(_run)


@mcp.tool()
def snyk_list_org_licenses(
    org_id: str,
    severity_filter: list[str] | None = None,
    limit: int = 100,
) -> dict:
    """List licenses in use across an organization's projects.

    Useful for license compliance audits. Returns license type, severity,
    and which packages and projects use each license.

    Args:
        org_id: The Snyk organization UUID.
        severity_filter: Filter by severity, e.g. ['high', 'medium'].
        limit: Maximum license entries to return (default 100).
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        licenses = org.licenses.all()

        if severity_filter:
            licenses = [lic for lic in licenses if lic.severity in severity_filter]

        licenses = licenses[:limit]
        return {"count": len(licenses), "licenses": _jsonable(licenses)}

    return _safe_call(_run)


@mcp.tool()
def snyk_list_project_licenses(
    org_id: str,
    project_id: str,
    limit: int = 100,
) -> dict:
    """List licenses for packages used in a specific Snyk project.

    Args:
        org_id: The Snyk organization UUID.
        project_id: The Snyk project UUID.
        limit: Maximum license entries to return (default 100).
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        project = org.projects.get(project_id)
        licenses = project.licenses.all()[:limit]
        return {"count": len(licenses), "licenses": _jsonable(licenses)}

    return _safe_call(_run)


# ---------------------------------------------------------------------------
# Members
# ---------------------------------------------------------------------------

@mcp.tool()
def snyk_list_members(org_id: str) -> dict:
    """List all members of a Snyk organization.

    Returns member IDs, usernames, names, email addresses, and roles.

    Args:
        org_id: The Snyk organization UUID.
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        members = org.members.all()
        return {"count": len(members), "members": _jsonable(members)}

    return _safe_call(_run)


# ---------------------------------------------------------------------------
# Integrations
# ---------------------------------------------------------------------------

@mcp.tool()
def snyk_list_integrations(org_id: str) -> dict:
    """List source control and registry integrations active for an organization.

    Returns integration names and IDs (e.g. GitHub, Docker Hub, npm, etc.).

    Args:
        org_id: The Snyk organization UUID.
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        integrations = org.integrations.all()
        return {"count": len(integrations), "integrations": _jsonable(integrations)}

    return _safe_call(_run)


# ---------------------------------------------------------------------------
# Package Testing
# ---------------------------------------------------------------------------

@mcp.tool()
def snyk_test_npm_package(
    org_id: str,
    package_name: str,
    version: str,
) -> dict:
    """Test an npm package for known vulnerabilities.

    Args:
        org_id: The Snyk organization UUID to scope the test to.
        package_name: npm package name, e.g. 'lodash'.
        version: Package version, e.g. '4.17.15'.
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        result = org.test_npm(package_name, version)
        return {
            "ok": result.ok,
            "package": package_name,
            "version": version,
            "packageManager": result.packageManager,
            "dependencyCount": result.dependencyCount,
            "issue_summary": {
                "vulnerabilities": len(result.issues.vulnerabilities),
                "licenses": len(result.issues.licenses),
            },
            "issues": _jsonable(result.issues),
        }

    return _safe_call(_run)


@mcp.tool()
def snyk_test_python_package(
    org_id: str,
    package_name: str,
    version: str,
) -> dict:
    """Test a Python (PyPI) package for known vulnerabilities.

    Args:
        org_id: The Snyk organization UUID to scope the test to.
        package_name: PyPI package name, e.g. 'flask'.
        version: Package version, e.g. '2.3.0'.
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        result = org.test_python(package_name, version)
        return {
            "ok": result.ok,
            "package": package_name,
            "version": version,
            "packageManager": result.packageManager,
            "dependencyCount": result.dependencyCount,
            "issue_summary": {
                "vulnerabilities": len(result.issues.vulnerabilities),
                "licenses": len(result.issues.licenses),
            },
            "issues": _jsonable(result.issues),
        }

    return _safe_call(_run)


@mcp.tool()
def snyk_test_maven_package(
    org_id: str,
    group_id: str,
    artifact_id: str,
    version: str,
) -> dict:
    """Test a Maven (Java) artifact for known vulnerabilities.

    Args:
        org_id: The Snyk organization UUID to scope the test to.
        group_id: Maven group ID, e.g. 'org.apache.logging.log4j'.
        artifact_id: Maven artifact ID, e.g. 'log4j-core'.
        version: Artifact version, e.g. '2.14.1'.
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        result = org.test_maven(group_id, artifact_id, version)
        return {
            "ok": result.ok,
            "artifact": f"{group_id}:{artifact_id}",
            "version": version,
            "packageManager": result.packageManager,
            "dependencyCount": result.dependencyCount,
            "issue_summary": {
                "vulnerabilities": len(result.issues.vulnerabilities),
                "licenses": len(result.issues.licenses),
            },
            "issues": _jsonable(result.issues),
        }

    return _safe_call(_run)


@mcp.tool()
def snyk_test_rubygem_package(
    org_id: str,
    gem_name: str,
    version: str,
) -> dict:
    """Test a Ruby gem for known vulnerabilities.

    Args:
        org_id: The Snyk organization UUID to scope the test to.
        gem_name: Ruby gem name, e.g. 'rails'.
        version: Gem version, e.g. '6.1.4'.
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        result = org.test_rubygem(gem_name, version)
        return {
            "ok": result.ok,
            "gem": gem_name,
            "version": version,
            "packageManager": result.packageManager,
            "dependencyCount": result.dependencyCount,
            "issue_summary": {
                "vulnerabilities": len(result.issues.vulnerabilities),
                "licenses": len(result.issues.licenses),
            },
            "issues": _jsonable(result.issues),
        }

    return _safe_call(_run)


# ---------------------------------------------------------------------------
# Tags
# ---------------------------------------------------------------------------

@mcp.tool()
def snyk_list_project_tags(
    org_id: str,
    project_id: str,
) -> dict:
    """List tags applied to a Snyk project.

    Tags are key/value pairs used for filtering and organising projects.
    Common uses include environment (prod/staging), team ownership, and criticality.

    Args:
        org_id: The Snyk organization UUID.
        project_id: The Snyk project UUID.
    """
    def _run() -> dict:
        client = get_client()
        org = client.organizations.get(org_id)
        project = org.projects.get(project_id)
        tags = project.tags.all()
        return {"count": len(tags), "tags": _jsonable(tags)}

    return _safe_call(_run)


# ---------------------------------------------------------------------------
# User / Health
# ---------------------------------------------------------------------------

@mcp.tool()
def snyk_get_user_info() -> dict:
    """Return details about the authenticated Snyk user (sanity / health check).

    Useful for verifying the API token is valid and checking which user
    account is associated with the token.
    """
    def _run() -> dict:
        client = get_client()
        # The v1 /user/me endpoint
        response = client.get("user/me")
        return _jsonable(response.json())

    return _safe_call(_run)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    """Console entrypoint. Selects transport based on TRANSPORT env var."""
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    transport = os.environ.get("TRANSPORT", "stdio").lower()
    if transport == "stdio":
        logger.info("Starting pysnyk-mcp on stdio transport")
        mcp.run(transport="stdio")
    elif transport in ("http", "sse"):
        host = os.environ.get("HTTP_HOST", "0.0.0.0")
        port = int(os.environ.get("HTTP_PORT", "8000"))
        mcp.settings.host = host
        mcp.settings.port = port
        logger.info("Starting pysnyk-mcp on SSE transport at %s:%d", host, port)
        mcp.run(transport="sse")
    else:
        raise SystemExit(
            f"Unknown TRANSPORT={transport!r}. Use 'stdio' or 'http'."
        )


if __name__ == "__main__":
    main()
