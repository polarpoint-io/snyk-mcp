"""Tests for pysnyk-mcp tools using a mocked Snyk client."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Minimal stubs to avoid requiring a live SNYK_TOKEN during tests
# ---------------------------------------------------------------------------


@dataclass
class StubIssueData:
    id: str = "SNYK-JS-LODASH-1018905"
    title: str = "Prototype Pollution"
    severity: str = "high"
    url: str = "https://security.snyk.io/vuln/SNYK-JS-LODASH-1018905"
    exploitMaturity: str = "proof-of-concept"
    description: Optional[str] = "Prototype Pollution vulnerability"
    identifiers: Any = None
    credit: Optional[List[str]] = None
    semver: Any = None
    publicationTime: Optional[str] = "2019-07-26T00:00:00Z"
    disclosureTime: Optional[str] = "2019-07-26T00:00:00Z"
    CVSSv3: Optional[str] = None
    cvssScore: Optional[str] = "7.5"
    cvssDetails: Optional[List[Any]] = None
    language: Optional[str] = "js"
    patches: Optional[Any] = None
    nearestFixedInVersion: Optional[str] = None
    ignoreReasons: Optional[List[Any]] = None


@dataclass
class StubFixInfo:
    isUpgradable: bool = True
    isPinnable: bool = False
    isPatchable: bool = False
    isFixable: bool = True
    isPartiallyFixable: bool = False
    nearestFixedInVersion: str = "4.17.21"
    fixedIn: Optional[List[str]] = field(default_factory=lambda: ["4.17.21"])


@dataclass
class StubAggregatedIssue:
    id: str = "SNYK-JS-LODASH-1018905"
    issueType: str = "vuln"
    pkgName: str = "lodash"
    pkgVersions: List[str] = field(default_factory=lambda: ["4.17.15"])
    issueData: StubIssueData = field(default_factory=StubIssueData)
    isPatched: bool = False
    isIgnored: bool = False
    fixInfo: StubFixInfo = field(default_factory=StubFixInfo)
    introducedThrough: Optional[List[Any]] = None
    ignoreReasons: Optional[List[Any]] = None
    priorityScore: Optional[int] = 714
    priority: Optional[Any] = None


@dataclass
class StubIssueSetAggregated:
    issues: List[StubAggregatedIssue] = field(
        default_factory=lambda: [StubAggregatedIssue()]
    )


@dataclass
class StubIssueCounts:
    low: int = 0
    medium: int = 1
    high: int = 2
    critical: int = 0


@dataclass
class StubOrganizationGroup:
    name: str = "Test Group"
    id: str = "group-123"


@dataclass
class StubOrganization:
    name: str = "test-org"
    id: str = "org-123"
    slug: str = "test-org"
    url: str = "https://app.snyk.io/org/test-org"
    group: Optional[StubOrganizationGroup] = field(
        default_factory=StubOrganizationGroup
    )
    client: Optional[Any] = None


@dataclass
class StubProject:
    name: str = "my-project"
    id: str = "proj-456"
    created: str = "2024-01-01T00:00:00Z"
    origin: str = "github"
    type: str = "npm"
    readOnly: bool = False
    testFrequency: str = "daily"
    lastTestedDate: str = "2024-06-01T00:00:00Z"
    isMonitored: bool = True
    issueCountsBySeverity: StubIssueCounts = field(default_factory=StubIssueCounts)
    organization: Optional[StubOrganization] = field(default_factory=StubOrganization)


@dataclass
class StubMember:
    id: str = "user-789"
    username: str = "johndoe"
    name: str = "John Doe"
    email: str = "john@example.com"
    role: str = "admin"


@dataclass
class StubIntegration:
    name: str = "github"
    id: str = "integ-101"


@dataclass
class StubLicense:
    id: str = "MIT"
    dependencies: List[Any] = field(default_factory=list)
    projects: List[Any] = field(default_factory=list)
    severity: Optional[str] = "none"


@dataclass
class StubDependency:
    id: str = "lodash@4.17.15"
    name: str = "lodash"
    version: str = "4.17.15"
    licenses: List[Any] = field(default_factory=list)
    projects: List[Any] = field(default_factory=list)


# Stub for issue set (package testing)
@dataclass
class StubIssue:
    vulnerabilities: List[Any] = field(default_factory=list)
    licenses: List[Any] = field(default_factory=list)


@dataclass
class StubIssueSet:
    ok: bool = True
    packageManager: str = "npm"
    dependencyCount: int = 10
    issues: StubIssue = field(default_factory=StubIssue)


def _make_mock_manager(items):
    """Create a mock manager that returns given items for .all() and .filter()."""
    manager = MagicMock()
    manager.all.return_value = items
    manager.filter.return_value = MagicMock(issues=items)
    return manager


def _make_mock_org(
    org_id="org-123",
    projects=None,
    members=None,
    licenses=None,
    dependencies=None,
    integrations=None,
):
    org = MagicMock()
    org.id = org_id
    org.name = "test-org"
    org.slug = "test-org"
    org.url = "https://app.snyk.io/org/test-org"

    stub_project = MagicMock()
    stub_project.name = "my-project"
    stub_project.id = "proj-456"
    stub_project.created = "2024-01-01T00:00:00Z"
    stub_project.origin = "github"
    stub_project.type = "npm"
    stub_project.readOnly = False
    stub_project.testFrequency = "daily"
    stub_project.lastTestedDate = "2024-06-01T00:00:00Z"
    stub_project.isMonitored = True
    stub_project.issueCountsBySeverity = StubIssueCounts()
    stub_project.organization = MagicMock(id=org_id, name="test-org")

    agg_issue = StubAggregatedIssue()
    stub_issueset = MagicMock()
    stub_issueset.issues = [agg_issue]
    stub_project.issueset_aggregated = MagicMock()
    stub_project.issueset_aggregated.filter.return_value = stub_issueset
    stub_project.vulnerabilities = []
    stub_project.dependencies = _make_mock_manager([StubDependency()])
    stub_project.licenses = _make_mock_manager([StubLicense()])
    stub_project.tags = _make_mock_manager([{"key": "env", "value": "prod"}])
    stub_project.dependency_graph = {"schemaVersion": "1.2.0", "pkgManager": {"name": "npm"}, "pkgs": [], "graph": {"rootNodeId": "root-node", "nodes": []}}

    org.projects = MagicMock()
    org.projects.all.return_value = projects if projects is not None else [stub_project]
    org.projects.get.return_value = stub_project

    org.members = _make_mock_manager(members if members is not None else [StubMember()])
    org.licenses = _make_mock_manager(licenses if licenses is not None else [StubLicense()])
    org.dependencies = _make_mock_manager(
        dependencies if dependencies is not None else [StubDependency()]
    )
    org.integrations = _make_mock_manager(
        integrations if integrations is not None else [StubIntegration()]
    )
    org.test_npm.return_value = StubIssueSet()
    org.test_python.return_value = StubIssueSet()
    org.test_maven.return_value = StubIssueSet()
    org.test_rubygem.return_value = StubIssueSet()

    return org


def _make_mock_client():
    client = MagicMock()
    mock_org = _make_mock_org()
    client.organizations.all.return_value = [mock_org]
    client.organizations.get.return_value = mock_org
    client.projects.all.return_value = []
    user_response = MagicMock()
    user_response.json.return_value = {
        "id": "user-123",
        "username": "testuser",
        "email": "test@example.com",
        "name": "Test User",
    }
    client.get.return_value = user_response
    return client


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_organizations(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_organizations

    result = snyk_list_organizations()
    assert "count" in result
    assert result["count"] == 1
    assert "organizations" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_get_organization(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_get_organization

    result = snyk_get_organization("org-123")
    assert result is not None


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_projects(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_projects

    result = snyk_list_projects(org_id="org-123")
    assert "count" in result
    assert "projects" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_projects_with_name_filter(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_projects

    # Filter that matches
    result = snyk_list_projects(org_id="org-123", name_filter="my-project")
    assert result["count"] == 1

    # Filter that doesn't match
    result = snyk_list_projects(org_id="org-123", name_filter="nonexistent")
    assert result["count"] == 0


@patch("pysnyk_mcp.server.get_client")
def test_snyk_get_project(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_get_project

    result = snyk_get_project("org-123", "proj-456")
    assert result is not None


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_project_vulnerabilities(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_project_vulnerabilities

    result = snyk_list_project_vulnerabilities("org-123", "proj-456")
    assert "count" in result
    assert "summary" in result
    assert "vulnerabilities" in result
    assert "critical" in result["summary"]


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_aggregated_issues(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_aggregated_issues

    result = snyk_list_aggregated_issues("org-123", "proj-456")
    assert "count" in result
    assert "issues" in result
    assert result["count"] == 1


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_aggregated_issues_severity_filter(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_aggregated_issues

    result = snyk_list_aggregated_issues("org-123", "proj-456", severity_filter=["high"])
    assert "count" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_dependencies(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_dependencies

    result = snyk_list_dependencies("org-123")
    assert "count" in result
    assert "dependencies" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_org_licenses(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_org_licenses

    result = snyk_list_org_licenses("org-123")
    assert "count" in result
    assert "licenses" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_members(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_members

    result = snyk_list_members("org-123")
    assert "count" in result
    assert result["count"] == 1
    assert "members" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_integrations(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_integrations

    result = snyk_list_integrations("org-123")
    assert "count" in result
    assert "integrations" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_test_npm_package(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_test_npm_package

    result = snyk_test_npm_package("org-123", "lodash", "4.17.15")
    assert "ok" in result
    assert result["package"] == "lodash"
    assert result["version"] == "4.17.15"
    assert "issue_summary" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_test_python_package(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_test_python_package

    result = snyk_test_python_package("org-123", "flask", "2.3.0")
    assert "ok" in result
    assert result["package"] == "flask"
    assert "issue_summary" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_test_maven_package(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_test_maven_package

    result = snyk_test_maven_package(
        "org-123",
        "org.apache.logging.log4j",
        "log4j-core",
        "2.14.1",
    )
    assert "ok" in result
    assert "log4j-core" in result["artifact"]
    assert "issue_summary" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_test_rubygem_package(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_test_rubygem_package

    result = snyk_test_rubygem_package("org-123", "rails", "6.1.4")
    assert "ok" in result
    assert result["gem"] == "rails"
    assert "issue_summary" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_project_tags(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_project_tags

    result = snyk_list_project_tags("org-123", "proj-456")
    assert "count" in result
    assert "tags" in result


@patch("pysnyk_mcp.server.get_client")
def test_snyk_get_user_info(mock_get_client):
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_get_user_info

    result = snyk_get_user_info()
    assert "id" in result
    assert result["username"] == "testuser"


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_projects_no_org(mock_get_client):
    """Test listing all projects across orgs when no org_id given."""
    mock_get_client.return_value = _make_mock_client()
    from pysnyk_mcp.server import snyk_list_projects

    result = snyk_list_projects()
    assert "count" in result
    assert "projects" in result


# ---------------------------------------------------------------------------
# CVE and container image tests
# ---------------------------------------------------------------------------

def _make_stub_vulnerability(
    snyk_id="SNYK-JS-LODASH-1018905",
    title="Prototype Pollution",
    severity="high",
    package="lodash",
    version="4.17.15",
    cve_ids=None,
    cvss_score="7.5",
    is_upgradable=True,
    upgrade_path=None,
):
    """Build a minimal MagicMock that looks like a pysnyk Vulnerability."""
    vuln = MagicMock()
    vuln.id = snyk_id
    vuln.title = title
    vuln.severity = severity
    vuln.package = package
    vuln.version = version
    vuln.cvssScore = cvss_score
    vuln.CVSSv3 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    vuln.isUpgradable = is_upgradable
    vuln.upgradePath = upgrade_path or ["lodash@4.17.21"]
    vuln.disclosureTime = "2019-07-26T00:00:00Z"
    vuln.publicationTime = "2019-07-26T00:00:00Z"
    vuln.exploitMaturity = "proof-of-concept"
    vuln.url = f"https://security.snyk.io/vuln/{snyk_id}"
    vuln.identifiers = {"CVE": cve_ids or ["CVE-2019-10744"], "CWE": ["CWE-400"]}
    return vuln


def _make_container_mock_client(origin="docker-hub", is_container=True):
    """Client whose first project is a container image project."""
    client = MagicMock()

    stub_vuln = _make_stub_vulnerability(
        snyk_id="SNYK-DEBIAN-LIBSSL-12345",
        title="Memory Corruption",
        severity="critical",
        package="libssl",
        version="1.1.1",
        cve_ids=["CVE-2021-3450"],
        cvss_score="9.1",
    )

    stub_project = MagicMock()
    stub_project.name = "nginx:1.21"
    stub_project.id = "proj-container-001"
    stub_project.origin = origin if is_container else "github"
    stub_project.type = "dockerimage" if is_container else "npm"
    stub_project.isMonitored = True
    stub_project.lastTestedDate = "2024-06-01T00:00:00Z"
    stub_project.remoteRepoUrl = None
    counts = MagicMock()
    counts.critical = 1
    counts.high = 3
    counts.medium = 5
    counts.low = 2
    stub_project.issueCountsBySeverity = counts
    stub_project.vulnerabilities = [stub_vuln]

    mock_org = MagicMock()
    mock_org.id = "org-123"
    mock_org.projects.all.return_value = [stub_project]
    mock_org.projects.get.return_value = stub_project

    client.organizations.get.return_value = mock_org
    return client


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_project_cves(mock_get_client):
    """CVE list should contain CVE IDs, severity and package info."""
    client = _make_mock_client()
    # Give the project a real vulnerability with CVE identifiers
    stub_vuln = _make_stub_vulnerability()
    client.organizations.get.return_value.projects.get.return_value.vulnerabilities = [stub_vuln]
    mock_get_client.return_value = client

    from pysnyk_mcp.server import snyk_list_project_cves

    result = snyk_list_project_cves("org-123", "proj-456")
    assert "count" in result
    assert "summary" in result
    assert "cves" in result
    assert result["count"] == 1
    cve = result["cves"][0]
    assert cve["cve"] == "CVE-2019-10744"
    assert cve["severity"] == "high"
    assert cve["package"] == "lodash"
    assert cve["cvss_score"] == "7.5"


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_project_cves_severity_filter(mock_get_client):
    """Severity filter should exclude non-matching vulns."""
    client = _make_mock_client()
    high_vuln = _make_stub_vulnerability(severity="high", cve_ids=["CVE-2019-10744"])
    low_vuln = _make_stub_vulnerability(
        snyk_id="SNYK-JS-OTHER-111", severity="low",
        package="other", version="1.0.0", cve_ids=["CVE-2020-9999"]
    )
    client.organizations.get.return_value.projects.get.return_value.vulnerabilities = [high_vuln, low_vuln]
    mock_get_client.return_value = client

    from pysnyk_mcp.server import snyk_list_project_cves

    result = snyk_list_project_cves("org-123", "proj-456", severity_filter=["high"])
    assert result["count"] == 1
    assert result["cves"][0]["cve"] == "CVE-2019-10744"


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_project_cves_no_cve_id(mock_get_client):
    """Vulns with no CVE identifier should still appear keyed by Snyk ID."""
    client = _make_mock_client()
    vuln = _make_stub_vulnerability(cve_ids=[])
    vuln.identifiers = {"CWE": ["CWE-400"]}  # no CVE key
    client.organizations.get.return_value.projects.get.return_value.vulnerabilities = [vuln]
    mock_get_client.return_value = client

    from pysnyk_mcp.server import snyk_list_project_cves

    result = snyk_list_project_cves("org-123", "proj-456")
    assert result["count"] == 1
    assert result["cves"][0]["cve"] == "SNYK-JS-LODASH-1018905"


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_container_projects(mock_get_client):
    """Container projects should be identified by origin."""
    mock_get_client.return_value = _make_container_mock_client(origin="docker-hub")

    from pysnyk_mcp.server import snyk_list_container_projects

    result = snyk_list_container_projects("org-123")
    assert "count" in result
    assert result["count"] == 1
    proj = result["container_projects"][0]
    assert proj["origin"] == "docker-hub"
    assert proj["name"] == "nginx:1.21"
    assert proj["issue_counts"]["critical"] == 1


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_container_projects_excludes_non_container(mock_get_client):
    """Non-container projects (e.g. npm) should not appear in the list."""
    mock_get_client.return_value = _make_container_mock_client(is_container=False)

    from pysnyk_mcp.server import snyk_list_container_projects

    result = snyk_list_container_projects("org-123")
    assert result["count"] == 0


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_container_image_cves(mock_get_client):
    """Container CVEs should include image name, origin and CVE details."""
    mock_get_client.return_value = _make_container_mock_client(origin="docker-hub")

    from pysnyk_mcp.server import snyk_list_container_image_cves

    result = snyk_list_container_image_cves("org-123", "proj-container-001")
    assert result["count"] == 1
    assert result["image_name"] == "nginx:1.21"
    assert result["origin"] == "docker-hub"
    cve = result["cves"][0]
    assert cve["cve"] == "CVE-2021-3450"
    assert cve["severity"] == "critical"


@patch("pysnyk_mcp.server.get_client")
def test_snyk_list_container_image_cves_rejects_non_container(mock_get_client):
    """Calling the container CVE tool on an npm project should return a clear error."""
    mock_get_client.return_value = _make_container_mock_client(is_container=False)

    from pysnyk_mcp.server import snyk_list_container_image_cves

    result = snyk_list_container_image_cves("org-123", "proj-container-001")
    assert result["error"] == "not_a_container_project"
    assert "snyk_list_container_projects" in result["message"]


@patch("pysnyk_mcp.server.get_client")
def test_configuration_error_surfaces_cleanly(mock_get_client):
    """Test that a SnykConfigError is returned as a dict not raised."""
    from pysnyk_mcp.client import SnykConfigError

    mock_get_client.side_effect = SnykConfigError("SNYK_TOKEN is required")
    from pysnyk_mcp.server import snyk_list_organizations

    result = snyk_list_organizations()
    assert result["error"] == "configuration"
    assert "SNYK_TOKEN" in result["message"]


@patch("pysnyk_mcp.server.get_client")
def test_generic_error_surfaces_cleanly(mock_get_client):
    """Test that unexpected errors are caught and returned gracefully."""
    mock_get_client.side_effect = RuntimeError("Network timeout")
    from pysnyk_mcp.server import snyk_list_organizations

    result = snyk_list_organizations()
    assert result["error"] == "RuntimeError"
    assert "Network timeout" in result["message"]
