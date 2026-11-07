# ==============================================================================
# Product:       lh-attack-surface-mapper (lh-attack)
# Module:        tests.test_exporters
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for Rich table, JSON, and SARIF report exporters."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console

from lh_attack_surface_mapper.exporters import (
    export_json,
    export_sarif,
    render_table_report,
    severity_to_sarif_level,
    severity_to_style,
)
from lh_attack_surface_mapper.models import (
    FindingSeverity,
    SurfaceFinding,
    SurfaceReport,
)


def _sample_report(has_findings: bool = True) -> SurfaceReport:
    findings: list[SurfaceFinding] = []
    if has_findings:
        findings.append(
            SurfaceFinding(
                rule_id="LH-ASM-001",
                severity=FindingSeverity.CRITICAL,
                category="Data Store Exposure",
                target_asset="db.example.com",
                title="Exposed Database Service on Public Perimeter",
                description="PostgreSQL port 5432 is open to the public internet",
                remediation="Move database to private subnet",
                evidence="Port 5432/tcp (postgresql)",
            )
        )
    return SurfaceReport(
        target="perimeter.yaml",
        files_scanned=1,
        assets_mapped=1,
        findings_count=len(findings),
        findings=findings,
    )


def test_render_table_report_with_findings() -> None:
    """Test Rich table rendering with findings."""
    buf = StringIO()
    con = Console(file=buf, width=160)
    report = _sample_report(has_findings=True)
    render_table_report(report, console=con)
    output = buf.getvalue()
    assert "LH-ASM-001" in output
    assert "db.example.com" in output
    assert "CRITICAL" in output


def test_render_table_report_clean() -> None:
    """Test Rich table rendering for clean scan."""
    buf = StringIO()
    con = Console(file=buf, width=160)
    report = _sample_report(has_findings=False)
    render_table_report(report, console=con)
    output = buf.getvalue()
    assert "Perimeter Clean" in output


def test_export_json_schema() -> None:
    """Test JSON export schema structure."""
    report = _sample_report(has_findings=True)
    raw_json = export_json(report)
    data = json.loads(raw_json)

    assert data["schema_version"] == "1.0.0"
    assert data["scanner"] == "lh-attack-surface-mapper"
    assert data["assets_mapped"] == 1
    assert data["risk_score"] > 0
    assert len(data["findings"]) == 1
    f = data["findings"][0]
    assert f["rule_id"] == "LH-ASM-001"
    assert f["target_asset"] == "db.example.com"


def test_export_sarif_schema() -> None:
    """Test OASIS SARIF v2.1.0 export."""
    report = _sample_report(has_findings=True)
    raw_sarif = export_sarif(report)
    data = json.loads(raw_sarif)

    assert data["version"] == "2.1.0"
    assert len(data["runs"]) == 1
    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "lh-attack-surface-mapper"
    assert len(driver["rules"]) == 10

    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "LH-ASM-001"
    assert results[0]["level"] == "error"


def test_severity_helpers() -> None:
    """Test severity to styling and SARIF level mappings."""
    assert severity_to_style(FindingSeverity.CRITICAL) == "bold red"
    assert severity_to_style(FindingSeverity.LOW) == "blue"
    assert severity_to_sarif_level(FindingSeverity.CRITICAL) == "error"
    assert severity_to_sarif_level(FindingSeverity.MEDIUM) == "warning"
    assert severity_to_sarif_level(FindingSeverity.LOW) == "note"
