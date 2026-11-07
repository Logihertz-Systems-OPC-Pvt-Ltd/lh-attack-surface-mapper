# ==============================================================================
# Product:       lh-attack-surface-mapper (lh-attack)
# Module:        tests.test_surface_analyzer
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for attack surface risk analyzer evaluating rules LH-ASM-001 to 010."""

from __future__ import annotations

from pathlib import Path

from lh_attack_surface_mapper.models import (
    RULES_REGISTRY,
    FindingSeverity,
    PerimeterAsset,
    PerimeterAssetType,
    PerimeterPort,
)
from lh_attack_surface_mapper.surface_analyzer import (
    analyze_perimeter_asset,
    audit_perimeter_surface,
)

# --------------------------------------------------------------------------
# --- Rule LH-ASM-001: Exposed Database or Cache on Public Perimeter (CRITICAL) ---
# Evaluates security posture against exposed database or cache on public
# perimeter.
# Rationale: Prevents policy violations and reduces vulnerable surface exposure.
# False Positive Defense: Contextual inspection ensures intentional configs are
# respected.
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# --- Rule LH-ASM-010: Verbose Server Banner Leakage (LOW) ---
# Evaluates security posture against verbose server banner leakage.
# Rationale: Prevents policy violations and reduces vulnerable surface exposure.
# False Positive Defense: Contextual inspection ensures intentional configs are
# respected.
# --------------------------------------------------------------------------


def test_rules_registry_has_ten_rules() -> None:
    """Verify rules LH-ASM-001 through LH-ASM-010 are registered."""
    for i in range(1, 11):
        rule_id = f"LH-ASM-{i:03d}"
        assert rule_id in RULES_REGISTRY
        assert RULES_REGISTRY[rule_id].title
        assert RULES_REGISTRY[rule_id].remediation


def test_analyze_vulnerable_perimeter_manifest(vulnerable_perimeter_manifest: Path) -> None:
    """Validate detection of all 10 rules across vulnerable assets."""
    report = audit_perimeter_surface(vulnerable_perimeter_manifest)
    rule_ids = {f.rule_id for f in report.findings}

    assert "LH-ASM-001" in rule_ids  # PostgreSQL 5432
    assert "LH-ASM-002" in rule_ids  # SSH 22
    assert "LH-ASM-003" in rule_ids  # Dangling CNAME to S3
    assert "LH-ASM-004" in rule_ids  # Public cloud storage bucket
    assert "LH-ASM-005" in rule_ids  # dev.example.com unmanaged
    assert "LH-ASM-006" in rule_ids  # HTTP 80 without redirect, FTP 21
    assert "LH-ASM-007" in rule_ids  # direct origin accessible, no WAF
    assert "LH-ASM-008" in rule_ids  # /admin, /actuator, /.env
    assert "LH-ASM-009" in rule_ids  # TLSv1.0, self-signed, 5 days expiry
    assert "LH-ASM-010" in rule_ids  # Apache/2.4.41 banner, missing owner

    assert report.risk_score > 50.0


def test_analyze_clean_perimeter(clean_perimeter_project: Path) -> None:
    """Verify clean perimeter produces zero findings and zero risk score."""
    report = audit_perimeter_surface(clean_perimeter_project)
    assert report.findings_count == 0
    assert report.risk_score == 0.0


def test_exposed_redis_and_k8s_ports() -> None:
    """Test individual port detections for Redis (6379) and K8s API (6443)."""
    asset = PerimeterAsset(
        identifier="internal-cluster.org",
        ports=[
            PerimeterPort(port=6379, service_name="redis"),
            PerimeterPort(port=6443, service_name="k8s"),
        ],
        owner="ops@org.com",
    )
    findings = analyze_perimeter_asset(asset)
    rule_ids = {f.rule_id for f in findings}
    assert "LH-ASM-001" in rule_ids
    assert "LH-ASM-002" in rule_ids
    # --------------------------------------------------------------------------
    # --- Rule LH-ASM-003: Dangling Subdomain / Subdomain Takeover Vector (CRITICAL) ---
    # Evaluates security posture against dangling subdomain / subdomain takeover
    # vector.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_subdomain_takeover_cname() -> None:
    """Test subdomain takeover vector (LH-ASM-003)."""
    asset = PerimeterAsset(
        identifier="docs.example.com",
        asset_type=PerimeterAssetType.SUBDOMAIN,
        cname="corp-docs.github.io",
        dns_status="unclaimed",
        owner="docs-team",
    )
    findings = analyze_perimeter_asset(asset)
    rule_ids = {f.rule_id for f in findings}
    assert "LH-ASM-003" in rule_ids
    assert any(f.severity == FindingSeverity.CRITICAL for f in findings)
    # --------------------------------------------------------------------------
    # --- Rule LH-ASM-004: Publicly Exposed Cloud Storage Bucket (CRITICAL) ---
    # Evaluates security posture against publicly exposed cloud storage bucket.
    # Rationale: Prevents policy violations and reduces vulnerable surface exposure.
    # False Positive Defense: Contextual inspection ensures intentional configs are
    # respected.
    # --------------------------------------------------------------------------


def test_storage_bucket_exposure() -> None:
    """Test public storage bucket exposure (LH-ASM-004)."""
    asset = PerimeterAsset(
        identifier="customer-data-bucket",
        asset_type=PerimeterAssetType.STORAGE_BUCKET,
        public_access=True,
        anonymous_write=True,
        owner="data-team",
    )
    findings = analyze_perimeter_asset(asset)
    rule_ids = {f.rule_id for f in findings}
    assert "LH-ASM-004" in rule_ids
