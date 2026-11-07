# ==============================================================================
# Product:       lh-attack-surface-mapper (lh-attack)
# Module:        src.lh_attack_surface_mapper.models
# Role:          Data Models & Rule Definitions
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Data models and rule definitions for lh-attack-surface-mapper."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class FindingSeverity(StrEnum):
    # --- Severity Rank & Weighting Structure ---
    # Defines discrete security tiers for findings and threshold gating.
    # Higher ordinal rankings enforce stricter build break / fail-on gates.
    """Severity ratings for attack surface findings."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def level(self) -> int:
        """Numeric rank for threshold comparison."""
        ranks = {
            FindingSeverity.CRITICAL: 4,
            FindingSeverity.HIGH: 3,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 1,
        }
        return ranks.get(self, 0)

    @classmethod
    def from_string(cls, val: str) -> FindingSeverity:
        """Convert string to FindingSeverity case-insensitively."""
        normalized = val.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        return cls.LOW

    def meets_threshold(self, threshold: FindingSeverity) -> bool:
        """Return True if this severity meets or exceeds threshold."""
        return self.level >= threshold.level


class PerimeterAssetType(StrEnum):
    """Types of external attack surface assets."""

    HOST = "Host"
    SUBDOMAIN = "Subdomain"
    STORAGE_BUCKET = "Storage Bucket"
    API_ENDPOINT = "API Endpoint"
    GENERIC = "Generic Asset"


@dataclass
class PerimeterPort:
    """Network port and active service running on a perimeter asset."""

    port: int
    protocol: str = "tcp"
    service_name: str = ""
    state: str = "open"
    banner: str = ""
    https_redirect: bool = False


@dataclass
class PerimeterAsset:
    """External internet-facing perimeter asset definition."""

    identifier: str
    asset_type: PerimeterAssetType = PerimeterAssetType.HOST
    ip_addresses: list[str] = field(default_factory=list)
    ports: list[PerimeterPort] = field(default_factory=list)
    cname: str | None = None
    dns_status: str | None = None
    waf_enabled: bool | None = None
    direct_origin_accessible: bool = False
    public_access: bool = True
    anonymous_read: bool = False
    anonymous_write: bool = False
    managed: bool = True
    environment: str = "production"
    endpoints: list[str] = field(default_factory=list)
    tls_versions: list[str] = field(default_factory=list)
    self_signed_cert: bool = False
    cert_expiry_days: int | None = None
    server_banner: str = ""
    owner: str | None = None
    contact: str | None = None
    source_file: str = ""


@dataclass
class SurfaceFinding:
    """Attack surface risk or misconfiguration finding."""

    rule_id: str
    severity: FindingSeverity
    category: str
    target_asset: str
    title: str
    description: str
    remediation: str
    evidence: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert finding into dictionary format."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "category": self.category,
            "target_asset": self.target_asset,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }


@dataclass
class SurfaceReport:
    """Aggregated attack surface audit and exposure report."""

    target: str
    files_scanned: int
    assets_mapped: int
    findings_count: int
    findings: list[SurfaceFinding]
    risk_score: float = 0.0
    summary: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.summary:
            crit = sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)
            hi = sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)
            med = sum(1 for f in self.findings if f.severity == FindingSeverity.MEDIUM)
            lo = sum(1 for f in self.findings if f.severity == FindingSeverity.LOW)
            self.summary = {"critical": crit, "high": hi, "medium": med, "low": lo}
            # Calculate composite perimeter risk score (0 to 100)
            raw = (crit * 25.0) + (hi * 10.0) + (med * 4.0) + (lo * 1.0)
            self.risk_score = min(100.0, round(raw, 1))


@dataclass
class SurfaceRuleDefinition:
    """Specification of an attack surface audit detection rule."""

    rule_id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    remediation: str


RULES_REGISTRY: dict[str, SurfaceRuleDefinition] = {
    "LH-ASM-001": SurfaceRuleDefinition(
        rule_id="LH-ASM-001",
        title="Exposed Database or Cache Service on Public Perimeter",
        severity=FindingSeverity.CRITICAL,
        category="Data Store Exposure",
        description=(
            "Detects open public ports for PostgreSQL (5432), MySQL (3306), Redis (6379), "
            "MongoDB (27017), Elasticsearch (9200), or Memcached (11211) on perimeter hosts."
        ),
        remediation="Isolate database services inside private subnets behind VPC security groups.",
    ),
    "LH-ASM-002": SurfaceRuleDefinition(
        rule_id="LH-ASM-002",
        title="Exposed Remote Management or Control Plane Port",
        severity=FindingSeverity.CRITICAL,
        category="Remote Access",
        description=(
            "Detects internet-facing SSH (22), Telnet (23), RDP (3389), VNC (5900), Docker "
            "(2375), or Kubernetes API (6443) without zero-trust or bastion restrictions."
        ),
        remediation="Enforce VPN/bastion access and disable direct public management listeners.",
    ),
    "LH-ASM-003": SurfaceRuleDefinition(
        rule_id="LH-ASM-003",
        title="Dangling Subdomain / Subdomain Takeover Vector",
        severity=FindingSeverity.CRITICAL,
        category="DNS Hygiene",
        description=(
            "Detects CNAME records pointing to deprovisioned or unclaimed cloud services "
            "(e.g., S3, Azure Websites, GitHub Pages, Heroku) with dangling status."
        ),
        remediation="Remove orphaned CNAME records or claim the destination third-party resource.",
    ),
    "LH-ASM-004": SurfaceRuleDefinition(
        rule_id="LH-ASM-004",
        title="Publicly Exposed Cloud Storage Bucket or Blob Container",
        severity=FindingSeverity.CRITICAL,
        category="Cloud Storage",
        description=(
            "Detects external storage buckets with public_access, anonymous_read, or "
            "anonymous_write permissions enabled."
        ),
        remediation="Enable S3 Block Public Access and enforce authenticated IAM policies.",
    ),
    "LH-ASM-005": SurfaceRuleDefinition(
        rule_id="LH-ASM-005",
        title="Unmanaged Shadow IT or Non-Production Asset on Public Internet",
        severity=FindingSeverity.HIGH,
        category="Asset Governance",
        description=(
            "Detects dev, staging, test, or uat subdomains/hosts exposed publicly without "
            "managed inventory tracking or access controls."
        ),
        remediation="Decommission unmanaged staging hosts or restrict via IP allowlisting.",
    ),
    "LH-ASM-006": SurfaceRuleDefinition(
        rule_id="LH-ASM-006",
        title="Cleartext Protocol Service on Public Perimeter",
        severity=FindingSeverity.HIGH,
        category="Transport Security",
        description=(
            "Detects active HTTP (80/8080) without HTTPS redirect, FTP (21), or unencrypted "
            "SMTP (25) accepting public connections."
        ),
        remediation="Enforce mandatory HTTPS redirection and decommission cleartext FTP/Telnet.",
    ),
    "LH-ASM-007": SurfaceRuleDefinition(
        rule_id="LH-ASM-007",
        title="Direct Origin IP Exposure Bypassing WAF/CDN",
        severity=FindingSeverity.HIGH,
        category="Network Perimeter",
        description=(
            "Detects origin servers directly reachable by IP, bypassing Cloudflare, CloudFront, "
            "or AWS WAF inspection."
        ),
        remediation="Restrict origin security groups to accept traffic exclusively from CDN CIDRs.",
    ),
    "LH-ASM-008": SurfaceRuleDefinition(
        rule_id="LH-ASM-008",
        title="Exposed Administrative Portal or Sensitive Route",
        severity=FindingSeverity.HIGH,
        category="Application Surface",
        description=(
            "Detects publicly reachable paths such as /admin, /phpmyadmin, /actuator, /.git, "
            "/.env, or /swagger-ui on perimeter hosts."
        ),
        remediation=(
            "Place administrative portals behind VPN/SSO and block /.git and /.env via WAF."
        ),
    ),
    "LH-ASM-009": SurfaceRuleDefinition(
        rule_id="LH-ASM-009",
        title="Weak Perimeter TLS Configuration or Expiring Certificate",
        severity=FindingSeverity.MEDIUM,
        category="Cryptography",
        description=(
            "Detects legacy TLSv1.0/TLSv1.1 support, self-signed certificates, or TLS "
            "certificates expiring within 14 days."
        ),
        remediation="Upgrade to TLS 1.2+ minimum and renew perimeter certificates automatically.",
    ),
    "LH-ASM-010": SurfaceRuleDefinition(
        rule_id="LH-ASM-010",
        title="Verbose Server Banner Leakage or Missing Asset Owner",
        severity=FindingSeverity.LOW,
        category="Information Disclosure",
        description=(
            "Detects detailed server/technology version leakage in HTTP banners or assets "
            "missing owner/contact governance tags."
        ),
        remediation="Suppress Server/X-Powered-By response headers and assign asset owners.",
    ),
}
