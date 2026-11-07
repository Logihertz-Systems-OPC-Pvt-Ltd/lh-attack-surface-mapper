# ==============================================================================
# Product:       lh-attack-surface-mapper (lh-attack)
# Module:        src.lh_attack_surface_mapper.surface_analyzer
# Role:          Security Analysis & Rule Evaluation Engine
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Attack surface risk analysis engine evaluating rules LH-ASM-001 to LH-ASM-010."""

from __future__ import annotations

import re
from pathlib import Path

from lh_attack_surface_mapper.models import (
    RULES_REGISTRY,
    FindingSeverity,
    PerimeterAsset,
    PerimeterAssetType,
    SurfaceFinding,
    SurfaceReport,
)
from lh_attack_surface_mapper.perimeter_parser import (
    find_perimeter_files,
    parse_any_perimeter_file,
)

DATABASE_PORTS = {
    5432: "PostgreSQL",
    3306: "MySQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
    11211: "Memcached",
}

MANAGEMENT_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
    2375: "Docker Daemon",
    6443: "Kubernetes API",
}

TAKEOVER_PATTERNS = [
    r"\.s3\.amazonaws\.com$",
    r"\.azurewebsites\.net$",
    r"\.github\.io$",
    r"\.herokuapp\.com$",
    r"\.trafficmanager\.net$",
    r"\.cloudfront\.net$",
]

SENSITIVE_PATHS = {
    "/admin",
    "/phpmyadmin",
    "/actuator",
    "/.git",
    "/.env",
    "/swagger-ui",
    "/wp-admin",
    "/console",
}
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


def analyze_perimeter_asset(asset: PerimeterAsset) -> list[SurfaceFinding]:
    """Audit a single perimeter asset against rules LH-ASM-001 through LH-ASM-010."""
    findings: list[SurfaceFinding] = []

    # 1. LH-ASM-001: Exposed Database or Cache Service
    for p in asset.ports:
        svc = DATABASE_PORTS.get(p.port) or (
            p.service_name
            if p.service_name.lower()
            in {"postgres", "postgresql", "mysql", "redis", "mongodb", "elasticsearch", "memcached"}
            else None
        )
        if svc:
            rule_def = RULES_REGISTRY["LH-ASM-001"]
            findings.append(
                SurfaceFinding(
                    rule_id="LH-ASM-001",
                    severity=FindingSeverity.CRITICAL,
                    category=rule_def.category,
                    target_asset=asset.identifier,
                    title=rule_def.title,
                    description=(
                        f"Database or cache service '{svc}' exposed on public port {p.port} "
                        f"without network isolation"
                    ),
                    remediation=rule_def.remediation,
                    evidence=f"Port: {p.port}/{p.protocol} ({svc})",
                )
            )

    # 2. LH-ASM-002: Exposed Remote Management or Control Plane Port
    for p in asset.ports:
        mgmt = MANAGEMENT_PORTS.get(p.port) or (
            p.service_name
            if p.service_name.lower()
            in {"ssh", "telnet", "rdp", "vnc", "docker", "kubernetes", "k8s"}
            else None
        )
        if mgmt:
            rule_def = RULES_REGISTRY["LH-ASM-002"]
            findings.append(
                SurfaceFinding(
                    rule_id="LH-ASM-002",
                    severity=FindingSeverity.CRITICAL,
                    category=rule_def.category,
                    target_asset=asset.identifier,
                    title=rule_def.title,
                    description=(
                        f"Remote management port {p.port} ({mgmt}) exposed directly to internet "
                        f"without bastion control"
                    ),
                    remediation=rule_def.remediation,
                    evidence=f"Port: {p.port}/{p.protocol} ({mgmt})",
                )
            )

    # 3. LH-ASM-003: Dangling Subdomain / Subdomain Takeover Vector
    if asset.cname:
        matches_takeover = any(
            re.search(pat, asset.cname, re.IGNORECASE) for pat in TAKEOVER_PATTERNS
        )
        is_dangling = str(asset.dns_status or "").lower() in {"dangling", "nxdomain", "unclaimed"}
        if matches_takeover and is_dangling:
            rule_def = RULES_REGISTRY["LH-ASM-003"]
            findings.append(
                SurfaceFinding(
                    rule_id="LH-ASM-003",
                    severity=FindingSeverity.CRITICAL,
                    category=rule_def.category,
                    target_asset=asset.identifier,
                    title=rule_def.title,
                    description=(
                        f"Subdomain points via CNAME '{asset.cname}' to unclaimed cloud "
                        f"resource with status '{asset.dns_status}'"
                    ),
                    remediation=rule_def.remediation,
                    evidence=f"CNAME: {asset.cname} (Status: {asset.dns_status})",
                )
            )

    # 4. LH-ASM-004: Publicly Exposed Cloud Storage Bucket
    is_bucket = (
        asset.asset_type == PerimeterAssetType.STORAGE_BUCKET
        or "bucket" in asset.identifier.lower()
        or asset.anonymous_read
        or asset.anonymous_write
    )
    if is_bucket and asset.public_access and (asset.anonymous_read or asset.anonymous_write):
        rule_def = RULES_REGISTRY["LH-ASM-004"]
        findings.append(
            SurfaceFinding(
                rule_id="LH-ASM-004",
                severity=FindingSeverity.CRITICAL,
                category=rule_def.category,
                target_asset=asset.identifier,
                title=rule_def.title,
                description=(
                    f"Cloud storage bucket allows unauthenticated public access "
                    f"(read: {asset.anonymous_read}, write: {asset.anonymous_write})"
                ),
                remediation=rule_def.remediation,
                evidence=f"Storage Bucket: {asset.identifier}",
            )
        )

    # 5. LH-ASM-005: Unmanaged Shadow IT or Non-Production Asset
    non_prod_prefixes = ("dev.", "staging.", "test.", "uat.", "stage.", "sandbox.")
    is_non_prod = any(asset.identifier.lower().startswith(p) for p in non_prod_prefixes)
    if (is_non_prod and not asset.managed) or (not asset.managed and asset.public_access):
        rule_def = RULES_REGISTRY["LH-ASM-005"]
        findings.append(
            SurfaceFinding(
                rule_id="LH-ASM-005",
                severity=FindingSeverity.HIGH,
                category=rule_def.category,
                target_asset=asset.identifier,
                title=rule_def.title,
                description=(
                    f"Asset '{asset.identifier}' identified as unmanaged shadow IT or "
                    f"non-production host on the public perimeter"
                ),
                remediation=rule_def.remediation,
                evidence=f"Managed: {asset.managed}, Env: {asset.environment}",
            )
        )

    # 6. LH-ASM-006: Cleartext Protocol Service
    for p in asset.ports:
        is_cleartext_http = p.port in {80, 8080} and not p.https_redirect
        is_insecure_proto = p.port in {21, 25} or p.service_name.lower() in {
            "ftp",
            "smtp",
            "telnet",
        }
        if is_cleartext_http or is_insecure_proto:
            proto_name = p.service_name.upper() if p.service_name else f"Port {p.port}"
            rule_def = RULES_REGISTRY["LH-ASM-006"]
            findings.append(
                SurfaceFinding(
                    rule_id="LH-ASM-006",
                    severity=FindingSeverity.HIGH,
                    category=rule_def.category,
                    target_asset=asset.identifier,
                    title=rule_def.title,
                    description=(
                        f"Cleartext unencrypted service '{proto_name}' exposed on port {p.port}"
                    ),
                    remediation=rule_def.remediation,
                    evidence=f"Port: {p.port}/{p.protocol} ({proto_name})",
                )
            )

    # 7. LH-ASM-007: Direct Origin IP Exposure Bypassing WAF/CDN
    if asset.direct_origin_accessible or asset.waf_enabled is False:
        rule_def = RULES_REGISTRY["LH-ASM-007"]
        findings.append(
            SurfaceFinding(
                rule_id="LH-ASM-007",
                severity=FindingSeverity.HIGH,
                category=rule_def.category,
                target_asset=asset.identifier,
                title=rule_def.title,
                description=(
                    "Direct origin IP is reachable from the public internet, bypassing "
                    "WAF and CDN edge protection"
                ),
                remediation=rule_def.remediation,
                evidence=(
                    f"WAF Enabled: {asset.waf_enabled}, Direct Accessible: "
                    f"{asset.direct_origin_accessible}"
                ),
            )
        )

    # 8. LH-ASM-008: Exposed Administrative Portal or Sensitive Route
    for ep in asset.endpoints:
        ep_norm = ep.strip().lower()
        if any(ep_norm.startswith(s) or ep_norm == s for s in SENSITIVE_PATHS):
            rule_def = RULES_REGISTRY["LH-ASM-008"]
            findings.append(
                SurfaceFinding(
                    rule_id="LH-ASM-008",
                    severity=FindingSeverity.HIGH,
                    category=rule_def.category,
                    target_asset=asset.identifier,
                    title=rule_def.title,
                    description=(
                        f"Administrative or sensitive diagnostic route '{ep}' exposed on perimeter"
                    ),
                    remediation=rule_def.remediation,
                    evidence=f"Endpoint: {ep}",
                )
            )

    # 9. LH-ASM-009: Weak Perimeter TLS Configuration or Expiring Certificate
    has_legacy_tls = any(v in asset.tls_versions for v in ("TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"))
    has_expiring_cert = asset.cert_expiry_days is not None and asset.cert_expiry_days < 14
    if has_legacy_tls or asset.self_signed_cert or has_expiring_cert:
        reasons = []
        if has_legacy_tls:
            reasons.append(f"Legacy TLS: {', '.join(asset.tls_versions)}")
        if asset.self_signed_cert:
            reasons.append("Self-signed certificate")
        if has_expiring_cert:
            reasons.append(f"Certificate expires in {asset.cert_expiry_days} days")

        rule_def = RULES_REGISTRY["LH-ASM-009"]
        findings.append(
            SurfaceFinding(
                rule_id="LH-ASM-009",
                severity=FindingSeverity.MEDIUM,
                category=rule_def.category,
                target_asset=asset.identifier,
                title=rule_def.title,
                description=f"Weak TLS configuration on perimeter: {'; '.join(reasons)}",
                remediation=rule_def.remediation,
                evidence="; ".join(reasons),
            )
        )

    # 10. LH-ASM-010: Verbose Server Banner Leakage or Missing Asset Owner
    has_banner_version = bool(re.search(r"/\d+\.\d+", asset.server_banner))
    missing_owner = not asset.owner and not asset.contact
    if has_banner_version or missing_owner:
        reasons = []
        if has_banner_version:
            reasons.append(f"Banner version leak: '{asset.server_banner}'")
        if missing_owner:
            reasons.append("Missing asset owner/contact tags")

        rule_def = RULES_REGISTRY["LH-ASM-010"]
        findings.append(
            SurfaceFinding(
                rule_id="LH-ASM-010",
                severity=FindingSeverity.LOW,
                category=rule_def.category,
                target_asset=asset.identifier,
                title=rule_def.title,
                description=f"Perimeter governance defect: {'; '.join(reasons)}",
                remediation=rule_def.remediation,
                evidence="; ".join(reasons),
            )
        )

    return findings


def audit_perimeter_surface(target: Path) -> SurfaceReport:
    """Scan perimeter files and analyze all discovered assets."""
    files = find_perimeter_files(target)
    all_assets: list[PerimeterAsset] = []

    for f in files:
        all_assets.extend(parse_any_perimeter_file(f))

    all_findings: list[SurfaceFinding] = []
    for asset in all_assets:
        all_findings.extend(analyze_perimeter_asset(asset))

    return SurfaceReport(
        target=str(target),
        files_scanned=len(files),
        assets_mapped=len(all_assets),
        findings_count=len(all_findings),
        findings=all_findings,
    )
