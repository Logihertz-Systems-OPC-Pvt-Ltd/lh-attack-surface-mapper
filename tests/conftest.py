# ==============================================================================
# Product:       lh-attack-surface-mapper (lh-attack)
# Module:        tests.conftest
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Test fixtures and mock perimeter inventory artifacts for lh-attack-surface-mapper."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def clean_perimeter_project(tmp_path: Path) -> Path:
    """Create a project with hardened, compliant perimeter assets."""
    proj = tmp_path / "clean_perimeter"
    proj.mkdir()

    manifest = proj / "perimeter.yaml"
    manifest.write_text(
        """organization: Example Corp
assets:
  - identifier: app.example.com
    asset_type: Host
    ip_addresses:
      - 198.51.100.25
    ports:
      - port: 443
        protocol: tcp
        service: https
        state: open
      - port: 80
        protocol: tcp
        service: http
        state: open
        https_redirect: true
    waf_enabled: true
    direct_origin_accessible: false
    managed: true
    environment: production
    tls_versions:
      - TLSv1.3
      - TLSv1.2
    self_signed_cert: false
    cert_expiry_days: 90
    server_banner: cloud-edge
    owner: sec-ops@example.com
    contact: oncall@example.com
""",
        encoding="utf-8",
    )
    return proj


@pytest.fixture
def vulnerable_perimeter_manifest(tmp_path: Path) -> Path:
    """Create perimeter manifest triggering rules LH-ASM-001 through LH-ASM-010."""
    manifest = tmp_path / "vulnerable_perimeter.yaml"
    manifest.write_text(
        """assets:
  - identifier: db-edge.example.com
    asset_type: Host
    ports:
      - port: 5432
        service: postgresql
      - port: 22
        service: ssh
      - port: 80
        service: http
        https_redirect: false
      - port: 21
        service: ftp
    waf_enabled: false
    direct_origin_accessible: true
    endpoints:
      - /admin
      - /actuator
      - /.env
    tls_versions:
      - TLSv1.0
    self_signed_cert: true
    cert_expiry_days: 5
    server_banner: Apache/2.4.41 (Ubuntu)
  - identifier: dev.example.com
    asset_type: Subdomain
    managed: false
    cname: example-app.s3.amazonaws.com
    dns_status: dangling
    environment: dev
  - identifier: corp-backups-bucket
    asset_type: Storage Bucket
    public_access: true
    anonymous_read: true
""",
        encoding="utf-8",
    )
    return manifest


@pytest.fixture
def nmap_xml_scan(tmp_path: Path) -> Path:
    """Create Nmap XML output triggering LH-ASM-001 and LH-ASM-002."""
    xml_file = tmp_path / "scan.xml"
    xml_file.write_text(
        """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 198.51.100.50" version="7.94">
<host>
<status state="up" reason="syn-ack"/>
<address addr="198.51.100.50" addrtype="ipv4"/>
<hostnames>
<hostname name="staging-db.example.com" type="user"/>
</hostnames>
<ports>
<port protocol="tcp" portid="3306">
  <state state="open" reason="syn-ack"/>
  <service name="mysql"/>
</port>
<port protocol="tcp" portid="3389">
  <state state="open" reason="syn-ack"/>
  <service name="ms-wbt-server"/>
</port>
</ports>
</host>
</nmaprun>
""",
        encoding="utf-8",
    )
    return xml_file
