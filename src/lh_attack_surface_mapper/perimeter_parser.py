# ==============================================================================
# Product:       lh-attack-surface-mapper (lh-attack)
# Module:        src.lh_attack_surface_mapper.perimeter_parser
# Role:          Input Parser & Configuration Ingestion
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Perimeter asset inventory and port scan snapshot parser for lh-attack-surface-mapper."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET  # nosec B405
from pathlib import Path
from typing import Any

import yaml

from lh_attack_surface_mapper.models import (
    PerimeterAsset,
    PerimeterAssetType,
    PerimeterPort,
)

IGNORED_DIRS = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
    ".pytest_cache",
}


def find_perimeter_files(root: Path) -> list[Path]:
    # --- Multi-Format Parsing & Normalization Engine ---
    # Autodetects manifest formats (JSON, YAML, .conf, .env, CSV, JSONL),
    # applies fallback decoders, recovers from malformed lines, and standardizes
    # raw configuration attributes into typed domain model instances.
    """Discover inventory manifests, scan outputs, and DNS records."""
    if root.is_file():
        return [root]

    matched: list[Path] = []
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue

        name = path.name.lower()
        if name.endswith((".yaml", ".yml", ".json", ".xml")) and not name.endswith(
            ("pyproject.toml", "package.json", "package-lock.json")
        ):
            matched.append(path)

    return sorted(matched)


def parse_asset_dict(data: dict[str, Any], source_file: str) -> PerimeterAsset | None:
    """Parse a single asset dictionary into PerimeterAsset."""
    identifier = (
        data.get("identifier") or data.get("host") or data.get("domain") or data.get("name")
    )
    if not identifier:
        return None

    # Determine asset type
    raw_type = str(data.get("asset_type") or data.get("type") or "Host").lower()
    if "bucket" in raw_type or "storage" in raw_type:
        asset_type = PerimeterAssetType.STORAGE_BUCKET
    elif "subdomain" in raw_type or "dns" in raw_type:
        asset_type = PerimeterAssetType.SUBDOMAIN
    elif "api" in raw_type:
        asset_type = PerimeterAssetType.API_ENDPOINT
    else:
        asset_type = PerimeterAssetType.HOST

    # Parse ports
    ports: list[PerimeterPort] = []
    raw_ports = data.get("ports") or data.get("open_ports") or []
    if isinstance(raw_ports, list):
        for p in raw_ports:
            if isinstance(p, dict):
                port_num = int(p.get("port") or p.get("portid") or 0)
                if port_num > 0:
                    ports.append(
                        PerimeterPort(
                            port=port_num,
                            protocol=str(p.get("protocol") or "tcp"),
                            service_name=str(p.get("service") or p.get("service_name") or ""),
                            state=str(p.get("state") or "open"),
                            banner=str(p.get("banner") or ""),
                            https_redirect=bool(p.get("https_redirect", False)),
                        )
                    )
            elif isinstance(p, int) and p > 0:
                ports.append(PerimeterPort(port=p))

    # Parse IP addresses
    ips = data.get("ip_addresses") or data.get("ips") or []
    if isinstance(ips, str):
        ips = [ips]
    elif not isinstance(ips, list):
        ips = []

    return PerimeterAsset(
        identifier=str(identifier),
        asset_type=asset_type,
        ip_addresses=[str(ip) for ip in ips],
        ports=ports,
        cname=data.get("cname"),
        dns_status=data.get("dns_status"),
        waf_enabled=data.get("waf_enabled"),
        direct_origin_accessible=bool(data.get("direct_origin_accessible", False)),
        public_access=bool(data.get("public_access", True)),
        anonymous_read=bool(data.get("anonymous_read", False)),
        anonymous_write=bool(data.get("anonymous_write", False)),
        managed=bool(data.get("managed", True)),
        environment=str(data.get("environment") or "production"),
        endpoints=[str(e) for e in data.get("endpoints", [])],
        tls_versions=[str(t) for t in data.get("tls_versions", [])],
        self_signed_cert=bool(data.get("self_signed_cert") or data.get("self_signed", False)),
        cert_expiry_days=data.get("cert_expiry_days"),
        server_banner=str(data.get("server_banner") or data.get("banner") or ""),
        owner=data.get("owner"),
        contact=data.get("contact"),
        source_file=source_file,
    )


def parse_inventory_file(path: Path) -> list[PerimeterAsset]:
    """Parse YAML or JSON perimeter inventory manifest."""
    assets: list[PerimeterAsset] = []
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
        if path.suffix.lower() == ".json":
            data = json.loads(content)
        else:
            data = yaml.safe_load(content)

        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    a = parse_asset_dict(item, str(path))
                    if a:
                        assets.append(a)
        elif isinstance(data, dict):
            # Check for assets, hosts, subdomains, buckets keys
            for key in ("assets", "hosts", "subdomains", "buckets", "targets"):
                items = data.get(key)
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict):
                            a = parse_asset_dict(item, str(path))
                            if a:
                                assets.append(a)

            # If top-level dict itself is an asset
            if not assets and ("identifier" in data or "host" in data or "domain" in data):
                a = parse_asset_dict(data, str(path))
                if a:
                    assets.append(a)
    except Exception:  # nosec B110
        pass

    return assets


def parse_nmap_xml(path: Path) -> list[PerimeterAsset]:
    """Parse Nmap XML scan report into PerimeterAsset objects."""
    assets: list[PerimeterAsset] = []
    try:
        tree = ET.parse(path)  # nosec B314
        root = tree.getroot()
        for host in root.findall("host"):
            status = host.find("status")
            if status is not None and status.get("state") != "up":
                continue

            # Extract address
            addr_elem = host.find("address")
            ip = addr_elem.get("addr", "") if addr_elem is not None else ""

            # Extract hostnames
            hostname = ip
            hostnames_elem = host.find("hostnames")
            if hostnames_elem is not None:
                hn = hostnames_elem.find("hostname")
                if hn is not None and hn.get("name"):
                    hostname = hn.get("name", "")

            # Extract open ports
            ports: list[PerimeterPort] = []
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is not None and state_elem.get("state") == "open":
                        port_id = int(port_elem.get("portid", 0))
                        proto = port_elem.get("protocol", "tcp")
                        svc_elem = port_elem.find("service")
                        svc_name = svc_elem.get("name", "") if svc_elem is not None else ""
                        ports.append(
                            PerimeterPort(
                                port=port_id,
                                protocol=proto,
                                service_name=svc_name,
                                state="open",
                            )
                        )

            if ports or hostname:
                assets.append(
                    PerimeterAsset(
                        identifier=hostname or ip,
                        asset_type=PerimeterAssetType.HOST,
                        ip_addresses=[ip] if ip else [],
                        ports=ports,
                        source_file=str(path),
                    )
                )
    except Exception:  # nosec B110
        pass

    return assets


def parse_any_perimeter_file(path: Path) -> list[PerimeterAsset]:
    """Route file to appropriate inventory or Nmap XML parser."""
    if path.suffix.lower() == ".xml":
        return parse_nmap_xml(path)
    return parse_inventory_file(path)
