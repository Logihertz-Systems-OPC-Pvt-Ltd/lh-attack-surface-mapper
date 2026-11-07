# ==============================================================================
# Product:       lh-attack-surface-mapper (lh-attack)
# Module:        tests.test_perimeter_parser
# Role:          Test Suite & Rule Verification
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Unit tests for perimeter asset inventory and Nmap XML parsers."""

from __future__ import annotations

from pathlib import Path

from lh_attack_surface_mapper.models import PerimeterAssetType
from lh_attack_surface_mapper.perimeter_parser import (
    find_perimeter_files,
    parse_any_perimeter_file,
    parse_inventory_file,
    parse_nmap_xml,
)


def test_find_perimeter_files(tmp_path: Path) -> None:
    """Test discovering YAML, JSON, and XML perimeter files."""
    f1 = tmp_path / "assets.yaml"
    f1.write_text("assets: []\n", encoding="utf-8")
    f2 = tmp_path / "nmap.xml"
    f2.write_text("<nmaprun></nmaprun>\n", encoding="utf-8")
    ignored = tmp_path / "package.json"
    ignored.write_text("{}\n", encoding="utf-8")

    files = find_perimeter_files(tmp_path)
    file_names = {f.name for f in files}
    assert "assets.yaml" in file_names
    assert "nmap.xml" in file_names
    assert "package.json" not in file_names


def test_parse_yaml_inventory(vulnerable_perimeter_manifest: Path) -> None:
    """Test parsing multi-asset YAML perimeter inventory."""
    assets = parse_inventory_file(vulnerable_perimeter_manifest)
    assert len(assets) == 3

    ids = {a.identifier for a in assets}
    assert "db-edge.example.com" in ids
    assert "dev.example.com" in ids
    assert "corp-backups-bucket" in ids

    db_asset = next(a for a in assets if a.identifier == "db-edge.example.com")
    assert len(db_asset.ports) == 4
    port_nums = {p.port for p in db_asset.ports}
    assert 5432 in port_nums
    assert 22 in port_nums


def test_parse_json_inventory(tmp_path: Path) -> None:
    """Test parsing JSON inventory manifest."""
    j_file = tmp_path / "inventory.json"
    j_file.write_text(
        """{
  "assets": [
    {
      "identifier": "api.test.org",
      "type": "API Endpoint",
      "ports": [443, 80],
      "owner": "team@test.org"
    }
  ]
}
""",
        encoding="utf-8",
    )
    assets = parse_inventory_file(j_file)
    assert len(assets) == 1
    assert assets[0].identifier == "api.test.org"
    assert assets[0].asset_type == PerimeterAssetType.API_ENDPOINT
    assert len(assets[0].ports) == 2


def test_parse_nmap_xml(nmap_xml_scan: Path) -> None:
    """Test parsing Nmap XML scan output."""
    assets = parse_nmap_xml(nmap_xml_scan)
    assert len(assets) == 1
    assert assets[0].identifier == "staging-db.example.com"
    assert "198.51.100.50" in assets[0].ip_addresses

    port_nums = {p.port for p in assets[0].ports}
    assert 3306 in port_nums
    assert 3389 in port_nums


def test_parse_any_perimeter_file_routing(
    vulnerable_perimeter_manifest: Path, nmap_xml_scan: Path
) -> None:
    """Test routing to appropriate parser by file extension."""
    yaml_assets = parse_any_perimeter_file(vulnerable_perimeter_manifest)
    assert len(yaml_assets) == 3

    xml_assets = parse_any_perimeter_file(nmap_xml_scan)
    assert len(xml_assets) == 1
