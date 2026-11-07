# ==============================================================================
# Product:       lh-attack-surface-mapper (lh-attack)
# Module:        src.lh_attack_surface_mapper.exporters
# Role:          SARIF, JSON & Rich Terminal Table Exporters
# Organization:  Logihertz Systems (OPC) Private Limited (logihertzsystems)
# Creator:       Sameer Tawade (Creator, Founder, Director & Whole and Sole Developer)
# Contact:       ops@logihertz.com | https://logihertz.com/
# License:       Apache License 2.0 (SPDX-License-Identifier: Apache-2.0)
# ==============================================================================

"""Report exporters for lh-attack-surface-mapper: Rich Table, JSON, and OASIS SARIF v2.1.0."""

from __future__ import annotations

import json
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from lh_attack_surface_mapper.models import (
    RULES_REGISTRY,
    FindingSeverity,
    SurfaceReport,
)


def severity_to_style(severity: FindingSeverity) -> str:
    """Return Rich markup style for severity rating."""
    mapping = {
        FindingSeverity.CRITICAL: "bold red",
        FindingSeverity.HIGH: "red",
        FindingSeverity.MEDIUM: "yellow",
        FindingSeverity.LOW: "blue",
    }
    return mapping.get(severity, "white")


def severity_to_sarif_level(severity: FindingSeverity) -> str:
    """Map FindingSeverity to OASIS SARIF 2.1.0 level."""
    mapping = {
        FindingSeverity.CRITICAL: "error",
        FindingSeverity.HIGH: "error",
        FindingSeverity.MEDIUM: "warning",
        FindingSeverity.LOW: "note",
    }
    return mapping.get(severity, "note")


def render_table_report(report: SurfaceReport, console: Console | None = None) -> None:
    # --- Rich Terminal Table Presentation Layout ---
    # Renders structured security findings with ANSI color highlights,
    # severity-coded badges, file locations, and executive posture summaries.
    """Render an enterprise Rich table report of attack surface findings."""
    con = console or Console()

    if not report.findings:
        con.print(
            Panel(
                f"[bold green]No perimeter exposure or attack surface vulnerabilities detected "
                f"across {report.assets_mapped} asset(s) in '{report.target}'.[/]",
                title="[bold green]Perimeter Clean[/]",
                border_style="green",
            )
        )
        return

    table = Table(
        title=(
            f"lh-attack-surface-mapper Audit Report "
            f"({report.findings_count} Findings | Risk Score: {report.risk_score}/100)"
        ),
        header_style="bold cyan",
        show_lines=True,
    )
    table.add_column("Rule ID", style="bold", width=14)
    table.add_column("Severity", width=10, justify="center")
    table.add_column("Category", width=20)
    table.add_column("Target Asset", width=24)
    table.add_column("Description & Evidence", width=44)

    for f in report.findings:
        sev_style = severity_to_style(f.severity)
        desc_text = f.description
        if f.evidence:
            desc_text += f"\n[dim]{f.evidence}[/dim]"
        table.add_row(
            f.rule_id,
            f"[{sev_style}]{f.severity.value}[/]",
            f.category,
            f.target_asset,
            desc_text,
        )

    con.print(table)

    summary_text = (
        f"[bold red]Critical:[/] {report.summary.get('critical', 0)} | "
        f"[red]High:[/] {report.summary.get('high', 0)} | "
        f"[yellow]Medium:[/] {report.summary.get('medium', 0)} | "
        f"[blue]Low:[/] {report.summary.get('low', 0)} | "
        f"[bold]Risk Score:[/] {report.risk_score}/100 | "
        f"[bold]Assets Mapped:[/] {report.assets_mapped}"
    )
    con.print(Panel(summary_text, title="[bold]Perimeter Exposure Summary[/]", border_style="cyan"))


def export_json(report: SurfaceReport, indent: int = 2) -> str:
    """Export attack surface report as structured JSON document."""
    data: dict[str, Any] = {
        "schema_version": "1.0.0",
        "scanner": "lh-attack-surface-mapper",
        "target": report.target,
        "files_scanned": report.files_scanned,
        "assets_mapped": report.assets_mapped,
        "risk_score": report.risk_score,
        "findings_count": report.findings_count,
        "summary": report.summary,
        "findings": [f.to_dict() for f in report.findings],
    }
    return json.dumps(data, indent=indent)


def export_sarif(report: SurfaceReport, indent: int = 2) -> str:
    # --- OASIS SARIF v2.1.0 Compliance Exporter ---
    # Serializes audit results into standard SARIF JSON format for native
    # GitHub Code Scanning, GitLab Security Dashboard, and IDE integrations.
    """Export attack surface report as OASIS SARIF v2.1.0 document."""
    rules_dict: dict[str, dict[str, Any]] = {}
    for rule_id, rule_def in RULES_REGISTRY.items():
        rules_dict[rule_id] = {
            "id": rule_id,
            "name": rule_def.title.replace(" ", ""),
            "shortDescription": {"text": rule_def.title},
            "fullDescription": {"text": rule_def.description},
            "defaultConfiguration": {"level": severity_to_sarif_level(rule_def.severity)},
            "help": {"text": f"Remediation: {rule_def.remediation}"},
        }

    results: list[dict[str, Any]] = []
    for f in report.findings:
        res = {
            "ruleId": f.rule_id,
            "level": severity_to_sarif_level(f.severity),
            "message": {"text": f"[{f.category}] {f.description} (Asset: {f.target_asset})"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.target_asset},
                        "region": {"startLine": 1},
                    }
                }
            ],
            "properties": {
                "evidence": f.evidence,
                "remediation": f.remediation,
            },
        }
        results.append(res)

    sarif_doc: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lh-attack-surface-mapper",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-attack-surface-mapper",
                        "rules": list(rules_dict.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_doc, indent=indent)
