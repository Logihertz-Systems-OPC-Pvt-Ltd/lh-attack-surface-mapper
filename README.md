# lh-attack-surface-mapper

[![CI](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-attack-surface-mapper/actions/workflows/ci.yml/badge.svg)](https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-attack-surface-mapper/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

An enterprise external attack surface management developed by **Logihertz Systems (OPC) Private Limited**.

Maps external network assets, nmap/masscan port inventories, subdomain enumerations, and edge service exposures to identify shadow IT, unencrypted management ports, and high-risk internet-facing services.

---

## Key Features

- **Multi-Source Perimeter Ingestion**: Correlates DNS records, port scan outputs, cloud asset manifests, and perimeter access logs.
- **Exposed Database & Control Plane Detection**: Flags public internet exposure of databases (Postgres, MySQL, Redis, Mongo) and management ports (SSH, RDP, Kubernetes API).
- **Dangling Subdomain & Takeover Analysis**: Identifies CNAME records pointing to unclaimed third-party cloud resources (AWS S3, GitHub Pages, Azure).
- **Shadow IT & Non-Production Exposure**: Flags staging, dev, and test environments directly exposed on public DNS or edge IPs.
- **Direct Origin Exposure**: Identifies server origins exposing true IP addresses and bypassing WAF/CDN perimeter protections.
- **Multi-Format Reporting**: Outputs rich terminal tables, JSON reports, and OASIS SARIF v2.1.0 for CI/CD ingestion.

---

## Core Detection Rules

| Rule ID | Severity | Description |
|:---|:---:|:---|
| `LH-ASM-001` | `CRITICAL` | Exposed Database or Cache on Public Perimeter — unfirewalled database service (Postgres, MySQL, Redis, Mongo) |
| `LH-ASM-002` | `CRITICAL` | Exposed Remote Management or Control Plane Port — SSH (22), RDP (3389), Kubernetes API (6443) exposed to public internet |
| `LH-ASM-003` | `CRITICAL` | Dangling Subdomain / Subdomain Takeover Vector — CNAME pointing to unclaimed AWS S3, GitHub Pages, or cloud target |
| `LH-ASM-004` | `CRITICAL` | Publicly Exposed Cloud Storage Bucket — cloud storage bucket or container with public read/write permissions |
| `LH-ASM-005` | `HIGH` | Unmanaged Shadow IT or Staging Asset Exposed — non-production or staging host exposed on public DNS/IP |
| `LH-ASM-006` | `HIGH` | Cleartext Protocol Service on Public Perimeter — unencrypted HTTP, Telnet, or FTP service exposed at perimeter |
| `LH-ASM-007` | `HIGH` | Direct Origin IP Exposure Bypassing WAF/CDN — public origin IP reachable without CDN/WAF proxying |
| `LH-ASM-008` | `HIGH` | Exposed Administrative Portal or Debug Route — admin interfaces or debug endpoints exposed on public endpoints |
| `LH-ASM-009` | `MEDIUM` | Weak Perimeter TLS Configuration or Expiring Cert — outdated TLS cipher suite or certificate expiration < 30 days |
| `LH-ASM-010` | `LOW` | Verbose Server Banner Leakage — detailed version headers or technology stacks disclosed in server headers |

---

## Installation

### Using `uv` (Recommended)

```bash
# Clone the repository
git clone https://github.com/Logihertz-Systems-OPC-Pvt-Ltd/lh-attack-surface-mapper.git
cd lh-attack-surface-mapper

# Create virtual environment and install in editable mode with development tools
uv venv
source .venv/bin/activate
uv pip install -e ".[dev]"
```

### Using standard `pip`

```bash
pip install -e .
```

---

## CLI Usage

The primary executable entrypoint is `lh-asm` (also accessible via `lh-asm`, `lh-attack-surface-mapper`).

```bash
# Scan a DNS zone file or Nmap XML export
lh-asm scan scan-results.xml

# Audit a cloud inventory JSON export
lh-asm scan assets.json --format json

# Export findings to OASIS SARIF v2.1.0
lh-asm scan ./recon/ --format sarif --output asm-report.sarif

# Filter by minimum severity
lh-asm scan ./recon/ --min-severity HIGH
```

---

## Exit Codes

| Exit Code | Meaning |
|:---:|:---|
| `0` | All audits and security checks passed; no policy violations detected. |
| `1` | One or more security findings, policy violations, or compliance failures detected. |
| `2` | Execution error (invalid arguments, missing input files, malformed syntax). |

---

## Documentation

Comprehensive enterprise documentation is available in the [`docs/`](docs/) directory and repository root:

- **[Architecture & Design](docs/ARCHITECTURE.md)**: Zero-daemon clean-room architecture, module responsibilities, domain models, and 0–100 risk score calculation formula.
- **[Security Rules Reference](docs/RULES.md)**: Exhaustive catalog of all 10 detection rules with threat models, severities, and remediation guides.
- **[CLI Usage Guide](docs/USAGE.md)**: Complete command-line manual, flags, exit codes, CI/CD SARIF upload workflows, and JSON pipelines.
- **[Test & Verification Declaration](docs/TESTING.md)**: Audited test inventory, AST security verification, SAST audit results, and per-module code coverage metrics.
- **[Changelog](CHANGELOG.md)**: Semantic release history and detailed changelog entries.
- **[Contributing Guidelines](CONTRIBUTING.md)**: Developer setup, coding standards, line length, typing, and PR requirements.
- **[Security Policy](SECURITY.md)**: Vulnerability disclosure procedure, reporting email, and 48-hour response SLA.
- **[Legal Notice & Attributions](NOTICE)**: Apache-2.0 Section 4 legal notice, trademark reservations, and third-party software attributions.

## Development & Testing

Run all project linters, security audits, and test suites:

```bash
# Run code style and lint checks
uv run ruff check src/ tests/

# Run static application security testing (SAST)
uv run bandit -r src/

# Run unit and integration tests with coverage
uv run pytest
```

---

## License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.

Developed with precision by **Logihertz Systems (OPC) Private Limited** (`logihertzsystems`).  
Created, architected, and engineered by **Sameer Tawade** (Creator, Founder, Director & Whole and Sole Developer — `ops@logihertz.com`).
