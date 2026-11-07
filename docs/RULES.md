# Security Rules Reference: lh-attack-surface-mapper

An enterprise external attack surface discovery & exposure mapper developed by **Logihertz Systems (OPC) Private Limited**.

This reference manual documents the complete 10-rule security detection registry enforced by `lh-attack-surface-mapper`.

---

## Detection Catalog Overview

| Rule ID | Severity | Category | Title |
|:---|:---:|:---|:---|
| `LH-ASM-001` | `CRITICAL` | Port Exposure | Exposed Database or Cache on Public Perimeter |
| `LH-ASM-002` | `CRITICAL` | Port Exposure | Exposed Remote Management or Control Plane Port |
| `LH-ASM-003` | `CRITICAL` | DNS Hygiene | Dangling Subdomain / Subdomain Takeover Vector |
| `LH-ASM-004` | `CRITICAL` | Cloud Exposure | Publicly Exposed Cloud Storage Bucket |
| `LH-ASM-005` | `HIGH` | Asset Governance | Unmanaged Shadow IT or Staging Asset Exposed |
| `LH-ASM-006` | `HIGH` | Transport Security | Cleartext Protocol Service on Public Perimeter |
| `LH-ASM-007` | `HIGH` | Perimeter Protection | Direct Origin IP Exposure Bypassing WAF/CDN |
| `LH-ASM-008` | `HIGH` | Access Control | Exposed Administrative Portal or Debug Route |
| `LH-ASM-009` | `MEDIUM` | TLS Posture | Weak Perimeter TLS Configuration or Expiring Cert |
| `LH-ASM-010` | `LOW` | Information Disclosure | Verbose Server Banner Leakage |

---

## Granular Rule Specifications

### `LH-ASM-001`: Exposed Database or Cache on Public Perimeter

- **Severity**: `CRITICAL`
- **Category**: `Port Exposure`
- **Description**: Database service (Postgres, MySQL, Redis, MongoDB) listening on unfirewalled public interface.
- **Remediation**: Bind databases strictly to localhost/internal VPC interfaces and enforce network firewalls.

---

### `LH-ASM-002`: Exposed Remote Management or Control Plane Port

- **Severity**: `CRITICAL`
- **Category**: `Port Exposure`
- **Description**: SSH (22), RDP (3389), or Kubernetes API (6443) exposed directly to public internet.
- **Remediation**: Restrict control plane access behind zero-trust proxies, VPNs, or IP allowlists.

---

### `LH-ASM-003`: Dangling Subdomain / Subdomain Takeover Vector

- **Severity**: `CRITICAL`
- **Category**: `DNS Hygiene`
- **Description**: CNAME pointing to unclaimed AWS S3, GitHub Pages, or Azure cloud storage resource.
- **Remediation**: Remove stale CNAME records immediately or claim the target resource in the cloud provider.

---

### `LH-ASM-004`: Publicly Exposed Cloud Storage Bucket

- **Severity**: `CRITICAL`
- **Category**: `Cloud Exposure`
- **Description**: Cloud storage bucket or container with public read or write permissions enabled.
- **Remediation**: Enable S3 Public Access Block or Azure storage account private access restrictions.

---

### `LH-ASM-005`: Unmanaged Shadow IT or Staging Asset Exposed

- **Severity**: `HIGH`
- **Category**: `Asset Governance`
- **Description**: Non-production or staging host exposed on public DNS or edge IP space.
- **Remediation**: Decommission obsolete staging hosts or isolate behind authenticated internal networks.

---

### `LH-ASM-006`: Cleartext Protocol Service on Public Perimeter

- **Severity**: `HIGH`
- **Category**: `Transport Security`
- **Description**: Unencrypted HTTP, Telnet, or FTP service exposed at public network perimeter.
- **Remediation**: Enforce TLS encryption or replace insecure protocols with SSH/SFTP.

---

### `LH-ASM-007`: Direct Origin IP Exposure Bypassing WAF/CDN

- **Severity**: `HIGH`
- **Category**: `Perimeter Protection`
- **Description**: Public origin IP reachable directly without passing through CDN/WAF proxy layer.
- **Remediation**: Configure origin firewalls to drop all traffic not originating from CDN/WAF IP CIDRs.

---

### `LH-ASM-008`: Exposed Administrative Portal or Debug Route

- **Severity**: `HIGH`
- **Category**: `Access Control`
- **Description**: Admin interfaces or debug dashboards exposed on public perimeter endpoints.
- **Remediation**: Place administrative consoles behind SSO, MFA, and internal corporate networks.

---

### `LH-ASM-009`: Weak Perimeter TLS Configuration or Expiring Cert

- **Severity**: `MEDIUM`
- **Category**: `TLS Posture`
- **Description**: Outdated TLS cipher suite, TLS 1.0/1.1 enabled, or certificate expiration < 30 days.
- **Remediation**: Upgrade TLS configuration to TLS 1.2+ with modern AEAD ciphers and automate renewal.

---

### `LH-ASM-010`: Verbose Server Banner Leakage

- **Severity**: `LOW`
- **Category**: `Information Disclosure`
- **Description**: Detailed server version headers or technology stacks disclosed in HTTP responses.
- **Remediation**: Disable verbose server tokens (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx).

---
