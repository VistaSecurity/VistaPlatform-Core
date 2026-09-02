# Container image vulnerability scan

Automatically generated. **Do not edit** — the next nightly run overwrites it.

- **Scanned**: `ghcr.io/vistasecurity/*:latest` (18 images)
- **Generated**: 2026-09-02T09:13:16Z
- **Scanner**: [Trivy](https://github.com/aquasecurity/trivy)
- **Scope**: fixable `CRITICAL` and `HIGH` findings (`--ignore-unfixed`) in OS packages and application dependencies

> [!WARNING]
> **1 of 18 images could not be scanned on this run.** The counts below therefore describe only the images that were: they are not a clean bill of health for the release. Unscanned images are listed at the bottom.

## 17 CRITICAL · 2 HIGH (fixable, across 17 scanned images)

| Image | CRITICAL | HIGH |
|---|---:|---:|
| `admin-service` | 1 | 0 |
| `admin-ui` | 1 | 1 |
| `audit-service` | 1 | 0 |
| `auth-service` | 1 | 0 |
| `cbom-service` | 1 | 0 |
| `cluster-sensor-service` | 1 | 0 |
| `compliance-engine` | 1 | 0 |
| `discovery-processor-service` | 1 | 0 |
| `inventory-service` | 1 | 0 |
| `mcp-service` | 1 | 0 |
| `monitoring-service` | 1 | 0 |
| `notification-service` | 1 | 0 |
| `pcap-processor` | 1 | 0 |
| `resource-tracker-service` | 1 | 0 |
| `sensor-manager` | 1 | 0 |
| `tenant-health-service` | 1 | 0 |
| `web-ui` | 1 | 1 |
| `device-interrogation-service` | ❌ not scanned | ❌ not scanned |

## Findings

### `admin-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `admin-ui`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |
| HIGH | [CVE-2026-84304](https://nvd.nist.gov/vuln/detail/CVE-2026-84304) | `google.golang.org/grpc` | `v1.82.1` | `1.83.1` |

### `audit-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `auth-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `cbom-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `cluster-sensor-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `compliance-engine`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `discovery-processor-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `inventory-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `mcp-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `monitoring-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `notification-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `pcap-processor`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `resource-tracker-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `sensor-manager`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `tenant-health-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |

### `web-ui`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| CRITICAL | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |
| HIGH | [CVE-2026-84304](https://nvd.nist.gov/vuln/detail/CVE-2026-84304) | `google.golang.org/grpc` | `v1.82.1` | `1.83.1` |

## Not scanned on this run

Trivy did not produce a usable report for these images. An image that was not scanned is reported as unscanned rather than as clean.

- `ghcr.io/vistasecurity/device-interrogation-service:latest`

## How to read this

- **Fixable only.** Findings with no fix available upstream are excluded, because they are not actionable by upgrading. A count of zero here does not mean zero known CVEs.
- **CRITICAL and HIGH only.** MEDIUM and LOW are not tracked in this report.
- **A point-in-time result.** Vulnerability databases change daily; an image that scored clean last night can score differently tonight without the image having changed.
- **Verify it yourself.** Every published image is cosign-signed and carries a CycloneDX SBOM attestation, and the scan is reproducible:

  ```bash
  trivy image --ignore-unfixed --severity CRITICAL,HIGH \
    ghcr.io/vistasecurity/auth-service:latest
  ```

To report a vulnerability, see [SECURITY.md](../SECURITY.md). Please do not open a public issue.

<sub>Produced by [this workflow run](https://github.com/bob-vistasecurity/VistaPlatform/actions/runs/33612733459).</sub>
