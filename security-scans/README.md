# Container image vulnerability scan

Automatically generated. **Do not edit** — the next nightly run overwrites it.

- **Scanned**: `ghcr.io/vistasecurity/*:latest` (18 images)
- **Generated**: 2026-08-28T17:01:20Z
- **Scanner**: [Trivy](https://github.com/aquasecurity/trivy)
- **Scope**: fixable `CRITICAL` and `HIGH` findings (`--ignore-unfixed`) in OS packages and application dependencies

> [!WARNING]
> **1 of 18 images could not be scanned on this run.** The counts below therefore describe only the images that were: they are not a clean bill of health for the release. Unscanned images are listed at the bottom.

## 0 CRITICAL · 0 HIGH (fixable, across 17 scanned images)

| Image | CRITICAL | HIGH |
|---|---:|---:|
| `admin-service` | 0 | 0 ✅ |
| `admin-ui` | 0 | 0 ✅ |
| `audit-service` | 0 | 0 ✅ |
| `auth-service` | 0 | 0 ✅ |
| `cbom-service` | 0 | 0 ✅ |
| `cluster-sensor-service` | 0 | 0 ✅ |
| `compliance-engine` | 0 | 0 ✅ |
| `device-interrogation-service` | 0 | 0 ✅ |
| `discovery-processor-service` | 0 | 0 ✅ |
| `inventory-service` | 0 | 0 ✅ |
| `mcp-service` | 0 | 0 ✅ |
| `monitoring-service` | 0 | 0 ✅ |
| `pcap-processor` | 0 | 0 ✅ |
| `resource-tracker-service` | 0 | 0 ✅ |
| `sensor-manager` | 0 | 0 ✅ |
| `tenant-health-service` | 0 | 0 ✅ |
| `web-ui` | 0 | 0 ✅ |
| `notification-service` | ❌ not scanned | ❌ not scanned |

## Not scanned on this run

Trivy did not produce a usable report for these images. An image that was not scanned is reported as unscanned rather than as clean.

- `ghcr.io/vistasecurity/notification-service:latest`

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

<sub>Produced by [this workflow run](https://github.com/bob-vistasecurity/VistaPlatform/actions/runs/33192553973).</sub>
