# Container image vulnerability scan

Automatically generated. **Do not edit** — the next nightly run overwrites it.

- **Scanned**: `ghcr.io/vistasecurity/*:latest` (18 images)
- **Generated**: 2026-10-23T10:55:08Z
- **Scanner**: [Trivy](https://github.com/aquasecurity/trivy)
- **Scope**: fixable `CRITICAL` and `HIGH` findings (`--ignore-unfixed`) in OS packages and application dependencies

## 0 CRITICAL · 24 HIGH (fixable, across 18 scanned images)

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
| `maintenance-service` | 0 | 24 |
| `mcp-service` | 0 | 0 ✅ |
| `monitoring-service` | 0 | 0 ✅ |
| `notification-service` | 0 | 0 ✅ |
| `pcap-processor` | 0 | 0 ✅ |
| `sensor-manager` | 0 | 0 ✅ |
| `tenant-health-service` | 0 | 0 ✅ |
| `web-ui` | 0 | 0 ✅ |

## Findings

### `maintenance-service`

| Severity | CVE | Package | Installed | Fixed in |
|---|---|---|---|---|
| HIGH | [CVE-2026-111943](https://nvd.nist.gov/vuln/detail/CVE-2026-111943) | `stdlib` | `v1.26.4` | `1.26.10, 1.27.3` |
| HIGH | [CVE-2026-111943](https://nvd.nist.gov/vuln/detail/CVE-2026-111943) | `stdlib` | `v1.26.9` | `1.26.10, 1.27.3` |
| HIGH | [CVE-2026-33818](https://nvd.nist.gov/vuln/detail/CVE-2026-33818) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-39821](https://nvd.nist.gov/vuln/detail/CVE-2026-39821) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-39822](https://nvd.nist.gov/vuln/detail/CVE-2026-39822) | `stdlib` | `v1.26.4` | `1.25.12, 1.26.5, 1.27.0-rc.2` |
| HIGH | [CVE-2026-46600](https://nvd.nist.gov/vuln/detail/CVE-2026-46600) | `stdlib` | `v1.26.4` | `1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56851](https://nvd.nist.gov/vuln/detail/CVE-2026-56851) | `golang.org/x/text` | `v0.38.0` | `0.41.0` |
| HIGH | [CVE-2026-56852](https://nvd.nist.gov/vuln/detail/CVE-2026-56852) | `golang.org/x/text` | `v0.38.0` | `0.39.0` |
| HIGH | [CVE-2026-56853](https://nvd.nist.gov/vuln/detail/CVE-2026-56853) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.53.0` | `0.55.0` |
| HIGH | [CVE-2026-56858](https://nvd.nist.gov/vuln/detail/CVE-2026-56858) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56859](https://nvd.nist.gov/vuln/detail/CVE-2026-56859) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56860](https://nvd.nist.gov/vuln/detail/CVE-2026-56860) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56862](https://nvd.nist.gov/vuln/detail/CVE-2026-56862) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56864](https://nvd.nist.gov/vuln/detail/CVE-2026-56864) | `golang.org/x/mod` | `v0.37.0` | `0.40.0` |
| HIGH | [CVE-2026-56865](https://nvd.nist.gov/vuln/detail/CVE-2026-56865) | `golang.org/x/mod` | `v0.37.0` | `0.40.0` |
| HIGH | [CVE-2026-63209](https://nvd.nist.gov/vuln/detail/CVE-2026-63209) | `github.com/klauspost/compress` | `v1.18.6` | `1.18.7` |
| HIGH | [CVE-2026-78667](https://nvd.nist.gov/vuln/detail/CVE-2026-78667) | `stdlib` | `v1.26.4` | `1.26.9, 1.27.2` |
| HIGH | [CVE-2026-78669](https://nvd.nist.gov/vuln/detail/CVE-2026-78669) | `golang.org/x/net` | `v0.56.0` | `0.60.0` |
| HIGH | [CVE-2026-78669](https://nvd.nist.gov/vuln/detail/CVE-2026-78669) | `stdlib` | `v1.26.4` | `1.26.9, 1.27.2` |
| HIGH | [CVE-2026-84304](https://nvd.nist.gov/vuln/detail/CVE-2026-84304) | `google.golang.org/grpc` | `v1.82.0` | `1.83.1` |
| HIGH | [CVE-2026-84445](https://nvd.nist.gov/vuln/detail/CVE-2026-84445) | `google.golang.org/grpc` | `v1.82.0` | `1.82.2, 1.83.2, 1.84.0-dev.0.20260825144003-d5a41119e0e3, 1.85.0-dev.0.20260825072537-93e31b48545e` |
| HIGH | [CVE-2026-97031](https://nvd.nist.gov/vuln/detail/CVE-2026-97031) | `stdlib` | `v1.26.4` | `1.26.9, 1.27.2` |
| HIGH | [GHSA-hrxh-6v49-42gf](https://github.com/advisories/GHSA-hrxh-6v49-42gf) | `google.golang.org/grpc` | `v1.82.0` | `1.82.1` |

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

<sub>Produced by [this workflow run](https://github.com/VistaSecurity/VistaPlatform/actions/runs/39933544747).</sub>
