# Container image vulnerability scan

Automatically generated. **Do not edit** — the next nightly run overwrites it.

- **Scanned**: `ghcr.io/vistasecurity/*:latest` (18 images)
- **Generated**: 2026-10-18T09:16:06Z
- **Scanner**: [Trivy](https://github.com/aquasecurity/trivy)
- **Scope**: fixable `CRITICAL` and `HIGH` findings (`--ignore-unfixed`) in OS packages and application dependencies

## 1 CRITICAL · 46 HIGH (fixable, across 18 scanned images)

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
| `maintenance-service` | 1 | 46 |
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
| CRITICAL | [CVE-2026-33186](https://nvd.nist.gov/vuln/detail/CVE-2026-33186) | `google.golang.org/grpc` | `v1.77.0` | `1.79.3` |
| HIGH | [CVE-2025-15558](https://nvd.nist.gov/vuln/detail/CVE-2025-15558) | `github.com/docker/cli` | `v29.0.3+incompatible` | `29.2.0` |
| HIGH | [CVE-2026-24051](https://nvd.nist.gov/vuln/detail/CVE-2026-24051) | `go.opentelemetry.io/otel/sdk` | `v1.38.0` | `1.40.0` |
| HIGH | [CVE-2026-25681](https://nvd.nist.gov/vuln/detail/CVE-2026-25681) | `golang.org/x/net` | `v0.48.0` | `0.55.0` |
| HIGH | [CVE-2026-27136](https://nvd.nist.gov/vuln/detail/CVE-2026-27136) | `golang.org/x/net` | `v0.48.0` | `0.55.0` |
| HIGH | [CVE-2026-29181](https://nvd.nist.gov/vuln/detail/CVE-2026-29181) | `go.opentelemetry.io/otel` | `v1.38.0` | `1.41.0` |
| HIGH | [CVE-2026-33814](https://nvd.nist.gov/vuln/detail/CVE-2026-33814) | `golang.org/x/net` | `v0.48.0` | `0.53.0` |
| HIGH | [CVE-2026-33818](https://nvd.nist.gov/vuln/detail/CVE-2026-33818) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-34986](https://nvd.nist.gov/vuln/detail/CVE-2026-34986) | `github.com/go-jose/go-jose/v4` | `v4.1.3` | `4.1.4` |
| HIGH | [CVE-2026-39821](https://nvd.nist.gov/vuln/detail/CVE-2026-39821) | `golang.org/x/net` | `v0.48.0` | `0.55.0` |
| HIGH | [CVE-2026-39821](https://nvd.nist.gov/vuln/detail/CVE-2026-39821) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-39822](https://nvd.nist.gov/vuln/detail/CVE-2026-39822) | `stdlib` | `v1.26.4` | `1.25.12, 1.26.5, 1.27.0-rc.2` |
| HIGH | [CVE-2026-39828](https://nvd.nist.gov/vuln/detail/CVE-2026-39828) | `golang.org/x/crypto` | `v0.46.0` | `0.52.0` |
| HIGH | [CVE-2026-39829](https://nvd.nist.gov/vuln/detail/CVE-2026-39829) | `golang.org/x/crypto` | `v0.46.0` | `0.52.0` |
| HIGH | [CVE-2026-39830](https://nvd.nist.gov/vuln/detail/CVE-2026-39830) | `golang.org/x/crypto` | `v0.46.0` | `0.52.0` |
| HIGH | [CVE-2026-39831](https://nvd.nist.gov/vuln/detail/CVE-2026-39831) | `golang.org/x/crypto` | `v0.46.0` | `0.52.0` |
| HIGH | [CVE-2026-39832](https://nvd.nist.gov/vuln/detail/CVE-2026-39832) | `golang.org/x/crypto` | `v0.46.0` | `0.52.0` |
| HIGH | [CVE-2026-39835](https://nvd.nist.gov/vuln/detail/CVE-2026-39835) | `golang.org/x/crypto` | `v0.46.0` | `0.52.0` |
| HIGH | [CVE-2026-39883](https://nvd.nist.gov/vuln/detail/CVE-2026-39883) | `go.opentelemetry.io/otel/sdk` | `v1.38.0` | `1.43.0` |
| HIGH | [CVE-2026-42508](https://nvd.nist.gov/vuln/detail/CVE-2026-42508) | `golang.org/x/crypto` | `v0.46.0` | `0.52.0` |
| HIGH | [CVE-2026-46595](https://nvd.nist.gov/vuln/detail/CVE-2026-46595) | `golang.org/x/crypto` | `v0.46.0` | `0.52.0` |
| HIGH | [CVE-2026-46597](https://nvd.nist.gov/vuln/detail/CVE-2026-46597) | `golang.org/x/crypto` | `v0.46.0` | `0.52.0` |
| HIGH | [CVE-2026-46600](https://nvd.nist.gov/vuln/detail/CVE-2026-46600) | `golang.org/x/net` | `v0.48.0` | `0.56.0` |
| HIGH | [CVE-2026-46600](https://nvd.nist.gov/vuln/detail/CVE-2026-46600) | `stdlib` | `v1.26.4` | `1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-48702](https://nvd.nist.gov/vuln/detail/CVE-2026-48702) | `github.com/sigstore/rekor` | `v1.4.3` | `1.5.2` |
| HIGH | [CVE-2026-49478](https://nvd.nist.gov/vuln/detail/CVE-2026-49478) | `github.com/sigstore/fulcio` | `v1.8.4` | `1.8.6` |
| HIGH | [CVE-2026-56851](https://nvd.nist.gov/vuln/detail/CVE-2026-56851) | `golang.org/x/text` | `v0.32.0` | `0.41.0` |
| HIGH | [CVE-2026-56852](https://nvd.nist.gov/vuln/detail/CVE-2026-56852) | `golang.org/x/text` | `v0.32.0` | `0.39.0` |
| HIGH | [CVE-2026-56853](https://nvd.nist.gov/vuln/detail/CVE-2026-56853) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56854](https://nvd.nist.gov/vuln/detail/CVE-2026-56854) | `golang.org/x/crypto` | `v0.46.0` | `0.55.0` |
| HIGH | [CVE-2026-56858](https://nvd.nist.gov/vuln/detail/CVE-2026-56858) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56859](https://nvd.nist.gov/vuln/detail/CVE-2026-56859) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56860](https://nvd.nist.gov/vuln/detail/CVE-2026-56860) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56862](https://nvd.nist.gov/vuln/detail/CVE-2026-56862) | `stdlib` | `v1.26.4` | `1.25.13, 1.26.6, 1.27.0-rc.3` |
| HIGH | [CVE-2026-56864](https://nvd.nist.gov/vuln/detail/CVE-2026-56864) | `golang.org/x/mod` | `v0.30.0` | `0.40.0` |
| HIGH | [CVE-2026-56865](https://nvd.nist.gov/vuln/detail/CVE-2026-56865) | `golang.org/x/mod` | `v0.30.0` | `0.40.0` |
| HIGH | [CVE-2026-78667](https://nvd.nist.gov/vuln/detail/CVE-2026-78667) | `stdlib` | `v1.26.4` | `1.26.9, 1.27.2` |
| HIGH | [CVE-2026-78667](https://nvd.nist.gov/vuln/detail/CVE-2026-78667) | `stdlib` | `v1.26.8` | `1.26.9, 1.27.2` |
| HIGH | [CVE-2026-78669](https://nvd.nist.gov/vuln/detail/CVE-2026-78669) | `golang.org/x/net` | `v0.48.0` | `0.60.0` |
| HIGH | [CVE-2026-78669](https://nvd.nist.gov/vuln/detail/CVE-2026-78669) | `stdlib` | `v1.26.4` | `1.26.9, 1.27.2` |
| HIGH | [CVE-2026-78669](https://nvd.nist.gov/vuln/detail/CVE-2026-78669) | `golang.org/x/net` | `v0.57.0` | `0.60.0` |
| HIGH | [CVE-2026-78669](https://nvd.nist.gov/vuln/detail/CVE-2026-78669) | `stdlib` | `v1.26.8` | `1.26.9, 1.27.2` |
| HIGH | [CVE-2026-84304](https://nvd.nist.gov/vuln/detail/CVE-2026-84304) | `google.golang.org/grpc` | `v1.77.0` | `1.83.1` |
| HIGH | [CVE-2026-84445](https://nvd.nist.gov/vuln/detail/CVE-2026-84445) | `google.golang.org/grpc` | `v1.77.0` | `1.82.2, 1.83.2, 1.84.0-dev.0.20260825144003-d5a41119e0e3, 1.85.0-dev.0.20260825072537-93e31b48545e` |
| HIGH | [CVE-2026-97031](https://nvd.nist.gov/vuln/detail/CVE-2026-97031) | `stdlib` | `v1.26.4` | `1.26.9, 1.27.2` |
| HIGH | [CVE-2026-97031](https://nvd.nist.gov/vuln/detail/CVE-2026-97031) | `stdlib` | `v1.26.8` | `1.26.9, 1.27.2` |
| HIGH | [GHSA-hrxh-6v49-42gf](https://github.com/advisories/GHSA-hrxh-6v49-42gf) | `google.golang.org/grpc` | `v1.77.0` | `1.82.1` |

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

<sub>Produced by [this workflow run](https://github.com/bob-vistasecurity/VistaPlatform/actions/runs/39114515505).</sub>
