# Crypto Inventory Network Sensor

## Build
```bash
make build-sensor          # builds bin/crypto-sensor
CROSS=1 make build-sensor  # builds cross-platform binaries
```

## Runtime dependencies (pre-built binaries)

Linux sensors dynamically link libpcap. Install the runtime with
`sudo apt-get install libpcap0.8` on Debian/Ubuntu (`libpcap0.8t64` on newer
releases), `sudo dnf install libpcap` on RHEL/Fedora, or
`sudo zypper install libpcap1` on SUSE. Offline hosts need the distribution's
packages and their dependencies supplied locally. macOS includes libpcap;
Windows requires [Npcap](https://npcap.com/).

The Linux systemd installer checks that the actual sensor binary can load before
prompting for settings, creating users, writing files, or registering the sensor.
It reports loader failures with libpcap installation instructions and preserves
the original error to help diagnose incompatible architectures or libc versions.
It does not install packages automatically.

After verifying the downloaded Linux binary, place it in your current directory
as `crypto-sensor`. From the repository root, check without root or registration:

```bash
chmod +x ./crypto-sensor
bash scripts/install-sensor.sh --check-dependencies
```

This verifies startup dependencies; it does not test packet-capture permissions
or connectivity to the control plane. Launching a bare binary bypasses the
installer's diagnostics.

## Configuration
The sensor currently reads configuration from environment variables. A sample YAML file is provided for reference/documentation and future file-based config support.

Create a config file based on the example (optional):
```bash
cp sensor/config.example.yaml sensor/config.yaml
```

Key fields (env var equivalents in parentheses):
- sensorId (SENSOR_ID)
- controlPlaneUrl (CONTROL_PLANE_URL)
- registrationKey (REGISTRATION_KEY)
- reportingIntervalSeconds (REPORTING_INTERVAL)
- storage.* (MAX_STORAGE_SIZE, ROTATION_SIZE, RETENTION_DAYS, DATA_PATH, ENCRYPTION_KEY)
- capture.* (INTERFACES, ACTIVE_PROBING, NETWORK_DISCOVERY, MAX_CONNECTIONS, TIMEOUT_SECONDS, BUFFER_SIZE)
- capture.dedupTTLMinutes — minimum **minutes** before re-reporting the same passive observation (same destination IP, port, protocol). Default **60**. Overrides: `DEDUP_TTL_MINUTES` env var; control-plane `capture_config.dedup_ttl_minutes` or `update_config` payload (applied live on next heartbeat without restart).

- capture.thirdPartyTLSEnrichment (`THIRD_PARTY_TLS_ENRICHMENT`) — default **false**. Let the TLS enricher connect to third-party TLS services the network talks to, to read their certificates. Without it the enricher only connects to private addresses, `capture.ownedNetworks` / platform-declared segments, and elevated connections. A **local** value: it applies only while the platform has never delivered its `third_party_tls_enrichment` setting; the platform's value wins from its first delivery and is recorded in `<dataPath>/platform-probe-consent.json` so it keeps winning after a restart. Delete that file to hand control back to the local value.
- capture.ownedNetworks (`OWNED_NETWORKS`, comma-separated) — public CIDRs this sensor may treat as the tenant's own, for an air-gapped sensor with no platform-declared network segments. IPv4 must be /8 or narrower, IPv6 /16 or narrower; wider entries are ignored. Same precedence as `thirdPartyTLSEnrichment`: replaced by the platform's owned networks from their first delivery.

The dedup window is shared by the passive connection cache (TLS/SSH TCP reassembly and fallback path) and the TLS enricher debounce (active probes for TLS 1.3–style certificate gaps).

## Run
```bash
./bin/crypto-sensor -verbose -register
```

## Package
```bash
make sensor-package
# output: dist/crypto-sensor-release.tar.gz
```
