# Crypto Inventory Network Sensor

## Build
```bash
make build-sensor          # builds bin/crypto-sensor
CROSS=1 make build-sensor  # builds cross-platform binaries
```

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
