# Sensor Artifacts Directory

Local build output for the sensor binary. `make sensor-<platform>` places
each platform's binary here, bundled with the matching installer script
(`install-sensor.sh` / `install-sensor.ps1`), ready to copy to a target host.

## Directory Structure

```
artifacts/sensor/
├── linux/
│   ├── amd64/{crypto-sensor,install-sensor.sh}   # Linux x86_64
│   └── arm64/{crypto-sensor,install-sensor.sh}   # Linux ARM64
├── windows/
│   ├── amd64/{crypto-sensor.exe,install-sensor.ps1}
│   └── 386/{crypto-sensor.exe,install-sensor.ps1}
└── darwin/
    ├── amd64/{crypto-sensor,install-sensor.sh}   # macOS x86_64
    └── arm64/{crypto-sensor,install-sensor.sh}   # macOS ARM64 (Apple Silicon)
```

## Building Artifacts

```bash
# Current platform only
make build-sensor

# All supported platforms
make sensor-all-platforms

# A specific platform
make sensor-linux-amd64
make sensor-linux-arm64
make sensor-windows-amd64
make sensor-windows-386
make sensor-darwin-amd64
make sensor-darwin-arm64
```

The sensor is CGO-linked against libpcap, so Linux and macOS builds run
natively per platform rather than cross-compiling; Windows is CGO-free and
cross-compiles from Linux. `.github/workflows/release-core.yml` builds every
platform this way on each release and attaches the binaries — plus a signed
`SHA256SUMS` — to the GitHub Release, which is the normal way to get a binary
without building it yourself.

## This directory is a local build convenience, not a distribution mechanism

Nothing serves these files over HTTP. An earlier version of this platform had
`sensor-manager` serve binaries directly from this directory (with an S3
fallback), and a later one had an `artifact-service` catalog of download URLs;
both were removed. Binary distribution happens through signed GitHub Release
assets (or a local build), not through the platform.

For the full sensor registration and installation flow — including how a
tenant actually gets and installs a sensor today — see
[`docsv4/core/features/SENSOR_REGISTRATION.md`](../docsv4/core/features/SENSOR_REGISTRATION.md).

## Cross-Compilation Notes

- **Linux**: Both amd64 and arm64 builds are supported (native per-arch).
- **Windows**: amd64 and 386 builds are supported (CGO-free, cross-compiles
  from Linux).
- **macOS**: Both amd64 and arm64 builds are supported (requires a macOS host
  — the capture code is CGO-linked against libpcap).
