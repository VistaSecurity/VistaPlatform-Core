#!/bin/bash
# Build Windows binaries for the sensor and device-agent from this Linux host.
#
# Both agents cross-compile cleanly with CGO_ENABLED=0:
#   - sensor:       gopacket/pcap uses pure Go syscalls on Windows (loads wpcap.dll at runtime)
#   - device-agent: pure Go, no native dependencies
#
# Runtime requirement on Windows: Npcap (https://npcap.com) must be installed for the sensor.
# The device-agent has no runtime native dependencies.
#
# Usage:
#   ./scripts/build-windows-agents.sh              # build both (amd64)
#   ./scripts/build-windows-agents.sh --sensor     # sensor only
#   ./scripts/build-windows-agents.sh --agent      # device-agent only
#   ./scripts/build-windows-agents.sh --tag v1.2.0 # embed version tag

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$SCRIPT_DIR")"
cd "$ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()   { echo -e "${GREEN}✅  $*${NC}"; }
info() { echo -e "${BLUE}>>  $*${NC}"; }
warn() { echo -e "${YELLOW}!!  $*${NC}"; }
err()  { echo -e "${RED}XX  $*${NC}"; exit 1; }

BUILD_SENSOR=true
BUILD_AGENT=true
VERSION_TAG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sensor) BUILD_AGENT=false; shift ;;
    --agent)  BUILD_SENSOR=false; shift ;;
    --tag)    VERSION_TAG="$2"; shift 2 ;;
    *) err "Unknown option: $1. Usage: $0 [--sensor|--agent] [--tag VERSION]" ;;
  esac
done

if ! command -v go &>/dev/null; then
  err "go not found. Install Go 1.26: https://go.dev/dl/"
fi

GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
GO_MINOR=$(echo "$GO_VERSION" | cut -d. -f2)
if [[ "$GO_MINOR" -lt 26 ]]; then
  err "Go $GO_VERSION detected — Go 1.26 required"
fi
info "Go $GO_VERSION"

LDFLAGS=""
if [[ -n "$VERSION_TAG" ]]; then
  # NB: the symbol is main.Version (capital V) in both sensor and device-agent;
  # a lowercase main.version silently stamps nothing.
  LDFLAGS="-ldflags=-X main.Version=${VERSION_TAG}"
  info "Version tag: $VERSION_TAG"
fi

mkdir -p bin artifacts/sensor/windows/amd64 artifacts/device-agent/windows/amd64

# ── Sensor ────────────────────────────────────────────────────────────────────
if [[ "$BUILD_SENSOR" == true ]]; then
  info "Building sensor (Windows amd64)..."
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -C sensor $LDFLAGS \
    -o "$ROOT/bin/crypto-sensor-windows-amd64.exe" \
    cmd/main.go
  cp bin/crypto-sensor-windows-amd64.exe artifacts/sensor/windows/amd64/crypto-sensor.exe
  ok "sensor → artifacts/sensor/windows/amd64/crypto-sensor.exe"
fi

# ── Device Agent ──────────────────────────────────────────────────────────────
if [[ "$BUILD_AGENT" == true ]]; then
  info "Building device-agent (Windows amd64)..."
  GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
    go build -C device-agent $LDFLAGS \
    -o "$ROOT/bin/device-agent-windows-amd64.exe" \
    ./cmd/main.go
  cp bin/device-agent-windows-amd64.exe artifacts/device-agent/windows/amd64/device-agent.exe
  ok "device-agent → artifacts/device-agent/windows/amd64/device-agent.exe"
fi

echo ""
echo "Output:"
if [[ "$BUILD_SENSOR" == true ]]; then
  ls -lh artifacts/sensor/windows/amd64/crypto-sensor.exe
fi
if [[ "$BUILD_AGENT" == true ]]; then
  ls -lh artifacts/device-agent/windows/amd64/device-agent.exe
fi

echo ""
echo "Runtime note (sensor only):"
echo "  Npcap must be installed on the target Windows host: https://npcap.com"
echo "  wpcap.dll is loaded at runtime — no DLL bundling required."
