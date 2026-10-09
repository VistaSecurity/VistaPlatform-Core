#!/bin/bash

# Vista Platform Device Agent installer (Linux, systemd).
#
# Installs ./device-agent as a service, writes its configuration, starts it,
# and waits for the agent to enroll itself with the platform. The counterpart
# of install-sensor.sh: the same steps, the same output, the same
# re-run-to-upgrade behaviour.
#
# Usage: sudo bash install-device-agent.sh --url URL --key KEY [options]

set -e

CONTROL_PLANE_URL=""
REGISTRATION_KEY=""
CA_FINGERPRINT=""
INSTALL_DIR="/opt/crypto-device-agent"
SERVICE_NAME="crypto-device-agent"
SERVICE_USER="crypto-device-agent"
CHECK_DEPENDENCIES=false
REGISTRATION_TIMEOUT=${REGISTRATION_TIMEOUT:-90}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status()  { echo -e "${GREEN}[INFO]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
print_error()   { echo -e "${RED}[ERROR]${NC} $1"; }
print_header()  { echo -e "${BLUE}$1${NC}"; }

show_usage() {
    cat << EOF
Vista Platform Device Agent Installer
=====================================

Usage: $0 --url URL --key KEY [options]

Options:
    -u, --url URL              Platform URL, as shown in the console (required)
    -k, --key KEY              Registration key (required)
    --ca-fingerprint SHA256    Expected SHA-256 fingerprint of the platform's CA, for a
                               platform whose certificate this host does not already trust
    -d, --dir DIRECTORY        Installation directory (default: $INSTALL_DIR)
    --check-dependencies       Check ./device-agent runs on this host, then exit (no root needed)
    -h, --help                 Show this help

Run it from the directory holding the downloaded agent, saved as ./device-agent.
Re-running it with the same key keeps the agent's enrollment and replaces only
the binary, which is how to upgrade it.
EOF
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--url) CONTROL_PLANE_URL="$2"; shift 2 ;;
        -k|--key) REGISTRATION_KEY="$2"; shift 2 ;;
        --ca-fingerprint) CA_FINGERPRINT="$2"; shift 2 ;;
        -d|--dir) INSTALL_DIR="$2"; shift 2 ;;
        --check-dependencies) CHECK_DEPENDENCIES=true; shift ;;
        -h|--help) show_usage; exit 0 ;;
        *) print_error "Unknown option: $1"; show_usage; exit 1 ;;
    esac
done

# The agent is statically linked; running it proves it is the right build for
# this host's architecture. --version exits before configuration or enrollment.
check_agent_binary() {
    local binary="./device-agent" output
    if [[ ! -f "$binary" ]]; then
        print_error "Device agent binary not found: $binary"
        print_error "Download the Linux device agent for this host's architecture, save it as device-agent, and place it in the current directory."
        return 1
    fi
    if [[ ! -x "$binary" ]]; then
        print_error "Device agent binary is not executable. Run: chmod +x ./device-agent"
        return 1
    fi
    if output=$(LC_ALL=C "$binary" -version 2>&1); then
        print_status "Device agent runs on this host."
        return 0
    fi
    print_error "The device agent cannot run on this host. Installation stopped before anything was changed."
    printf '%s\n' "$output"
    print_error "Check that the binary matches this host's architecture (amd64 or arm64)."
    return 1
}

if [[ $(uname -s) != Linux ]]; then
    print_error "This installer requires Linux with systemd. On Windows use install-device-agent.ps1."
    exit 1
fi

if [[ "$CHECK_DEPENDENCIES" == "true" ]]; then
    check_agent_binary
    exit $?
fi

check_agent_binary

if [[ -z "$CONTROL_PLANE_URL" || -z "$REGISTRATION_KEY" ]]; then
    print_error "--url and --key are required"
    show_usage
    exit 1
fi

if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

AGENT_VERSION=$(./device-agent -version 2>/dev/null | head -1 | sed -n 's/.* v\([^ ]*\)$/\1/p')

print_header "🚀 Vista Platform Device Agent Installer"
echo "=================================================="
echo "  Agent Version: ${AGENT_VERSION:-unknown}"
echo "  Platform: $CONTROL_PLANE_URL"
echo "  Install Directory: $INSTALL_DIR"

# Step 1: Service user
print_status "Creating service user: $SERVICE_USER"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
fi

# Step 2: Directories
mkdir -p "$INSTALL_DIR" "$INSTALL_DIR/data"

CONFIG_FILE="$INSTALL_DIR/device-agent.yaml"
UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# Prints the value of a top-level `key: value` line in the agent config, with
# optional surrounding double quotes removed (the agent writes agent_id and
# data_path quoted, platform_url and registration_key bare).
read_config_value() {
    sed -n "s/^$1:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*\$/\1/p" "$2" 2>/dev/null | head -1
}

# A host this key already enrolled keeps its identity. Re-running the same
# install command (to upgrade the binary, or by mistake) must not discard the
# certificate and agent ID and send it back to register with a key it has
# already spent. A different key means a fresh enrollment.
KEEP_ENROLLMENT=false
if [[ -f "$CONFIG_FILE" ]] \
    && [[ "$(read_config_value agent_id "$CONFIG_FILE")" =~ $UUID_RE ]] \
    && [[ "$(read_config_value registration_key "$CONFIG_FILE")" == "$REGISTRATION_KEY" ]]; then
    KEEP_ENROLLMENT=true
    print_status "This host is already enrolled with this key (agent $(read_config_value agent_id "$CONFIG_FILE")); keeping its identity and configuration."
fi

# Stop a previous install: its binary cannot be replaced while it runs ("Text
# file busy"), and it must not rewrite the config while we replace it.
systemctl stop "$SERVICE_NAME.service" 2>/dev/null || true

# Step 3: Binary
print_status "Installing device agent binary..."
cp ./device-agent "$INSTALL_DIR/device-agent"
chmod 755 "$INSTALL_DIR/device-agent"

# Step 4: Configuration
#
# The installer does NOT register the agent. The agent enrolls itself on first
# start: it generates its keypair locally (the private key never leaves the
# host), sends a CSR, and rewrites this file with the agent ID the platform
# accepted, the mTLS endpoint it was given and its data path — where the client
# certificate and the platform CA that signs that endpoint are kept. The data
# path is inside the install directory and owned by the service user; the
# agent's own default (/var/lib/crypto-device-agent) is root-owned, which is
# how running it by hand as an ordinary user spent the key on an enrollment it
# could not save.
if [[ "$KEEP_ENROLLMENT" != "true" ]]; then
    print_status "Creating configuration file..."
    # A fresh enrollment must not inherit a previous agent's certificate.
    rm -rf "$INSTALL_DIR/data/certs"
    # Holds the registration key until the agent redeems it: owner-only before
    # any content is written (cat > keeps the mode of the file it truncates).
    : > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    cat > "$CONFIG_FILE" << EOF
# Vista Platform Device Agent configuration (generated by install-device-agent.sh)
platform_url: $CONTROL_PLANE_URL
registration_key: $REGISTRATION_KEY
poll_interval: 30s
data_path: "$INSTALL_DIR/data"
EOF
fi

# Step 5: systemd service
print_status "Creating systemd service..."
EXEC_START="$INSTALL_DIR/device-agent -config $CONFIG_FILE -interactive=false"
if [[ -n "$CA_FINGERPRINT" ]]; then
    # Pins the platform's CA on first start, verified against this
    # fingerprint; ignored once a CA is in the config.
    EXEC_START+=" -ca-fingerprint $CA_FINGERPRINT"
fi
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Vista Platform Device Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
# Enrolls on first start with the key in the config, then runs from the
# certificate it was issued. A failed enrollment exits; the restart retries.
ExecStart=$EXEC_START
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

[Install]
WantedBy=multi-user.target
EOF

# Step 6: Permissions. The agent rewrites its config and writes its
# certificate under data/, so the service user must own both.
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chmod 600 "$CONFIG_FILE"

# Step 7: Start; the agent enrolls itself
print_status "Starting the device agent; it enrolls itself with the platform..."
systemctl daemon-reload
systemctl enable "$SERVICE_NAME.service"
START_EPOCH=$(date +%s)
if ! systemctl restart "$SERVICE_NAME.service"; then
    print_error "Failed to start the device agent service"
    print_status "Check logs with: journalctl -u $SERVICE_NAME -f"
    exit 1
fi

# Step 8: Wait for enrollment
#
# Enrollment is confirmed only by the agent itself: it rewrites agent_id with
# the ID the platform accepted. A running service is not an enrolled agent.
print_status "Waiting up to ${REGISTRATION_TIMEOUT}s for the agent to enroll..."
AGENT_ID=""
REJECTED=false
while (( $(date +%s) - START_EPOCH < REGISTRATION_TIMEOUT )); do
    current_id=$(read_config_value agent_id "$CONFIG_FILE")
    if [[ "$current_id" =~ $UUID_RE ]]; then
        AGENT_ID="$current_id"
        break
    fi
    if journalctl -u "$SERVICE_NAME.service" --since "@$START_EPOCH" --no-pager -o cat 2>/dev/null \
        | grep -q -E 'Registration was REJECTED|cannot store its enrollment'; then
        REJECTED=true
        break
    fi
    sleep 2
done

if [[ -z "$AGENT_ID" ]]; then
    echo ""
    journalctl -u "$SERVICE_NAME.service" --since "@$START_EPOCH" --no-pager -o cat 2>/dev/null \
        | grep -E '⛔|❌' | tail -8 || true
    echo ""
    if [[ "$REJECTED" == "true" ]]; then
        # A rejected key never succeeds; stop the service rather than leave it
        # restarting every 10 seconds.
        systemctl stop "$SERVICE_NAME.service" || true
        systemctl disable "$SERVICE_NAME.service" 2>/dev/null || true
        print_error "The agent could not enroll (see above). If the key was rejected it is invalid, expired, or already used."
        print_error "Generate a new key (Discovery → Sensors & Agents → Register → Device agent) and re-run this installer with it."
        print_status "The device agent service has been stopped and disabled."
    else
        print_error "The agent did not enroll within ${REGISTRATION_TIMEOUT}s."
        print_status "It is still running and retrying; check that $CONTROL_PLANE_URL is reachable from this host."
        print_status "Watch it with: journalctl -u $SERVICE_NAME -f"
    fi
    exit 1
fi

if ! systemctl is-active --quiet "$SERVICE_NAME.service"; then
    print_error "❌ The agent enrolled but is not running"
    print_status "Check logs with: journalctl -u $SERVICE_NAME -f"
    exit 1
fi

print_header "🎉 Installation Complete!"
echo "================================"
echo "Agent ID: $AGENT_ID"
echo "Agent Version: ${AGENT_VERSION:-unknown}"
echo "Installation Directory: $INSTALL_DIR"
echo "Configuration: $CONFIG_FILE"
echo "Service: $SERVICE_NAME.service"
echo ""
echo "📋 Management Commands:"
echo "  Status:     systemctl status $SERVICE_NAME"
echo "  Logs:       journalctl -u $SERVICE_NAME -f"
echo "  Restart:    systemctl restart $SERVICE_NAME"
echo "  Uninstall:  systemctl stop $SERVICE_NAME && systemctl disable $SERVICE_NAME"
echo ""
print_status "The agent is enrolled and polling for interrogation jobs."
print_status "It appears under Discovery → Sensors & Agents once its first heartbeat arrives."
