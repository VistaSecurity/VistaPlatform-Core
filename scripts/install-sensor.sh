#!/bin/bash

# Crypto Inventory Sensor Installer
# Usage: ./install-sensor.sh [options]

set -e

# Default values
CONTROL_PLANE_URL="https://app.vistasecurity.io"
REGISTRATION_KEY=""
SENSOR_NAME=""
INTERFACES=""
PROFILE="datacenter_host"
INSTALL_DIR="/opt/crypto-sensor"
SERVICE_USER="crypto-sensor"
VERBOSE=false
EXPECTED_IP=""
INTERACTIVE=false
CHECK_DEPENDENCIES=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${BLUE}$1${NC}"
}

# Show usage
show_usage() {
    cat << EOF
Crypto Inventory Sensor Installer
=================================

Usage: $0 [options]

Options:
    -u, --url URL              Control plane URL (default: $CONTROL_PLANE_URL)
    -k, --key KEY              Registration key (required)
    -n, --name NAME            Sensor name (default: auto-detect)
    -i, --interfaces IFACES    Network interfaces (default: auto-detect)
    -p, --profile PROFILE      Deployment profile (default: $PROFILE; not yet applied —
                               the sensor registers as datacenter_host)
    -d, --dir DIRECTORY        Installation directory (default: $INSTALL_DIR)
    --ip IP_ADDRESS            Expected IP address for validation (required)
    --interactive              Run in interactive mode (ask for all settings)
    --check-dependencies       Check ./crypto-sensor can load, then exit (no root needed)
    --verbose                  Enable verbose output
    -h, --help                 Show this help

Examples:
    # Interactive installation (recommended)
    $0 --interactive

    # Basic installation with arguments
    $0 --key REG-550e8400-20241215-A7B3C9 --ip 192.168.1.100

    # Custom configuration
    $0 --key REG-550e8400-20241215-A7B3C9 \\
       --ip 192.168.1.100 \\
       --name sensor-dc01 \\
       --interfaces "eth0,eth1" \\
       --profile datacenter_host

    # Air-gapped installation
    $0 --key REG-550e8400-20241215-A7B3C9 \\
       --ip 10.0.1.50 \\
       --profile air_gapped \\
       --interfaces "eth0"

Profiles:
    - end_user_machine    : Minimal footprint, single interface
    - datacenter_host     : Full features, multiple interfaces
    - cloud_instance      : Cloud-optimized, periodic reporting
    - air_gapped         : Offline mode, export files

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -u|--url)
            CONTROL_PLANE_URL="$2"
            shift 2
            ;;
        -k|--key)
            REGISTRATION_KEY="$2"
            shift 2
            ;;
        -n|--name)
            SENSOR_NAME="$2"
            shift 2
            ;;
        -i|--interfaces)
            INTERFACES="$2"
            shift 2
            ;;
        -p|--profile)
            PROFILE="$2"
            shift 2
            ;;
        -d|--dir)
            INSTALL_DIR="$2"
            shift 2
            ;;
        --ip)
            EXPECTED_IP="$2"
            shift 2
            ;;
        --interactive)
            INTERACTIVE=true
            shift
            ;;
        --check-dependencies)
            CHECK_DEPENDENCIES=true
            shift
            ;;
        --verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Run the actual binary: a library filename or installed package alone does not
# prove that its architecture, SONAME and transitive dependencies are compatible.
# --version exits before configuration, registration or packet capture.
check_sensor_dependencies() {
    local binary="./crypto-sensor" loader_output
    if [[ ! -f "$binary" ]]; then
        print_error "Sensor binary not found: $binary"
        print_error "Download and verify the Linux sensor for this host's architecture, rename it crypto-sensor, and place it in the current directory."
        return 1
    fi
    if [[ ! -x "$binary" ]]; then
        print_error "Sensor binary is not executable. Run: chmod +x ./crypto-sensor"
        return 1
    fi
    if loader_output=$(LC_ALL=C "$binary" --version 2>&1); then
        print_status "Sensor runtime dependencies are available."
        return 0
    fi

    print_error "The sensor cannot load. Installation stopped before creating users, writing configuration or registering with the control plane."
    print_error "The Linux sensor requires the libpcap runtime and a compatible system loader."
    printf '%s\n' "$loader_output"
    print_status "If libpcap is missing, install it using your distribution's package manager:"
    echo "  Debian / Ubuntu:                    sudo apt-get update && sudo apt-get install libpcap0.8"
    echo "                                      (apt installs libpcap0.8t64 on Ubuntu 24.04+ / Debian 13+)"
    echo "  RHEL / Fedora / Rocky / Alma:       sudo dnf install libpcap"
    echo "  Amazon Linux 2 / CentOS 7 (yum):    sudo yum install libpcap"
    echo "  SUSE / openSUSE:                    sudo zypper install libpcap1"
    echo "  Arch / Manjaro:                     sudo pacman -S libpcap"
    echo "  For offline hosts, provide the distribution's libpcap package and its dependencies from an approved local repository."
    print_error "If libpcap is installed, check that the binary matches this host's architecture and libc; installing libpcap alone cannot fix an incompatible build."
    echo "  Retry: bash scripts/install-sensor.sh --check-dependencies"
    return 1
}

# This installer installs a systemd service and uses Linux networking tools.
if [[ $(uname -s) != Linux ]]; then
    print_error "This installer requires Linux with systemd. On Windows use install-sensor.ps1; on macOS use the macOS sensor binary (libpcap is supplied by the OS)."
    exit 1
fi

if [[ "$CHECK_DEPENDENCIES" == "true" ]]; then
    check_sensor_dependencies
    exit $?
fi

# Interactive mode function
# Provides a guided, user-friendly installation experience
# Prompts for all required configuration parameters with validation
# Shows available options and provides helpful descriptions
run_interactive_mode() {
    print_header "🎛️ Interactive Sensor Installation"
    echo "======================================"
    echo ""
    print_status "This will guide you through the sensor installation process."
    echo ""

    # Get registration key - required for sensor authentication
    # Format: REG-{tenant_id}-{timestamp}-{checksum}
    while [[ -z "$REGISTRATION_KEY" ]]; do
        read -p "Enter registration key: " REGISTRATION_KEY
        if [[ -z "$REGISTRATION_KEY" ]]; then
            print_error "Registration key is required"
        fi
    done

    # Get IP address - required for security validation
    # Must match one of the host's network interface IPs
    while [[ -z "$EXPECTED_IP" ]]; do
        read -p "Enter expected IP address: " EXPECTED_IP
        if [[ -z "$EXPECTED_IP" ]]; then
            print_error "IP address is required"
        elif ! [[ $EXPECTED_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            print_error "Invalid IP address format"
            EXPECTED_IP=""
        fi
    done

    # Get sensor name
    read -p "Enter sensor name (default: auto-detect): " SENSOR_NAME_INPUT
    if [[ -n "$SENSOR_NAME_INPUT" ]]; then
        SENSOR_NAME="$SENSOR_NAME_INPUT"
    fi

    # Get control plane URL
    read -p "Enter control plane URL (default: $CONTROL_PLANE_URL): " CONTROL_PLANE_URL_INPUT
    if [[ -n "$CONTROL_PLANE_URL_INPUT" ]]; then
        CONTROL_PLANE_URL="$CONTROL_PLANE_URL_INPUT"
    fi

    # Get profile
    echo ""
    print_status "Available profiles:"
    echo "  1) datacenter_host - Full features, multiple interfaces"
    echo "  2) cloud_instance - Cloud-optimized, periodic reporting"
    echo "  3) end_user_machine - Minimal footprint, single interface"
    echo "  4) air_gapped - Offline mode, export files"
    echo ""
    
    while true; do
        read -p "Select profile (1-4, default: 1): " PROFILE_CHOICE
        case $PROFILE_CHOICE in
            1|"")
                PROFILE="datacenter_host"
                break
                ;;
            2)
                PROFILE="cloud_instance"
                break
                ;;
            3)
                PROFILE="end_user_machine"
                break
                ;;
            4)
                PROFILE="air_gapped"
                break
                ;;
            *)
                print_error "Invalid choice. Please select 1-4."
                ;;
        esac
    done

    # Get network interfaces
    echo ""
    print_status "Available network interfaces:"
    ip -o link show | awk -F': ' '{print "  " $2}' | grep -E '^(eth|ens|enp|wl)' | head -10
    echo ""
    read -p "Enter network interfaces (comma-separated, default: auto-detect): " INTERFACES_INPUT
    if [[ -n "$INTERFACES_INPUT" ]]; then
        INTERFACES="$INTERFACES_INPUT"
    fi

    # Get installation directory
    read -p "Enter installation directory (default: $INSTALL_DIR): " INSTALL_DIR_INPUT
    if [[ -n "$INSTALL_DIR_INPUT" ]]; then
        INSTALL_DIR="$INSTALL_DIR_INPUT"
    fi

    # Show configuration summary
    echo ""
    print_header "📋 Installation Configuration"
    echo "=================================="
    echo "Registration Key: $REGISTRATION_KEY"
    echo "IP Address: $EXPECTED_IP"
    echo "Sensor Name: $SENSOR_NAME"
    echo "Control Plane: $CONTROL_PLANE_URL"
    echo "Profile: $PROFILE"
    echo "Interfaces: $INTERFACES"
    echo "Install Directory: $INSTALL_DIR"
    echo ""

    # Confirm installation
    while true; do
        read -p "Proceed with installation? (y/N): " CONFIRM
        case $CONFIRM in
            [Yy]|[Yy][Ee][Ss])
                break
                ;;
            [Nn]|[Nn][Oo]|"")
                print_status "Installation cancelled."
                exit 0
                ;;
            *)
                print_error "Please answer yes or no."
                ;;
        esac
    done

    echo ""
    print_status "Starting installation..."
}

# Run interactive mode if requested
# Fail before prompts, installation side effects or control-plane registration.
check_sensor_dependencies

if [[ "$INTERACTIVE" == "true" ]]; then
    run_interactive_mode
fi

# Validate required parameters (skip if interactive mode already handled)
if [[ "$INTERACTIVE" != "true" ]]; then
    if [[ -z "$REGISTRATION_KEY" ]]; then
        print_error "Registration key is required"
        show_usage
        exit 1
    fi

    if [[ -z "$EXPECTED_IP" ]]; then
        print_error "Expected IP address is required for validation"
        show_usage
        exit 1
    fi
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root (use sudo)"
    exit 1
fi

# The version the platform will show is the one stamped into this binary — the
# sensor reports it itself at registration and on every heartbeat.
SENSOR_VERSION=$(./crypto-sensor --version 2>/dev/null | head -1 | sed -n 's/.* v\([^ ]*\)$/\1/p')

print_header "🚀 Crypto Inventory Sensor Installer"
echo "=================================================="

# Step 1: Detect environment
print_status "Detecting environment..."

# Detect platform
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# Detect network interfaces if not specified
if [[ -z "$INTERFACES" ]]; then
    print_status "Auto-detecting network interfaces..."
    INTERFACES=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(eth|ens|enp|wl)' | head -5 | tr '\n' ',' | sed 's/,$//')
    if [[ -z "$INTERFACES" ]]; then
        INTERFACES="eth0"
    fi
fi

# Generate sensor name if not specified
if [[ -z "$SENSOR_NAME" ]]; then
    HOSTNAME=$(hostname)
    SENSOR_NAME="sensor-${HOSTNAME}-$(date +%Y%m%d)"
fi

print_status "Environment detected:"
echo "  Platform: $PLATFORM/$ARCH"
echo "  Sensor Version: ${SENSOR_VERSION:-unknown}"
echo "  Interfaces: $INTERFACES"
echo "  Sensor Name: $SENSOR_NAME"
echo "  Profile: $PROFILE"
echo "  Control Plane: $CONTROL_PLANE_URL"
echo "  Expected IP: $EXPECTED_IP"

if [[ "$PROFILE" != "datacenter_host" ]]; then
    print_warning "--profile $PROFILE is not applied yet: the sensor registers itself and reports the datacenter_host profile."
fi

# Step 1.5: Validate IP address
print_status "Validating IP address..."
if ! ip addr show | grep -q "$EXPECTED_IP"; then
    print_error "Expected IP address $EXPECTED_IP not found on any interface"
    print_status "Available IP addresses:"
    ip addr show | grep "inet " | awk '{print "  " $2}' | cut -d'/' -f1
    exit 1
fi
print_status "✅ IP address validation passed"

# Step 2: Create service user
print_status "Creating service user: $SERVICE_USER"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
    print_status "Service user created"
else
    print_status "Service user already exists"
fi

# Step 3: Create installation directory
print_status "Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR/data"
mkdir -p "$INSTALL_DIR/logs"

CONFIG_FILE="$INSTALL_DIR/sensor-config.yaml"
UUID_RE='^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# Prints the value of a top-level `key: value` line in the sensor config, with
# optional surrounding double quotes removed (the sensor writes sensorId quoted
# and controlPlaneUrl bare).
read_config_value() {
    sed -n "s/^$1:[[:space:]]*\"\{0,1\}\([^\"]*\)\"\{0,1\}[[:space:]]*\$/\1/p" "$2" 2>/dev/null | head -1
}

# A host this key already enrolled keeps its identity. Re-running the same
# install command (to upgrade the binary, or by mistake) must not discard the
# certificate and UUID the sensor holds and send it back to register with a key
# it has already spent. A different key means the operator wants a fresh
# enrolment, and gets one.
KEEP_ENROLMENT=false
if [[ -f "$CONFIG_FILE" ]] \
    && [[ "$(read_config_value sensorId "$CONFIG_FILE")" =~ $UUID_RE ]] \
    && [[ "$(read_config_value registrationKey "$CONFIG_FILE")" == "$REGISTRATION_KEY" ]]; then
    KEEP_ENROLMENT=true
    print_status "This host is already enrolled with this key (sensor $(read_config_value sensorId "$CONFIG_FILE")); keeping its identity and configuration."
fi

# Stop a previous install: its binary cannot be replaced while it runs ("Text
# file busy"), and it must not rewrite the config while we replace it.
systemctl stop crypto-sensor.service 2>/dev/null || true

# Step 4: Install sensor binary
print_status "Installing sensor binary..."
if [[ -f "./crypto-sensor" ]]; then
    cp ./crypto-sensor "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/crypto-sensor"
    print_status "Sensor binary installed"
else
    print_error "Sensor binary not found. Please build it first:"
    echo "  cd sensor && go build -o crypto-sensor ./cmd"
    exit 1
fi

# Step 5: Create configuration file
#
# The installer does NOT register the sensor. The sensor binary registers itself
# on first start: it generates its keypair locally (the private key never leaves
# the host), proposes a UUID, sends a CSR along with its build-stamped version
# and capabilities, then rewrites this file with the UUID and the paths of the
# certificate it was issued. An installer that registered on the sensor's behalf
# spent the single-use key before the binary could use it, recorded a version
# the installer made up rather than the binary's, and left the sensor unable to
# enrol — it retried "Registration key has already been used" while the console
# showed a sensor that had never heartbeated.
#
# sensorId carries the sensor NAME until registration: the loader uses a
# non-UUID sensorId as the registration name, and the sensor replaces it with
# the UUID the platform accepts. Flat camelCase keys — the schema the loader
# (sensor/internal/config.ConfigFile) parses; a nested control_plane:/url: block
# is silently ignored.
if [[ "$KEEP_ENROLMENT" != "true" ]]; then
    print_status "Creating configuration file..."

    # Earlier versions of this installer registered with curl and left the response
    # — including a control-plane-generated private key — beside the config. That
    # identity was never usable by the sensor; do not leave its key on disk. A fresh
    # enrolment also must not inherit the previous sensor's certificate.
    rm -f "$INSTALL_DIR/registration-response.json"
    rm -rf "$INSTALL_DIR/certs" "$INSTALL_DIR/data/certs"

    yaml_quote() {
        local s=${1//\\/\\\\}
        s=${s//\"/\\\"}
        printf '"%s"' "$s"
    }

    INTERFACES_YAML=""
    IFS=',' read -ra INTERFACE_ARRAY <<< "$INTERFACES"
    for iface in "${INTERFACE_ARRAY[@]}"; do
        iface="${iface//[[:space:]]/}"
        [[ -z "$iface" ]] && continue
        [[ -n "$INTERFACES_YAML" ]] && INTERFACES_YAML+=", "
        INTERFACES_YAML+=$(yaml_quote "$iface")
    done

    # Holds the registration key until the sensor redeems it: owner-only before any
    # content is written (cat > keeps the mode of the file it truncates).
    : > "$CONFIG_FILE"
    chmod 600 "$CONFIG_FILE"
    cat > "$CONFIG_FILE" << EOF
# Vista Platform Sensor configuration (generated by install-sensor.sh)
# sensorId holds the sensor's name until it registers, then its UUID.
sensorId: $(yaml_quote "$SENSOR_NAME")
controlPlaneUrl: $(yaml_quote "$CONTROL_PLANE_URL")
registrationKey: $(yaml_quote "$REGISTRATION_KEY")
reportingIntervalSeconds: 30

capture:
  interfaces: [$INTERFACES_YAML]
  activeProbing: true
  networkDiscovery: true

storage:
  dataPath: $(yaml_quote "$INSTALL_DIR/data")
EOF
fi

# Step 6: Create systemd service
print_status "Creating systemd service..."
cat > "/etc/systemd/system/crypto-sensor.service" << EOF
[Unit]
Description=Crypto Inventory Network Sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
# The address the operator entered when creating the registration key (--ip),
# already checked to be on this host. Pinning it makes registration report the
# address the platform expects even on a multi-homed host, where the sensor's
# own guess (the source address of its route to the control plane) can differ.
# Remove this line to have the sensor report whatever address it detects.
Environment=SENSOR_IP_ADDRESS=$EXPECTED_IP
# Registers on first start with the key in the config, then runs from the
# certificate it was issued.
ExecStart=$INSTALL_DIR/crypto-sensor --verbose -config $CONFIG_FILE
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=crypto-sensor

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR

# Network settings
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

# Step 7: Set permissions
# The sensor rewrites its config and writes its certificate under data/, so the
# service user must own both.
print_status "Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chmod 600 "$CONFIG_FILE"

# Step 8: Start the service; the sensor registers itself
print_status "Starting the sensor; it registers itself with the control plane..."
systemctl daemon-reload
systemctl enable crypto-sensor.service
START_EPOCH=$(date +%s)
if ! systemctl restart crypto-sensor.service; then
    print_error "Failed to start sensor service"
    print_status "Check logs with: journalctl -u crypto-sensor -f"
    exit 1
fi

# Step 9: Wait for registration
#
# Registration is confirmed only by the sensor itself: it rewrites sensorId with
# the UUID the platform accepted. A running service is not a registered sensor —
# an unregistered one captures traffic and can submit none of it.
REGISTRATION_TIMEOUT=${REGISTRATION_TIMEOUT:-90}
print_status "Waiting up to ${REGISTRATION_TIMEOUT}s for the sensor to register..."
SENSOR_ID=""
REJECTED=false
while (( $(date +%s) - START_EPOCH < REGISTRATION_TIMEOUT )); do
    current_id=$(read_config_value sensorId "$CONFIG_FILE")
    if [[ "$current_id" =~ $UUID_RE ]]; then
        SENSOR_ID="$current_id"
        break
    fi
    if journalctl -u crypto-sensor.service --since "@$START_EPOCH" --no-pager -o cat 2>/dev/null \
        | grep -q 'Registration was REJECTED'; then
        REJECTED=true
        break
    fi
    sleep 2
done

if [[ -z "$SENSOR_ID" ]]; then
    echo ""
    journalctl -u crypto-sensor.service --since "@$START_EPOCH" --no-pager -o cat 2>/dev/null \
        | grep -E '⛔|❌|Registration (FAILED|retry failed)' | tail -8 || true
    echo ""
    if [[ "$REJECTED" == "true" ]]; then
        # A rejected key never succeeds; stop the service rather than leave it
        # restarting every 10 seconds.
        systemctl stop crypto-sensor.service || true
        systemctl disable crypto-sensor.service 2>/dev/null || true
        print_error "The control plane REJECTED the registration key (see above): it is invalid, expired, or already used."
        print_error "Generate a new key (Discovery → Sensors & Agents → Register) and re-run this installer with it."
        print_status "The sensor service has been stopped and disabled."
    else
        print_error "The sensor did not register within ${REGISTRATION_TIMEOUT}s."
        print_status "It is still running and retrying in the background; check that $CONTROL_PLANE_URL is reachable from this host."
        print_status "Watch it with: journalctl -u crypto-sensor -f"
    fi
    exit 1
fi

if ! systemctl is-active --quiet crypto-sensor.service; then
    print_error "❌ The sensor registered but is not running"
    print_status "Check logs with: journalctl -u crypto-sensor -f"
    exit 1
fi

# Final status
print_header "🎉 Installation Complete!"
echo "================================"
echo "Sensor Name: $SENSOR_NAME"
echo "Sensor ID: $SENSOR_ID"
echo "Sensor Version: $SENSOR_VERSION"
echo "Installation Directory: $INSTALL_DIR"
echo "Configuration: $CONFIG_FILE"
echo "Service: crypto-sensor.service"
echo "Control Plane: $CONTROL_PLANE_URL"
echo ""
echo "📋 Management Commands:"
echo "  Status:     systemctl status crypto-sensor"
echo "  Logs:       journalctl -u crypto-sensor -f"
echo "  Restart:    systemctl restart crypto-sensor"
echo "  Stop:       systemctl stop crypto-sensor"
echo "  Uninstall:  systemctl stop crypto-sensor && systemctl disable crypto-sensor"
echo ""
print_status "Sensor is registered and monitoring network traffic on: $INTERFACES"
print_status "It appears under Discovery → Sensors & Agents once its first heartbeat arrives."
