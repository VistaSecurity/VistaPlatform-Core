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
Crypto Inventory Sensor Installer v1.0.0
========================================

Usage: $0 [options]

Options:
    -u, --url URL              Control plane URL (default: $CONTROL_PLANE_URL)
    -k, --key KEY              Registration key (required)
    -n, --name NAME            Sensor name (default: auto-detect)
    -i, --interfaces IFACES    Network interfaces (default: auto-detect)
    -p, --profile PROFILE      Deployment profile (default: $PROFILE)
    -d, --dir DIRECTORY        Installation directory (default: $INSTALL_DIR)
    --ip IP_ADDRESS            Expected IP address for validation (required)
    --interactive              Run in interactive mode (ask for all settings)
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

print_header "🚀 Crypto Inventory Sensor Installer v1.0.0"
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
echo "  Interfaces: $INTERFACES"
echo "  Sensor Name: $SENSOR_NAME"
echo "  Profile: $PROFILE"
echo "  Control Plane: $CONTROL_PLANE_URL"
echo "  Expected IP: $EXPECTED_IP"

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
mkdir -p "$INSTALL_DIR/certs"

# Step 4: Download and install sensor binary
print_status "Installing sensor binary..."

# For this example, we'll copy the local binary
# In production, you would download from a secure repository
if [[ -f "./crypto-sensor" ]]; then
    cp ./crypto-sensor "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/crypto-sensor"
    print_status "Sensor binary installed"
else
    print_error "Sensor binary not found. Please build it first:"
    echo "  cd sensor && go build -o crypto-sensor cmd/main.go"
    exit 1
fi

# Step 5: Create configuration file
print_status "Creating configuration file..."
# Flat camelCase keys — this is the schema the sensor's config loader
# (sensor/internal/config.ConfigFile) actually parses. A nested
# control_plane:/url: block is silently ignored, which makes the sensor fall
# back to its localhost default instead of the real control plane, so the
# config MUST be written in this shape and at this filename (sensor-config.yaml,
# which is what the binary reads via -config below).
cat > "$INSTALL_DIR/sensor-config.yaml" << EOF
# Vista Platform Sensor configuration (generated by install-sensor.sh)
sensorId: "$SENSOR_NAME"
controlPlaneUrl: "$CONTROL_PLANE_URL"
registrationKey: "$REGISTRATION_KEY"
reportingIntervalSeconds: 30

capture:
  interfaces: [$(echo "$INTERFACES" | sed 's/,/", "/g' | sed 's/^/"/' | sed 's/$/"/')]
  activeProbing: true
  networkDiscovery: true

storage:
  dataPath: "$INSTALL_DIR/data"

security:
  useTLS: true
  clientCertPath: "$INSTALL_DIR/certs/client.crt"
  clientKeyPath: "$INSTALL_DIR/certs/client.key"
  serverCACertPath: "$INSTALL_DIR/certs/server-ca.crt"
EOF

# Step 6: Create systemd service
print_status "Creating systemd service..."
cat > "/etc/systemd/system/crypto-sensor.service" << EOF
[Unit]
Description=Crypto Inventory Network Sensor
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
# The sensor is registered out-of-band below (Step 8) and its certs are on disk
# before this service starts, so run in normal mode pointed at the generated
# config. (Passing --register here as well would re-register with an
# already-consumed key on every restart.)
ExecStart=$INSTALL_DIR/crypto-sensor --verbose -config $INSTALL_DIR/sensor-config.yaml
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
print_status "Setting permissions..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chmod 755 "$INSTALL_DIR"
chmod 644 "$INSTALL_DIR/sensor-config.yaml"
chmod 600 "$INSTALL_DIR/certs" 2>/dev/null || true

# Step 8: Register sensor with control plane
print_status "Registering sensor with control plane..."

# Convert interfaces to JSON array
IFS=',' read -ra INTERFACE_ARRAY <<< "$INTERFACES"
INTERFACES_JSON="["
for i in "${!INTERFACE_ARRAY[@]}"; do
    if [[ $i -gt 0 ]]; then
        INTERFACES_JSON+=","
    fi
    INTERFACES_JSON+="\"${INTERFACE_ARRAY[i]}\""
done
INTERFACES_JSON+="]"

# Create registration payload
REGISTRATION_PAYLOAD=$(cat << EOF
{
  "registration_key": "$REGISTRATION_KEY",
  "name": "$SENSOR_NAME",
  "description": "Sensor installed on $(hostname)",
  "platform": "$PLATFORM",
  "version": "1.0.0",
  "profile": "$PROFILE",
  "network_interfaces": $INTERFACES_JSON,
  "ip_address": "$EXPECTED_IP"
}
EOF
)

# Register with control plane
if curl -s -X POST "$CONTROL_PLANE_URL/api/v1/sensor-manager/sensors/register" \
    -H "Content-Type: application/json" \
    -d "$REGISTRATION_PAYLOAD" > "$INSTALL_DIR/registration-response.json"; then
    print_status "Sensor registered successfully"
    
    # Extract certificates from response
    if command -v jq &> /dev/null; then
        jq -r '.client_cert' "$INSTALL_DIR/registration-response.json" > "$INSTALL_DIR/certs/client.crt"
        jq -r '.client_key' "$INSTALL_DIR/registration-response.json" > "$INSTALL_DIR/certs/client.key"
        jq -r '.server_ca_cert' "$INSTALL_DIR/registration-response.json" > "$INSTALL_DIR/certs/server-ca.crt"
        chmod 600 "$INSTALL_DIR/certs/"*.crt "$INSTALL_DIR/certs/"*.key
        print_status "Certificates installed"
    else
        print_warning "jq not found, certificates not extracted"
    fi
else
    print_error "Failed to register sensor with control plane"
    print_warning "Sensor will be installed but not registered"
fi

# Step 9: Enable and start service
print_status "Enabling and starting service..."
systemctl daemon-reload
systemctl enable crypto-sensor.service

if systemctl start crypto-sensor.service; then
    print_status "Sensor service started successfully"
else
    print_error "Failed to start sensor service"
    print_status "Check logs with: journalctl -u crypto-sensor -f"
    exit 1
fi

# Step 10: Verify installation
print_status "Verifying installation..."
sleep 2

if systemctl is-active --quiet crypto-sensor.service; then
    print_status "✅ Sensor is running"
else
    print_error "❌ Sensor is not running"
    print_status "Check logs with: journalctl -u crypto-sensor -f"
    exit 1
fi

# Final status
print_header "🎉 Installation Complete!"
echo "================================"
echo "Sensor Name: $SENSOR_NAME"
echo "Installation Directory: $INSTALL_DIR"
echo "Configuration: $INSTALL_DIR/sensor-config.yaml"
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
echo "🔍 Monitoring:"
echo "  Check sensor health: curl $CONTROL_PLANE_URL/api/v1/sensors/$SENSOR_NAME/health"
echo "  View discoveries: curl $CONTROL_PLANE_URL/api/v1/sensors/$SENSOR_NAME/discoveries"
echo ""
print_status "Sensor is now monitoring network traffic on: $INTERFACES"

# Display copy-paste command for future reference
echo ""
print_header "📋 Copy-Paste Installation Command"
echo "======================================"
echo "For future installations or documentation, use this command:"
echo ""
echo "curl -sSL https://app.vistasecurity.io/scripts/install-sensor.sh | sudo bash -s -- \\"
echo "  --key $REGISTRATION_KEY \\"
echo "  --ip $EXPECTED_IP \\"
echo "  --name $SENSOR_NAME \\"
echo "  --profile $PROFILE \\"
echo "  --interfaces \"$INTERFACES\" \\"
echo "  --url $CONTROL_PLANE_URL"
echo ""
print_status "You can also run the installer interactively:"
echo "curl -sSL https://app.vistasecurity.io/scripts/install-sensor.sh | sudo bash -s -- --interactive"
