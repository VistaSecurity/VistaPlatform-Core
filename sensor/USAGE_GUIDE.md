# Crypto Inventory Network Sensor - Complete Usage Guide

## 🚀 Quick Start

### First Time Setup (Recommended)

```bash
# Interactive configuration - guides you through setup
./crypto-sensor -interactive
```

### Test Mode (Perfect for Testing)

```bash
# Test mode - logs to file instead of control plane
./crypto-sensor -test -verbose
```

### Production Mode

```bash
# Normal operation with verbose logging
./crypto-sensor -verbose
```

## 📋 Command Line Options

| Flag | Description | Example |
|------|-------------|---------|
| `-interactive` | Interactive configuration setup | `-interactive` |
| `-test` | Test mode (logs to file) | `-test` |
| `-verbose` | Enable detailed logging | `-verbose` |
| `-register` | Register with control plane | `-register` |
| `-config` | Path to config file | `-config config.yaml` |
| `-version` | Show version and exit | `-version` |

## 🔧 Interactive Configuration Mode

The interactive mode provides a guided setup experience:

```bash
./crypto-sensor -interactive
```

### What it does

1. **Sensor ID**: Prompts for unique sensor ID (auto-generates if empty)
2. **Control Plane URL**: Asks for control plane endpoint
3. **Registration Key**: Requests registration key (optional)
4. **Reporting Interval**: Configures how often to report (default: 30s)
5. **Data Path**: Sets where to store data (auto-detects OS-appropriate path)
6. **Network Interfaces**: Shows available interfaces and lets you select
7. **Test Mode**: Option to enable test mode
8. **Configuration Summary**: Shows all settings before applying
9. **Environment Setup**: Sets all configuration as environment variables

### Example Interactive Session

```
🔧 Crypto Inventory Network Sensor - Interactive Configuration
=============================================================

Enter Sensor ID (or press Enter for auto-generated): 
Generated Sensor ID: hostname-1234567890

Enter Control Plane URL (default: http://localhost:8080): 
http://my-control-plane:8080

Enter Registration Key (optional): 
my-registration-key

Enter Reporting Interval in seconds (default: 30): 
60

Enter Data Path (default: auto-detect): 

🌐 Network Interface Selection
Available network interfaces:
  1. eth0 (IP: 192.168.1.100, MTU: 1500)
  2. wlan0 (IP: 192.168.1.101, MTU: 1500)

Select interface(s) by number (comma-separated, e.g., 1,2 or just 1): 
1

Run in test mode? (y/N): 
n

📋 Configuration Summary
========================
Sensor ID: hostname-1234567890
Control Plane URL: http://my-control-plane:8080
Registration Key: my***key
Reporting Interval: 60 seconds
Data Path: /var/lib/crypto-sensor
Selected Interfaces: [eth0]
Test Mode: false

Save this configuration and start the sensor? (Y/n): 
y

✅ Configuration saved! Starting sensor...
```

## 🧪 Test Mode

Test mode is perfect for:

- **Testing without control plane**: No need for a running control plane
- **Debugging**: Detailed logging to files for analysis
- **Development**: Validate sensor behavior
- **Troubleshooting**: See exactly what the sensor detects

```bash
./crypto-sensor -test -verbose
```

### Test Mode Features

- **File-based logging**: All discoveries logged to `test-discoveries.log`
- **Automatic rotation**: Files rotate at 10MB, keeps 5 backups
- **Detailed information**: Timestamps, sensor ID, interface, protocol details
- **Heartbeat logging**: Sensor health information logged
- **Error logging**: All errors captured with context

### Test Mode Output

```
🧪 Running in TEST MODE - discoveries will be logged to file instead of control plane
🧪 Test logger initialized: /var/lib/crypto-sensor/test-discoveries.log
📝 Logged 3 discoveries to test file: /var/lib/crypto-sensor/test-discoveries.log
💓 Logged heartbeat to test file
```

### Test Mode Log Format

```json
{
  "timestamp": "2025-09-24T22:51:22Z",
  "type": "discovery",
  "message": "Cryptographic implementation discovered",
  "data": {
    "protocol": "TLS",
    "dest_ip": "192.168.1.1",
    "port": 443,
    "confidence": 0.95,
    "sensor_id": "hostname-1234567890",
    "interface": "eth0"
  }
}
```

## 🌐 Network Interface Selection

The sensor automatically detects available network interfaces:

### Interface Detection

- **Active interfaces only**: Skips loopback and inactive interfaces
- **IP address display**: Shows current IP and MTU for each interface
- **Multiple selection**: Choose multiple interfaces with comma-separated numbers
- **Validation**: Ensures selected interfaces are valid

### Example Interface List

```
🌐 Network Interface Selection
Available network interfaces:
  1. eth0 (IP: 192.168.1.100, MTU: 1500)
  2. wlan0 (IP: 192.168.1.101, MTU: 1500)
  3. docker0 (IP: 172.17.0.1, MTU: 1500)
  4. br-abc123 (IP: 172.18.0.1, MTU: 1500)

Select interface(s) by number (comma-separated, e.g., 1,2 or just 1): 
1,2
```

## 📁 Data Storage

### Default Data Paths by OS

- **Windows**: `%LOCALAPPDATA%\CryptoSensor`
- **macOS**: `~/Library/Application Support/CryptoSensor`
- **Linux**: `/var/lib/crypto-sensor`

### Files Created

- **Configuration**: `sensor-config.yaml` (created by interactive mode)
- **Normal mode**: `discoveries.db`, `sensor.log`, `config.cache`
- **Test mode**: `test-discoveries.log`, `test-discoveries.log.1234567890` (backups)

## 🔧 Configuration

### Environment Variables

```bash
# Required
export SENSOR_ID="your-sensor-id"
export CONTROL_PLANE_URL="http://your-control-plane:8080"

# Optional
export REGISTRATION_KEY="your-registration-key"
export DATA_PATH="/custom/data/path"
export REPORTING_INTERVAL="30s"
export INTERFACES="eth0,wlan0"
export TEST_MODE="true"
```

### Configuration Priority

1. **Command line flags** (highest priority)
2. **Environment variables**
3. **Default values** (lowest priority)

## 🚨 Troubleshooting

### Common Issues

#### 1. Windows: "couldn't load wpcap.dll" or "no interfaces available for capture"

```
❌ Failed to start packet capture: couldn't load wpcap.dll
```

**Cause**: Missing packet capture library (Npcap/WinPcap)

**Solution**:

1. Install [Npcap](https://npcap.com/) (recommended) or [WinPcap](https://www.winpcap.org/)
2. Restart your computer
3. Run Command Prompt as Administrator
4. See [WINDOWS_SETUP.md](WINDOWS_SETUP.md) for detailed instructions

#### 2. Permission Denied

```
❌ Failed to initialize sensor: permission denied
```

**Solution**: Run as Administrator/root or use a writable data path

#### 3. No Network Interfaces

```
❌ No network interfaces found!
```

**Solution**: Check network configuration, ensure interfaces are up

#### 4. Packet Capture Failed

```
❌ Failed to start packet capture: Operation not permitted
```

**Solution**: Run as Administrator/root (required for packet capture)

#### 5. Control Plane Unreachable

```
❌ Failed to submit discoveries: connection refused
```

**Solution**: Check control plane URL and network connectivity

### Debug Steps

1. **Use verbose logging**:

   ```bash
   ./crypto-sensor -verbose
   ```

2. **Test mode for debugging**:

   ```bash
   ./crypto-sensor -test -verbose
   ```

3. **Check log files**:
   - Normal mode: Check `sensor.log`
   - Test mode: Check `test-discoveries.log`

4. **Verify configuration**:

   ```bash
   ./crypto-sensor -version
   ```

## 📊 Expected Behavior

### Normal Operation

```
🚀 Starting Crypto Inventory Network Sensor v1.0.0
Platform: linux/amd64
Command line flags: verbose=true, register=false, interactive=false, test=false
Configuration loaded:
  Sensor ID: hostname-1234567890
  Control Plane URL: http://localhost:8080
  Registration Key: (empty)
  Reporting Interval: 30s
  Data Path: /var/lib/crypto-sensor
  Interfaces: [eth0]
🔧 Initializing sensor components...
✅ Sensor components initialized successfully
ℹ️  Skipping registration (no registration key provided)
🚀 Starting sensor services...
✅ Sensor services started successfully
📡 Monitoring network traffic for cryptographic configurations...
🔄 Reporting interval: 30s
💡 Press Ctrl+C to stop the sensor
```

### Test Mode Operation

```
🧪 Running in TEST MODE - discoveries will be logged to file instead of control plane
🧪 Test logger initialized: /var/lib/crypto-sensor/test-discoveries.log
📝 Logged 5 discoveries to test file: /var/lib/crypto-sensor/test-discoveries.log
💓 Logged heartbeat to test file
```

## 🛑 Stopping the Sensor

Press `Ctrl+C` to stop gracefully:

```
🛑 Received signal interrupt, shutting down gracefully...
🧹 Performing cleanup...
📤 Submitting 2 remaining discoveries...
🧪 Test logger closed
✅ Cleanup completed
👋 Sensor shutdown complete
```

## 📚 Additional Resources

- **Windows-specific guide**: `WINDOWS_USAGE.md`
- **Configuration examples**: `config.example.yaml`
- **API documentation**: See control plane documentation
- **Troubleshooting**: Check log files for detailed error information
