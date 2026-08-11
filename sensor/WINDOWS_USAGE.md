# Windows Sensor Usage Guide

## 🚨 **IMPORTANT: Required Setup First**

Before using the sensor, you **MUST** install a packet capture library and run as Administrator. See **[WINDOWS_SETUP.md](WINDOWS_SETUP.md)** for complete setup instructions.

**Quick Setup**:

1. Install [Npcap](https://npcap.com/) (recommended) or [WinPcap](https://www.winpcap.org/)
2. Restart your computer
3. Run Command Prompt as Administrator
4. Navigate to sensor directory and run the sensor

## Quick Start

### 1. Interactive Configuration (RECOMMENDED for first-time setup)

```cmd
crypto-sensor-windows-amd64.exe -interactive
```

### 2. Test Mode (Perfect for testing without control plane)

```cmd
crypto-sensor-windows-amd64.exe -test -verbose
```

### 3. Basic Usage (After configuration)

```cmd
crypto-sensor-windows-amd64.exe -verbose
```

**Note**: After initial registration, the sensor automatically loads its configuration and mTLS certificates from disk, allowing it to reconnect to the control plane without re-registering.

### 4. With Registration (if you have a control plane)

```cmd
crypto-sensor-windows-amd64.exe -verbose -register
```

### 5. Show Version Information

```cmd
crypto-sensor-windows-amd64.exe -version
```

## Command Line Options

| Flag | Description | Example |
|------|-------------|---------|
| `-interactive` | Run interactive configuration setup | `-interactive` |
| `-test` | Run in test mode (logs to file) | `-test` |
| `-verbose` | Enable detailed logging | `-verbose` |
| `-register` | Register with control plane | `-register` |
| `-config` | Path to config file (future use) | `-config config.yaml` |
| `-version` | Show version and exit | `-version` |

## Configuration

The sensor reads configuration from environment variables. Set these before running:

### Required Environment Variables

```cmd
set SENSOR_ID=your-unique-sensor-id
set CONTROL_PLANE_URL=http://your-control-plane:8080
set REGISTRATION_KEY=your-registration-key
```

### Optional Environment Variables

```cmd
set DATA_PATH=%LOCALAPPDATA%\CryptoSensor
set REPORTING_INTERVAL=30s
set INTERFACES=eth0,eth1
set ACTIVE_PROBING=true
set NETWORK_DISCOVERY=true
```

**Note**: If `DATA_PATH` is not set, the sensor will automatically use `%LOCALAPPDATA%\CryptoSensor` on Windows.

## New Features

### Interactive Configuration Mode

The interactive mode guides you through the setup process:

```cmd
crypto-sensor-windows-amd64.exe -interactive
```

**What it does:**

- Prompts for sensor ID (auto-generates if empty)
- Asks for control plane URL
- Requests registration key (optional)
- Shows available network interfaces for selection
- Configures reporting interval and data path
- Optionally enables test mode
- **Creates persistent configuration file**: `{DATA_PATH}/sensor-config.yaml`
- Sets all configuration as environment variables for current session

### Test Mode

Test mode is perfect for:

- Testing the sensor without a control plane
- Debugging network issues
- Validating configuration
- Development and troubleshooting

```cmd
crypto-sensor-windows-amd64.exe -test -verbose
```

**What it does:**

- Logs all discoveries to a file instead of sending to control plane
- Creates rotating log files (10MB max, keeps 5 backups)
- Includes timestamps and detailed information
- Logs heartbeats and errors for troubleshooting

**Test mode files:**

- `test-discoveries.log` - Current log file
- `test-discoveries.log.1234567890` - Rotated backup files

## 📁 File Locations

### Configuration Files

- **Interactive config**: `{DATA_PATH}/sensor-config.yaml`
- **Windows example**: `C:\Users\{username}\AppData\Local\CryptoSensor\sensor-config.yaml`

### Log Files

- **Test mode logs**: `{DATA_PATH}/test-discoveries.log`
- **Normal mode logs**: `{DATA_PATH}/sensor.log`
- **Database**: `{DATA_PATH}/discoveries.db`
- **Cache**: `{DATA_PATH}/config.cache`
- **Certificates**: `{DATA_PATH}/certs/` (client.crt, client.key, ca.crt)

### Data Path by OS

- **Windows**: `%LOCALAPPDATA%\CryptoSensor` (e.g., `C:\Users\{username}\AppData\Local\CryptoSensor`)
- **Linux**: `/var/lib/crypto-sensor`
- **macOS**: `~/Library/Application Support/CryptoSensor`

## Troubleshooting

### Common Issues

1. **Error: "couldn't load wpcap.dll" or "no interfaces available for capture"**
   - **Cause**: Missing packet capture library (Npcap/WinPcap)
   - **Solution**: See [WINDOWS_SETUP.md](WINDOWS_SETUP.md) for complete setup instructions

2. **Registration fails**
   - **Cause**: Control plane not reachable or invalid registration key
   - **Solution**: Check CONTROL_PLANE_URL and REGISTRATION_KEY

3. **No network traffic detected**
   - **Cause**: Wrong network interface or insufficient permissions
   - **Solution**: Run as Administrator and verify INTERFACES setting

### Debugging Steps

1. **Run with verbose logging**:

   ```cmd
   crypto-sensor-windows-amd64.exe -verbose
   ```

2. **Check what the sensor is trying to do**:
   - Look for "Configuration loaded" messages
   - Check if network interfaces are detected
   - Verify control plane connectivity

3. **Test without registration**:

   ```cmd
   crypto-sensor-windows-amd64.exe -verbose
   ```

## Expected Behavior

When running correctly, you should see:

```
🚀 Starting Crypto Inventory Network Sensor v1.0.0
Platform: windows/amd64
Command line flags: verbose=true, register=false, config=config.yaml
Configuration loaded:
  Sensor ID: your-sensor-id
  Control Plane URL: http://localhost:8080
  Registration Key: (empty)
  Reporting Interval: 30s
  Data Path: C:\Users\YourUsername\AppData\Local\CryptoSensor
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

## Files Created

The sensor creates these files in the data directory:

- `sensor-config.yaml` - Configuration file with sensor ID and settings
- `certs/` - Directory containing mTLS certificates (after registration)
  - `client.crt` - Client certificate for authentication
  - `client.key` - Private key (secured with restrictive permissions)
  - `ca.crt` - CA certificate for server verification
- `discoveries.db` - Encrypted discovery database
- `sensor.log` - Sensor operation log
- `config.cache` - Cached configuration

**Important**: The sensor can be stopped and restarted without re-registering. Configuration and certificates are automatically loaded from disk.

## Stopping the Sensor

Press `Ctrl+C` to stop the sensor gracefully. You should see:

```
🛑 Received signal interrupt, shutting down gracefully...
🧹 Performing cleanup...
👋 Sensor shutdown complete
```
