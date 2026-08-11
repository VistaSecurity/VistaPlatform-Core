# Windows Sensor Setup Guide

## 🚨 Required Dependencies

The Windows sensor requires a packet capture library to monitor network traffic. You need to install one of the following:

### Option 1: Npcap (Recommended)

**Npcap** is the modern, actively maintained packet capture library for Windows.

1. **Download Npcap**:
   - Go to: <https://npcap.com/>
   - Download the latest version (Npcap installer)

2. **Install Npcap**:
   - Run the installer as Administrator
   - **Important**: Check "Install Npcap in WinPcap API-compatible Mode"
   - Check "Start Npcap service at boot time"
   - Complete the installation

3. **Verify Installation**:

   ```cmd
   sc query npcap
   ```

   Should show "RUNNING" status.

### Option 2: WinPcap (Legacy)

**WinPcap** is the older packet capture library.

1. **Download WinPcap**:
   - Go to: <https://www.winpcap.org/>
   - Download the latest version

2. **Install WinPcap**:
   - Run the installer as Administrator
   - Complete the installation

3. **Verify Installation**:

   ```cmd
   sc query npf
   ```

   Should show "RUNNING" status.

## 🔧 Installation Steps

### Step 1: Install Packet Capture Library

Choose either Npcap or WinPcap (Npcap recommended).

### Step 2: Run Sensor as Administrator

**Important**: The sensor must run with Administrator privileges to access network interfaces.

```cmd
# Right-click Command Prompt and select "Run as administrator"
# Then navigate to your sensor directory and run:
crypto-sensor-windows-amd64.exe -interactive
```

### Step 3: Configure Sensor

Use the interactive mode to set up your sensor:

```cmd
crypto-sensor-windows-amd64.exe -interactive
```

### Step 4: Test the Sensor

```cmd
crypto-sensor-windows-amd64.exe -test -verbose
```

## 🚨 Troubleshooting

### Error: "couldn't load wpcap.dll"

**Cause**: Packet capture library not installed or not running.

**Solution**:

1. Install Npcap or WinPcap (see above)
2. Restart your computer
3. Run sensor as Administrator

### Error: "Operation not permitted"

**Cause**: Not running as Administrator.

**Solution**:

1. Right-click Command Prompt
2. Select "Run as administrator"
3. Navigate to sensor directory
4. Run the sensor

### Error: "no interfaces available for capture"

**Cause**: No network interfaces detected or packet capture service not running.

**Solution**:

1. Check network interfaces:

   ```cmd
   ipconfig /all
   ```

2. Check packet capture service:

   ```cmd
   sc query npcap
   # or for WinPcap:
   sc query npf
   ```

3. Start the service if not running:

   ```cmd
   sc start npcap
   # or for WinPcap:
   sc start npf
   ```

### Error: Antivirus Blocking

**Cause**: Antivirus software blocking packet capture.

**Solution**:

1. Add sensor executable to antivirus exclusions
2. Add packet capture service to exclusions
3. Temporarily disable real-time protection for testing

### Error: "failed to parse config file: yaml: line X: did not find expected hexdecimal number"

**Cause**: Windows paths with backslashes in the configuration file are not properly quoted.

**Solution**:

This issue was fixed in sensor version 1.2.0. If you encounter it:

1. **Update to the latest sensor version** (recommended)
2. **OR manually fix the config file**:
   - Open `%LOCALAPPDATA%\CryptoSensor\sensor-config.yaml`
   - Ensure all Windows paths are quoted and backslashes are doubled:
     ```yaml
     dataPath: "C:\\Users\\username\\AppData\\Local\\CryptoSensor"
     interfaces:
       - "\\Device\\NPF_{GUID}"
     ```
3. **OR delete the config and re-run interactive setup**:
   ```cmd
   del "%LOCALAPPDATA%\CryptoSensor\sensor-config.yaml"
   crypto-sensor-windows-amd64.exe -interactive
   ```

## 📁 Data and Key Storage

The sensor writes two categories of files to disk:

| Category | Default Path | Notes |
|---|---|---|
| **Discovery data** (encrypted) | `%APPDATA%\CryptoSensor\discoveries\` | Ciphertext only — safe to back up without key |
| **Encryption key** | `%APPDATA%\CryptoSensor\` | `encryption.key` — keep this path separate and protected |

> **Important:** The encryption key directory is intentionally separate from the discovery data directory so that ciphertext and key are never co-located. Do not store both on the same removable drive or shared network path.

To override the key path, add `keyPath` under `storage:` in your config file:

```yaml
storage:
  dataPath: "C:\\CryptoSensorData"
  keyPath: "C:\\CryptoSensorKeys"   # Recommended: separate volume or protected share
```

### Windows Firewall Note

The sensor makes **outbound-only** connections to the control plane. No inbound ports are opened. Windows Firewall rules need to allow outbound HTTPS (443) from the sensor executable to the configured `controlPlaneUrl`.

## ✅ Verification Steps

### 1. Check Packet Capture Service

```cmd
sc query npcap
```

Should show:

```
SERVICE_NAME: npcap
        TYPE               : 1  KERNEL_DRIVER
        STATE              : 4  RUNNING
```

### 2. Check Network Interfaces

```cmd
ipconfig /all
```

Should show active network adapters.

### 3. Test with Wireshark (Optional)

1. Install Wireshark
2. Open Wireshark
3. Check if network interfaces are listed
4. If Wireshark works, the sensor should work too

### 4. Test Sensor

```cmd
crypto-sensor-windows-amd64.exe -test -verbose
```

## 📋 Quick Setup Checklist

- [ ] Install Npcap or WinPcap
- [ ] Restart computer
- [ ] Open Command Prompt as Administrator
- [ ] Navigate to sensor directory
- [ ] Run: `crypto-sensor-windows-amd64.exe -interactive`
- [ ] Configure sensor settings
- [ ] Test with: `crypto-sensor-windows-amd64.exe -test -verbose`

## 🔗 Download Links

- **Npcap**: <https://npcap.com/>
- **WinPcap**: <https://www.winpcap.org/>
- **Wireshark**: <https://www.wireshark.org/>

## 💡 Tips

1. **Npcap is recommended** over WinPcap for better Windows 10/11 compatibility
2. **Always run as Administrator** - packet capture requires elevated privileges
3. **Check antivirus settings** - some may block packet capture
4. **Use test mode first** - `-test -verbose` to verify everything works
5. **Check Windows Firewall** - ensure it's not blocking the sensor
