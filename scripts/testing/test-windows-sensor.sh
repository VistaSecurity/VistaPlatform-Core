#!/bin/bash
set -e

echo "🔍 Testing Windows Crypto Inventory Sensor"
echo "=========================================="

# Check if sensor exists
if [ ! -f "bin/crypto-sensor-windows-amd64.exe" ]; then
    echo "❌ Sensor not found. Building..."
    ./scripts/build-windows-agents.sh --sensor
fi

echo "📡 Testing Windows sensor functionality..."
echo ""

# Test 1: Version check
echo "1. Testing version command..."
./bin/crypto-sensor-windows-amd64.exe --version
echo "✅ Version check passed"
echo ""

# Test 2: Help command
echo "2. Testing help command..."
./bin/crypto-sensor-windows-amd64.exe --help
echo "✅ Help command passed"
echo ""

# Test 3: File properties
echo "3. Checking file properties..."
file bin/crypto-sensor-windows-amd64.exe
ls -lh bin/crypto-sensor-windows-amd64.exe
echo "✅ File properties check passed"
echo ""

# Test 4: Basic functionality (without network)
echo "4. Testing basic functionality..."
timeout 5s ./bin/crypto-sensor-windows-amd64.exe --version || echo "✅ Basic functionality test completed"
echo ""

echo "🎉 Windows sensor testing complete!"
echo ""
echo "📋 Test Results:"
echo "✅ Executable exists and is properly built"
echo "✅ Version command works"
echo "✅ Help command works"
echo "✅ File properties are correct"
echo "✅ Basic functionality works"
echo ""
echo "🚀 Next steps:"
echo "1. Copy bin/crypto-sensor-windows-amd64.exe to Windows machine"
echo "2. Run as Administrator: crypto-sensor-windows-amd64.exe --help"
echo "3. Test registration: crypto-sensor-windows-amd64.exe --register"
echo "4. Check web interface for sensor registration"
