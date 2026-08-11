#!/usr/bin/env bash
set -euo pipefail

echo "Checking Electron runtime dependencies..."

required_pkgs=(
  libnspr4
  libnss3
  libatk-bridge2.0-0
  libdrm2
  libxkbcommon0
  libxcomposite1
  libxdamage1
  libxrandr2
  libgbm1
  libxss1
  libasound2t64
)

if command -v lsb_release >/dev/null 2>&1; then
  distro=$(lsb_release -is 2>/dev/null || echo "")
else
  distro=""
fi

missing=()
for pkg in "${required_pkgs[@]}"; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    missing+=("$pkg")
  fi
done

if [ ${#missing[@]} -eq 0 ]; then
  echo "✅ All Electron runtime dependencies are installed."
  exit 0
fi

echo "⚠️  Missing packages detected: ${missing[*]}"
echo ""
echo "To install them (Ubuntu/WSL), run:"
echo "  sudo apt update && sudo apt install -y ${missing[*]}"
echo ""
exit 0
