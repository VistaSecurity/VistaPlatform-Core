#!/usr/bin/env bash
# Quick HTTP/DNS checks after ./start-session.sh (or docker compose up).
# Sources .env when present so API_GATEWAY_HOST_PORT / TRAEFIK_METRICS_HOST_PORT / WEB_UI_HOST_PORT match compose.

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

DCMD="${DCMD:-docker compose}"
if command -v docker-compose >/dev/null 2>&1; then
  DCMD="docker-compose"
elif docker compose version >/dev/null 2>&1; then
  DCMD="docker compose"
fi

API_GATEWAY_HOST_PORT="${API_GATEWAY_HOST_PORT:-8080}"
TRAEFIK_METRICS_HOST_PORT="${TRAEFIK_METRICS_HOST_PORT:-9082}"

echo "API gateway health → http://localhost:${API_GATEWAY_HOST_PORT}/api/v1/health"
curl -sf -o /dev/null -w "  HTTP %{http_code}\n" "http://localhost:${API_GATEWAY_HOST_PORT}/api/v1/health"

echo "Traefik Prometheus metrics → http://localhost:${TRAEFIK_METRICS_HOST_PORT}/metrics"
curl -sf -o /dev/null -w "  HTTP %{http_code}\n" "http://localhost:${TRAEFIK_METRICS_HOST_PORT}/metrics"

echo "Compose DNS from api-gateway → auth-service"
if $DCMD exec -T api-gateway getent hosts auth-service >/dev/null 2>&1; then
  echo "  OK"
else
  echo "  FAILED (is api-gateway running?)" >&2
  exit 1
fi

echo "OK — session HTTP + gateway DNS checks passed."
