---
render_macros: false
---

# Recovery and Resume After Reboot

This guide helps you resume development after a reboot or a full Docker cleanup.

## Prerequisites
- Docker and Docker Compose available
- Repo checked out and up to date on `main`

## Steps
1. Start infra, gateway, and services via session initialization:
   ```bash
   ./scripts/session-init.sh
   ```
   This script will:
   - Validate registry and regenerate configs
   - Start core infra and API gateway
   - Build sensor artifacts (Linux amd64 at minimum)
   - Start all services and UIs
   - Smoke-test routes and CORS

2. If sensor binary downloads return 404 in dev, mount artifacts:
   - Ensure `docker-compose.override.yml` exists with:
     ```yaml
     services:
       sensor-manager:
         environment:
           - SENSOR_ARTIFACTS_DIR=/app/artifacts/sensor
         volumes:
           - ./artifacts/sensor:/app/artifacts/sensor:ro
     ```
   - Recreate the service:
     ```bash
     docker compose up -d sensor-manager
     ```

3. Build sensor artifacts if needed for downloads:
   ```bash
   # Currently only Linux x86_64 is built (cross-platform builds temporarily disabled)
   make sensor-linux-amd64
   ```

4. Rebuild specific services only if needed (after code changes):
   ```bash
   docker compose build web-ui sensor-manager
   docker compose up -d web-ui sensor-manager
   ```

5. Reload API gateway after config changes:
   ```bash
   docker kill -s HUP crypto-api-gateway || true
   ```

## Troubleshooting
- If Docker builds stall:
  ```bash
  docker builder prune -af
  docker system prune -af
  ```
- Verify downloads endpoint:
  ```bash
  curl -I http://localhost:8080/api/v1/sensor-manager/downloads/sensor/linux/amd64
  ```
- Verify UI:
  - Open http://localhost:3000
  - Sensor Management → Register New Sensor (modal)

## Notes
- Volumes were preserved during cleanup to retain DB data unless explicitly removed.
- Production images should bake artifacts; dev uses a bind mount for speed.
