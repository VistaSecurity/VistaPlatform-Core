#!/bin/bash
set -euo pipefail

API=http://localhost:8080

echo "=== Auth service ==="
echo "Auth: login (expect 400/422)"
curl -sS -o /dev/null -w "%{http_code} login\n" -X POST "$API/api/v1/auth-service/auth/login" -H 'Content-Type: application/json' -d '{"email":"x","password":"y"}'

echo "Auth: me (expect 401)"
curl -sS -o /dev/null -w "%{http_code} me\n" -H 'Authorization: Bearer invalid' "$API/api/v1/auth-service/auth/me"

echo "Auth: SSO providers (expect 200/401)"
curl -sS -o /dev/null -w "%{http_code} sso/providers\n" "$API/api/v1/auth-service/auth/sso/providers"

echo ""
echo "=== Inventory service (v1 + v2) ==="
echo "Inventory: assets v1 (expect 401)"
curl -sS -o /dev/null -w "%{http_code} assets-v1\n" "$API/api/v1/inventory-service/assets"

echo "Inventory: infrastructure-assets v2 (expect 401)"
curl -sS -o /dev/null -w "%{http_code} infrastructure-assets-v2\n" "$API/api/v2/inventory-service/infrastructure-assets"

echo "Inventory: crypto-configurations v2 (expect 401)"
curl -sS -o /dev/null -w "%{http_code} crypto-configurations-v2\n" "$API/api/v2/inventory-service/crypto-configurations"

echo ""
echo "=== Admin service ==="
echo "Admin: tenants (expect 401)"
curl -sS -o /dev/null -w "%{http_code} admin tenants\n" "$API/api/v1/admin-service/admin/tenants"

echo ""
echo "=== Newer services (expect 401 when auth is required) ==="
echo "Audit: events (expect 401)"
curl -sS -o /dev/null -w "%{http_code} audit-service\n" "$API/api/v1/audit-service/events"

echo "Notification: notifications (expect 401)"
curl -sS -o /dev/null -w "%{http_code} notification-service\n" "$API/api/v1/notification-service/notifications"

echo "Device Interrogation: jobs (expect 401)"
curl -sS -o /dev/null -w "%{http_code} device-interrogation-service\n" "$API/api/v1/device-interrogation-service/jobs"

echo "Discovery Processor: health (expect 200)"
curl -sS -o /dev/null -w "%{http_code} discovery-processor-service health\n" "$API/api/v1/discovery-processor-service/health"

echo ""
echo "=== Gateway health ==="
echo "Gateway: /health (expect 200)"
curl -sS -o /dev/null -w "%{http_code} gateway-health\n" "$API/health"
curl -sS -o /dev/null -w "%{http_code} gateway-health-v1\n" "$API/api/v1/health"
curl -sS -o /dev/null -w "%{http_code} gateway-health-v2\n" "$API/api/v2/health"
