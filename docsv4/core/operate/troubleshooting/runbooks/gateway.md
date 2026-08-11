---
render_macros: false
---

# Gateway Runbook

## Purpose
Operational guide for the API gateway (Traefik) in dev/prod Compose.

## Key behaviors
- Gateway-first: all traffic via gateway; prefixes preserved
- Dynamic service discovery: Traefik watches Docker labels and config files automatically
- Resilience: Retry middleware with configurable attempts for transient backend failures
- Auto-reload on change: Traefik watches config files and picks up changes without manual reload
- mTLS Support: Client certificate passthrough for sensor routes
- Binary Downloads: Direct file serving for sensor artifacts

## Quick checks
```bash
# Check gateway health
curl -i http://localhost:8080/api/v1/health

# Tail logs
docker logs -f crypto-api-gateway

# Validate config in container
docker compose exec api-gateway traefik healthcheck

# Show current config
docker compose exec api-gateway cat /etc/traefik/traefik.yaml
```

## Common fixes
```bash
# Re-generate configs (dev)
DEPLOY_ENV=development NODE_ENV=development make generate
node scripts/generate-traefik-config.mjs

# Traefik watches config files automatically and picks up changes without manual reload.
```

## mTLS Configuration

### Client Certificate Passthrough

For sensor outbound routes requiring mTLS validation, Traefik uses middleware to pass client certificate headers to backend services. Configure TLS options and passthrough headers in `dynamic.yaml`.

### Binary Download Routes

For sensor binary downloads, Traefik routes requests to the sensor-manager backend which serves files directly. Content-Type and Content-Disposition headers are set by the backend service.

### Gateway Termination Strategy

**Development**: 
- Gateway terminates TLS and forwards client cert headers
- Services validate certificates using forwarded headers
- Allows easier debugging and certificate inspection

**Production**:
- Gateway can terminate TLS with client cert validation
- Forward certificate details via headers to services
- Or pass raw TLS to services for end-to-end encryption

## Troubleshooting

### Common Issues
- **502 Bad Gateway**: upstream container restarted; verify service `/health` (Traefik auto-detects recovered services)
- **Missing CORS headers**: ensure requests go through gateway and Origin matches allowed map
- **404 at service root**: expected for many services; test a concrete endpoint
- **mTLS validation failures**: check client certificate CN matches sensor ID
- **Binary download failures**: verify artifacts directory exists and is accessible

### mTLS Debugging
```bash
# Test sensor registration endpoint
curl -v -X POST http://localhost:8080/api/v1/sensor-manager/sensors/register \
  -H "Content-Type: application/json" \
  -d '{"registration_key": "test-key", "name": "test-sensor"}'

# Test binary download
curl -v http://localhost:8080/api/v1/sensor-manager/downloads/sensor/linux/amd64

# Check client certificate headers (if TLS terminated at gateway)
curl -v -H "X-SSL-Certificate-Subject: CN=sensor-123" \
  http://localhost:8080/api/v1/sensor-manager/sensors/sensor-123/heartbeat
```

### Certificate Management
- **Certificate Generation**: Automatic during sensor registration
- **Certificate Validation**: CN must match sensor ID in route parameter
- **Certificate Rotation**: Use sensor management UI or API endpoints
- **Certificate Storage**: Backend services handle certificate persistence

## References
- `docsv4/architecture/api-gateway-patterns.md`
- `docsv4/development/standards/QUICK_REFERENCE.md`
- `docsv4/operations/security/certificates.md`
- `docsv4/product/features/sensor-registration.md`
