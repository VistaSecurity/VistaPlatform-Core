---
render_macros: false
---

# Troubleshooting Guide

This guide covers common issues and their solutions.

## Authentication & Login Issues

### Login Screen Not Loading / Stuck on Loading

**Symptom**: Login page shows a loading spinner indefinitely and never displays the login form.

**Cause**: Cached authentication state (e.g. expired or invalid cookies, or legacy localStorage tokens) can cause authentication initialization to hang.

**Immediate Fix**:

1. **Clear site data (Recommended)**  
   The platform uses httpOnly cookies for auth. Clear cookies and site data for the app origin (e.g. `http://localhost:3000`):
   - Chrome/Edge: Application tab → Storage → Clear site data
   - Firefox: Application → Storage → Clear All
   - Or clear cookies for the site in browser settings and refresh.

2. **If using legacy token storage (localStorage)**:
   - Open Developer Tools (F12) → Application/Storage → Local Storage → your domain
   - Remove `crypto_inventory_token` and `crypto_inventory_refresh_token` if present, then refresh

3. **Browser console (localStorage only)**:
   ```javascript
   localStorage.removeItem('crypto_inventory_token');
   localStorage.removeItem('crypto_inventory_refresh_token');
   location.reload();
   ```

4. **Clear All Site Data**:
   - Chrome/Edge: Settings → Privacy → Clear browsing data → Cookies and other site data
   - Firefox: Settings → Privacy & Security → Cookies and Site Data → Clear Data
   - Safari: Develop → Empty Caches

**Prevention**: The application now automatically:
- Validates token structure and expiration
- Clears invalid/expired tokens automatically
- Shows a "Clear cache" button if stuck loading
- Has a 10-second timeout on authentication initialization

### Token Expired Errors

**Symptom**: "Token expired" or 401 Unauthorized errors.

**Fix**: The application should automatically refresh tokens. If it doesn't:
1. Log out and log back in
2. Clear cache as described above
3. Check browser console for errors

## Build Issues

### Go Version Mismatch

**Symptom**: `go: go.work requires go >= 1.26.0 (running go X.X.X)`

**Fix**: Upgrade Go to 1.26:
```bash
# Download and install Go 1.26
cd /tmp
wget https://go.dev/dl/go1.26.0.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.26.0.linux-amd64.tar.gz
sudo update-alternatives --install /usr/bin/go go /usr/local/go/bin/go 100
sudo update-alternatives --set go /usr/local/go/bin/go
```

### Docker Build Failures

**Symptom**: Docker builds fail with "go.work not found" or module resolution errors.

**Fix**: 
1. Ensure build context is repository root (`.`)
2. Check Dockerfile uses `WORKDIR /workspace` and builds from workspace root
3. Verify `GOTOOLCHAIN=local` is set in Dockerfile

## Service Startup Issues

### Services Not Starting

**Symptom**: Services fail to start or crash immediately.

**Fix**:
1. Check logs: `docker compose logs <service-name>`
2. Verify environment variables: `docker compose config`
3. Check database connectivity: `docker compose ps postgres`
4. Restart services: `docker compose restart <service-name>`

### Port Conflicts

**Symptom**: "Port already in use" errors.

**Fix**:
1. Find process using port: `lsof -i :8080` (or your port)
2. Stop conflicting service or change port in `.env`
3. Restart: `docker compose down && docker compose up -d`

## Cache Issues

### Slow Builds

**Symptom**: Builds are slower than expected.

**Fix**:
1. Check cache status: `make dev-dashboard`
2. Validate cache: `make validate-cache`
3. Clean cache if needed: `make clean-cache`
4. Pre-warm cache: `make install-deps`

### Docker Cache Issues

**Symptom**: Docker builds not using cache.

**Fix**:
1. Check Docker BuildKit is enabled: `export DOCKER_BUILDKIT=1`
2. Verify `.dockerignore` is correct
3. Check Dockerfile layer ordering
4. Clean and rebuild: `docker builder prune -f`

## Network Issues

### API Gateway Not Responding

**Symptom**: 502 Bad Gateway or connection refused.

**Fix**:
1. Check gateway logs: `docker compose logs api-gateway`
2. Verify Traefik config: `docker compose exec api-gateway traefik healthcheck`
3. Check service health: `make health-check`
4. Restart gateway: `docker compose restart api-gateway`

### CORS Errors

**Symptom**: CORS errors in browser console.

**Fix**:
1. Verify API Gateway is running: `curl http://localhost:8080/health`
2. Check CORS configuration in Traefik dynamic config (`config/traefik/`)
3. Verify frontend origin matches CORS allowed origins
4. Run CORS tests: `make test-cors`

## Database Issues

### Migration Failures

**Symptom**: Database migrations fail or services can't connect.

**Fix**:
1. Check Postgres logs: `docker compose logs postgres`
2. Verify database exists: `docker compose exec postgres psql -U crypto_user -l`
3. Check connection string in `.env`
4. Reset database if needed: `make db-reset` (⚠️ destroys data)

### Connection Pool Exhausted

**Symptom**: "too many connections" errors.

**Fix**:
1. Check connection pool settings in service configs
2. Reduce concurrent connections
3. Restart Postgres: `docker compose restart postgres`

## Subscription Tier / Limit Issues

### "Sensor limit exceeded: 0/0" registering the first sensor

**Symptom**: Sensor registration returns HTTP 402 with `Sensor limit exceeded:
0/0`, on a tenant that has no sensors. Adding an asset fails the same way.

**Cause**: The tenant has no subscription tier. Every capacity limit then falls
back to the platform default, which is deliberately conservative — 0 sensors, 0
assets. It is a misconfiguration wearing a quota error's clothes: since v0.5.1
the message says so explicitly, but a tenant that signed up on v0.5.0 or earlier
reports the bare `0/0`.

**Fix**: Upgrade to v0.5.1 or later — the seed applied on every `helm upgrade`
puts tier-less tenants on the `community` tier (unlimited capacity, no paid
capability), and new signups are placed there at creation. To confirm, or to
repair without upgrading:

```sql
SELECT t.name, COALESCE(st.name, '(no tier)') AS tier
FROM tenants t LEFT JOIN subscription_tiers st ON st.id = t.subscription_tier_id;
```

A platform admin can also assign a tier per tenant from the admin UI under
**Tenants**.

**Related setting**: `DEFAULT_SIGNUP_TIER` on auth-service selects which tier new
tenants land on. It defaults to `community` and should stay there for any
self-hosted install; set it only if you are running a multi-tenant service that
wants signups on a trial tier. In the Helm chart, set it via
`backends.auth-service.extraEnv`.

## Cloud Discovery Processing Issues

### Cloud Discoveries Not Appearing in Discovery Approvals

**Symptom**: Cloud discovery jobs complete successfully, but discovered assets don't appear in the Discovery Approvals modal.

**Troubleshooting Steps**:

1. **Check sensor_discoveries table for cloud entries**:
   ```sql
   SELECT batch_id, COUNT(*) as count, MIN(created_at) as first_seen, 
          MAX(processed_at) as last_processed
   FROM sensor_discoveries 
   WHERE metadata->>'discovery_method' = 'cloud_api'
   GROUP BY batch_id
   ORDER BY first_seen DESC
   LIMIT 10;
   ```

2. **Verify discoveries are unprocessed**:
   ```sql
   SELECT COUNT(*) as unprocessed_count
   FROM sensor_discoveries 
   WHERE metadata->>'discovery_method' = 'cloud_api'
   AND processed_at IS NULL;
   ```

3. **Check discovery-processor-service logs**:
   ```bash
   docker compose logs discovery-processor-service | grep -i cloud
   ```

4. **Verify discovery-processor-service is running**:
   ```bash
   docker compose ps discovery-processor-service
   ```

5. **Check for processing errors**:
   ```sql
   SELECT batch_id, error_message, created_at
   FROM sensor_discoveries 
   WHERE metadata->>'discovery_method' = 'cloud_api'
   AND error_message IS NOT NULL
   ORDER BY created_at DESC
   LIMIT 10;
   ```

**Common Causes**:
- `discovery-processor-service` is not running or crashed
- Batch processing failed due to validation errors
- Network space classification failed
- Inventory service API errors during asset import

**Fix**:
1. Restart discovery-processor-service: `docker compose restart discovery-processor-service`
2. Check service health: `docker compose logs discovery-processor-service --tail 100`
3. Verify Platform Device Interrogation Agent system sensor exists and is active
4. Check inventory-service is responding: `curl http://localhost:8080/api/v1/inventory-service/health`

### Cloud Discovery Batch Stuck in Processing

**Symptom**: Cloud discoveries remain in `sensor_discoveries` with `processed_at IS NULL` for extended periods.

**Troubleshooting**:
1. Check if batch is locked (being processed):
   ```sql
   SELECT batch_id, COUNT(*) as count, MIN(created_at) as created
   FROM sensor_discoveries 
   WHERE metadata->>'discovery_method' = 'cloud_api'
   AND processed_at IS NULL
   GROUP BY batch_id;
   ```

2. Review discovery-processor-service logs for that batch_id
3. Check for database locks or connection issues
4. Verify batch has valid data (IP addresses, ports, protocols)

**Fix**: If batch is truly stuck, you may need to manually mark it as failed or restart the discovery-processor-service to retry processing.
