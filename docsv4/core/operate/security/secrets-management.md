---
render_macros: false
---

# Secrets Management Guide

This guide covers how secrets are managed in Vista Platform, including the encryption master key for platform integrations.

## Overview

The platform uses various secrets for different purposes:
- **Database credentials**: PostgreSQL, Redis, InfluxDB
- **JWT secrets**: Token signing keys
- **Service secrets**: API keys, webhook secrets
- **Platform integration credentials**: AWS, cloud providers, SaaS integrations (encrypted)

## Development Environment

### Automatic Secret Generation

`./scripts/bootstrap-env.sh` generates every secret a fresh checkout needs,
`ENCRYPTION_MASTER_KEY` included, into a new `.env`:

```bash
./scripts/bootstrap-env.sh
```

**What it does:**
- Copies `env.example` to `.env`, then replaces every value that still matches
  its published placeholder (`dev-master-key-change-in-production` for
  `ENCRYPTION_MASTER_KEY`, and similarly for `JWT_SECRET`,
  `INTERNAL_AUTH_SECRET`, and the datastore passwords) with a fresh
  cryptographically random value, alphanumeric so it survives being embedded
  in a connection string
- Never overwrites an existing `.env` — delete it first if you need to rotate
- Only rewrites values that still match their placeholder exactly, so it's
  safe to re-run against a partially hand-edited file

**Where it's used:**
- `admin-service` for encrypting integration credentials
- Automatically picked up by `docker-compose.yml` via `${ENCRYPTION_MASTER_KEY}`

### Manual Setup (Optional)

You can manually set the key in your shell environment:

```bash
# Generate a key
export ENCRYPTION_MASTER_KEY=$(openssl rand -base64 32)

# Or add to .env file
echo "ENCRYPTION_MASTER_KEY=$(openssl rand -base64 32)" >> .env
```

### docker-compose.yml Configuration

The `admin-service` in `docker-compose.yml` is configured to use the encryption key:

```yaml
admin-service:
  environment:
    - ENCRYPTION_MASTER_KEY=${ENCRYPTION_MASTER_KEY}
```

**Behavior:**
- Uses `${ENCRYPTION_MASTER_KEY}` from environment
- Certificate generation scripts will **fail** if the key is not set (no silent fallback)
- Auth service refuses to start in production if `JWT_SECRET` or `INTERNAL_AUTH_SECRET` use dev defaults

> **Security Note (Mar 2026 audit):** Dev default fallbacks were removed from all certificate generation scripts and the auth service. Always set `ENCRYPTION_MASTER_KEY`, `JWT_SECRET`, and `INTERNAL_AUTH_SECRET` to strong random values. Generate with: `openssl rand -hex 32`

## Production Environment (Helm chart)

Production runs the Helm chart, not a `.env` file — see the
[production checklist](../deployment/production-checklist.md). The chart
handles `ENCRYPTION_MASTER_KEY` (and the other platform secrets — JWT signing
key, internal-auth HMAC secret) one of two ways:

- **Chart-generated (default).** If you don't supply
  `platform.existingSecretName`, the chart generates the platform Secret on
  first install and keeps it — every subsequent `helm upgrade` reads the
  existing Secret back rather than regenerating it.
- **Operator-supplied (recommended for anything you'd call real).** Create the
  Kubernetes `Secret` yourself, out of band, and reference it via
  `platform.existingSecretName` in `values.yaml`. This is what lets you source
  `ENCRYPTION_MASTER_KEY` from whatever your organization already uses —
  a `SealedSecret`, the External Secrets Operator pulling from AWS Secrets
  Manager or HashiCorp Vault, or a plain `kubectl create secret generic`
  against a value you generated with `openssl rand -base64 32`.

**Never rotate `ENCRYPTION_MASTER_KEY` on a live deployment.** Whichever way
you manage the Secret, changing its value after you have live integrations
makes every credential encrypted under the old key permanently undecryptable
— see [Cannot Decrypt Existing Credentials](#cannot-decrypt-existing-credentials)
below.

## Platform Integration Credentials

### How Encryption Works

When a platform admin creates an AWS integration:

1. **User enters credentials** in the admin UI (plaintext)
2. **Frontend sends** to backend API
3. **Backend encrypts** sensitive fields (access_key_id, secret_access_key, etc.) using `ENCRYPTION_MASTER_KEY`
4. **Encrypted credentials** are stored in `platform_integrations.config` (JSONB column)
5. **When retrieved**, credentials are automatically decrypted

### Encryption Details

- **Algorithm**: AES-256-GCM (authenticated encryption)
- **Key Derivation**: PBKDF2 (4096 iterations, SHA-256)
- **Nonce**: Random for each encryption operation
- **Sensitive Fields**: `access_key_id`, `secret_access_key`, `session_token`, `api_token`, `api_key`, `password`, `client_secret`

### Security Features

- **Encrypted at rest**: All credentials stored encrypted in database
- **RBAC protected**: Only platform admins with `platform.settings` permission can access
- **Audit logging**: All credential changes logged to `platform_integration_audit_log`
- **No plaintext storage**: Credentials never stored in plaintext

## Migration to Key Management Service

When moving to a 3rd party secrets management service:

### Step 1: Export Current Credentials

1. Connect to database
2. Query all integrations (credentials are encrypted)
3. Decrypt with current key
4. Store securely for migration

### Step 2: Set Up Key Management Service

1. Create key in AWS KMS / HashiCorp Vault / etc.
2. Store key ID/reference in environment or configuration
3. Update deployment scripts to fetch key from service

### Step 3: Update Application Code

1. Update encryption service to fetch key from management service
2. Test with existing encrypted credentials (if key is the same)
3. Or re-encrypt all credentials with new key

### Step 4: Deploy and Verify

1. Deploy updated code
2. Test integration creation/retrieval
3. Verify credentials are encrypted/decrypted correctly
4. Monitor audit logs for any issues

## Troubleshooting

### "Platform integration management will be disabled" Warning

**Problem**: `ENCRYPTION_MASTER_KEY` is not set.

**Solution**:
1. Development: Run `./scripts/bootstrap-env.sh` (automatically generates key)
2. Production: Verify `platform.existingSecretName` (or the chart-generated
   Secret) actually contains `encryption-master-key`
3. Restart the `admin-service` pod/container

### "Failed to encrypt config" Error

**Problem**: Encryption service failed to initialize.

**Possible Causes**:
- `ENCRYPTION_MASTER_KEY` is empty
- Key derivation failed
- Key management service unavailable

**Solution**:
1. Verify `ENCRYPTION_MASTER_KEY` is set and not empty
2. Check service logs for detailed error messages
3. Verify key management service is accessible (if using one)

### Cannot Decrypt Existing Credentials

**Problem**: Error decrypting credentials after key change.

**Cause**: The encryption master key was changed, but existing credentials were encrypted with the old key.

**Solution**:
- **DO NOT** change the encryption key if you have existing integrations
- If you must change the key:
  1. Export all integration credentials (decrypt with old key)
  2. Update encryption key
  3. Re-create all integrations (encrypt with new key)
  4. Or implement a key rotation mechanism

**Prevention**: Use a key management service that handles key rotation automatically (AWS KMS, HashiCorp Vault, etc.)

## Related Documentation

- [Platform Integrations Setup](../configuration/platform-integrations.md) - Detailed integration configuration guide
- [Service-mesh mTLS](service-mesh-mtls.md) - Overall internal-transport security design
- AWS Cost Explorer Setup - AWS-specific integration setup

## Future Enhancements

### Planned Features

1. **AWS KMS Integration** - Direct integration with AWS KMS for key management
2. **Key Rotation** - Automatic key rotation without downtime
3. **Multi-Key Support** - Support for multiple encryption keys (for migration)
4. **Credential Rotation** - Automated credential rotation for integrations
5. **HashiCorp Vault Integration** - Direct integration with HashiCorp Vault
6. **Azure Key Vault Integration** - Direct integration with Azure Key Vault
