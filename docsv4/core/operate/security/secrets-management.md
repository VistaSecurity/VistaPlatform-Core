---
render_macros: false
---

# Secrets Management Guide

This guide covers how secrets are managed in the Crypto Inventory Platform, including the encryption master key for platform integrations.

## Overview

The platform uses various secrets for different purposes:
- **Database credentials**: PostgreSQL, Redis, InfluxDB
- **JWT secrets**: Token signing keys
- **Service secrets**: API keys, webhook secrets
- **Platform integration credentials**: AWS, cloud providers, SaaS integrations (encrypted)

## Development Environment

### Automatic Secret Generation

The development scripts automatically generate and manage secrets:

#### `session-init.sh` (Development)

This script automatically generates `ENCRYPTION_MASTER_KEY` if not set:

```bash
# Script checks if ENCRYPTION_MASTER_KEY is set
if [[ -z "${ENCRYPTION_MASTER_KEY:-}" ]]; then
    # Generates a secure key using openssl
    ENCRYPTION_MASTER_KEY=$(openssl rand -base64 32)
    export ENCRYPTION_MASTER_KEY
fi
```

**What it does:**
- Generates a secure base64-encoded 32-byte key
- Exports it for the current session
- Sets a default if `openssl` is not available

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

## Production Environment

### `generate-prod-env.sh` (Production)

This script automatically generates `ENCRYPTION_MASTER_KEY` for production:

```bash
# Generates secure key
ENCRYPTION_MASTER_KEY=$(openssl rand -base64 32)
```

**What it does:**
- Generates a secure random key
- Adds it to `.env.prod` with documentation comments
- Includes warnings about using key management services

### `deploy-aws.sh` (Production)

This script validates that `ENCRYPTION_MASTER_KEY` is set:

```bash
if [[ -z "${ENCRYPTION_MASTER_KEY:-}" ]]; then
    warn "ENCRYPTION_MASTER_KEY not set in .env.prod"
    warn "Platform integration management will be disabled"
    warn "For production, use AWS KMS or similar key management service"
fi
```

**What it does:**
- Validates key is present before deployment
- Warns if key is missing (does not block deployment)
- Provides guidance on using key management services

### Production Best Practices

#### Option 1: AWS KMS (Recommended)

**Setup:**
1. Create a KMS key in AWS:
```bash
aws kms create-key --description "Platform Integrations Encryption Key"
```

2. Store the key ID in AWS Systems Manager Parameter Store:
```bash
aws ssm put-parameter \
  --name "/crypto-inventory/encryption-master-key-id" \
  --value "<key-id>" \
  --type "String"
```

3. Update `deploy-aws.sh` to fetch the key:
```bash
# Fetch key from KMS via Systems Manager
KEY_ID=$(aws ssm get-parameter --name "/crypto-inventory/encryption-master-key-id" --query "Parameter.Value" --output text)
ENCRYPTION_MASTER_KEY=$(aws kms decrypt --ciphertext-blob fileb://encrypted_key.bin --key-id $KEY_ID --query Plaintext --output text)
```

#### Option 2: HashiCorp Vault

**Setup:**
1. Store the key in Vault:
```bash
vault kv put secret/crypto-inventory encryption_master_key="<key>"
```

2. Update deployment scripts to fetch from Vault:
```bash
ENCRYPTION_MASTER_KEY=$(vault kv get -field=encryption_master_key secret/crypto-inventory)
```

#### Option 3: AWS Secrets Manager

**Setup:**
1. Store the key in Secrets Manager:
```bash
aws secretsmanager create-secret \
  --name crypto-inventory/encryption-master-key \
  --secret-string "<key>"
```

2. Update deployment scripts to fetch from Secrets Manager:
```bash
ENCRYPTION_MASTER_KEY=$(aws secretsmanager get-secret-value \
  --secret-id crypto-inventory/encryption-master-key \
  --query SecretString --output text)
```

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
1. Development: Run `session-init.sh` (automatically generates key)
2. Production: Set `ENCRYPTION_MASTER_KEY` in `.env.prod` or key management service
3. Restart `admin-service` container

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
- [Security Architecture](architecture.md) - Overall security design
- AWS Cost Explorer Setup - AWS-specific integration setup

## Future Enhancements

### Planned Features

1. **AWS KMS Integration** - Direct integration with AWS KMS for key management
2. **Key Rotation** - Automatic key rotation without downtime
3. **Multi-Key Support** - Support for multiple encryption keys (for migration)
4. **Credential Rotation** - Automated credential rotation for integrations
5. **HashiCorp Vault Integration** - Direct integration with HashiCorp Vault
6. **Azure Key Vault Integration** - Direct integration with Azure Key Vault
