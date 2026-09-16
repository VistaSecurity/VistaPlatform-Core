---
render_macros: false
---

# Platform Integrations Configuration Guide

This guide explains how the Platform Integrations feature stores credentials
(AWS, and in future Azure/GCP/SaaS), including the encryption key that
protects them at rest.

## Overview

Platform integrations — currently AWS, used by the [Resource Tracker](#resource-tracker-aws-cost-sync)
cost-sync job — are configured via the admin-service API described below.
**There is no admin console page for this today.** The `platform_integrations`
table, the encryption, and the API endpoints are all live; admin-ui-v2 has not
wired a Settings screen to them, so creating or updating an integration
currently means calling the API directly (or scripting it once, as part of
provisioning). All credentials are encrypted at rest using AES-256-GCM
encryption regardless of how they're written.

## Encryption Master Key

### Purpose

The `ENCRYPTION_MASTER_KEY` is used to encrypt sensitive integration credentials (AWS access keys, API tokens, etc.) before storing them in the database. This ensures credentials are never stored in plaintext.

**Security Features:**
- AES-256-GCM encryption (authenticated encryption)
- PBKDF2 key derivation (4096 iterations, SHA-256)
- Random nonce for each encryption operation
- Only sensitive fields are encrypted (access_key_id, secret_access_key, api_token, etc.)

### Development Setup

For development, `./scripts/bootstrap-env.sh` generates a random
`ENCRYPTION_MASTER_KEY` into `.env` the first time you run it (see
[Secrets Management](../security/secrets-management.md)). You can also set it
manually:

#### Option 1: Environment Variable

Add to your `.env` file or shell environment:

```bash
export ENCRYPTION_MASTER_KEY="your-secure-dev-master-key-change-in-production"
```

#### Option 2: Docker Compose Environment

Add to `docker-compose.yml` under the `admin-service` section:

```yaml
admin-service:
  environment:
    - ENCRYPTION_MASTER_KEY=${ENCRYPTION_MASTER_KEY:-dev-master-key-change-in-production}
```

### Production Setup

See [Secrets Management](../security/secrets-management.md) for how
`ENCRYPTION_MASTER_KEY` is generated and rotated for a Helm-chart deployment,
and why you should **never** rotate it once you have live integrations —
existing encrypted credentials become permanently undecryptable under a new
key.

**Security Best Practices:**
- Use a dedicated secrets management service
- Rotate keys regularly
- Never commit keys to version control
- Use least-privilege access policies
- Enable audit logging for key access

## Configuration Files

### Database Schema

The integration schema is part of the consolidated
[`scripts/database/schema.sql`](../../../../scripts/database/schema.sql) — there
is no separate migration script (see
[Database Migrations](../deployment/database-migrations.md)).

This creates:
- `platform_integrations` - Main integration configuration table
- `platform_integration_secrets` - Encrypted secrets storage (future use)
- `platform_integration_audit_log` - Audit trail for credential changes

### Service Configuration

`admin-service` enables integration management only when
`ENCRYPTION_MASTER_KEY` is set; otherwise it logs a warning at startup and the
integration endpoints are disabled.

### Resource Tracker (AWS Cost Sync)

The `resource-tracker-service` reuses the same encryption key to decrypt AWS credentials when ingesting real cost data:

```yaml
resource-tracker-service:
  environment:
    - ENCRYPTION_MASTER_KEY=${ENCRYPTION_MASTER_KEY}
    - AWS_COST_EXPLORER_ENABLED=true
    - AWS_COST_SYNC_INTERVAL=1h
```

When enabled, the service automatically loads the most recent active AWS integration, decrypts the stored access keys, and instantiates the AWS Cost Explorer client with those credentials. If no integration or key is available the job is automatically disabled and a warning is logged.

## Usage

There is no admin console page for platform integrations today — create and
manage them through the API. Credentials are automatically encrypted before
storage regardless of how the record is written.

### Via API

```bash
# List integrations
curl -X GET http://localhost:8080/api/v1/admin-service/admin/integrations \
  -H "Authorization: Bearer <admin-token>"

# Create AWS integration
curl -X POST http://localhost:8080/api/v1/admin-service/admin/integrations \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "integration_type": "aws",
    "integration_name": "Production AWS",
    "provider": "cloud",
    "config": {
      "access_key_id": "AKIAIOSFODNN7EXAMPLE",
      "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "region": "us-east-1"
    },
    "account_id": "123456789012",
    "region": "us-east-1",
    "environment": "production",
    "is_enabled": true
  }'
```

## Integration Types

### AWS

**Required Fields:**
- `access_key_id` - AWS Access Key ID
- `secret_access_key` - AWS Secret Access Key
- `account_id` - AWS Account ID (12-digit number)
- `region` - Primary AWS region

**Optional Fields:**
- `session_token` - For temporary credentials (STS)
- `environment` - production, staging, development
- `description` - Human-readable description

### Azure (Coming Soon)

Configuration form will be added in future release.

### GCP (Coming Soon)

Configuration form will be added in future release.

### SaaS Integrations (Coming Soon)

Support for Slack, PagerDuty, Datadog, and other SaaS platforms will be added.

## Security Considerations

### Credential Storage

- All sensitive fields are encrypted using AES-256-GCM
- Encryption uses PBKDF2 key derivation (4096 iterations)
- Each encryption operation uses a unique random nonce
- Encrypted credentials are stored in JSONB columns in the database

### Access Control

- Integration management requires `platform.settings` permission
- Only platform administrators can create/update/delete integrations
- All credential changes are logged in the audit trail
- Audit log includes user ID, timestamp, and changed fields (without exposing values)

### Audit Logging

Every integration change is logged to `platform_integration_audit_log`:
- Action type (created, updated, deleted, tested, credential_rotated)
- User who performed the action
- Config hashes (for comparison without exposing values)
- Changed fields (field names only, not values)
- Success/failure status
- Error messages (if applicable)

## Troubleshooting

### "Integration management will be disabled" Warning

**Problem**: `ENCRYPTION_MASTER_KEY` is not set.

**Solution**: 
1. Set `ENCRYPTION_MASTER_KEY` in your environment
2. Restart the `admin-service` container
3. Verify the key is loaded: Check service logs for "Integration service initialized"

### "Failed to encrypt config" Error

**Problem**: Encryption service failed to initialize.

**Possible Causes**:
- `ENCRYPTION_MASTER_KEY` is empty
- Key derivation failed

**Solution**:
1. Verify `ENCRYPTION_MASTER_KEY` is set and not empty
2. Check service logs for detailed error messages
3. Ensure the key is a valid string (not binary data if using plain text)

### Integration Not Appearing in a Listing

**Problem**: `GET /admin-service/admin/integrations` doesn't return an
integration you created.

**Possible Causes**:
- Integration soft-deleted (`deleted_at` is set)
- RBAC permission issue — the caller lacks `platform.settings`
- A `provider`/`integration_type` filter was passed on the list call

**Solution**:
1. Re-check integration status via API: `GET /admin-service/admin/integrations`
2. Verify the caller's token has `platform.settings`
3. Re-run the list call without any query filters

### Cannot Decrypt Existing Credentials

**Problem**: Error decrypting credentials after key change.

**Cause**: The encryption master key was changed, but existing encrypted credentials were encrypted with the old key.

**Solution**:
- **DO NOT** change the encryption key if you have existing integrations
- If you must change the key, you must:
  1. Export all integration credentials (decrypt with old key)
  2. Update the encryption key
  3. Re-create all integrations (encrypt with new key)
  4. Or implement a key rotation mechanism

**Prevention**: Use a key management service that handles key rotation automatically.

## Future Enhancements

### Planned Features

1. **AWS KMS Integration** - Use AWS KMS for key management in production
2. **Key Rotation** - Automatic key rotation without downtime
3. **Multi-Key Support** - Support for multiple encryption keys (for migration)
4. **Credential Rotation** - Automated credential rotation for integrations
5. **Connection Testing** - Test integration connections before saving
6. **Integration Templates** - Pre-configured templates for common integrations

### Migration to Secrets Management Service

When moving to a 3rd party secrets management service:

1. **Export current credentials** (decrypt with current key)
2. **Store in secrets management service** (HashiCorp Vault, AWS Secrets Manager, etc.)
3. **Update encryption service** to fetch keys from the service
4. **Re-encrypt existing credentials** with new key source
5. **Test thoroughly** before removing old key

## Related Documentation

- AWS Cost Explorer Setup - AWS-specific integration setup
- [Service-mesh mTLS](../security/service-mesh-mtls.md) - Overall internal-transport security design

## Support

For issues or questions:
1. Check service logs: `docker-compose logs admin-service`
2. Review audit logs: Query `platform_integration_audit_log` table
3. Check encryption service logs for initialization errors
4. Verify RBAC permissions for your user account
