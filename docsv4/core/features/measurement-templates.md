# Measurement Templates

Measurement templates provide pre-configured measurement rules that can be quickly applied to controls when building compliance frameworks. This feature significantly speeds up framework creation and ensures consistency across frameworks.

## Overview

Measurement templates are reusable rule configurations that define:
- **Measurement Type**: What to measure (e.g., `tls_version`, `cert_expiration_days`)
- **Rule Type**: How to evaluate (threshold, range, pattern, presence)
- **Predicate**: Pre-configured rule logic
- **Category**: Organization grouping (tls, certificate, cipher)
- **Framework Tags**: Relevant frameworks (SOC2, PCI-DSS, NIST, etc.)

## Benefits

1. **Faster Framework Creation**: Apply common rules instantly instead of configuring from scratch
2. **Consistency**: Standardized rules across frameworks
3. **Best Practices**: Templates encode security best practices
4. **Versioning**: Templates track changes over time
5. **Filtering**: Find templates by category or framework

## Using Templates

### In the UI

When adding a measurement to a control:

1. **Select Template** (optional): Choose a template from the dropdown at the top of the measurement rule builder
2. **Auto-Population**: Form fields are automatically filled with template values
3. **Customize** (optional): Modify the pre-filled values as needed
4. **Save**: Create the measurement

The template selector shows:
- Templates grouped by category
- Framework tags for each template
- Template descriptions
- Rule type indicators

### Via API

Apply a template to a control:

```bash
POST /api/v1/compliance-engine/admin/templates/:templateId/apply
{
  "control_id": "control-uuid",
  "framework_type": "platform"
}
```

## Available Templates

The system includes pre-built templates for common compliance requirements:

### TLS Templates

- **TLS 1.2+ Required** (`tls-1.2-required`)
  - Pattern rule excluding TLS 1.0 and 1.1
  - Tags: SOC2, PCI-DSS, NIST

### Certificate Templates

- **Certificate Expiration Warning** (`cert-expiration-30-days`)
  - Threshold rule requiring at least 30 days remaining
  - Tags: SOC2, PCI-DSS, NIST, ISO27001

- **Minimum RSA Key Size 2048 bits** (`min-key-size-rsa-2048`)
  - Threshold rule requiring 2048+ bit keys
  - Tags: SOC2, PCI-DSS, NIST

### Cipher Templates

- **SHA256+ Hash Required** (`sha256-hash-required`)
  - Pattern rule excluding SHA1 and MD5
  - Tags: SOC2, PCI-DSS, NIST

- **Strong Key Exchange Required** (`strong-key-exchange-only`)
  - Pattern rule requiring ECDHE or DHE (excluding static RSA)
  - Tags: SOC2, NIST

- **Strong Symmetric Encryption** (`strong-symmetric-encryption`)
  - Pattern rule excluding weak ciphers (3DES, DES, RC4)
  - Tags: SOC2, PCI-DSS, NIST

### TLS Security Templates

- **PFS Required** (`pfs-required`)
  - Presence rule requiring Perfect Forward Secrecy
  - Tags: SOC2, NIST

## Creating Custom Templates

Platform admins can create custom templates for organization-specific requirements.

### Via UI

1. Navigate to **Admin UI → Compliance → Measurement Templates**
2. Click **Create Template**
3. Fill in template details:
   - Code (unique identifier)
   - Name and description
   - Measurement type
   - Rule type and predicate
   - Category
   - Framework tags
4. Save template

### Via API

```bash
POST /api/v1/compliance-engine/admin/templates
{
  "code": "custom-template-code",
  "name": "Custom Template Name",
  "description": "Template description",
  "measurement_type_id": "measurement-type-uuid",
  "rule_type": "threshold",
  "predicate": {
    "operator": ">=",
    "value": 30
  },
  "category": "certificate",
  "framework_tags": ["SOC2"],
  "is_active": true
}
```

## Template Management

### Filtering Templates

Templates can be filtered by:
- **Category**: tls, certificate, cipher
- **Framework Tag**: SOC2, PCI-DSS, NIST, ISO27001
- **Active Status**: Show only active templates

### Template Versioning

Templates include version tracking:
- Version increments on each update
- Historical versions are preserved
- Active templates use the latest version

### Template Lifecycle

- **Active**: Template is available for use
- **Inactive**: Template is soft-deleted (not shown in UI, but preserved)

## Best Practices

1. **Use Templates First**: Check for existing templates before creating custom measurements
2. **Tag Appropriately**: Add framework tags to make templates discoverable
3. **Document Purpose**: Include clear descriptions explaining when to use each template
4. **Version Carefully**: Update templates only when necessary, as changes affect all frameworks using them
5. **Test Templates**: Verify template predicates work correctly before applying widely

## Integration with Measurement Validation

Templates work seamlessly with the measurement validation system:
- Templates only include valid rule types for the measurement type
- Predicates are validated when templates are created
- Applying a template ensures compatibility with the measurement type

## Related Documentation

- [Compliance Frameworks](./compliance-frameworks.md) - Framework management
