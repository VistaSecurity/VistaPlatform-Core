# Network Spaces Feature

> **Deprecated (removed in favor of Network Segments).** Network Spaces have been replaced by **Network Segments**. Segments are first-class entities (stored in the `network_segments` table) and are managed under **Organization Settings** → **Infrastructure** → **Network Segments**. Use [Operational Context](./operational-context.md) and the `/api/v2/inventory-service/network-segments` API for all new integrations. The legacy `/api/v1/inventory-service/network-spaces` endpoints remain for backward compatibility only and proxy to the segment model.

---

Network Spaces allowed classification of assets into logical network groups (DMZ, internal, external, etc.) for better organization and security management. The following documentation describes the legacy behavior.

## Overview

Network Spaces provide:
- **Logical Grouping**: Organize assets by network zones
- **Automatic Classification**: Auto-classify assets based on IP address
- **CIDR-based Matching**: Match assets to spaces using CIDR ranges
- **Ownership Classification**: Classify assets as internal, third-party, or unknown
- **Automatic Tagging**: Automatically apply tags to assets based on network space matching

## Network Space Structure

Each network space has:
- **Type**: Network space type (`cidr`, `ip_range`, or `domain`)
- **Value**: CIDR block, IP range, or domain pattern
- **Network Type**: Classification (`private`, `public`, `vpn`, or `cloud`)
- **Description**: Space description
- **Tags**: Key-value pairs that are automatically applied to matching assets
- **Active Status**: Whether the network space is currently active

## Creating Network Spaces

### Create Space

**UI:** Network Spaces → Create Space

**API:** `POST /api/v1/inventory-service/network-spaces`

**Request Body:**
```json
{
  "network_spaces": [
    {
      "id": "space-uuid",  // Omit for new spaces
      "type": "cidr",
      "value": "192.168.100.0/24",
      "network_type": "private",
      "description": "Development network",
      "is_active": true,
      "tags": {
        "environment": "dev",
        "team": "backend"
      }
    },
    {
      "type": "cidr",
      "value": "10.0.0.0/8",
      "network_type": "private",
      "description": "Internal corporate network",
      "is_active": true,
      "tags": {
        "environment": "production"
      }
    }
  ]
}
```

### Update Space

Update existing network space:

**UI:** Network Spaces → Edit Space

**API:** `POST /api/v1/inventory-service/network-spaces` (includes existing spaces with IDs)

## Listing Network Spaces

**UI:** Network Spaces page

**API:** `GET /api/v1/inventory-service/network-spaces`

**Response:**
```json
{
  "network_spaces": [
    {
      "id": "space-uuid",
      "type": "cidr",
      "value": "192.168.100.0/24",
      "network_type": "private",
      "description": "Development network",
      "is_active": true,
      "tags": {
        "environment": "dev",
        "team": "backend"
      }
    }
  ]
}
```

## Asset Classification

### Automatic Classification

Automatically classify assets based on IP address matching:

**UI:** Network Spaces → Classify Assets

**API:** `POST /api/v1/inventory-service/network-spaces/classify-assets`

**Request Body:**
```json
{
  "network_space_id": "space-uuid"
}
```

**Process:**
1. System matches asset IP addresses, hostnames, and FQDNs to network space definitions
2. Assets are classified with ownership (`internal` if matched, `third_party` if not)
3. Tags from all matching network spaces are applied to assets
4. If asset matches multiple spaces, tags are merged (last match wins for duplicate keys)

### Manual Classification

Classify specific assets:

**API:** `POST /api/v1/inventory-service/network-spaces/classify-assets`

**Request Body:**
```json
{
  "network_space_id": "space-uuid",
  "asset_ids": ["asset-uuid-1", "asset-uuid-2"]
}
```

### Classification During Discovery

Assets can be automatically classified when imported from discovery:

1. Discovery results are imported (or sensor discoveries are automatically processed)
2. Assets are created with IP addresses, hostnames, and FQDNs
3. Network space classification runs automatically
4. Assets are classified with ownership (`internal` or `third_party`)
5. Tags from matching network spaces are automatically applied

### Auto-Approval for Sensor Discoveries

Network spaces can be configured to automatically approve sensor discoveries:

**UI:** Network Spaces → Edit Space → Enable "Auto-approve sensor discoveries from this network space"

**How It Works:**
1. Sensor discoveries are automatically processed by `discovery-processor-service`
2. Discoveries are classified by network space
3. If network space has auto-approval enabled, matching discoveries are auto-approved
4. Assets are created with `monitoring` status (instead of `pending_approval`)
5. Auto-approval rule is automatically created/updated in the system

**Configuration:**
- Enable auto-approval per network space
- Auto-approval applies only to sensor discoveries (not discovery jobs)
- Auto-approval rules are evaluated based on:
  - Network ownership: `internal`
  - Network type: matches space's `network_type`
  - Network space match: asset must match the network space

**Benefits:**
- Reduce manual approval workload for trusted network spaces
- Faster time-to-monitoring for internal assets
- Consistent approval decisions based on network classification

**Best Practices:**
- Enable auto-approval only for trusted internal network spaces
- Review auto-approved assets periodically
- Use network space tags to identify auto-approved assets
- Monitor auto-approval statistics in the network space settings

## Asset Ownership Classification

Network spaces help classify asset ownership:

- **Internal**: Assets matching defined network spaces (CIDR ranges, IP ranges, or domain patterns)
- **Third Party**: Assets not matching any defined network space
- **Unknown**: Assets when no network spaces are defined

Ownership is automatically determined when assets are created or updated.

## Automatic Tag Application

Network spaces support automatic tag application to matching assets. Tags defined in a network space are automatically applied to any asset whose IP address, hostname, or FQDN matches the network space definition.

### Defining Tags

Tags are defined as key-value pairs in the network space configuration:

```json
{
  "type": "cidr",
  "value": "192.168.100.0/24",
  "tags": {
    "environment": "dev",
    "team": "backend",
    "location": "datacenter-1"
  }
}
```

### Tag Application Behavior

Tags are automatically applied when:
- Assets are created (via discovery or manual creation)
- Assets are updated during discovery
- Assets are reclassified via the classify-assets endpoint

### Tag Merging

When an asset matches multiple network spaces:
- Tags from all matching spaces are merged
- If multiple spaces define the same tag key, the value from the last matching space takes precedence
- Tags are merged with any existing asset tags (network space tags override existing tags for the same keys)

### Example Use Cases

**Environment Tagging:**
```json
{
  "type": "cidr",
  "value": "192.168.100.0/24",
  "tags": {
    "environment": "dev"
  }
}
```
All assets in the `192.168.100.0/24` range will automatically receive the `environment:dev` tag.

**Multi-Tag Example:**
```json
{
  "type": "cidr",
  "value": "10.0.0.0/8",
  "tags": {
    "environment": "production",
    "region": "us-east-1",
    "compliance": "pci-dss"
  }
}
```
Assets matching this range will receive all three tags automatically.

## Use Cases

### Security Zones

Organize assets by security zones:
- **DMZ**: Public-facing servers
- **Internal**: Corporate network
- **External**: Third-party or cloud assets

### Compliance Reporting

Group assets for compliance reporting:
- Assets in specific network spaces
- Compliance status by network space
- Risk assessment by zone

### Access Control

Use network spaces for access control:
- Restrict access based on network space
- Apply different policies per space
- Monitor access by network zone

## Best Practices

1. **Define Spaces First**: Set up network spaces before discovery
2. **Use CIDR Ranges**: Use CIDR notation for IP ranges
3. **Avoid Overlaps**: Ensure CIDR ranges don't overlap (or define priorities)
4. **Regular Updates**: Update spaces as network changes
5. **Document Purpose**: Document the purpose of each network space

## Filtering by Network Space

Filter assets by network space:

**UI:** Assets → Filter → Network Space

**API:** `GET /api/v1/inventory-service/assets?network_space_id=space-uuid`

## Integration with Discovery

Network space classification integrates with discovery workflow:

1. **Discovery**: Assets discovered via discovery jobs
2. **Import**: Assets imported with IP addresses
3. **Classification**: Assets automatically classified into network spaces
4. **Review**: Review assets by network space

## Related Documentation

- [Discovery Feature](./discovery.md) - Discovery workflow
- [Asset Approval Feature](./asset-approval.md) - Approval workflow
