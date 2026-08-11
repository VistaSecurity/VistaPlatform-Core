# Operational Context

**Status:** Implemented  
**Last Updated:** 2026-04-07

## Summary

Operational context adds **location**, **environment**, and **service** to infrastructure assets so discovery results are actionable. Tenants define locations (e.g. datacenter, cloud region) and network segments (CIDR/value + environment + location). During discovery import, assets are enriched with segment and service identification. The UI provides a **location-first operational overview** and a **remediation queue** with optional ticket creation.

## User-Facing Features

### Locations and Network Segments (Settings)

- **Locations** – Hierarchical CRUD (e.g. region → datacenter → rack). Used as the required location for each network segment. Managed under **Organization Settings** → **Infrastructure** → **Locations**. Supports physical address, cloud provider/region, and geo/timezone.
- **Network segments** – Define CIDRs, IP ranges, or domains with a required **environment** (production, staging, development, test) and **location**. Optional description, business unit, owner email, tags (applied to matching assets on reclassify), and auto-approve for discoveries. Managed under **Organization Settings** → **Infrastructure** → **Network Segments**.

Segments are required before running discovery; the onboarding wizard includes a “Define Networks” step and a persistent banner when no segments exist.

### Asset Enrichment

- **Environment and location** – Set from the segment that matches the asset’s IP/hostname.
- **Service name** – Set from port heuristic, SSH/SMTP/FTP banners, or JA3S (passive). Can be overridden manually on the asset (PUT infrastructure-assets/:id/service).

Asset table and asset detail modal show **Location**, **Environment**, and **Service** (with confidence).

### Operational Overview (Inventory)

- **Route:** `/inventory/operational`
- **Drill-down:** Locations (cards with asset/finding counts) → Environments (per location) → Assets (table for location + environment). Breadcrumb: “All Locations > Location Name > Environment”.
- **Data source:** Materialized view `mv_location_finding_summary` (refreshed after discovery import).

### Remediation Progress (Risk & Compliance)

- **Route:** `/risk-compliance?tab=remediation`
- **Content:** Progress dashboard showing ticket resolution trends (30-day opened/resolved chart), PQC migration readiness (stacked progress bar over the four readiness categories), and per-category ticket breakdown.
- **Ticket creation:** Done per-risk from the **Crypto Risks** tab via per-row action buttons. Tickets are stored in the unified `tickets` table (compliance-engine). External ticket system linking (Jira/ServiceNow) is supported via manual link fields.
- **Data sources:** `GET /api/v1/compliance-engine/tickets/progress`, `GET /api/v1/inventory-service/pqc/progress`.

> **Note:** The former remediation queue (`mv_remediation_queue` materialized view at `/inventory/remediation`) has been superseded by this dashboard. The old backend API endpoints remain for backward compatibility but are no longer used by the UI.

## API (v2)

All under `/api/v2/inventory-service/`:

- `GET /operational/locations-summary` – All location × environment rows.
- `GET /operational/locations/:id/environments` – Environments for a location.
- `GET /operational/locations/:id/environments/:env/assets` – Paginated assets for location + environment.
- `GET /operational/remediation-queue`, `GET /operational/remediation-queue/stats` – Queue and aggregates.
- `GET /operational/remediation-templates` – Templates for remediation text.

Ticket CRUD lives in compliance-engine under `/api/v1/compliance-engine/tickets`
(unified ticketing system); the inventory-service no longer exposes ticket
endpoints.

## Terminology (CMDB-aligned)

- **Infrastructure assets** – Discovered servers/endpoints (not “network assets” in UI).
- **Crypto configurations** – TLS/SSH configurations on assets (not “crypto implementations” in UI).
- **Locations** – Hierarchical operational places (datacenter, cloud region, etc.).

