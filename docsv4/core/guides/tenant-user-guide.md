# Tenant User Guide

**Version:** 1.6
**Last Updated:** 2026-06-24

> **v1.6 navigation correction:** the navigation section now reflects the current 5-section top navigation (Dashboard · Discovery · Inventory · Risk & Compliance · Remediation) and the profile dropdown. References to the retired v1 "Crypto Workbench" page, the standalone "Tickets" page, and the legacy "Reports" surface have been updated to their current homes (the Inventory lenses, Remediation → Queue, and page-local Export + CBOM artifacts).

This guide provides comprehensive instructions for tenant users using the Vista Platform platform.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard](#dashboard)
3. [Crypto Inventory](#crypto-inventory)
5. [Asset Management](#asset-management)
6. [Discovery](#discovery)
7. [Sensor Management](#sensor-management)
8. [Compliance](#compliance)
9. [CBOM & Exports](#cbom--exports)
10. [Settings](#settings)
11. [Profile Management](#profile-management)
12. [Activity Logs & Audit Trail](#activity-logs--audit-trail)
13. [Notifications](#notifications)
14. [Alert Management](#alert-management)
15. [SIEM Integration](#siem-integration)
16. [Retention Policies](#retention-policies)
18. [Best Practices](#best-practices)
19. [Troubleshooting](#troubleshooting)
20. [Support](#support)

---

## Getting Started

### First Login

1. Receive invitation email from tenant administrator
2. Click invitation link
3. Choose your authentication method:
   - **Email and Password**: Create a password for your account
   - **SSO Provider**: Sign in with your organization's identity provider (Google, Microsoft, Okta, etc.)
4. Complete authentication
5. Verify your email (if required)
6. Complete onboarding workflow
7. Access the dashboard

**Note:** The authentication options available depend on your tenant's authentication policy configured by administrators. Some tenants may require SSO authentication for all users.

### Signing In

Your tenant administrator configures the authentication methods available for your organization. You may see one or more of the following options on the login page:

#### Password Authentication

Sign in with your email address and password:

1. Enter your email address
2. Enter your password
3. Click **Sign In**

**Forgot Password?** Click the "Forgot Password" link to reset your password via email.

#### SSO Authentication

Sign in with your organization's Single Sign-On provider:

1. Your login page will display available SSO providers (e.g., "Sign in with Google", "Sign in with Microsoft")
2. Click the SSO provider button
3. You'll be redirected to your organization's identity provider
4. Sign in with your corporate credentials
5. You'll be redirected back to Vista Platform automatically

**First-Time SSO Users**: If your account doesn't exist yet and your tenant has auto-provisioning enabled, your account will be created automatically on your first SSO login.

#### Authentication Policy Types

Your tenant administrator sets an authentication policy that determines which authentication methods are available:

- **Password Only**: You can only sign in with email and password. SSO is not available.
- **Prefer SSO**: SSO providers are shown first, but you can still use password authentication as a fallback.
- **Enforce SSO**: Regular users must use SSO. Only administrators can use password authentication for emergency access.
- **SSO Only**: All users, including administrators, must use SSO. Password authentication is disabled.

**Linked Accounts**: If you've linked your password account to an SSO provider, you can use either method to sign in (unless your tenant enforces SSO-only authentication).

### Onboarding

New users complete an onboarding workflow:

1. **Welcome**: Platform introduction
2. **Profile**: Complete your profile
3. **Tutorial**: Platform tutorial (optional)
4. **First Asset**: Add or discover your first asset (optional)

You can skip optional steps and complete them later.

---

## Dashboard

### Overview

The dashboard provides:
- **Asset Summary**: Total assets, risk levels
- **Recent Activity**: Latest discoveries and changes
- **Compliance Status**: Current compliance scores with finding breakdown
- **Quick Actions**: Common tasks

### Compliance Metrics

The Compliance Score card shows:
- **Overall Score**: Percentage of controls passing
- **Active Findings**: Number of currently detected violations (red)
- **Suppressed Findings**: Number of temporarily suppressed findings (yellow)
- **New Findings**: Findings not yet processed (blue)
- **Resolved Findings**: Findings that have been resolved (green)

Click the Compliance Score card to navigate to the Compliance Workspace for detailed analysis.

### Navigation

The platform uses a **5-section primary navigation** organized around the lifecycle of your cryptographic assets. The sections appear as a vertical rail; clicking a section expands its sub-navigation beneath it.

| Section | Purpose | Sub-navigation |
|---------|---------|----------------|
| **Dashboard** | Priority-based health overview — assets, compliance status, and recent activity | — |
| **Discovery** | Find assets — sensors, scanning, device interrogation, and cloud/PCAP sources | Command Center; Sensors & Agents, Discovery Jobs, Devices, Scheduled Scans; Approvals; Job Logs; Cloud, PCAP Upload |
| **Inventory** | One unified inventory, viewed through switchable **lenses** | Lenses (Infrastructure, Certificates, Keys, and more) plus By-Protocol lenses — see [Inventory & Lenses](../features/inventory-and-lenses.md) |
| **Risk & Compliance** | Where you stand and what's failing | Posture, Findings, CBOM |
| **Remediation** | Fixing what was found, end to end | Triage, Queue, Plans |

**Settings** and **My Profile** are *not* in the primary rail — they live in the **profile dropdown** at the bottom of the rail (see below).

#### Profile Dropdown

Click your account chip at the bottom of the navigation rail to open the profile menu. It contains:

- **Getting Started** — the onboarding checklist (shown while onboarding is still in progress)
- **My Profile** — your personal settings (Personal, Security, Notifications, Sessions & Devices, Connected Accounts, API Tokens, and more)
- **Organization Settings** — all tenant configuration (see the grouped list below)
- **About** — version and build information for the running platform
- **Theme toggle** — switch between Light and Dark mode
- **Sign out**

#### Global Search (Command Palette)

Press **`Cmd+K`** (Mac) or **`Ctrl+K`** (Windows/Linux) anywhere in the application — or click the search icon in the header — to open the **Command Palette**.

- **Empty state**: Shows quick-navigation links across the platform's sections (Dashboard, Discovery, Inventory, Risk & Compliance, Remediation, Settings).
- **Search**: Type (2+ characters) to search across assets, certificates, devices, and sensors simultaneously. Results are grouped by type with section headers. Selecting an asset or certificate opens the matching Inventory lens with the search pre-filled.
- **Keyboard navigation**: Use ↑↓ arrows to move through results, **Enter** to navigate, **Esc** to close.

See [Global search (⌘K)](../features/global-search.md) for the full reference.

#### Mobile & Tablet Navigation

On smaller screens (tablets and phones), the top navigation bar is replaced by a menu icon (☰) in the header. Tap the icon to open a slide-out navigation drawer from the left side of the screen. The drawer contains all the same navigation sections listed above, organized as expandable groups. Tap a section header (e.g., "Inventory") to expand it and see its sub-items. Tap any link to navigate — the drawer closes automatically. You can also close the drawer by tapping the X button, tapping the dimmed background, or pressing the Escape key.

#### Section Details

- **Dashboard**: Priority-based overview of assets, compliance status, and recent activity.
- **Discovery** — find assets and bring them into inventory:
  - *Command Center*: Discovery overview and entry point
  - *Sensors & Agents*: Manage deployed sensors and discovery agents
  - *Discovery Jobs*: Create and monitor discovery jobs
  - *Devices*: View and manage discovered network devices
  - *Scheduled Scans*: Configure automated, recurring discovery
  - *Approvals*: Review and approve (or deny) discovered assets
  - *Job Logs*: Inspect discovery job run logs
  - *Cloud* / *PCAP Upload*: Cloud-provider discovery (AWS, Azure, GCP) and PCAP file ingestion
- **Inventory** — one unified inventory, reshaped by **lenses** (not separate pages). Switch lenses to view the same assets through different angles — Infrastructure, Certificates, Keys, and by-protocol views. See [Inventory & Lenses](../features/inventory-and-lenses.md).
- **Risk & Compliance**:
  - *Posture*: Standing compliance/risk view, with Algorithm Reference and Framework transparency sub-views
  - *Findings*: Active compliance findings, filterable by lens
  - *CBOM*: Generate and compare audit-grade CBOM artifacts
- **Remediation**:
  - *Triage*: Prioritize what to fix next
  - *Queue*: The unified ticket queue — every remediation ticket lives here
  - *Plans*: Track multi-step remediation and migration plans (e.g. PQC migration)
- **My Profile** (via the profile dropdown): your personal settings — Personal, Preferences, Security, Notifications, Sessions & Devices, Connected Accounts, API Tokens, Accessibility, and Account & Privacy.
- **Organization Settings** (via the profile dropdown):
  All tenant configuration is consolidated under Organization Settings, grouped into categories:
  - *Organization*: Overview, Branding
  - *Account*: Billing, Usage & Limits
  - *People & Access*: Members, Roles & Permissions, Security & SSO
  - *Integrations*: Integrations hub (SIEM, CMDB/ITSM, messaging, storage)
  - *Notifications & Alerts*: Routing Rules, Alert Rules
  - *Policies*: Compliance Frameworks, Custom Policies, Severity Ratings, Asset Lifecycle, Retention Policies, Scopes
  - *Audit*: Audit trail search and export
  - *Infrastructure*: Sensor Configuration, Locations, Network Segments

---

## Crypto Risks

The Crypto Risks page provides a focused view of cryptographic weaknesses across your network, with detailed remediation guidance to help you prioritize and fix security issues.

### Risk Summary

The page displays severity-based summary cards:
- **Critical**: Immediate action required (SSL/TLS 1.0, RC4, MD5, DES)
- **High**: High priority remediation (TLS 1.1, SHA-1, 3DES, RSA-1024)
- **Medium**: Medium priority (expiring certificates, weak keys)
- **Assets Affected**: Total count of assets with crypto risks

Click on any severity card to filter the list by that severity level.

### Category Breakdown

View issues grouped by category:
- **Protocol Issues**: Outdated TLS/SSL versions
- **Algorithm Issues**: Weak ciphers and hash algorithms
- **Certificate Issues**: Certificate-related problems
- **Key Size Issues**: Insufficient key lengths

### Filtering and Search

- Use the search bar to find specific assets by hostname, IP, or protocol
- Click severity cards to filter by risk level
- Click category cards to filter by issue type
- Multiple filters can be combined

### Remediation Guidance

Click on any risk row or the wrench icon to open the Remediation Panel, which provides:

1. **Risk Score**: Overall risk assessment
2. **Priority Actions**: Most critical steps to take
3. **Issues List**: Detailed breakdown of each issue with:
   - Severity and type
   - Impact description
   - Step-by-step remediation instructions
   - Recommended timeline
   - Alternative technologies to migrate to
4. **Compliance Impact**: How the issue affects compliance with frameworks (PCI-DSS, NIST, FIPS)
5. **Resources**: Links to external documentation and standards

### Ticket Integration

Each risk row includes an **Action** column:
- **Create Ticket**: Click the ticket icon to create a remediation ticket pre-filled with the risk details (severity, description, affected asset)
- **View Ticket**: If a ticket already exists for that risk, click the eye icon to view the ticket details

You can also create tickets from the risk detail panel by clicking "Create Ticket" in the panel footer.

Tickets created from Crypto Risks are tracked in **Remediation → Queue** (the unified ticket queue) and surfaced in the **Remediation Progress** dashboard. See [Remediation](../features/remediation.md).

### Export

Click "Export CSV" to download a CSV file of all risks for reporting or further analysis.

---

## Remediation Progress

The Remediation tab on the Risk & Compliance page provides a dashboard view of your remediation efforts across all ticket categories.

### Summary Cards

Four cards at the top show your current remediation posture:
- **Open Tickets**: Total tickets in open or in-progress status
- **Resolved (30d)**: Tickets resolved in the last 30 days
- **Overdue**: Tickets past their due date (highlighted in red)
- **Avg Resolution**: Average time to resolve a ticket

### Remediation Trend

A 30-day bar chart shows daily ticket activity:
- **Orange bars**: Tickets opened per day
- **Green bars**: Tickets resolved per day

Use this to track whether your team is keeping up with incoming remediation work.

### PQC Migration Progress

A stacked progress bar and table show your organization's post-quantum cryptography readiness:
- **PQC-Ready** (green): Implementations using post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA)
- **Quantum-Safe** (blue): Symmetric algorithms that are inherently quantum-safe (AES, ChaCha20, SHA-256)
- **Needs Migration** (amber): Asymmetric algorithms vulnerable to quantum attack (RSA, ECDSA, ECDH)

The by-family table shows each algorithm family with its count, status, and recommended migration target.

### Category Breakdown

Cards for each ticket category (compliance, certificate, remediation, vulnerability, operational, general) show open vs. resolved counts. Click any card to open **Remediation → Queue** filtered by that category. See [Remediation](../features/remediation.md).

---

## Posture: Algorithm Reference & Frameworks

Open **Risk & Compliance → Posture**. Three sub-links appear under it: **Overview**, **Frameworks**, and **Algorithm Reference**. Overview is the standing/score view; the other two let you see exactly *why* the platform rates things the way it does — so a verdict is never a black box.

### Algorithm Reference

A read-only catalogue of every cryptographic algorithm the platform knows about, with our assessment of each. Search or filter by **strength** (recommended / strong / acceptable / weak), **status** (current / deprecated / obsolete), or **quantum** (PQC vs classical). Click any algorithm to open a detail panel showing its strength, deprecation and post-quantum status, risk score, our migration guidance, and the specific recommended alternatives to move to. This is the same rating used to flag risk across your inventory — so when something is marked "weak" or "deprecated," this is where you see why and what to do about it.

### Frameworks

Browse compliance frameworks and, crucially, what each one actually measures. The view opens on **My frameworks** — the ones you've activated, which drive your compliance score — and an **All published** toggle reveals the full catalogue, each with a preview score showing what you'd score against it today. Open a framework to see its controls; expand a control to read its measurement in plain language (for example, *"Passes when RSA key size is at least 2,048 bits"*). Nothing is marked failing without a rule you can read here.

See [Algorithm Reference](../features/algorithm-reference.md) and [Viewing Frameworks, Controls & Measurements](../features/framework-transparency.md) for more detail.

---

## Crypto Inventory

The Crypto Inventory page provides a unified view of assets, certificates, and cryptographic configurations, enabling comprehensive search and filtering across all entity types.

### View Modes

The Crypto Inventory page supports three view modes:

1. **Assets**: View only infrastructure assets
2. **Certificates**: View only certificates
3. **Unified**: View assets and certificates together in a single list

Switch between view modes using the tabs at the top of the page.

### Summary Statistics

The page displays summary statistics:
- **Total Assets**: Count of all assets in your inventory
- **Total Certificates**: Count of all certificates
- **Expiring Soon**: Certificates expiring within 30 days
- **Deprecated Algorithms**: Count of deprecated algorithm usage

### Filtering

The unified filter panel supports comprehensive filtering:

#### Common Filters
- **Search**: Search across all entity types (hostname, IP, certificate CN, issuer, etc.)
- **Risk Level**: Filter by risk level (Critical, High, Medium, Low, Informational)
- **Environment**: Filter by environment (production, staging, development, test)

#### Asset Filters
- **Asset Type**: Filter by asset type (server, endpoint, service, appliance)
- **Business Unit**: Filter by business unit
- **Operating System**: Filter by operating system
- **Owner Email**: Filter by asset owner
- **Asset Ownership**: Filter by ownership type (customer, third_party, unknown)
- **Asset Status**: Filter by status (monitoring, pending_approval, denied)

#### Certificate Filters
- **Expiring Within**: Filter certificates expiring within X days
- **Min Key Size**: Filter certificates with minimum key size
- **Algorithm**: Filter by public key algorithm (RSA, ECDSA, etc.)
- **Issuer**: Filter by certificate issuer

#### Crypto Configuration Filters
- **Protocol Version**: Filter by TLS/SSL version (TLSv1.3, TLSv1.2, TLSv1.1, TLSv1.0, SSLv3)
- **Hash Algorithm**: Filter by hash algorithm (SHA256, SHA1, MD5)
- **Min Key Size**: Filter by minimum key size
- **Deprecated Algorithms**: Filter for deprecated algorithms

#### Cross-Entity Filters
- **Assets with Certificates**: Show only assets that have associated certificates
- **Uses Deprecated Algorithms**: Show only assets using deprecated algorithms (TLS 1.0, SHA1, weak keys)

### Smart Filters

Pre-configured filter sets for common use cases:
- **TLS 1.0 Implementations**: Find all assets using deprecated TLS 1.0
- **Certificates Expiring in 30 Days**: Certificates that need renewal soon
- **Assets with Weak Cryptography**: Assets using deprecated algorithms or weak keys
- **Self-Signed Certificates**: Certificates that are self-signed
- **Certificates with Weak Key Size**: Certificates with key size less than 2048 bits

### Viewing Entities

#### Entity Cards

Each entity is displayed as a card showing:
- **Entity Type Badge**: Asset or Certificate indicator
- **Risk Level Badge**: Visual risk indicator
- **Key Information**: Hostname/CN, IP/Issuer, environment
- **Relationship Counts**: Number of associated certificates or assets
- **Expiration Warning**: Days until certificate expiration (if applicable)

#### Certificate List View

In Certificates view mode, certificates are displayed in a sortable table with:
- **Common Name**: Certificate common name
- **Issuer**: Certificate issuer DN
- **Expiration**: Expiration date and days remaining
- **Key Size**: Public key size in bits
- **Algorithm**: Public key algorithm
- **Status**: Expiration status (Valid, Warning, Critical, Expired)
- **Used By**: Number of assets using this certificate

Click on any certificate to view detailed information.

### Certificate Details

Click on a certificate to view detailed information:

1. **Basic Information**:
   - Common name and serial number
   - Subject DN and Issuer DN
   - Subject Alternative Names (SANs)

2. **Validity & Security**:
   - Valid from/to dates
   - Days until expiration
   - Public key size and algorithm
   - Signature algorithm
   - Fingerprints (SHA1, SHA256)

3. **Properties**:
   - Self-signed status
   - CA certificate status
   - Key usage and extended key usage

4. **Associated Assets**:
   - List of assets using this certificate
   - Asset details (hostname, type, environment)

5. **Export Options**:
   - Export certificate as PEM
   - Export certificate details as JSON

### Bulk Actions

Select multiple entities to perform bulk operations:
- **Export CSV**: Export selected entities to CSV format
- **Export JSON**: Export selected entities to JSON format
- **Generate Report**: Create a report for selected entities
- **Bulk Tag**: Apply tags to multiple entities

### Best Practices

- Use Smart Filters for common security checks (expiring certs, deprecated algorithms)
- Regularly review certificates expiring within 30 days
- Use cross-entity filters to find assets with certificate issues
- Export certificate lists for external tracking systems
- Monitor deprecated algorithm usage across your infrastructure

---

## Asset Management

### Understanding Assets vs Certificates

**Assets** are network endpoints (servers, services, appliances) in your infrastructure. They represent the physical or logical devices that host your applications and services.

**Certificates** are X.509 certificates that can be used by multiple assets. They're linked to assets through **crypto configurations**, which capture the cryptographic protocols and configurations used by each asset.

**Relationship:** One asset can have multiple certificates (through multiple crypto configurations), and one certificate can be used by multiple assets. This many-to-many relationship is managed through the crypto configurations table.

**To find certificates:** Use the "Crypto Inventory" page and select "Certificates" view, or filter assets by "Has Certificates" to see which assets have associated certificates.

### Assets Overview Page

The Assets Overview page (`/assets`) provides a quick dashboard view of your asset inventory:

#### Overview Metrics

The page displays key metrics at a glance:
- **Total Assets**: Total count of all assets in your inventory
- **Pending Approvals**: Assets awaiting approval (with action needed badge)
- **Stale Assets**: Assets that haven't been seen recently (with needs attention badge)
- **Crypto Configurations**: Total count of cryptographic configurations
- **High Risk Assets**: Assets with high or critical risk levels (with critical badge)
- **Recent Activity**: Link to view recent activity feed

Each metric card includes a link to the relevant management view.

#### Quick Actions Panel

Quick access to common tasks:
- **Discover Assets**: Start a new asset discovery job
- **Review Approvals**: View and manage pending asset approvals
- **Manage Stale Assets**: View and manage stale assets
- **New Asset**: Manually create a new asset

Actions are permission-gated based on your role.

#### Navigation Cards

Quick navigation to different views:
- **Full Asset Management**: Complete CRUD operations, filtering, and bulk actions
- **Crypto Configurations**: View and filter cryptographic configurations
- **Inventory lenses**: Open the **Inventory** section and switch lenses (Infrastructure, Certificates, Keys, and more) to view your assets from different angles — see [Inventory & Lenses](../features/inventory-and-lenses.md)

#### Recent Activity Feed

Displays recent activity including:
- New asset discoveries
- Expiring certificates (with warning badges)
- High risk assets (with severity indicators)

Click any activity item to view details.

#### Quick Asset List

Shows the last 10 assets sorted by last seen date. Click any asset to view details or click "View all" to go to the full management page.

### Asset Management Page

Open the **Inventory** section and use the **Infrastructure** lens to access the complete asset management interface.

#### View Modes

The management page supports two view modes:

1. **Assets View** (default): View and manage infrastructure assets
2. **Crypto Configurations View**: View cryptographic configurations as first-class entities

Switch between views using the toggle at the top of the page.

#### Viewing Assets

In Assets view mode:

1. View asset list with:
   - Asset name and type
   - IP address and port
   - Risk level
   - **Certificate count badge** (if asset has certificates)
   - **Stale status badge** — `Stale Xd` (yellow) or `Archived` (orange) for assets with stale or archived status
   - Compliance status
   - Last updated

**Certificate Badges:** Assets with associated certificates display a green badge showing the number of certificates (e.g., "3 certificates"). Click the badge or use the "Has Certificates" filter to find assets with certificates.

**Stale Badges:** Assets that haven't been seen recently show an inline badge in the Status column. `Stale 32d` means the asset was last seen 32 days ago and is in warning state. `Archived` means the asset has been marked as inactive. Use the **Stale Assets** button to manage these assets.

#### Saved Searches

The asset management page lets you save and reapply named filter presets:

1. Configure your desired filters
2. Click **Save current filters** in the saved searches strip above the bulk toolbar
3. Enter a name (e.g., "Production TLS 1.0 assets") and click **Save**
4. The preset appears as a chip in the strip — click it to reapply those filters instantly
5. Click **×** on a chip to delete that preset

Up to 20 presets are stored per user (saved in browser storage, scoped to your account).

#### Bulk Actions

Select multiple assets using the checkboxes in the asset table, then use the **Bulk Actions** dropdown:

| Action | Effect | Permission |
|--------|--------|------------|
| **Approve** | Move pending-approval assets to monitoring | `assets.manage` |
| **Deny** | Deny pending discovered assets | `assets.manage` |
| **Rescan** | Trigger re-discovery for selected assets | `assets.manage` |
| **Revalidate** | Re-run compliance validation | `assets.manage` |
| **Archive** | Archive stale/inactive assets | `assets.manage` |

Use the **select all** checkbox in the table header to select all assets on the current page.

#### Viewing Crypto Configurations

In Crypto Configurations view mode:

1. View implementations table with:
   - **Asset**: Link to the associated asset
   - **Protocol & Version**: Protocol type and version (e.g., TLS 1.3)
   - **Cipher Suite**: Cipher suite used
   - **Certificate**: Link to associated certificate (if any)
   - **Risk Score**: Risk level and score
   - **Last Verified**: Last verification timestamp

2. Filter implementations by:
   - Protocol (TLS, SSH, IPSec, etc.)
   - Protocol version
   - Cipher suite
   - Hash algorithm
   - Risk level
   - Discovery method
   - Deprecated algorithms
   - Search across all fields

3. Click any implementation to view details or navigate to the associated asset.

### Filtering Assets

The Asset Management page (Assets view mode) provides comprehensive filtering organized into logical groups:

#### Asset Properties
- **Environment**: Production, staging, development, test
- **Asset Type**: Server, endpoint, service, appliance
- **Risk Level**: Critical, High, Medium, Low, Informational
- **Business Unit**: Filter by business unit
- **Operating System**: Filter by operating system
- **Owner Email**: Filter by asset owner
- **Asset Ownership**: Customer, third party, unknown
- **Asset Status**: Monitoring, pending approval, denied, archived

#### Certificate Relationships
- **Has Certificates**: Check this box to show only assets that have associated certificates. This is the correct way to find assets with certificates - certificates are not asset types.

#### Cryptographic Properties
- **Protocol Version**: Filter by TLS/SSL version (TLSv1.3, TLSv1.2, TLSv1.1, TLSv1.0, SSLv3)
- **Hash Algorithm**: Filter by hash algorithm (SHA256, SHA1, MD5)
- **Min Key Size**: Filter by minimum key size
- **Uses Deprecated Algorithms**: Filter for assets using deprecated algorithms

**Filter Tooltips:** Hover over filter labels to see helpful tooltips explaining each filter's purpose and usage.

**Help Panel:** Click the "Understanding Assets vs Certificates" help panel at the top of the page for detailed information about the relationship between assets and certificates.

**Error Handling:** If you accidentally try to filter by "certificates" as an asset type, the system will display a helpful error message with suggestions to use the "Has Certificates" filter or navigate to the Crypto Inventory page.

### Asset Details

1. Click on an asset to view details
2. View:
   - **Overview**: Basic information
   - **Crypto Configurations**: Cryptographic configurations
   - **History**: Change history and audit trail
   - **Compliance Findings**: Active compliance findings for this asset
     - View finding severity, workflow status, and detection state
     - See occurrence count and resurfaced indicators
     - Click "View all →" to see all findings in Compliance Workspace
   - **Notes**: User notes and comments

### Asset History

View asset change history:

1. Open asset → **History**
2. View timeline of changes:
   - Change type (created, updated, deleted)
   - Changed fields
   - Actor (user or system)
   - Source (manual, discovery, API)
   - Timestamp

### Adding Assets

#### Manual Entry

1. Navigate to **Assets** (Overview) → **New Asset** (Quick Actions) or **Assets** → **Full Asset Management** → **New Asset**
2. Enter asset information:
   - **Name**: Asset name
   - **Type**: Asset type
   - **IP Address**: IP address
   - **Port**: Port number
   - **Environment**: Environment type
3. Add cryptographic configurations
4. Click **Save**

#### Import from Discovery

1. Navigate to **Discovery** → **Import Results**
2. Select discovery job
3. Review discovered assets
4. Resolve conflicts (if any)
5. Click **Import**

### Managing Stale Assets

Assets that haven't been seen recently are automatically marked as stale to help keep your inventory current.

#### Viewing Stale Assets

1. Navigate to **Assets** (Overview) → **Manage Stale Assets** (Quick Actions) or **Assets** → **Full Asset Management** → **Stale Assets** button
2. The button shows a count badge if stale assets exist
3. View stale assets with:
   - Hostname and IP address
   - Stale status (warning or archived)
   - Days since last seen
   - Last seen timestamp

#### Filtering Stale Assets

Filter stale assets by status:
- **All**: All stale assets
- **Warning**: Assets not seen in X days (configurable, default: 30)
- **Archived**: Assets not seen in Y days (configurable, default: 60)

#### Rescanning Assets

Verify if stale assets are still alive:

1. Open **Stale Assets** modal
2. Select assets to rescan
3. Click **Rescan Selected**
4. A discovery job is created to verify the assets
5. If found: Assets are updated and stale status is cleared
6. If not found: Assets remain stale

#### Archiving Assets

Move warning-status assets to archived state (an intermediate step before removal):

1. Open **Stale Assets** modal
2. Select assets to archive
3. Click **Archive Selected**
4. Assets move from `warning` to `archived` status
5. Assets remain in inventory with an **Archived** badge and can be removed later

Use this when you want to flag assets as inactive but keep them visible for reference before deciding to remove them.

#### Removing Assets from Inventory

Remove assets from active inventory while preserving them for reporting:

1. Open **Stale Assets** modal
2. Select assets to remove
3. Click **Remove from Inventory**
4. Assets are soft-deleted (preserved for historical reporting)
5. Assets can be restored if needed

#### Permanently Deleting Assets

**Note:** This action requires administrator permissions and cannot be undone.

1. Open **Stale Assets** modal
2. Select assets to delete
3. Click **Permanently Delete**
4. Confirm the deletion
5. Assets are permanently removed from the database

**Warning:** Permanent deletion removes all asset data and cannot be reversed. Use with caution.

---

## Inventory & Lenses

Vista Platform keeps **one** inventory of your cryptographic assets. Rather than scattering assets, certificates, and crypto configurations across separate pages, the **Inventory** section reshapes that single inventory through **lenses** — each lens is a different angle on the same data, not a different dataset.

### Switching Lenses

1. Open **Inventory** in the primary navigation.
2. The lenses appear in the sub-navigation beneath the Inventory section. Click a lens to reshape the view.
3. Primary lenses include **Infrastructure** (assets in their CMDB context), **Certificates** (every certificate, including manually uploaded ones), and **Keys** (your cryptographic-key inventory — algorithm, size, lifecycle state, and how many assets use each key). Additional **By-Protocol** lenses let you focus on specific protocols.

The lens you choose only changes *your* view — it doesn't filter or alter anyone else's inventory.

### Working Within a Lens

Each lens presents the data in a sortable, filterable table tuned to that angle:

- **Search & filter** within the lens to narrow to the assets, certificates, or keys you care about.
- **Click a row** to open a detail drawer — for example, the Keys lens drills through to the assets using each key, and the Certificates lens opens full certificate details (validity, key size, signature algorithm, fingerprints, and associated assets).
- **Export** the current view as CSV using the **Export** button in the toolbar (see [CBOM & Exports](#cbom--exports)).

### Global Search Lands in a Lens

When you use Global Search (⌘K) and select an asset or certificate, Vista Platform opens the matching **Inventory lens** with your search pre-filled — so search and inventory share one surface.

For the full design and the complete list of available lenses, see [Inventory & Lenses](../features/inventory-and-lenses.md).

---

## Discovery

### Discovery Jobs

Create discovery jobs to automatically discover assets:

1. Navigate to **Discovery** → **Create Job**
2. Configure discovery:
   - **Name**: Job name
   - **Type**: Discovery type (network scan, cloud API, device interrogation)
   - **Targets**: IP ranges, cloud accounts, devices
   - **Schedule**: One-time or recurring
3. Click **Create Job**
4. Job runs and discovers assets

### Discovery Results

1. Navigate to **Discovery** → **Results**
2. View discovered assets:
   - Asset details
   - Cryptographic configurations
   - Risk assessment
   - Compliance findings
3. Review and approve assets

### Asset Approval

Approve or deny discovered assets:

1. Navigate to **Discovery** → **Pending Approval**
2. Review asset details
3. Choose action:
   - **Approve**: Add to inventory
   - **Deny**: Reject and suppress from rediscovery
   - **Edit**: Modify before approval
4. Bulk actions available for multiple assets

### Import Conflicts

When importing assets, conflicts may occur:

1. Review conflict dialog
2. Compare existing vs. incoming data
3. Choose resolution policy:
   - **Overwrite**: Replace existing data
   - **Fill Blanks**: Only update empty fields
   - **Merge**: Combine data intelligently
   - **Skip**: Keep existing data
4. Apply to all conflicts (optional)
5. Click **Resolve**

---

## Sensor Management

### Overview

The Sensor Management page provides a centralized interface for managing network sensors that monitor your infrastructure for cryptographic configurations, certificates, and TLS connections.

### System Sensors

Your sensor list includes two **System Sensors** that are automatically provided by the platform:

1. **Platform Discovery Sensor** - A platform-managed sensor that performs network discovery operations
2. **Platform Device Interrogation Agent** - A platform-managed agent that handles device interrogation, data collection, and cloud discovery operations. This sensor is also used for cloud discovery results from AWS, Azure, and GCP integrations.

#### Identifying System Sensors

System sensors are visually distinguished in the UI:
- **Blue background row** - System sensors are highlighted with a blue/indigo background
- **"System" type label** - Instead of showing "network" or "endpoint", system sensors display a "System" badge
- **No delete button** - System sensors cannot be deleted by tenants as they are shared platform resources

#### System Sensor Features

System sensors provide the same functionality as tenant-deployed sensors:
- **Live Status** - Real-time online/offline status based on platform service health
- **Heartbeat Updates** - Regular heartbeat updates showing when the sensor was last seen
- **Tenant-Specific Discovery Counts** - The number of discoveries shown is specific to your tenant's data
- **Sensor Details** - Click on a system sensor to view its details, activity, and health information

#### System Sensor Details View

When viewing a system sensor's details:
- A **blue banner** indicates "This is a platform-managed system sensor"
- Certificate details are hidden (system sensors use platform-level authentication)
- Activity and health information reflect the sensor's operations for your tenant

> **Note**: System sensors are shared platform resources. While they appear in your sensor list and you can view their details and tenant-specific activity, they are managed by the platform and cannot be modified or deleted.

### Navigation

The sensor management page features a simplified navigation structure:

- **Status Filters**: Filter sensors by status (Active, Inactive, Error, Pending)
- **Location Filters**: Filter by sensor location
- **Network Filters**: Filter by network segment
- **Teams Filters**: Filter by team assignment
- **Quick Stats**: View overall sensor health, status breakdown, and activity metrics

All navigation sections are collapsible and can be expanded or collapsed as needed.

### Pending Registrations

When you create a new sensor registration, it appears in the **Pending Registrations** section at the top of the page:

- **Visual Distinction**: Pending registrations are highlighted with a yellow/amber background
- **Expiration Countdown**: See how much time remains before the registration key expires
- **Quick Actions**:
  - **View Guide**: Opens the installation guide with registration-specific details
  - **Delete**: Remove the pending registration if no longer needed

The section automatically hides when no pending registrations exist.

### Installation Guide

Access installation instructions from multiple entry points:

1. **Installation Guide Button**: Located in the page header, next to "Register new"
   - Opens a generic installation guide
   - Select your platform (Linux, Windows, macOS)
   - View platform-specific prerequisites
   - Copy installation commands
   - Download sensor binaries

2. **Pending Registration Cards**: Click "View Guide" on any pending registration
   - Opens installation guide with pre-filled registration details
   - Registration key and IP address are included in commands
   - Ready-to-use installation commands

3. **Registration Details Modal**: After generating a registration key
   - Complete installation instructions
   - Registration-specific commands
   - Binary downloads for all platforms
   - mTLS certificate information

### Viewing Sensors

The main sensor table displays:

- **Sensor Name**: Click to view detailed information
- **Type**: Sensor type (network, device agent, etc.)
- **Status**: Current operational status with color-coded badges
- **Last Reading**: Timestamp of last data received
- **Sensor Version**: Installed sensor version
- **IP Address**: Sensor network address

### Filtering Sensors

Use the filter bar at the top of the page to:

- **Status**: Filter by Active, Inactive, Error, or Pending
- **Location**: Filter by sensor location
- **Network**: Filter by network segment
- **Search**: Search by name, IP address, MAC address, or tags

### Sensor Details

Click on any sensor to view detailed information:

- **Overview**: Basic sensor information and status
- **Configuration**: Network interfaces, profile, and settings
- **Activity**: Recent discoveries and network activity
- **Health**: Sensor health metrics and diagnostics

### Registering New Sensors

1. Click **"Register new"** button in the page header
2. Fill in the registration form:
   - **Name**: Human-readable sensor name (required)
   - **IP Address**: Expected IP address for validation (required)
   - **Description**: Optional description
3. Click **"Generate Registration Key"**
4. Use the installation guide to deploy the sensor

The registration key expires after 60 minutes. If expired, generate a new registration key.

### Best Practices

- Monitor pending registrations regularly and complete installation before expiration
- Use descriptive sensor names that indicate location or purpose
- Review sensor health metrics in the Quick Stats section
- Keep sensor versions up to date
- Use tags to organize sensors by environment, team, or function

---

## Compliance

### Framework Selection

The platform uses compliance frameworks to evaluate your cryptographic inventory. You can switch between available frameworks to see how your inventory performs against different standards.

#### Understanding Default vs Selected Framework

- **Tenant Default Framework**: Set by your tenant administrator, used by default for all calculations
- **Your Framework Preference**: You can override the default with your own framework selection
- **Active Framework**: The framework currently being used (your preference or tenant default)

#### Switching Frameworks

1. Look for the **Framework Selector** in the header (top right, next to notifications)
2. Click the dropdown to see all licensed frameworks
3. Select a framework to use it for all calculations:
   - Dashboard compliance scores
   - Risk & Compliance evaluations (Posture and Findings)
   - Inventory metrics
4. Your selection persists across pages and sessions
5. Select "Use Default" to return to the tenant default framework

#### Framework Impact

When you switch frameworks:
- **Dashboard**: Compliance scores recalculate using the new framework
- **Risk & Compliance**: Posture and Findings re-evaluate against the new framework
- **Inventory**: Compliance violation counts update
- **All Calculations**: Every compliance metric uses your selected framework

**Note**: Framework selection only affects your view. Other users see their own framework preferences or the tenant default.

### Compliance Frameworks

View compliance frameworks:

1. Navigate to **Compliance** → **Frameworks**
2. View available frameworks:
   - **Published Frameworks**: Platform-provided frameworks
   - **Custom Frameworks**: Tenant-specific frameworks
3. Select framework to view details

### Compliance Status

1. Navigate to **Compliance** → **Status**
2. View compliance scores:
   - Overall compliance score (uses your active framework)
   - Framework-specific scores
   - Control compliance status
   - Finding details

### Compliance Findings

1. Navigate to **Compliance** → **Findings**
2. View compliance findings:
   - Finding type
   - Severity
   - Affected assets
   - Remediation recommendations
3. Filter by framework, control, or severity

### Compliance Workspace

The Compliance Workspace provides an auditor-focused view of your compliance posture, allowing you to evaluate frameworks, assign findings to team members, create remediation tickets, and generate actionable intelligence.

#### Overview

1. Navigate to **Compliance** → **Workspace**
2. Select a framework from the dropdown
3. View compliance summary:
   - Overall compliance score
   - Key performance indicators (KPIs)
   - Control families with pass/warn/fail counts
   - Individual control status

#### Framework and Assessment Management

**Selecting a Framework:**
- Choose from available frameworks in the header dropdown
- Framework selection determines which controls are evaluated
- Your selection persists for the session

**Saving Assessments:**
- Name your assessment (e.g., "Q1 2025 Audit")
- Click "Save" to store your current framework, filters, and overrides
- Load saved assessments to quickly return to a specific compliance view
- Assessments can be shared with team members

#### Filtering and Views

**Active Filters:**
- **Environment**: Filter by production, staging, development, or test
- **Severity**: Filter by Critical, High, Med, or Low
- **Family**: Click family cards to filter controls by family
- **Owner**: Filter by assigned owner (when findings are assigned)
- **Tags**: Filter by asset tags

**Note:** Filters are optional. By default, all controls are displayed regardless of findings status. This allows you to see the complete compliance posture, including controls that are passing with no findings.

**Family Cards:**
- Click any family card to filter controls to that family
- View pass/warn/fail counts for each family
- See compliance trend sparklines (7-day trend) showing compliance health over time
- Selected families are highlighted in blue
- Use the family filter dropdown in the controls table header for quick filtering

#### Control Details

**Viewing Control Details:**
1. Click any control in the controls table
2. View detailed sidebar with:
   - Control rationale and description
   - Evidence summary (failing findings, affected assets, last seen)
   - List of findings with full details
   - Override status and history

**Findings Table:**
- **Checkbox Selection**: Select individual findings or use "Select All" for bulk operations
- **Sortable Columns**: Click column headers to sort by:
  - Severity (Critical, High, Med, Low)
  - Asset name
  - First seen date
  - Last seen date
- **Detection State**: Shows the system-detected state of the finding:
  - **ACTIVE**: Violation is currently detected (red badge)
  - **INACTIVE**: No violation detected, but finding retained for audit (gray badge)
  - **ARCHIVED**: Finding has been archived after extended inactivity (gray badge)
- **Workflow Status**: Shows the human workflow state (filterable via dropdown):
  - **NEW**: Finding detected but not yet processed (blue badge)
  - **NOTIFIED**: Stakeholders have been notified (yellow badge)
  - **RESOLVED**: Finding has been resolved (green badge)
  - **SUPPRESSED**: Finding is temporarily suppressed (gray badge)
- **Resurfaced Indicator**: Shows 🔄 icon if finding was previously resolved but violation reappeared
- **Occurrence Count**: Shows how many times this finding has been detected
- **Assignment Display**: View assigned owner badges with assignment details
- **Ticket Count**: See ticket count badges (clickable to view tickets)
- **Quick Actions**: Access actions for each finding:
  - Copy Evidence ID (clipboard icon)
  - Assign Owner (user icon)
  - Create Ticket (ticket icon)
  - Update Workflow Status (checkmark icon)
  - View History (clock icon)
- **Bulk Actions Toolbar**: When findings are selected, use:
  - Bulk Assign: Assign multiple findings at once
  - Create Tickets: Create tickets for selected findings

#### Assigning Findings

**Assign Owner to Finding:**
1. In the control details sidebar, find the finding
2. Click the "Assign Owner" button (user icon)
3. Select a user from the dropdown
4. Optionally add remediation notes
5. Click "Assign"

**Bulk Assignment:**
1. Select multiple findings using checkboxes
2. Click "Bulk Assign" in the toolbar
3. Assign all selected findings to a user

**Viewing Assignments:**
- Assigned findings show a blue badge with the owner's email
- Unassigned findings show "Unassigned" in gray
- Assignment information includes:
  - Assigned owner (email)
  - Assignment date and time
  - Who assigned the finding (assigned_by)
  - Remediation notes (if provided)

#### Creating Tickets

**Create Ticket from Finding:**
1. In the control details sidebar, find the finding
2. Click the "Create Ticket" button (ticket icon)
3. Enter ticket details:
   - Title (required)
   - Description
   - Priority (low, medium, high, critical)
   - Assign to user (optional)
4. Click "Create Ticket"

**Managing Tickets:**
- View ticket count badge on findings (clickable to view details)
- Tickets are linked to findings and controls
- **Ticket Status**: open, in_progress, resolved, closed
- **Ticket Priority**: low, medium, high, critical
- **Update Tickets**: Edit status, priority, assigned user, and resolution notes
- **Resolution Notes**: Add notes when resolving or closing tickets
- Filter tickets by status, priority, or assigned user
- Tickets can be created from findings or controls directly

#### Managing Workflow Status

**Update Workflow Status:**
1. In the findings table, click the "Update Workflow Status" button (checkmark icon)
2. Select the new workflow status:
   - **NEW**: Mark as new (default for new findings)
   - **NOTIFIED**: Mark as notified (after stakeholders are informed)
   - **RESOLVED**: Mark as resolved (when remediation is complete)
   - **SUPPRESSED**: Temporarily suppress the finding
3. If suppressing, provide:
   - Suppression reason (required)
   - Suppression expiration date (optional - finding will auto-activate after this date)
4. Click "Update Status"

**Understanding Detection State vs Workflow Status:**
- **Detection State** (system-controlled): Automatically managed based on evaluation results
  - Changes from ACTIVE → INACTIVE when violation is fixed
  - Changes from INACTIVE → ACTIVE when violation reappears (resurfaced)
  - Auto-archived after extended inactivity
- **Workflow Status** (user-controlled): Managed by your team for remediation tracking
  - Use to track your remediation process
  - Can be updated independently of detection state
  - Suppressed findings are excluded from active reports but still tracked

**Resurfaced Findings:**
- Findings that go from INACTIVE → ACTIVE are marked as "resurfaced"
- The 🔄 icon indicates a finding that was previously resolved but the violation has reappeared
- Workflow status automatically resets to NEW when a finding resurfaces
- Review resurfaced findings to understand why violations are recurring

**View Finding History:**
1. In the findings table, click the "View History" button (clock icon)
2. View complete audit trail of all changes:
   - Field changes (detection_state, workflow_status, severity, etc.)
   - Who made the change
   - When the change occurred
   - Reason for the change
   - Old and new values

#### Managing Workflow Status

**Update Workflow Status:**
1. In the findings table, click the "Update Workflow Status" button (checkmark icon)
2. Select the new workflow status:
   - **NEW**: Mark as new (default for new findings)
   - **NOTIFIED**: Mark as notified (after stakeholders are informed)
   - **RESOLVED**: Mark as resolved (when remediation is complete)
   - **SUPPRESSED**: Temporarily suppress the finding
3. If suppressing, provide:
   - Suppression reason (required)
   - Suppression expiration date (optional - finding will auto-activate after this date)
4. Click "Update Status"

**Understanding Detection State vs Workflow Status:**
- **Detection State** (system-controlled): Automatically managed based on evaluation results
  - Changes from ACTIVE → INACTIVE when violation is fixed
  - Changes from INACTIVE → ACTIVE when violation reappears (resurfaced)
  - Auto-archived after extended inactivity
- **Workflow Status** (user-controlled): Managed by your team for remediation tracking
  - Use to track your remediation process
  - Can be updated independently of detection state
  - Suppressed findings are excluded from active reports but still tracked

**Resurfaced Findings:**
- Findings that go from INACTIVE → ACTIVE are marked as "resurfaced"
- The 🔄 icon indicates a finding that was previously resolved but the violation has reappeared
- Workflow status automatically resets to NEW when a finding resurfaces
- Review resurfaced findings to understand why violations are recurring

**View Finding History:**
1. In the findings table, click the "View History" button (clock icon)
2. View complete audit trail of all changes:
   - Field changes (detection_state, workflow_status, severity, etc.)
   - Who made the change
   - When the change occurred
   - Reason for the change
   - Old and new values

#### Evidence Management

**Copy Evidence ID:**
1. In the findings table, click the "Copy Evidence ID" button (clipboard icon)
2. Evidence reference (e.g., "CF-12345678") is copied to clipboard
3. Use this ID for external tracking systems or documentation

**View Asset Details:**
1. Click the asset name link in any finding
2. Navigate to the asset detail page
3. View full asset information, certificates, and compliance status
4. View compliance findings for this asset in the asset details modal
4. View compliance findings for this asset in the asset details modal

#### Applying Overrides

**Disregard Control:**
1. In control details, click "Disregard Control"
2. Provide rationale for disregarding
3. Control is excluded from compliance calculations

**Change Severity:**
1. In control details, click "Change Severity"
2. Select new severity level
3. Provide rationale for the change
4. Severity override applies to this assessment

**Override Scope:**
- **Global Overrides**: Apply to all assessments (default)
- **Assessment-Specific**: Apply only to the current saved assessment

#### Exporting Reports

**Quick Export:**
- Click "Export PDF", "Export JSON", or "Export CSV" in the header
- The export downloads the current view

> The standalone Reports surface has been retired. For convenience exports of what's on screen, use the page-local **Export** button (e.g. on the Inventory lenses). For audit-grade output with provenance and a content hash, generate a **CBOM Artifact** — see [CBOM & Exports](#cbom--exports).

**Custom Report Builder:**
1. Click "Build Custom Report"
2. Configure report parameters
3. Select data sources and filters
4. Generate comprehensive compliance report

**Controls Table:**
- **Checkbox Selection**: Select controls for bulk operations
- **Sortable Columns**: Sort by Control ID, Name, Status, Findings count, or Last seen
- **Family Filter**: Use dropdown in table header to filter by family
- **Quick Actions**: Access actions directly from table rows:
  - Disregard Control
  - Change Severity
  - Assign Finding (for controls with findings)
  - Create Ticket
- **Override Indicators**: Yellow highlight shows controls with active overrides

#### Best Practices

1. **Save Assessments Regularly**: Save your work as you apply filters and overrides
2. **Assign Findings Promptly**: Assign findings to team members for faster remediation
3. **Create Tickets for Tracking**: Use tickets to track remediation work in external systems
4. **Use Family Filters**: Click family cards or use dropdown to focus on specific control areas
5. **Review Overrides**: Regularly review overrides to ensure they're still valid
6. **Export for Audits**: Export compliance data for external audits and documentation
7. **Use Bulk Actions**: Select multiple findings to assign or create tickets efficiently
8. **Monitor Trends**: Check family trend sparklines to identify compliance health trends

#### Tips

- Use the "Encryption-only" filter to focus on crypto-relevant controls
- Family cards show trend sparklines for quick compliance health checks
- Findings table is sortable - click column headers to sort
- Bulk actions allow you to assign or create tickets for multiple findings at once
- Evidence IDs can be copied for external tracking systems
- Asset links provide quick navigation to asset details

---

## CBOM & Exports

Vista Platform's reporting surface has two parts: **CBOM Artifacts** for audit-grade cryptographic snapshots, and **page-local CSV exports** for convenience exports of whatever you're looking at on screen.

### CBOM Artifacts

A **CBOM Artifact** is an immutable, content-hashed, dated snapshot of every cryptographic component matching a [Scope](../features/scopes.md) at the moment of generation. It's what you submit to an auditor, attach to a vendor questionnaire, or use as before/after evidence in a PQC migration program.

#### Generating a CBOM

1. Navigate to **Risk & Compliance → CBOM** (or go directly to `/risk-compliance/cbom`).
2. Click **Generate CBOM**.
3. Select a **Scope** — the named boundary that defines which assets the CBOM will include. Use *All* for a complete snapshot or *Production* for a scoped one. See [Scopes](../features/scopes.md).
4. Optionally give it a meaningful name (e.g., "Q2 2026 PCI Submission").
5. Click **Generate**. The artifact appears in the list immediately.

#### Downloading a CBOM

Click the **Download** dropdown on any artifact row:
- **CycloneDX 1.7 (.json)** — canonical format, industry standard for CBOMs, matches the content hash (artifacts generated before v0.2.0 declare 1.6 and keep their original bytes)


### Page-Local CSV Exports

On the **Inventory** page, every lens view has an **Export** button in the toolbar. This exports the currently visible rows as a CSV — no backend round-trip, no wait time. Each lens exports a layout tailored to its data.

> Page-local exports are for convenience. For audit-grade output with provenance and a content hash, generate a CBOM Artifact instead.

---

## Notifications & Alerts

The platform provides a unified notification system that allows you to configure how you receive alerts and notifications across multiple channels.

Every account gets a working setup with zero configuration: new organizations
are seeded with an **in-app channel**, an **email channel** that reaches your
admins, and default routing so critical and high-severity alerts reach you
immediately. The pieces below let you extend or customize that setup.

### The Notification Bell

The bell icon in the header shows your unread count and, when clicked, your
ten most recent notifications with mark-as-read and **mark all read**. From
there, **View alerts** takes you to [Remediation → Alerts](../features/remediation.md#alerts)
(the work surface — where you act on conditions demanding attention) and
**View delivery history** takes you to the settings page described below
(where you can see every notification that was ever sent — the record of
what was communicated).

### Notification Channels

Notification channels define where alerts are sent. You can configure multiple channels of different types:

#### Channel Types

- **Slack**: Send notifications to a Slack channel via webhook
- **Email**: Send email notifications to specified recipients
- **Webhook**: Send notifications to a custom webhook endpoint
- **PagerDuty**: Send alerts to PagerDuty for incident management
- **In-App**: Display notifications in the platform's notification center

#### Managing Channels

1. Navigate to **Organization Settings** → **Notifications & Alerts** → **Channels**
2. Click **Add Channel** to create a new channel
3. Select the channel type and configure:
   - **Slack**: Provide webhook URL and optional channel name
   - **Email**: List recipient email addresses
   - **Webhook**: Provide URL and optional authentication
   - **PagerDuty**: Provide integration key
4. Test the channel to verify connectivity
5. Enable or disable channels as needed

#### Testing Channels

After creating a channel, use the **Test** button to send a test notification. This verifies that the channel is configured correctly and can receive notifications.

### Notification Rules

Notification rules determine which alerts are sent to which channels based on:
- **Alert Source**: Where the alert originates (monitoring, discovery, compliance, audit, inventory)
- **Alert Type**: Specific alert type or all types from a source
- **Severity**: Filter by severity level (critical, high, medium, low)
- **Category**: Filter by category (security, sensors, billing, system, reports, users)

#### Creating Rules

1. Navigate to **Organization Settings** → **Notifications & Alerts** → **Routing Rules**
2. Click **Add Rule**
3. Configure the rule:
   - **Rule Name**: Descriptive name for the rule
   - **Alert Source**: Select the source (monitoring, discovery, etc.)
   - **Alert Type**: Optional - leave empty for all types
   - **Channels**: Select one or more channels to route to
   - **Severity Filter**: Optional - select specific severities
   - **Frequency**: Choose immediate delivery or digest mode
   - **Priority**: Higher priority rules are evaluated first
4. Enable the rule

#### Rule Priority

Rules are evaluated in priority order. Higher priority rules are checked first. If multiple rules match an alert, channels from all matching rules are used.

### The Alert Catalog

Above the audit alert rules, **Organization Settings → Notifications &
Alerts → Alert Rules** also shows the **alert catalog** — the platform's
built-in library of conditions it can raise a stateful alert for (certificate
expiry, failing compliance controls, and more; some entries are marked
"coming soon" — registered but not yet wired to a detector). For each type
you can enable or disable it, and for time-based types like certificate
expiry you can see and adjust the **warning ladder**: the schedule of
thresholds (e.g., 60 days, 30 days) at which the alert opens or escalates.

Any compliance framework your organization has activated can add its own
rung to that ladder automatically — for example, activating a framework that
requires 30-day certificate warnings adds a 30-day rung you cannot remove
from this screen (only by deactivating the framework). Your own preference
can replace the platform's default rung, but framework-required rungs always
stay — so tightening your notification schedule to match a compliance
commitment happens automatically, and you can't accidentally silence a
requirement you've committed to. See
[Remediation → Alerts](../features/remediation.md#alerts) for what these
alerts look like once raised.

### Delivery History

View a history of every notification the platform has sent — or attempted
to send — on your organization's behalf:

1. Navigate to **Organization Settings** → **Notifications & Alerts** →
   **Delivery History**
2. View details including:
   - Timestamp
   - Alert source and type
   - Severity
   - Message
   - Channels used
   - Delivery status

Rows where no channel matched (nothing was actually delivered) are called
out — a quick way to spot a routing rule that needs adjusting.

### User Preferences

Configure your personal notification preferences:

1. Open your profile menu (top right) → **My Profile** → **Notifications**
2. Configure:
   - **Categories**: Enable/disable notification categories
   - **Delivery**: Choose in-app and/or email delivery
   - **Frequency**: Immediate or digest mode

These preferences currently record what you'd like to receive; the alerts
that actually reach you are still governed by your organization's routing
rules above.

## Settings

### Notification Preferences

Configure notification preferences:

1. Navigate to **Settings** → **Notifications**
2. Configure notification categories:
   - **Security Alerts**: Security-related notifications
   - **Compliance Updates**: Compliance status changes
   - **System Notifications**: System messages
   - **Stale Assets**: Notifications when assets become stale
3. Configure delivery methods:
   - **In-App**: In-app notifications
   - **Email**: Email notifications
4. Set notification frequency:
   - **Immediate**: Real-time notifications
   - **Daily**: Daily digest
   - **Weekly**: Weekly summary
5. Click **Save**

### Locations and Network Segments

Locations and network segments define where your infrastructure lives and how discovered assets are classified. You need at least one **location** and one **network segment** before running discovery.

#### Locations

Locations are hierarchical (e.g. region → datacenter → rack) and can represent physical sites or cloud regions.

1. Navigate to **Organization Settings** → **Infrastructure** → **Locations**
2. Click **Add location**
3. Enter **Name** and **Type** (e.g. datacenter, cloud_region, office)
4. Optionally set **Parent** (for hierarchy), **Description**, physical address, cloud provider/region, or geo/timezone
5. Click **Save**

Locations are required before you can create network segments.

#### Network Segments

Segments define CIDR blocks, IP ranges, or domain patterns and assign them an **environment** (production, staging, development, test) and a **location**. Matching assets get that environment and location when you reclassify.

1. Navigate to **Organization Settings** → **Infrastructure** → **Network Segments**
2. Ensure at least one location exists (create one under Locations if needed)
3. Click **Add segment**
4. Enter **Name**, **Type** (cidr, ip_range, domain, or cloud_vpc), and **Value** (e.g. `10.0.0.0/8` for CIDR)
5. Select **Environment** and **Location**
6. Optionally set **Description**, **Business unit**, **Owner email**, and **Tags** (key:value per line; tags are applied to matching assets when you reclassify)
7. Enable **Auto-approve discoveries** if sensor discoveries in this range should be auto-approved
8. Click **Save**

**Reclassify all assets:** Use **Reclassify all assets** on the Network Segments page to match existing assets to segments and update their location, environment, and tags.

#### Sensor Configuration

The **Sensor Configuration** page (under **Organization Settings** → **Infrastructure**) controls fleet-wide sensor behavior beyond individual sensor records.

1. Navigate to **Organization Settings** → **Infrastructure** → **Sensor Configuration**
2. **Active scanning policy** — Turn active probing (TLS handshakes, SSH key exchange, related scans) on or off for the tenant, and optionally restrict which **network segments** allow active scanning. Unchecked segments remain passive-only.
3. **Observation rest period** — Choose how long deployable sensors wait before sending another report for the **same** observation (same server IP, port, and protocol, for example repeated TLS to the same `443` endpoint). The default is **1 hour**. Shorter periods mean fresher data and more traffic to the platform; longer periods reduce duplicate noise.
4. Click **Apply to All Sensors** to save the rest period. Active sensors receive an `update_config` command and apply the new TTL on their **next heartbeat** (no binary restart required).
5. Use the **Select Platform** controls to view or override which **sensor binary** artifact is offered for download per OS and architecture.

> **Note:** Bulk updates are queued for every sensor in **active** or **healthy** status for your tenant, including platform-managed **system** sensors that participate in the same heartbeat/command channel. Deployable agents pick up changes on the next checkin after you apply the rest period.

### User Preferences

1. Navigate to **Settings** → **Preferences**
2. Configure:
   - **Language**: Interface language
   - **Timezone**: Timezone for timestamps
   - **Date Format**: Date display format
   - **Theme**: Light or dark theme
3. Click **Save**

### Billing & Subscription

Manage your subscription, view invoices, track usage, and apply discount coupons.

#### View Subscription Details

1. Navigate to **Settings** → **Billing**
2. View current subscription information:
   - **Plan**: Current subscription tier (Trial, Professional, Enterprise)
   - **Status**: Active, Trial, Suspended, Cancelled
   - **Billing Cycle**: Monthly billing date
   - **Next Charge**: Amount and date of next payment

#### Payment Method

Update your payment method:

1. Navigate to **Settings** → **Billing** → **Payment Method**
2. Click **Update Payment Method**
3. Enter new card details (processed securely via Stripe)
4. Click **Save**

**Note:** Card details are never stored on Vista Platform servers. All payment processing is PCI-DSS compliant.

#### Invoices

Access and download your invoices:

1. Navigate to **Settings** → **Billing** → **Invoices**
2. View all invoices with details:
   - Invoice number
   - Billing period
   - Amount charged
   - Payment status
   - Due date
3. Click **Download PDF** to download any invoice
4. Click **Email Invoice** to send to your billing contact

Invoices include:
- Subscription fees
- Applied discounts
- Detailed line items

#### Usage Tracking

Monitor your resource usage against plan limits:

1. Navigate to **Settings** → **Billing** → **Usage**
2. View current month's usage:
   - **API Requests**: Current vs. plan limit
   - **Storage**: Data stored vs. plan limit
   - **Infrastructure Assets**: Active assets
3. Review usage charts showing historical trends
4. See projected end-of-month usage

**Usage Alerts:** You'll receive email notifications when usage reaches 80%, 90%, and 100% of your plan limits.

#### Usage Limits (No Overage Charges)

Your subscription is a flat per-plan price — there are no usage-based
overage charges. If you reach a hard limit (assets, sensors, users), the
platform prevents adding more rather than billing you for the excess.

**Tip:** If you consistently approach your plan limits, upgrade your plan
or contact sales about a custom limit (Enterprise plans are tuned per
contract).

#### Discount Coupons

Apply promotional or discount codes to your subscription:

1. Navigate to **Settings** → **Billing** → **Coupons**
2. Click **Apply Coupon**
3. Enter coupon code (e.g., WELCOME20)
4. Click **Apply**

View active coupons:
- Discount amount or percentage
- Duration (one-time, repeating, or forever)
- Expiration date
- Remaining discount period

**Note:** Only one coupon can be active per subscription. Coupons apply to subscription fees only, not taxes.

#### Plan Changes

**Upgrade Your Plan:**

1. Navigate to **Settings** → **Billing** → **Plan**
2. Click **Upgrade Plan**
3. Select desired tier (Professional or Enterprise)
4. Review prorated charges
5. Click **Confirm Upgrade**

When upgrading mid-cycle, you're credited for unused time on your current plan and charged a prorated amount for the new plan.

**Moving to a Lower Plan:**

Paid subscriptions are 12-month agreements, so moving to a lower-priced tier
isn't self-service — contact support and your account team can apply it for
you. The change takes effect at your next invoice (annual prepayments aren't
automatically refunded). Make sure your usage fits within the new plan's
limits before requesting a downgrade.

#### Trial Period

If you're on a free trial:
- View trial end date
- See days remaining
- Upgrade to paid plan anytime

You'll receive email notifications:
- 7 days before trial ends
- 1 day before trial ends
- When trial expires

After trial expiration, your account is downgraded to the free tier or suspended until you upgrade.

#### Cancel Subscription

To cancel your subscription:

1. Navigate to **Settings** → **Billing** → **Plan**
2. Click **Cancel Subscription**
3. Select reason for cancellation (optional)
4. Click **Confirm Cancellation**

**Important:**
- Your subscription is a 12-month agreement. On monthly billing, billing and
  service continue through the end of the agreement year (the confirmation
  shows the exact end date); on annual prepay, the plan ends at the close of
  the paid year and does not renew
- You retain full access until the end date
- No partial refunds for unused time
- Data is retained for 30 days after the subscription ends
- Easy to reactivate any time before the end date

**Before cancelling:** Export your data from **Settings** → **Data Management** → **Export All Data**.

#### Billing Contact

Update billing contact information:

1. Navigate to **Settings** → **Billing** → **Contact Information**
2. Update:
   - Billing email address
   - Company name
   - Billing address
   - Tax ID (if applicable)
3. Click **Save**

This information appears on all invoices.

#### Billing Support

For billing questions or issues:
- Email: your platform operator's billing contact
- In-app: Click **Help** → **Contact Billing Support**


---

## Profile Management

### View Profile

1. Navigate to **Profile**
2. View profile information:
   - Name and email
   - Role and permissions
   - Tenant information
   - Account status

### Update Profile

1. Open **My Profile → Personal** (from the user profile dropdown, top-right)
2. Edit any of:
   - First name
   - Last name
   - Timezone (e.g. `America/New_York`)
3. Click **Save changes**

To update your photo, click **Upload photo** in the Photo row and choose an image (JPEG, PNG, GIF, or WebP, up to 5 MB). The new photo appears immediately and is saved automatically.

> Email and Role are shown here but are not self-editable — email changes require confirming a link sent to the new address, and your role is assigned by your organization's admins under **Settings → Members**.

### Change Password

1. Open **My Profile → Security**
2. Enter:
   - Current password
   - New password (minimum 8 characters)
   - Confirm new password
3. Click **Change password**

After a successful change you may be signed out of the current session and need to sign in again with the new password.

### Multi-Factor Authentication (MFA)

Enable MFA for additional security:

1. Navigate to **Profile** → **Security**
2. Click **Enable 2FA**
3. Follow setup instructions
4. Scan QR code with authenticator app
5. Enter verification code
6. MFA is enabled

**Note:** MFA setup is coming soon. The UI is prepared for future implementation.

### SSO Account Linking

> **Availability:** Viewing and unlinking already-connected SSO providers (under **My Profile → Connected Accounts**) is available today. *Linking a new* provider from this page is being finalized; until it ships, the page shows a notice in place of the link button. The steps below describe the linking flow once enabled.

Link your account to SSO providers for seamless authentication:

1. Navigate to **Profile** → **Security**
2. Locate the **SSO Accounts** section
3. Click **Link SSO Account**
4. Select an available SSO provider from the list
5. You'll be redirected to the identity provider
6. Complete authentication with your corporate credentials
7. You'll be redirected back to Vista Platform
8. Account is linked successfully

Once linked, you can sign in using either your password or your SSO provider (depending on your tenant's authentication policy).

#### Managing Linked Accounts

- **View Linked Accounts**: See all SSO providers linked to your account in the Security settings
- **Unlink Account**: Click **Unlink** next to an SSO provider to remove the connection
- **Multiple Providers**: You can link multiple SSO providers to the same account

**Important Restrictions:**
- You must maintain at least one authentication method (you cannot unlink your only SSO account if password auth is disabled)
- If your tenant uses **Enforce SSO** or **SSO Only** authentication policy, you cannot unlink SSO accounts
- Some tenants may limit which SSO providers are available based on organizational policies

#### Troubleshooting SSO Linking

**"No SSO Providers Available":**
- Contact your tenant administrator to configure SSO providers
- Verify your tenant's authentication policy allows SSO

**"Email Address Already in Use":**
- The email address from your SSO provider is already associated with another account
- Contact your tenant administrator for assistance

**"SSO Authentication Failed":**
- Verify you're using the correct corporate credentials
- Check with your IT department that your account has access to the application
- Try clearing your browser cookies and trying again

---

## Activity Logs & Audit Trail

### Overview

The Activity Logs feature provides complete visibility into all actions performed within your tenant. Every system event is logged with detailed information for security auditing, compliance reporting, and troubleshooting.

### Viewing Activity Logs

Access the Activity Logs page from **Operations → Activity Logs** to view all system activity.

### Filtering Options

Use filters to narrow down logs:

- **Date Range**: Last hour, 24 hours, 7 days, 30 days, or custom range
- **Event Type**: Filter by specific event types (asset.created, user.login, etc.)
- **Event Category**: Filter by category (security, asset, compliance, etc.)
- **Status**: Filter by success or failure
- **Search**: Search across all log fields including user email, resource ID, and action

### Analytics Tab

The Analytics tab provides visual insights:

- **Events by Category**: Pie chart showing distribution of events
- **Top Event Types**: Bar chart of most frequent events
- **Success vs Failure Ratio**: Overall system health indicator
- **Activity Timeline**: Event volume over time

### Advanced Queries

Click **Advanced Query** to build complex filters:

1. Click the **Advanced Query** button
2. Add multiple filter conditions
3. Combine conditions with AND/OR logic
4. Filter by:
   - Event types (multi-select)
   - Compliance tags (soc2, iso27001, gdpr, hipaa, pci_dss)
   - User IDs
   - Resource types
   - Date ranges
5. Save frequently used queries for quick access
6. Export query results

### Exporting Logs

Export logs for external analysis or compliance reporting:

1. Apply your desired filters
2. Click **Export** button
3. Choose format (CSV or JSON)
4. Download begins automatically

**CSV Format**: Best for spreadsheet analysis
**JSON Format**: Best for programmatic processing

### Resource Audit Trail

View complete history for any resource:

1. Navigate to the resource (asset, certificate, user, etc.)
2. Click the **View Audit Trail** button
3. View all changes including:
   - Who made the change
   - When it was made
   - What fields changed
   - Old and new values
4. Filter by date range to narrow results
5. Export audit trail for documentation

### User Activity Timeline

View complete activity for a specific user:

1. Access from user management pages
2. Filter by date range
3. View detailed timeline with:
   - All user actions
   - Success/failure indicators
   - Activity patterns
   - Risk indicators
4. Expand any event for full details
5. Export user activity for security reviews

---

## Notifications

### Notification Channels

Configure channels to receive platform notifications.

#### Accessing Channels

Navigate to **Organization Settings → Notifications & Alerts → Channels** to manage delivery channels.

#### Supported Channel Types

**Email**
- Send notifications to email addresses
- Configure multiple recipients
- Set email templates

**Slack**
- Post notifications to Slack channels
- Configure webhook URL
- Customize message format

**Webhook**
- Send notifications to custom HTTP endpoints
- Configure headers and authentication
- Support for JSON payloads

**PagerDuty**
- Create incidents in PagerDuty
- Configure integration key
- Set severity mapping

**SMS** (Coming Soon)
- Send text message notifications
- Configure phone numbers

**In-App**
- Receive notifications in the platform
- Real-time notifications
- Notification history

#### Creating a Channel

1. Navigate to **Organization Settings → Notifications & Alerts → Channels**
2. Click **Add Channel**
3. Select channel type
4. Enter configuration details:
   - Channel name
   - Type-specific settings (URL, API key, etc.)
5. Click **Test Connection** to verify setup
6. Click **Create**

#### Testing Channels

Always test channels after creation:

1. Click the **Test** button on the channel card
2. System sends a test notification
3. Verify you receive the notification
4. Check notification formatting

### Notification Rules

Create rules to automatically send notifications when specific events occur.

#### Accessing Rules

Navigate to **Organization Settings → Notifications & Alerts → Routing Rules** to manage notification rules.

#### Creating a Rule

1. Click **Create Rule**
2. Configure rule details:
   - **Rule Name**: Descriptive name
   - **Description**: Optional details
   - **Event Triggers**: Select which events trigger notifications
   - **Channels**: Select delivery channels
   - **Filters**: Add conditions to refine when rule triggers
3. Click **Create**

#### Event Triggers

Select from various event types:
- Asset created, updated, deleted
- Compliance findings created, resolved
- Discovery jobs completed, failed
- User authentication events
- Certificate expiration warnings
- System errors

#### Notification Filters

Refine when notifications are sent:
- Event severity (critical, high, medium, low)
- Specific asset types
- Compliance frameworks
- User roles
- Time of day

### Notification History

View all sent notifications.

#### Accessing History

Navigate to **Operations → Notification History** to view past notifications.

#### History Details

For each notification:
- **Timestamp**: When notification was sent
- **Event**: What triggered the notification
- **Channels**: Where it was sent
- **Status**: Delivery status (sent, failed, pending)
- **Content**: Notification message
- **Metadata**: Additional context

#### Filtering History

Use filters to find specific notifications:
- Date range
- Event type
- Channel used
- Delivery status
- Severity level

---

## Alert Management

### Overview

This section covers **audit alert rules** — pattern- and threshold-based
detection over your activity log (failed-login bursts, bulk exports,
privileged actions). Unlike notification rules that trigger on individual
events, alert rules can detect patterns, thresholds, and anomalies.

> **Looking for the alert inbox with acknowledge/snooze/resolve buttons and
> an evidence timeline?** That's a separate, newer capability:
> **[Remediation → Alerts](../features/remediation.md#alerts)**. It covers
> stateful conditions across the platform — certificate expiry today, with
> more alert types planned — each with a full lifecycle (active →
> acknowledged → snoozed → resolved) and an audit-grade evidence trail. The
> audit alert rules on this page are a different, narrower mechanism scoped
> to activity-log patterns; both surfaces route through the same
> notification channels and rules above.

### Alert Rules

#### Accessing Alert Rules

Navigate to **Organization Settings → Notifications & Alerts → Alert Rules** to manage alert rules.

#### Creating Alert Rules

1. Click **Create Rule**
2. Configure rule settings:
   - **Rule Name**: Descriptive name
   - **Description**: What the rule monitors
   - **Severity**: critical, high, medium, or low
   - **Conditions**: When the alert triggers
   - **Actions**: What happens when triggered
   - **Cooldown**: Minimum time between alerts
3. Click **Create**

#### Rule Conditions

Configure what triggers the alert:

**Threshold-Based**
- Count of events in a time window
- Example: 5 failed login attempts in 5 minutes

**Pattern-Based**
- Specific sequence of events
- Example: User creates asset, then immediately deletes it

**Event Type Filters**
- Monitor specific event types
- Example: All asset deletion events

**Failure Detection**
- Monitor for failed operations
- Example: Any failed API calls

#### Rule Actions

Configure what happens when an alert triggers:

**Email Notifications**
- Send to specific recipients
- Include alert details
- Link to relevant resources

**Webhooks**
- Call external HTTP endpoints
- Send alert payload
- Custom headers and authentication

**SIEM Forwarding**
- Forward to configured SIEM system
- Include full event context

#### Cooldown Period

Set minimum time between alert instances to prevent spam:
- 5 minutes: For frequently occurring events
- 15 minutes: Default for most rules
- 60 minutes: For low-frequency events
- Custom: Set any duration

#### Example Alert Rules

**Multiple Failed Logins**
- Condition: 5 failed login attempts in 5 minutes
- Action: Email security team
- Severity: High

**Asset Deletion**
- Condition: Any asset deleted
- Action: Email administrators
- Severity: Medium

**High-Severity Changes**
- Condition: Any critical resource modified
- Action: Webhook + Email
- Severity: Critical

### Where Triggered Audit Alerts Go

When an audit alert rule fires, it's delivered as a notification through
your organization's channels and routing rules (above) — there is currently
no separate dashboard for browsing and acknowledging *audit* alert
instances. For a full acknowledge / snooze / resolve workflow with an
evidence timeline, use **[Remediation → Alerts](../features/remediation.md#alerts)**,
described in the note above.

---

## SIEM Integration

### Overview

Forward audit events to your Security Information and Event Management (SIEM) system for centralized monitoring and analysis.

### Accessing SIEM Integration

Navigate to **Organization Settings → Integrations → SIEM Integration** to configure integrations.

### Supported SIEM Systems

**Splunk**
- HTTP Event Collector (HEC)
- Real-time event forwarding
- Configurable format

**Datadog**
- Log Management integration
- Automatic tagging
- Metric generation

**Elasticsearch / OpenSearch**
- Direct indexing
- Custom index patterns
- Bulk operations

**Generic Webhook**
- Any HTTP endpoint
- Custom headers
- Flexible authentication

### Configuring SIEM Integration

1. Click **Add Integration**
2. Select your SIEM type
3. Configure connection details:
   
   **Splunk**
   - HEC URL
   - Auth Token
   - Index name (optional)
   
   **Datadog**
   - API Key
   - Site (US/EU)
   
   **Elasticsearch**
   - Cluster URL
   - Index pattern
   - Authentication (basic/API key)
   
   **Generic Webhook**
   - URL
   - Headers
   - Authentication method

4. Configure event filters (optional):
   - Event categories to forward
   - Minimum severity level
   - Compliance tags to include
5. Click **Test Connection** to verify
6. Click **Create**

### Event Filters

Control which events are forwarded:

**Event Categories**
- Security events only
- Compliance-related events
- All events

**Severities**
- Critical only
- High and above
- All severities

**Compliance Tags**
- soc2
- iso27001
- gdpr
- hipaa
- pci_dss

### Monitoring Health

The SIEM Integration page shows health status for each integration:

**Health Indicators**
- ✅ **Healthy**: Events flowing normally
- ⚠️ **Degraded**: Some failures occurring
- ❌ **Unhealthy**: Multiple consecutive failures

**Metrics**
- Events sent today
- Recent failures
- Last successful event
- Consecutive failures count

### Testing Integration

Always test after creating or modifying:

1. Click **Test** button on integration card
2. System sends a test event
3. Check your SIEM for the test event
4. Verify formatting and fields

### Troubleshooting

**Connection Failures**
- Verify URL and authentication
- Check network connectivity
- Review SIEM system logs

**Missing Events**
- Check event filters configuration
- Verify SIEM system is accepting events
- Review health metrics

---

## Scheduled Compliance Reports

Scheduled compliance reports are generated automatically by the audit-service. Navigate to **Organization Settings → Notifications & Alerts → Scheduled Reports** to configure automated framework-level compliance reports that are generated on a schedule and emailed to designated recipients.

> For ad-hoc audit evidence with cryptographic provenance (content hash, optional signing), use [CBOM Artifacts](#cbom--exports) instead.

---

## Retention Policies

### Overview

Configure how long audit logs are retained in hot (fast access) and cold (archival) storage.

### Accessing Retention Policies

Navigate to **Organization Settings → Policies → Retention Policies** to manage policies.

### Storage Tiers

**Hot Storage**
- Fast access
- Recent events
- Frequent queries
- Higher cost

**Cold Storage**
- Archival
- Older events
- Infrequent access
- Lower cost

**Total Retention**
- Sum of hot + cold
- Maximum retention period
- After this, logs are permanently deleted

### Compliance Framework Templates

Pre-configured retention periods based on common compliance requirements:

| Framework | Total Days | Hot Days | Cold Days |
|-----------|------------|----------|-----------|
| SOC2      | 365        | 90       | 275       |
| ISO 27001 | 730        | 90       | 640       |
| HIPAA     | 2555 (7y)  | 90       | 2465      |
| PCI DSS   | 365        | 90       | 275       |
| GDPR      | 730        | 90       | 640       |

### Creating Policies

1. Click **Create Policy**
2. Configure policy:
   - **Policy Name**: Descriptive name
   - **Scope**: Framework-based or event type-based
   - **Hot Storage Days**: Fast access period
   - **Cold Storage Days**: Archival period
3. System calculates total retention
4. Click **Create**

### Policy Types

**Framework-Based**
- Apply to all events tagged with framework
- Use compliance templates
- Example: All HIPAA-tagged events

**Event Type-Based**
- Apply to specific event types
- Custom retention periods
- Example: user.login events

### Editing Policies

1. Click edit icon on policy card
2. Modify retention periods
3. Click **Update**
4. Changes apply to new events immediately

### Policy Visualization

Each policy shows:
- Hot storage bar (orange)
- Cold storage bar (blue)
- Total retention days
- Visual percentage breakdown

### Best Practices

**Compliance Requirements**
- Use framework templates as starting point
- Verify against your specific requirements
- Document policy decisions

**Storage Optimization**
- Keep hot storage minimal for cost efficiency
- Use cold storage for compliance-required retention
- Review policies quarterly

**Event-Specific Policies**
- Create custom policies for high-volume event types
- Separate security events (longer retention)
- Separate operational events (shorter retention)

---

## Best Practices

### Asset Management

- Regularly review and update asset information
- Approve discovered assets promptly
- Add notes for important assets
- Monitor asset risk levels
- Review stale assets regularly to keep inventory current
- Rescan stale assets before removing them to verify they're truly gone

### Discovery

- Schedule regular discovery jobs
- Review discovery results regularly
- Approve or deny assets promptly
- Use bulk actions for efficiency

### Compliance

- Monitor compliance scores regularly
- Address compliance findings promptly
- Review compliance reports monthly
- Keep frameworks up to date

### Security

- **Use Strong Passwords**: Create unique, complex passwords with at least 12 characters
- **Prefer SSO**: Use your organization's SSO provider when available for enhanced security
- **Link SSO Accounts**: Link your account to SSO providers in Profile → Security for seamless authentication
- **Enable MFA**: Enable Multi-Factor Authentication when available for additional security
- **Review Account Activity**: Regularly check the Activity Logs for any suspicious sign-ins or actions
- **Report Suspicious Activity**: Immediately report any unauthorized access or unusual behavior to your tenant administrator
- **Keep Credentials Private**: Never share your password or SSO credentials with others
- **Sign Out on Shared Devices**: Always sign out when using shared or public computers

---

## Troubleshooting

### Cannot Access Assets

1. Check your role permissions
2. Verify asset filters are not too restrictive
3. Contact tenant administrator

### Discovery Not Working

1. Check discovery job status
2. Verify discovery targets are correct
3. Review discovery logs
4. Contact tenant administrator

### Reports Not Generating

1. Check report status
2. Verify report parameters are valid
3. Wait for async generation to complete
4. Contact support if issues persist

---

## Support

For user support:

- **Documentation**: See [Tenant Admin Guide](./tenant-admin-guide.md)
- **API Reference**: See [API Documentation](../../../api/)
- **Tenant Support**: Contact your tenant administrator

---

**Last Updated:** 2026-02-09
