# Spreadsheet Import

Already have an inventory in a spreadsheet? Import it directly instead of typing
targets by hand. Upload a CSV or Excel file, map its columns, and the platform
bulk-creates either **network segments** (so they can be scanned for cryptographic
assets) or **infrastructure assets** (configuration-item records). It's the fastest
way to onboard an existing server list or IP-range inventory.

## Overview

Most organizations already track their servers, networks, and IP ranges somewhere —
a spreadsheet exported from an ITAM/ITSM system, a network team's CIDR list, or a
hand-maintained asset register. Spreadsheet Import lets you bring that inventory into
Vista Platform in one step:

- **Two import targets, one wizard** — choose whether each import creates *network
  segments* (CIDRs / IP ranges / domains that Discovery scans) or *infrastructure
  assets* (known servers/devices as CI records).
- **CSV and Excel** — `.csv`, `.xlsx`, and `.xls` are all supported.
- **Column mapping** — your spreadsheet's columns are auto-matched to the right fields
  by header name; you can adjust the mapping before importing.
- **Validation before import** — rows are checked client-side (for example, a malformed
  CIDR or a missing required field) and flagged so you can fix them. Invalid rows are
  skipped, never imported.
- **Duplicate-safe** — rows that match something already in your inventory (by any of
  the identifiers you mapped for assets, or by value for segments) are skipped rather
  than duplicated.
- **Up to 1000 rows per import.**

## Where to find it

- **Operations → Discovery → Command Center → Import from spreadsheet** — for either
  target (network segments or infrastructure assets).
- **Settings → Network Segments → Import** — a shortcut that imports straight into your
  network-segment registry.

Both entry points open the same wizard. (Importing requires the **Manage Discovery**
permission for the Discovery entry, or **Update Settings** for the Network Segments entry.)

## Importing network segments (scan targets)

This is the common path for onboarding a list of networks you want scanned.

1. Open the wizard and choose **Network segments**.
2. Upload your CSV/Excel file. The first row must be a header row.
3. **Map columns** to segment fields:
   - **Name** *(required)* — a label for the segment.
   - **Value** *(required)* — the CIDR (`10.0.0.0/24`), IP range (`10.0.0.1-10.0.0.254`),
     or domain (`*.example.com`).
   - **Segment type**, **Network type**, **Environment** *(required)* — pick a column to
     read these from, or set a single default applied to every row (handy when your whole
     sheet is, say, all `cidr` / `private` / `production`).
   - Optionally map **Business unit**, **Owner email**, **Description**.
4. **Review** the preview. Valid and skipped (invalid) row counts are shown.
5. Click **Import**. You'll see how many segments were created, skipped (duplicates), or
   failed.
6. Run a discovery scan on the new segments from the Command Center to find cryptographic
   assets on them.

## Importing infrastructure assets (CI records)

Use this when your spreadsheet is a list of known servers/devices rather than networks.

1. Open the wizard and choose **Infrastructure assets**.
2. Upload your file and map columns:
   - **Class** *(required)* — map a column or choose a single default for the whole
     file. The list is the platform's class taxonomy (Server, Workstation, Switch,
     Firewall, Object storage, Web application, Business service, …) — the same
     taxonomy the Inventory class facet uses, so an imported asset lands in the class
     you'd expect to find it under. A column whose value isn't a known class is
     flagged in the preview with the offending value quoted, and that row is skipped.
   - **Identifiers** — **FQDN**, **Hostname**, **IP address**, **MAC address** and
     **Serial number**. At least one is required per row, and the wizard auto-maps
     them from the obvious headers ("Host Name", "Service Tag", …).
   - Optionally map **Display name**, **Environment**, **Operating system**,
     **Support group**, **Business unit**, **Owner email**, **Description**.
3. Review and import. Assets are created in `pending_approval` and appear in your
   inventory; subsequent discovery enriches them with cryptographic detail.

### Why identifiers, and not just a hostname column

The identifier columns are the part worth getting right. They are what let the
platform recognise a machine it has seen before rather than create a second copy of
it: a row carrying a serial number will match the same physical server whether a
sensor saw it by hostname, your CMDB exported it by `sys_id`, or you imported it
again next quarter from a different spreadsheet.

Map as many as your sheet has. A file with only a hostname column still imports
fine — it just gives the platform less to match on later. Where a match is
plausible but not certain, you get a **merge proposal** in Discovery → Approvals
rather than a silent decision either way.

### Operating system

**Operating system** is a property of the *class*, not of every asset: a server has
one, a switch does not. Map the column if your sheet has it — rows whose class has
no operating-system field simply ignore it rather than failing.

### Services

A row whose class is under **Service** (Business service, Technical service) needs a
**Display name** instead of an identifier. A service has no address or serial to be
known by; its name is its identity.

> **Note on plan limits.** Importing infrastructure assets counts against your
> subscription's asset limit. If an import would exceed your limit, the whole import is
> declined and nothing is created — reduce the file or upgrade your plan, then retry.

## Tips for preparing your spreadsheet

- Keep a single header row at the top; the wizard reads column names from it.
- One record per row.
- For segments, make sure CIDRs and IP ranges are well-formed — invalid values are
  flagged in the preview and skipped.
- Re-importing the same file is safe: anything already present is skipped, so you can
  fix a few rows and re-upload without creating duplicates.

## What this is *not*

Spreadsheet Import is for getting inventory **in**. To export inventory **out**, use the
per-page **Export** button (CSV of the current view) or generate a **CBOM artifact** for
audit-grade, content-hashed output. To sync with an ITAM/ITSM system continuously, use
[CMDB Integrations](./cmdb-integrations.md).
