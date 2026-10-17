# Spreadsheet Import

Already have an inventory in a spreadsheet? Import it directly instead of typing
targets by hand. Upload a CSV or Excel file, map its columns, and the platform
bulk-creates either **prefixes** (so they can be scanned for cryptographic
assets) or **infrastructure assets** (configuration-item records). It's the fastest
way to onboard an existing server list or a network team's CIDR list.

## Overview

Most organizations already track their servers, networks, and IP ranges somewhere —
a spreadsheet exported from an ITAM/ITSM system, a network team's CIDR list, or a
hand-maintained asset register. Spreadsheet Import lets you bring that inventory into
Vista Platform in one step:

- **Two import targets, one wizard** — choose whether each import creates *prefixes* (the CIDRs Discovery scans, in Inventory → Networks) or *infrastructure
  assets* (known servers/devices as CI records).
- **CSV and Excel** — `.csv`, `.xlsx`, and `.xls` are all supported.
- **Column mapping** — your spreadsheet's columns are auto-matched to the right fields
  by header name; you can adjust the mapping before importing.
- **Validation before import** — rows are checked client-side (for example, a malformed
  CIDR or a missing required field) and flagged so you can fix them. Invalid rows are
  skipped, never imported.
- **Duplicate-safe** — rows that match something already in your inventory (by any of
  the identifiers you mapped for assets, or by CIDR for prefixes) are skipped rather
  than duplicated.
- **Up to 1000 rows per import.**

## Where to find it

- **Discovery → Command Center → Import from spreadsheet** — for either
  target (prefixes or infrastructure assets).
- **Inventory → Import** — locked to infrastructure assets.

Importing prefixes needs **Manage IPAM** (`ipam.manage`) — each row is created
the way **Add prefix** creates one, so the change log, the auto-approval rule
and the scan-scope checks behave exactly as for a prefix added by hand.
Importing assets needs **Create assets**.

## Importing prefixes (scan targets)

This is the common path for onboarding a list of networks you want scanned.

1. Open the wizard and choose **Networks (prefixes)**.
2. Upload your CSV/Excel file. The first row must be a header row.
3. **Map columns** to prefix fields:
   - **Prefix (CIDR)** *(required)* — `10.0.0.0/24` or `2001:db8:10::/64`.
   - **Description** — a label for the prefix.
   - **Network type**, **Environment** *(required)* — pick a column to read these
     from, or set a single default applied to every row (handy when your whole
     sheet is, say, all `private` / `production`).
4. **Review** the preview. Valid and skipped (invalid) row counts are shown.
5. Click **Import**. You'll see how many prefixes were created, skipped (duplicates), or
   failed.
6. Run a discovery scan on the new prefixes from the Command Center to find cryptographic
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
   - Optionally map **Interface name**, **Prefix length** and **VLAN** (see
     *Interfaces* below).
   - Optionally map **Display name**, **Environment**, **Operating system**,
     **Support group**, **Business unit**, **Owner email**, **Description**.
3. Review and import. The preview shows each row's interface. Assets are created
   in `pending_approval` and appear in your inventory; subsequent discovery
   enriches them with cryptographic detail.

Not sure how to lay out the sheet? The upload step offers **Download a template
(CSV)** — a header row whose every column maps itself, and one example row.

### Interfaces

A row's **IP address** and **MAC address** are on one of the machine's network
interfaces. Map an **Interface name** column (`eth0`, `port1`, `Ethernet 2`) and
the row creates that interface on the asset, holding the MAC and the IP — at the
**Prefix length** you give (`24` for a `/24`), on the access **VLAN** you give —
and it shows on the asset's **Interfaces** tab. A row with an IP or MAC but no
interface name still records both, on one interface the platform names
(`observed-1`); a prefix length or VLAN needs an interface name to be kept, and
the preview says so. A prefix length outside 0–128 or a VLAN outside 1–4094 is
flagged and the row is skipped.

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
- For prefixes, make sure CIDRs are well-formed — invalid values are
  flagged in the preview and skipped.
- Re-importing the same file is safe: anything already present is skipped, so you can
  fix a few rows and re-upload without creating duplicates.

## What this is *not*

Spreadsheet Import is for getting inventory **in**. To export inventory **out**, use the
per-page **Export** button (CSV of the current view) or generate a **CBOM artifact** for
audit-grade, content-hashed output. To sync with an ITAM/ITSM system continuously,
use an Enterprise CMDB integration (Settings → Integrations).

