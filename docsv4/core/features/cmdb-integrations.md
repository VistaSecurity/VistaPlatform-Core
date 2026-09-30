# CMDB Integrations

> **Enterprise capability — not included in Core.** Both directions of CMDB
> integration (push *and* pull) ship in the Enterprise edition. A Core build does
> not mount these endpoints at all, so there is no CMDB screen to configure and
> the API answers **402 Payment Required**. Don't provision a CMDB service
> account for this until you know which edition you are running. Core keeps the
> complete internal CMDB — assets, crypto configurations, certificates, keys and
> every inventory lens; what Enterprise adds is synchronizing it with a *foreign*
> CMDB/ITSM system. See [Editions](../editions.md).

Sync your cryptographic inventory with external Configuration Management Database (CMDB) platforms for unified IT asset management. The CMDB integration lets you **push** the infrastructure assets you have approved — with their certificates, cryptographic keys and crypto configurations — into your existing CMDB, and **pull** the CMDB's server inventory into the platform.

## Overview

The Vista Platform discovers and tracks cryptographic posture across your infrastructure. CMDB integration closes the loop with your IT operations teams: push cryptographic posture into the CMDB tools they already use, and pull the servers they already track into the platform to be enriched with cryptographic discovery.

**Key capabilities:**

- **Push** — Send your approved inventory to the CMDB. Each record's CMDB id is kept from the push response, so the next push updates the same record instead of creating another. Your CMDB remains the system of record. See [What a push sends](#what-a-push-sends).
- **Pull (inbound import)** — Import CIs from your CMDB into the platform as pending-approval assets, so you don't re-enter inventory the CMDB already has. See [Pull Inventory From Your CMDB](#pull-inventory-from-your-cmdb).
- **Schedules that run** — Sync manually, hourly, daily, or weekly. A scheduled run pushes, pulls, or both, according to the platform. See [Schedules](#schedules).
- **Incremental, two-way safe** — A run sends and writes only what changed since the last one; records the platform pushed are recognised when a pull reads them back, so nothing is duplicated and nothing bounces back and forth; a CI retired in your CMDB is marked absent, never deleted. See [Keeping Vista and your CMDB in step](#keeping-vista-and-your-cmdb-in-step).
- **On-premises CMDBs** — Reach a CMDB on your own network and trust your own certificate authority, per profile. See [On-premises CMDBs](#on-premises-cmdbs).
- **Cryptographic context write-back** — Optionally append a plain-language crypto-posture summary to each pushed CI's description, with no custom-field setup. See [Cryptographic Context in Your CMDB](#cryptographic-context-in-your-cmdb).
- **Four supported platforms** — ServiceNow, Device42, SolarWinds, and Oomnitza.
- **Job history** — Every run, manual or scheduled, push or pull, is recorded with its counts and the per-item errors the CMDB returned.

## Supported Platforms and Direction

Which way data moves is fixed per platform:

| Platform | Push (Sync) | Pull |
|----------|-------------|------|
| **ServiceNow** | Yes | Yes |
| **Device42** | Yes | Yes |
| **SolarWinds** | **No — pull only** | Yes |
| **Oomnitza** | Yes | Yes |

**SolarWinds is pull-only.** SolarWinds is a monitoring system of record: pushing
discovered devices into it would create nodes it then tries to poll. A SolarWinds
profile has no **Sync** button, and the API refuses a push to it with
`400 — SolarWinds is a pull-only platform`.

## Setting Up a CMDB Integration

### Prerequisites

- The **Update Settings** permission to create and edit profiles and run **Test**;
  **Manage Assets** to run **Sync** and **Pull**; **View Settings** to see profiles
  and their sync history
- Network connectivity from the platform to your CMDB instance
  (see [On-premises CMDBs](#on-premises-cmdbs))
- API credentials for the target CMDB platform
- (Recommended) A dedicated service account on the CMDB side with the permissions the
  platform section below lists

### Step 1: Navigate to CMDB Integrations

1. Open the profile menu and go to **Settings → Integrations**.
2. Scroll to the **CMDB / ITSM sync** section.
3. Click **Add CMDB sync**.

Each connection appears as a card showing its platform and last-run status (hover
the status for the last error). From a card you can **Test** the connection,
**Pull** the CMDB's inventory, **Sync** (push your inventory now — not offered for a
pull-only platform), view **Sync history**, edit the configuration, or remove it.

### Step 2: Select a Platform and Connect

Choose the platform, then provide the URL and credentials. The authentication
methods, URL formats and required CMDB roles differ per platform — see
[Per-platform details](#per-platform-details).

Credentials are **write-only**: once saved, a password, API token or client secret
is never shown again. When you edit a profile, leave a secret blank to keep the
current one. Don't put credentials in the URL (`https://user:pass@…`) — the form
refuses it, because a URL is not treated as a secret.

### On-premises CMDBs

Two optional settings on the profile, for a CMDB that is not on the public internet:

| Setting | When you need it |
|---------|------------------|
| **CMDB is on our own network** | The CMDB's address is private (10.x, 172.16–31.x, 192.168.x, or a name that resolves only to such addresses). This is the usual case for an on-premises SolarWinds or Device42. Without it, saving a private URL is refused with *"this URL points inside a private network"*. Loopback and cloud-metadata addresses are never reachable, whatever this is set to. Turning it on is recorded in the audit log. Your platform operator can disable private targets for the whole deployment (`CONNECTOR_ALLOW_PRIVATE_ENDPOINTS=false`); the form then says so. |
| **CA bundle (PEM)** | The CMDB's HTTPS certificate was issued by your own certificate authority. Paste that CA's certificate (or chain). It is trusted **in addition to** the public roots; certificate checking is never switched off. A bundle that doesn't parse, or that contains a private key, is refused on save. |

The platform never follows a redirect to a different host than the CMDB you
configured, because the credentials would travel with it.

### Step 3: Test the Connection

Click **Test** on the profile card. The platform reaches your CMDB with the saved
credentials and reports the result. On failure the message says why:

| Message | Meaning | What to do |
|---------|---------|------------|
| *The CMDB address is on a private network…* | The URL resolves to a private address and the profile doesn't allow it. | Turn on **CMDB is on our own network**. |
| *…is never reachable* | The URL points at loopback, link-local/metadata space, or the platform's own cluster. | Use the CMDB's real address. |
| *The CMDB's TLS certificate is not trusted…* | An internal CA issued the certificate. | Paste the CA certificate into **CA bundle**. |
| *The CMDB rejected the credentials or the account lacks permission (HTTP 401 / 403)* | Wrong credentials, or the account lacks the roles it needs. | Check the credentials and the account's roles. |
| *The CMDB host name does not resolve* | DNS can't find the host. | Check the URL. |
| *The CMDB refused the connection* | Nothing is listening at that address and port. | Check the URL and port. |
| *The CMDB did not answer in time* | The CMDB or a firewall on the way is dropping the connection. | Check network paths and firewall rules. |
| *The CMDB redirected to a different address…* | The CMDB sent the request to another host. | Configure the final URL directly. |

Messages never include credentials, request headers or the CMDB's response body;
a URL is shown as `scheme://host` only.

### Step 4: Configure Sync Options

| Option | Default | Description |
|--------|---------|-------------|
| **Schedule** | Manual | *Manual*, *Hourly*, *Daily* or *Weekly*. See [Schedules](#schedules). |
| **Push batch size** | 100 | How many CIs a push sends per batch (1–1000). Each batch's results are recorded before the next is sent, so a run that stops part-way keeps what it already pushed linked, and the next run updates those records instead of creating them again. Push platforms only. |
| **Include cryptographic summary** | Off | See [Cryptographic Context in Your CMDB](#cryptographic-context-in-your-cmdb). Push platforms only. |
| **Enabled** | On | While off, **nothing runs**: no scheduled runs, and **Sync** and **Pull** are refused with *"this CMDB profile is disabled"*. |

There is no profile-wide conflict-resolution setting. Which side wins is decided
**per field** by the profile's field mapping: by default every field a push sends
is owned by the platform, so a push overwrites the fields it sends on the record it
created earlier (or creates the record), and fields it doesn't send are left alone.
See [Field mapping](#field-mapping).

### Step 5: Run It

Click **Sync** (push) or **Pull** on the card, or let the schedule run it.

## Schedules

A profile on an **Hourly**, **Daily** or **Weekly** schedule is run by the platform:

- **What a scheduled run does** follows the platform's direction. A pull-only
  platform (SolarWinds) is pulled. A two-way platform is **pulled first, then
  pushed**: the CMDB is your system of record for what exists, so reading it first
  lets the platform link records the CMDB already holds before anything is written
  back. The two halves are independent — a failed pull doesn't stop the push — and
  each is recorded as its own job. The card shows the worse of the two, with both
  errors.
- **Cadence** is measured from the start of the previous *scheduled* run. A manual
  Sync or Pull does not move the schedule. The platform checks for due profiles
  every five minutes, so a run starts within a few minutes of falling due.
- **One run per profile at a time.** A scheduled run, a manual Sync and a manual
  Pull of the same profile never overlap, across every replica of the service.
  Clicking **Sync** or **Pull** while a run is in progress answers
  *"a sync for this profile is already running"*; a scheduled run that finds one in
  progress waits for its next turn.
- **Skipped** for a disabled profile, a suspended or canceled tenant, and a tenant
  whose plan no longer includes CMDB sync.
- **Time limit.** A run stops after 60 minutes. A run cut short by a service restart
  is closed as failed — *"interrupted (service restarted)"* — rather than left
  "in progress".

## What a push sends

A push sends your **configuration items** — not everything the platform has ever
observed:

| Sent | Not sent |
|------|----------|
| Infrastructure assets you have **approved** (in monitoring) | Assets pending approval, denied, archived (including from the Stale lens), merged into another asset, or deleted |
| Crypto configurations on an approved asset | Crypto configurations on any other asset, or deleted |
| Certificates used by a crypto configuration on an approved asset — including expired and revoked ones, which is exactly what your CMDB should show | Certificates linked to nothing in scope, and certificates in the *destroyed* state |
| Keys used by a crypto configuration on an approved asset — including compromised ones | Keys linked to nothing in scope, and keys in the *destroyed* state |

That is the scope; what a platform *accepts* of it differs. **Device42** and
**Oomnitza** take infrastructure assets only — a certificate, key or crypto
configuration is not a device or an asset there, so they are skipped (see each
platform's section under [Per-platform details](#per-platform-details)).

To get an asset into the CMDB, approve it (Discovery → Approvals). To take one out
of future pushes, archive it. A push never deletes records from your CMDB; on a
platform that supports it, archiving (or merging away) an asset marks its CMDB
record retired instead — see [Retirement](#retirement).


## Keeping Vista and your CMDB in step

These apply to every platform that runs on the platform's shared field mapping
(Oomnitza and ServiceNow today; Device42 and SolarWinds follow as their mappings
are verified).

### Incremental runs

- **Push** sends a record only when what it would send has changed since the last
  successful push of it. An unchanged inventory produces a run with nothing sent
  (counted as *unchanged*).
- **Pull** remembers the newest *last modified* time it has read from your CMDB and,
  next time, writes only records modified after it. A run in which any record fails
  does not move that mark, so the failed record is read again next time.
- **Full re-sync.** At least once a day each direction runs in full, ignoring both,
  which catches a record deleted in the CMDB and a field someone edited there that
  Vista owns. You can ask for one at any time through the API:
  `POST /api/v2/inventory-service/cmdb/profiles/{id}/sync?full=true` (or `/pull?full=true`).
  Sync history shows whether each run was *full* or *delta*.

### Retirement

Nothing is ever hard-deleted in either system.

- **Retired or removed in your CMDB.** A record whose lifecycle status says it is
  retired (for Oomnitza: *Retired*, *Disposed* or *Decommissioned*), or that a
  complete listing of the CMDB no longer contains, is marked **absent from that
  source**. The asset's history records it; the asset itself is left alone — your
  lifecycle rules in Vista decide what happens to it — and Vista stops pushing to
  that record. If the record comes back, it is linked again and the history says so.
  An empty listing, or one the platform could not read in full, never marks anything
  absent.
- **Archived or merged away in Vista.** Where the platform supports it, the CMDB
  record is marked retired rather than deleted, once. (Oomnitza does not yet: its
  records are left as they are.)

### No duplicates, no ping-pong

- A record Vista pushed is linked to the asset it came from. When a pull reads it
  back, it is recognised: Vista's own values coming back are ignored, and anything
  your CMDB added is applied to **the same asset**. A record standing for one of
  your certificates or keys is never turned into an asset.
- An asset a pull brought in is pushed back to **the record it came from**, never as
  a new record next to it.

## Field mapping

What a push sends and what a pull reads are defined by the profile's **field
mapping**: the platform's default mapping, plus any changes you make to it. It
decides which of Vista's CIs are sent and as what type, which field goes where,
how values are translated (for example *PROD* ↔ *production*), which of the CMDB's
fields identify a record, and which side owns each field.

- **Only mapped fields come in.** A pull reads the fields the mapping names and
  nothing else, so a custom field holding a password or a key never reaches Vista.
- **Personal data is recorded.** A mapped field that carries personal data (such as
  an owner's email address) is recorded against the asset it was written to, so a
  data-subject request can find it.
- **An invalid mapping pauses the profile.** The mapping is checked when you save
  it, before every run, and whenever the service starts (a platform upgrade can
  change the defaults). If it no longer checks out — for example it names a class or
  a field Vista no longer has — the card shows **Mapping invalid** with the reason,
  scheduled runs skip the profile, and **Sync** / **Pull** are refused until the
  mapping is fixed. Nothing is synced with a mapping that cannot be applied.
- There is no mapping editor in the form yet. The mapping can be read and changed
  through the API: `GET` / `PUT /api/v2/inventory-service/cmdb/profiles/{id}/mapping`
  (Update Settings permission to change it). A change that doesn't check out is
  refused with the entry that is wrong, and nothing is saved.

## Pull Inventory From Your CMDB

If your CMDB already tracks your servers, you can import them into Vista instead of
re-entering them. On a connected profile card (Settings → Integrations → CMDB / ITSM
sync) click **Pull**, or put the profile on a schedule. Vista fetches the platform's
CIs and creates them as **pending-approval infrastructure assets** — hostname, IP
address, and operating system are carried over. They then appear in Discovery →
Approvals and Inventory, where normal discovery enriches them with cryptographic
detail.

- **Duplicate-safe.** A pull matches records it has seen before — including records
  Vista itself pushed — so you can re-pull without creating duplicates.
- **Classified by type.** On a platform with a field mapping, each record's type in
  the CMDB decides its asset class (a *Laptop* becomes a laptop); a record whose type
  isn't mapped is imported as generic hardware rather than guessed to be a server.
- **The result says what happened**: how many assets were created, how many were
  already present, how many are held for identity review, and how many failed. The
  sync history lists each failed record with the reason.
- A pull respects your plan's **asset limit**: if importing the pulled records would
  exceed it, the pull is declined and nothing is created (upgrade your plan, then
  retry).
- Every pull is recorded in the profile's sync history, like a push.
- Requires the **Manage assets** permission.

## Cryptographic Context in Your CMDB

When editing or creating a CMDB profile for a push platform, enable **Include
cryptographic summary**. With it on, every asset Vista pushes carries a one-line,
plain-language summary of its cryptographic posture appended to the CI's
description/notes field — for example:

> `Vista crypto posture — risk=high · protocols: TLS 1.2 · algorithms: RSA-2048, AES-256-GCM · PQC: classical (migration recommended)`

This writes to a standard free-text field (see [Per-platform details](#per-platform-details)),
so it needs no custom-field setup. The toggle is **off by default**.

## Monitoring Sync Jobs

Every run — manual or scheduled, push or pull — creates a **job**:

| Status | Meaning |
|--------|---------|
| `in_progress` | Running now. |
| `success` | Every item was handled. |
| `partial` | Some items failed; the rest went through. |
| `failed` | Nothing went through, or the run stopped (bad configuration, CMDB unreachable, time limit, *interrupted (service restarted)*). |

Click the history icon on a profile card to open **Sync history**. Each row shows
when the run happened, whether it was a push or a pull, whether it was manual or
scheduled, its status, and its counts (created; updated for a push, or already
present for a pull; failed; skipped or held for review). The run's summary also
records whether it was *full* or *delta* and how many records were unchanged,
recognised as Vista's own, retired, or absent. Click a row with errors to
see what the CMDB refused, item by item (the first 50), or why the whole run failed.
The history requires the **View Settings** permission.

Each profile card also shows the last run's time and status; hover the status for
the last error.

**API:** `GET /api/v2/inventory-service/cmdb/profiles/{id}/jobs?limit=20`

## Troubleshooting

| Symptom | Cause | What to do |
|---------|-------|------------|
| **Test** fails | See the message table in [Step 3](#step-3-test-the-connection). | |
| *this CMDB profile is disabled* | The profile's **Enabled** toggle is off. | Edit the profile and turn it on. |
| *SolarWinds is a pull-only platform* | Sync was requested for a pull-only platform. | Use **Pull**. |
| *a sync for this profile is already running* | A manual or scheduled run of the profile is in progress. | Wait for it; its result appears in Sync history. |
| All items fail | Expired or rotated credentials, or the account lost a role. | Update the credentials; run **Test**. |
| Some items fail | The CMDB refused those records. | Open the run in **Sync history** to see each refusal. |
| A job shows *interrupted (service restarted)* | The service restarted during the run. | Run it again, or let the schedule do it. |
| An asset you expect isn't in the CMDB | It isn't approved, or it's archived or merged — or its CMDB record was retired or removed there. | See [What a push sends](#what-a-push-sends) and [Retirement](#retirement). |
| The card shows **Mapping invalid** and nothing runs | The profile's field mapping names something Vista no longer accepts (the reason is on the card). | Fix the mapping (see [Field mapping](#field-mapping)); the profile resumes on its own. |

## Per-platform details

<!-- Per-platform behaviour (auth schemes, CI classes, field mapping, what each
     connector pushes and pulls, pagination, required CMDB roles) is being
     verified platform by platform and is maintained here, separately from the
     engine-level facts above. -->

> **Being revised.** The per-platform behaviour below is being verified against each
> vendor and may change. The engine-level behaviour above — schedules, direction,
> push scope, on-premises options and error messages — applies to every platform.

| Platform | API Used | Authentication offered | Free-text field used for the crypto summary |
|----------|----------|------------------------|---------------------------------------------|
| **ServiceNow** | Identification and Reconciliation API (writes), Table API (reads) | Basic Auth, OAuth 2.0 client credentials | `short_description` |
| **Device42** | REST API v1 (`/api/1.0/`) | Basic Auth | `notes` |
| **SolarWinds** | SWIS REST API (Orion SDK) — read only | Basic Auth | — (pull only) |
| **Oomnitza** | REST API v3 | API token (`Authorization2` header), Basic Auth | `notes` |

### ServiceNow

> **Verification status:** contract-tested against ServiceNow's documented APIs
> (the Identification and Reconciliation API, the Table API and OAuth), **not yet
> verified against a live ServiceNow instance.** Class names, relationship types
> and choice values are ServiceNow base-system names; every one can be changed per
> profile through the field mapping.

ServiceNow runs on the shared field mapping, so everything in
[Keeping Vista and your CMDB in step](#keeping-vista-and-your-cmdb-in-step) applies
to it. A ServiceNow pull reads **every** record of the classes it covers, page by page —
there is no record limit.

#### Set it up

1. **Create an integration user** in ServiceNow (User Administration → Users). Tick
   *Web service access only*. Give it the **`itil`** role (or **`asset`**) — see
   [ServiceNow roles](#servicenow-roles). Don't use an admin account.
2. **Add Vista Platform as a discovery source.** Every write names where the data
   came from, and ServiceNow only accepts a value from the choice list of the
   **Discovery source** field on the **Configuration Item [cmdb_ci]** table. Add the
   choice `Vista Platform` there (right-click the field label on a CI form →
   *Show Choice List*, or System Definition → Choice Lists). To use a value your
   instance already has instead, set the profile's `options.discovery_source`
   through the mapping API (see [Field mapping](#field-mapping)). If the value is
   missing, every push fails with a message naming it.
3. **Pick an authentication method:**
   - **Username & password** — the integration user's credentials (HTTP Basic).
   - **OAuth 2.0 client credentials** — needs ServiceNow's Washington DC release or
     later. An administrator sets the system property
     `glide.oauth.inbound.client.credential.grant_type.enabled` to `true`, creates
     an OAuth API endpoint for external clients in **System OAuth → Application
     Registry**, and sets its **OAuth Application User** to the integration user
     (the grant acts as that user). Vista exchanges the client ID and secret for an
     access token at `<instance>/oauth_token.do`, reuses it until shortly before it
     expires, and exchanges again if ServiceNow rejects it.

   There is no "API token" option: ServiceNow's REST APIs do not accept one, and a
   profile saved with one from an earlier version must be edited to one of the two
   methods above.
4. **Instance URL:** `https://yourinstance.service-now.com`.
5. Click **Test**. It reads one configuration item — the least a sync needs — so a
   correctly scoped integration user passes. A 403 means the user cannot read the
   CMDB: check its roles.

We recommend setting the integration user's **time zone to UTC**. ServiceNow reads
the date in an incremental pull's filter in the user's time zone; Vista allows for
any offset, so another time zone costs only a few extra records per pull.

#### ServiceNow roles

| What Vista does | ServiceNow API | Role it needs |
|---|---|---|
| Push CIs, retire CIs, push relationships | Identification and Reconciliation API (`POST /api/now/identifyreconcile`) | `itil` or `asset` — the roles ServiceNow documents for this API |
| Pull CIs; check a linked CI still exists; **Test** | Table API (`GET /api/now/table/<class>`) | Read access to the CI classes pulled — `itil` has it in the base system. If your instance restricts CMDB reads further, grant read on each class in [What is pulled](#what-a-servicenow-pull-reads). |

Relationships are written through the Identification and Reconciliation API too,
so no separate write access to the CI Relationship table is needed. Vista never
calls admin-only APIs.

#### How a push is written

- **No duplicates of what ServiceNow already knows.** Every CI goes through
  ServiceNow's **Identification and Reconciliation Engine** — the same engine its
  own Discovery and Service Graph connectors use. Your identification rules decide
  whether the CI already exists (for hardware: serial number, then name, …), so a
  server ServiceNow's Discovery found is updated, not created a second time. Your
  **reconciliation rules** decide which discovery source may overwrite which field:
  if you want ServiceNow Discovery to own a field Vista also sends, say so there.
- A CI a previous push created or matched is updated **by its sys_id**, and keeps
  the class ServiceNow gave it: a *Linux Server* is never turned back into a
  generic *Server*.
- Each CI records its source (discovery source + Vista's id for it, visible in the
  CI's source records), and `correlation_id` carries Vista's id as well.
- Fields sent: `name` (the asset's display name), `short_description` (its
  description, plus the [crypto summary](#cryptographic-context-in-your-cmdb) when
  enabled), `correlation_id`, and — when Vista has them — `serial_number` and
  `ip_address`. Nothing else is written.
- **Retirement:** when you archive or merge away an asset in Vista, its CI's
  **Install status** is set to *Retired* (`7`), once. Nothing is ever deleted.

**What is pushed, as which class:**

| Vista class | ServiceNow class |
|---|---|
| Server, Hypervisor | Server `cmdb_ci_server` |
| Computer | Computer `cmdb_ci_computer` |
| Workstation, Laptop | Personal Computer `cmdb_ci_pc_hardware` |
| Network device | Network Gear `cmdb_ci_netgear` |
| Switch | IP Switch `cmdb_ci_ip_switch` |
| Router | IP Router `cmdb_ci_ip_router` |
| Firewall | IP Firewall `cmdb_ci_ip_firewall` |
| Load balancer | Load Balancer `cmdb_ci_lb` |
| Access point | Wireless Access Point `cmdb_ci_wap_network` |
| Storage device | Storage Device `cmdb_ci_storage_device` |
| Printer | Printer `cmdb_ci_printer` |
| Any other hardware (OT, IoT, mobile, BMC, …) | Hardware `cmdb_ci_hardware` |

**Not pushed**, and counted as *skipped* in the sync history:

- **Certificates, keys and crypto configurations.** They are not configuration
  items in ServiceNow's model. (ServiceNow's *Unique Certificate* class is
  populated by its own certificate discovery and identified by a fingerprint.)
  Their cryptographic posture reaches ServiceNow through the asset's
  description — turn on **Include cryptographic summary**. Earlier versions tried
  to push them to classes a standard instance does not have; anything those
  pushes created is left as it is.
- **Applications, services, virtual machines, containers and cloud resources.**
  ServiceNow identifies these through what they run on or are hosted by, and
  usually learns them from its own discovery. Vista pulls them (below) and links
  relationships to them, but does not create them.

#### ServiceNow relationships

After each push, Vista sends the **approved** relationships between assets that
are both linked to a ServiceNow CI (pushed or pulled), as standard ServiceNow
relationship types:

| Vista relationship | ServiceNow type (parent → child) |
|---|---|
| A *runs on* B | Runs on::Runs (A → B) |
| A *hosted on* B | Hosted on::Hosts (A → B) |
| A *virtualized by* B | Virtualized by::Virtualizes (A → B) |
| A *depends on* B | Depends on::Used by (A → B) |
| A *contains* B | Contains::Contained by (A → B) |
| A *sends data to* B | Sends data to::Receives data from (A → B) |
| A *member of* B | Members::Member of (B → A) |
| A *manages* B | Managed by::Manages (B → A) |

*Connects to* (network flows the sensors observed) and *impacts* are not sent:
an observed flow is not a CMDB dependency until someone says it is. Pending
relationships are not sent until approved. A relationship Vista no longer has is
not removed from ServiceNow. Relationships are sent again only when the set
changes (or on a full run); one ServiceNow already holds is left unchanged. The
sync history's summary counts them (created, already present, unchanged, failed),
and a refused relationship makes the run *partial* with ServiceNow's reason.

#### What a ServiceNow pull reads

A pull lists these classes, each on its own table, and creates the records as
pending-approval assets of the matching Vista class:

| ServiceNow class | Vista class |
|---|---|
| `cmdb_ci_server`, `cmdb_ci_linux_server`, `cmdb_ci_win_server`, `cmdb_ci_unix_server`, `cmdb_ci_solaris_server`, `cmdb_ci_aix_server`, `cmdb_ci_hpux_server` | Server |
| `cmdb_ci_esx_server` | Hypervisor |
| `cmdb_ci_computer` | Computer |
| `cmdb_ci_pc_hardware` | Workstation |
| `cmdb_ci_netgear` · `cmdb_ci_ip_switch` · `cmdb_ci_ip_router` · `cmdb_ci_ip_firewall` · `cmdb_ci_lb` · `cmdb_ci_wap_network` | Network device · Switch · Router · Firewall · Load balancer · Access point |
| `cmdb_ci_storage_device` · `cmdb_ci_printer` · `cmdb_ci_hardware` | Storage device · Printer · Hardware |
| `cmdb_ci_vm_instance` | Virtual machine |
| `cmdb_ci_appl` | Application |
| `cmdb_ci_service_business`, `cmdb_ci_service` | Business service |

A class your instance doesn't have (a plugin not installed) is skipped. A class
the integration user may not read fails the pull, naming the class — grant read,
or remove the class from the profile's mapping.

- **Fields read** (and nothing else — the request names exactly these):
  `name`, `host_name`, `fqdn`, `ip_address`, `mac_address`, `serial_number`,
  `short_description`, `os`, `os_version`, the manufacturer's and model's names,
  the support group's and location's names, `environment` / `used_for`
  (*Production*, *Staging*, *Development*, *Test*, *QA* → Vista's environment;
  other values are left empty), `install_status`, `sys_class_name`,
  `sys_updated_on`.
- **Identity:** the CI's `sys_id` links it; its serial number, MAC address and FQDN
  help match it to an asset Vista already discovered.
- **Retired in ServiceNow:** a CI whose Install status is *Retired* (`7`) marks its
  asset absent from ServiceNow (see [Retirement](#retirement)).
- **Incremental:** after the first pull, only CIs updated since the last one
  (`sys_updated_on`) are read, with a full pull at least once a day.

#### Changing the defaults

Everything above is the default mapping. A profile can change any of it through
`GET` / `PUT /api/v2/inventory-service/cmdb/profiles/{id}/mapping`: add or remove
classes (which also changes what a pull lists), map a custom field (`u_…`),
change or disable a relationship type, or set `options.discovery_source`.

### Device42, SolarWinds and Oomnitza

**Device42:**

*Verification status: **contract-tested against Device42's published API
(`api.device42.com`), not verified against a live Device42 instance.** See
[what to check on a live instance](#device42-checks).*

- **Set-up.** Base URL `https://device42.example.com` (no path). Authentication is
  **HTTP Basic with a Device42 user** — the API-token option was removed: Device42
  does not accept a static token, its token scheme is a short-lived bearer token
  requested with an API client's key and secret, which the profile form does not
  offer. Use a dedicated user, and untick *Staff Status* on it (Tools → Admins &
  Permissions → Administrators) if it should reach the API but not the web UI.
  A new or edited profile with any other sign-in method (API token, API key,
  OAuth2) is refused when saved; a profile stored earlier with the old *API token*
  option must be edited to use a username and password, and until then **Test**
  says so.
- **Permissions the user needs.** Read access to devices (Test, Pull and the
  lookups a push does) and permission to add and change devices (Sync).
- **What Sync sends: devices only.** A server, workstation, network device, virtual
  machine or cluster you have approved becomes a Device42 **device**. Certificates,
  keys, crypto configurations and crypto libraries are **not** sent (they are not
  devices — sending them created a bogus device per TLS configuration), and neither
  are assets that are not devices (applications, services, cloud resources). The
  cryptographic posture reaches Device42 in the device's **Notes** field when *Include
  cryptographic summary* is on.
- **How a device is recognised — never by name alone.** Vista updates the device it
  created earlier (by its Device42 id); if it has none, the device that holds the same
  **serial number**; otherwise it creates one. Device42 matches a create by *name* and
  would silently overwrite an existing device of the same name, so when Vista has no
  id and no serial number and Device42 already has a device with that name, the record
  is **skipped** with a message saying why, and nothing is written. A serial number
  that firmware reports when it has none (*To Be Filled By O.E.M.*, *Default string*, …)
  or that is shorter than three characters is not used.
- **What an update changes.** Device42 owns what a device *is*: its name, serial
  number, UUID, manufacturer, hardware model and operating system are written only
  when Vista **creates** the device, never on an update. Vista's own field is the
  Notes text, rewritten on every update.
- **Device types Vista creates:**

  | Vista class | Device42 type |
  |-------------|---------------|
  | Server, workstation, laptop, network devices, printers, other hardware, hypervisor | `physical` |
  | Virtual machine, container | `virtual` |
  | Cluster | `cluster` |
  | Unknown host | `unknown` |

- **What Pull reads.** Every device, in pages of 1000 (`limit` / `offset` until
  `total_count`), so an estate of any size is read completely. There is **no
  incremental read**: Device42's `/devices/all/` listing has no last-updated filter,
  so each pull reads every device and Vista writes only the ones whose `last_updated`
  moved since the last pull. Because the listing is complete, a device that has
  disappeared (archived or deleted) is marked absent — never deleted from Vista.
  Read: name (display name and hostname), first usable IP address, building (site),
  operating system and version, manufacturer, hardware model, serial number and MAC
  address (identity). Nothing else is read — custom fields, notes and passwords stay
  in Device42.
- **Classes a Pull assigns:**

  | Device42 record | Vista class |
  |-----------------|-------------|
  | flagged *is a switch* | switch |
  | flagged *is a virtual host* | hypervisor |
  | flagged *is a blade host* (chassis) | hardware |
  | type `blade` | server |
  | type `virtual` | virtual machine |
  | type `cluster` | cluster |
  | type `physical`, `other`, `unknown`, or anything else | hardware |

  Device42 does not distinguish servers from workstations, so a plain physical device
  is *hardware* — the honest "a physical thing, kind unknown" — rather than a guessed
  server. Change what a type becomes with a class override in the profile's mapping.

<a id="device42-checks"></a>
*To check on a live instance:* that Test succeeds for a user who can read devices but
not buildings; that a create is a form POST to `/api/1.0/device/` and returns the
device id in `msg[1]`; that an update by `device_id` (PUT) changes only the Notes;
that `GET /api/1.0/devices/serial/<serial>/` and `/name/<name>/` answer 404 for an
unknown device and a device (or `Devices` list) otherwise; that a deleted device's
`GET /api/1.0/devices/id/<id>/` answers 404; and that the `is_it_switch` /
`is_it_virtual_host` / `is_it_blade_host` flags and `ip_addresses[].ip` /
`mac_addresses[].mac` appear in `/api/1.0/devices/all/` as documented.

**SolarWinds:**

*Verification status: **contract-tested against the published Orion SDK / SWIS
documentation, not verified against a live Orion.** See
[what to check on a live Orion](#solarwinds-checks).*

- **Pull only** (see [Supported Platforms and Direction](#supported-platforms-and-direction)):
  Vista reads SolarWinds' nodes and never writes to it. There is no push code — a
  request to Sync is refused before any connection is made.
- **Set-up.** Base URL `https://orion.example.com:17774` **including the SWIS port**:
  `17774` from Orion Platform 2023.1, `17778` before it. Authentication is **HTTP
  Basic with an Orion account** (the API-token option was removed; SWIS does not
  accept one). The account needs the right to query `Orion.Nodes` (a read-only
  Orion user is enough).
- **Certificate.** Orion commonly serves a self-signed certificate. Paste it (or the
  CA that issued it) into the profile's **CA bundle**; Vista never switches
  certificate checking off. Turn on **CMDB is on our own network** for a private
  address.
- **What Pull reads.** `Orion.Nodes`, with SWQL (`SELECT TOP 1000 … WHERE NodeID > @after
  ORDER BY NodeID`), one page at a time until an empty page, so a monitoring estate
  of any size is read completely. There is **no incremental read**: `Orion.Nodes` has
  no modified-time (its `LastSync` moves on every poll), so each pull reads every
  node; re-reading a node that has not changed writes nothing. A node that is gone
  from the complete listing is marked absent, never deleted from Vista.
  Read: caption (display name), DNS name / SysName / caption (hostname, in that
  order), IP address, node description (description), location (site), and the node
  id (identity). Orion nodes carry no serial number, so none is read.
- **Classes a Pull assigns.** Orion has no class for a node, only free text. Vista
  reads `MachineType`, then `NodeDescription`, then `Vendor`, and the first that
  contains a recognised keyword decides:

  | Keyword in the node's text (examples) | Vista class |
  |---------------------------------------|-------------|
  | firewall, FortiGate, Palo Alto, ASA, Check Point | firewall |
  | load balancer, BIG-IP, NetScaler | load balancer |
  | wireless LAN controller, WLC | wireless controller |
  | access point, Aironet | access point |
  | router, ISR, ASR, MikroTik | router |
  | switch, Catalyst, Nexus, ProCurve | switch |
  | printer, LaserJet, JetDirect | printer |
  | NetApp, storage, NAS, Synology | storage device |
  | ESXi, Hyper-V, Proxmox | hypervisor |
  | Windows 10 / 11, macOS, workstation | workstation |
  | Windows Server, Linux, UNIX, Net-SNMP, … | server |
  | nothing recognised | hardware |

  A node nothing recognises is *hardware*, never a guessed server. What each kind
  becomes is the template's rule and can be changed with a class override; the
  keywords themselves are fixed.
- **Not read.** `Vendor` and `MachineType` describe the polling vendor and the
  operating system or model text, not the hardware manufacturer, so they are used
  only to classify and are not stored as hardware facts.

<a id="solarwinds-checks"></a>
*To check on a live Orion:* that `POST /SolarWinds/InformationService/v3/Json/Query`
with `{"query": …, "parameters": {"after": 0}}` is accepted on your SWIS port and
answers `{"results": […]}`; that the account can read `Orion.Nodes` and the columns
`NodeID, Caption, DNS, SysName, IPAddress, MachineType, Vendor, NodeDescription,
Location`; that a listing of more than 1000 nodes comes back in pages; and that the
classification of your real `MachineType` values matches what you expect.

**Oomnitza:**

*Verification status: **contract-tested against Oomnitza's published REST API (v3),
not verified against a live Oomnitza instance.** See
[what to check on a live instance](#oomnitza-checks).*

- **Set-up.** Base URL `https://acme.oomnitza.com`. Authentication is your **API
  token** — sent in the `Authorization2` header, not `Authorization` — or HTTP Basic.
  The token's user needs permission to read and create assets.
- **What Sync sends: infrastructure assets only.** Oomnitza is an IT-asset register;
  a certificate, key, crypto configuration or crypto library is not an asset, and
  sending them filled it with one "asset" per TLS configuration. Records pushed that
  way by an earlier version stay in Oomnitza — Vista does not delete them. To send a
  category again, add its class rule to the profile's mapping.
- **What Pull reads.** Every asset, page by page (`limit` / `skip`, 1000 at a time,
  until an empty page), so an instance of any size is read completely; a server that
  cannot page is detected rather than looped on. Oomnitza's listing has no
  last-modified filter that Vista relies on, so each pull reads every asset and Vista
  writes only those whose `last_modified` moved.
- Runs on the shared field mapping. A pull classifies each asset by its type
  (`asset_type`, `equipment_type` or `type`): Laptop → laptop, Desktop / Workstation →
  workstation, Server → server, Mobile Phone / Tablet → mobile, Printer → printer,
  Network Device / Switch / Router / Firewall / Access Point → the matching network
  class, Storage → storage device; a type it does not know is *hardware*. It identifies
  an asset by `equipment_id` (or `id`) and its `serial_number`, and reads the
  last-modified time from `last_modified`. Oomnitza deployments rename fields freely;
  a field your instance doesn't have is simply not read, and the profile's field
  mapping can point at the one it does.

<a id="oomnitza-checks"></a>
*To check on a live instance:* that `GET /api/v3/assets?limit=1000&skip=1000` returns
the next page (and `skip` past the end returns `[]`); the actual names of the type,
status and last-modified fields and the values that mean retired (the defaults above
are Oomnitza's common ones, unverified); and that a PATCH of `asset_name` / `notes`
to `/api/v3/assets/<id>` updates the asset.

**Pull limits:** none. A pull of any of the four platforms reads every record, page by page.

**Field mapping** (`field_mapping_config`) and **CI type mapping** (`ci_type_mapping`)
hold the profile's changes to the platform's default mapping — see
[Field mapping](#field-mapping).

## FAQ

**Q: Can I sync data from the CMDB back into the platform?**
A: Yes — use **Pull**, or a schedule (see [Pull Inventory From Your CMDB](#pull-inventory-from-your-cmdb)).

**Q: How many CMDB profiles can I create?**
A: There is no hard limit. You can create multiple profiles for different CMDB instances or even multiple profiles for the same platform (e.g., separate ServiceNow instances for different environments).

**Q: What happens if I delete a profile?**
A: Deleting a profile is a soft-delete. The profile and its entity mappings are retained in the database for audit purposes but are no longer active, and its schedule stops. Existing CIs in the CMDB are not affected. The name can be reused for a new profile.

**Q: Are credentials stored securely?**
A: Connection credentials are encrypted at rest. They are write-only: the platform never shows a stored password, API token, or client secret again — not in the UI and not in the API, which reports only whether each one is set. When you edit a profile, leave a secret blank to keep the current one, or type a new one to replace it. Viewing CMDB profiles requires the **View Settings** permission.

**Q: What entities are included in a push?**
A: Your approved infrastructure assets, plus the crypto configurations, certificates and keys in use on them — see [What a push sends](#what-a-push-sends).

**Q: Can I push only some entity types?**
A: Not today. A push sends every in-scope entity type.

**Q: What triggers a scheduled sync?**
A: The platform runs every enabled profile on an hourly, daily or weekly schedule once that interval has passed since its last scheduled run — see [Schedules](#schedules). Manual runs can be started at any time and don't move the schedule.

**Q: How do I know if a sync succeeded?**
A: The profile card shows the last run's time and status. For details, open **Sync history**: it lists recent runs with their counts, and each failed item with the CMDB's reason.
