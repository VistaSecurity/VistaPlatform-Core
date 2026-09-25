# Tenant User Guide

**Version:** 3.0
**Last Updated:** 2026-09

This guide walks through Vista Platform the way you actually use it: from the
left navigation rail outward, one section at a time, as a sequence of tasks. Each
part tells you where to click, what you will see, and links to the feature page
that carries the full detail.

It covers what a **tenant user** does day to day. Configuration that belongs to a
**Tenant Admin** — members and roles, connected systems, notification channels and
routing, retention, locations and network segments, billing — lives in the
[Tenant Admin Guide](./tenant-admin-guide.md), and this guide points there rather
than repeating it.

If a term is unfamiliar — asset, endpoint, class, relationship, fact, finding —
[Concepts](../concepts.md) defines the vocabulary the whole product uses.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Dashboard](#dashboard)
3. [Discovery](#discovery)
4. [Inventory](#inventory)
5. [Risk & Compliance](#risk--compliance)
6. [Remediation](#remediation)
7. [Global Search and Ask](#global-search-and-ask)
8. [Notifications](#notifications)
9. [Organization Settings at a Glance](#organization-settings-at-a-glance)
10. [My Profile](#my-profile)
11. [Troubleshooting](#troubleshooting)
12. [Support](#support)

---

## Getting Started

### First sign-in

You reach the console one of two ways:

- **An invitation email** from someone in your organization. Click the link, set
  a password, and you land on the Dashboard.
- **Self-service signup**, if your deployment offers it. You create the
  organization, verify your email address, and become its first administrator.

Either way, the first thing worth doing is the setup checklist — see
[The setup checklist](#the-setup-checklist) below.

### Signing in

The sign-in page asks for your **work email** first, then adapts to what your
organization allows.

**Password.** Enter your email, then your password, and continue. "Forgot
password" sends a reset link to your address.

> Single sign-on is an Enterprise capability. On a Core deployment, email and
> password is the only way in and the rest of this subsection does not apply.


### Finding your way around

The console has a **left navigation rail** with five sections, ordered as the
lifecycle of an asset:

| Section | What it is for |
|---|---|
| **Dashboard** | Where you stand right now — two heroes, a triage strip, and the lifecycle end to end |
| **Discovery** | Finding things: sensors and agents, jobs, devices, scans, the review queue, and file/cloud sources |
| **Inventory** | Everything the platform tracks, viewed through switchable **lenses** |
| **Risk & Compliance** | Posture, findings, and the evidence documents you hand an auditor |
| **Remediation** | Fixing what was found: alerts, the ticket queue, and plans |

Click a section to open it; its sub-navigation appears beneath it in the rail.
Inventory's sub-items are **lenses** — they all live at the same page and differ
by what they show.

**Settings** and **My Profile** are not in the rail. Click your account chip at
the bottom of the rail to open the profile menu:

- **Getting Started** — the setup checklist, shown while onboarding is in progress
- **My Profile** — your own account
- **Organization Settings** — everything your organization configures
- **About** — the running version and build
- **Switch to Light Mode / Switch to Dark Mode**
- **Sign out**

On a narrow screen the rail collapses behind a menu icon in the header; tap it
to slide the same navigation in, tap a link to go, and it closes itself.

### The setup checklist

**Profile chip → Getting Started** opens a short checklist that makes the
platform useful faster. It tracks three steps:

1. **Add network segments** — so discovery is scoped and results carry location
   and environment context.
2. **Add locations** — so assets can be organized by site or cloud region.
3. **Add an agent** — register a sensor or discovery agent so things start being
   found.

Each step has a button that takes you to the page that does it, and a way to mark
it done by hand if you already did it elsewhere. **Dismiss setup guide** hides the
reminders for you only; the page stays reachable from the profile menu.

The first two steps need settings permissions and the third needs permission to
register a sensor, so a read-only user is never nagged about them. Full detail:
[Getting Started](../features/getting-started.md).

---

## Dashboard

**Dashboard** is the standing answer to "how are we doing?" It has two heroes,
because two different people read this page: one cares about cryptographic
posture, the other about whether the inventory is any good.

### The cryptographic posture hero

The top band shows a **risk index out of 100** — the share of your assets sitting
at high risk — with the risk level beside it, and a sentence naming how many
critical findings are open across how many monitored assets. Under it, four
figures: **Assets**, **Configs**, **Critical**, and **PQC configs**.

Beside it, **Posture trend · 30 days** plots the same risk index over time; lower
is better. On the right, **External Exposure** counts observed third-party
connections and the internal hosts making them — click it to open the **3rd
Party** inventory lens.

### The inventory health hero

Directly beneath, **Inventory Health** answers the operations question. It leads
with the number of **configuration items** the platform tracks — everything, not
only the things that speak TLS — and two lifecycle counts you can click:

- **Pending approval** — discovered assets waiting for someone to accept or deny
  them; this links to Discovery → Approvals, the one review queue.
- **Stale** — assets not seen recently. Still in the inventory, still counted.

**By class** breaks the inventory down by asset class, with a **Topology** link
into the map's tenant-wide view. **Data Quality** shows your Inventory Hygiene
score with how many checks pass, fail, and were not assessed.

> A count that could not be loaded shows an em dash and "Couldn't load", never a
> zero. A reassuring zero on a failed read is the one thing this page must not
> say.

### Needs attention now

A strip of clickable tiles, prioritized across every section: **Critical
findings** (all producers), **High-risk assets**, **Certs expiring** within 30
days, **Unscored assets**, **Not PQC-ready**, **Not yet assessed**, and **Overdue
tickets**. Each opens the filtered list behind it.

### The lifecycle, end to end

Four stages — **Discovery**, **Inventory**, **Risk & Compliance**, **Remediation**
— each showing its own headline number (sensors online, crypto configurations,
critical findings, overdue tickets) and linking into that section.

Below that, **Certificate expiry outlook** and **Quantum readiness** give the two
supporting views most people come back for.

Full reference: [The Dashboard](../features/dashboard.md).

---

## Discovery

Discovery is how things get *into* the inventory. Everything under it either
finds assets, or decides what to do with what was found.

### Command Center

**Discovery → Command Center** is the section's front page. Four stat cards —
**Fleet online**, **Jobs running**, **Failed jobs**, **Pending approvals** — each
link to the page behind them, and two panels list your **Sensor fleet** and
**Recent jobs**.

Two buttons in the header start work immediately:

- **Discover assets** — opens the scan dialog (see below).
- **Import from spreadsheet** — brings in a CSV or Excel file of assets or
  network segments. See [Spreadsheet Import](../features/spreadsheet-import.md).

**To run a discovery scan:** click **Discover assets**, then

1. Type **Targets** — one per line or comma-separated; IP addresses, CIDR
   ranges, or hostnames, up to 1000.
2. Tick the **Protocols** to probe.
3. Set **Ports** (comma-separated) and an **Execution mode** — *Auto* lets the
   platform decide, *Cloud* runs it from the platform sensor.
4. Start it. The dialog shows progress; you can leave it running and check
   **Discovery → Discovery Jobs** later.

What it finds flows into your inventory automatically: hosts on a network segment
marked auto-approve are monitored straight away, everything else waits in
**Approvals**.

### Sensors & Agents

**Discovery → Sensors & Agents** is where the fleet lives. Two tables, because
they are two different things:

**Sensors** — the passive capture binaries deployed on your network. Columns:
Sensor, Type, Segment, Assets found, Version, Status. A coloured dot shows
online/offline based on the last heartbeat.

**Discovery agents** — the command-driven binaries that log in to network devices
(F5, Palo Alto, Cisco, Fortinet and so on) and read their configuration. The table
is hidden entirely if you have none. Columns: Agent, Host, Interrogates, Jobs,
Version, Status. **Host** is the address the agent reaches the platform from, plus
a count of the other addresses its host holds — hover for the full list with
network prefixes, which answers which segments the agent can actually reach.
**Jobs** shows when it last ran work and how many it has run; one that never has
reads "Never run".

> An agent that has stopped sending heartbeats shows as offline even when its
> stored status still reads *active*. The heartbeat is the truth.

**To register a sensor or agent:** click **Register sensor or agent**, fill in the
name and expected address, and generate a registration key. The installation
instructions that follow are platform-specific (Linux, Windows, macOS) and include
the key. Keys expire, so install before the countdown runs out or generate a new
one.

**Platform-managed sensors** appear in the list with a lock rather than a delete
button. They are shared platform resources — the in-cluster sensor and the
platform interrogation agent — and the discovery counts you see beside them are
your organization's alone. Deleting one is not offered, and would be refused.

**To remove a sensor or agent:** click the ✕ on its row and confirm. Removing an
agent revokes its certificate, returns its queued jobs to the pool for another
agent, and marks any job it was mid-way through as failed. It does **not**
uninstall the binary — stop and remove that on its host separately, or it will
keep trying to check in and logging rejections.

#### The sensor drawer

Click any sensor row to open its drawer. Four tabs (a platform-managed sensor
shows the first two only):

- **Overview** — status, last heartbeat, reporting interval, version, address,
  deployment (connected or air-gapped), uptime, monitored interfaces, and the
  sensor's certificate with its serial, issue and expiry dates.
- **Discoveries** — what this sensor has found: protocol, destination, port,
  confidence, timestamp.
- **Health** — current metrics plus a **History** chart over a range you choose.
  If the sensor reports them, a **Host observations** block shows **Hosts seen**,
  **Shed**, and **Accumulating now**: devices seen on the wire without connecting
  to them, each of which becomes a pending asset in Approvals. A non-zero *Shed*
  count means the segment is busier than the sensor is sized for — that is
  actionable, not cosmetic.
- **Control** — **Send command** queues a typed command with an optional JSON
  payload, and **Command history** shows every command sent, its lifecycle and
  its response.

Full reference: [Sensor Registration & Management](../features/SENSOR_REGISTRATION.md).

### Discovery Jobs

**Discovery → Discovery Jobs** lists every job: id, type, target, source, how many
assets it found, duration and status. A failed or cancelled job can be **retried**
from its row; a running one can be **cancelled**. Click a row for the run detail.

### Devices

**Discovery → Devices** lists the assets you have given the platform credentials
for, so it can log in and read their cryptographic configuration directly. Every
device here is also an asset in Inventory — this page is where its *management*
settings live.

Columns: Asset, Management address, Class, Interrogator, Firmware, Last
interrogated, Connection. Per row you can **open the asset's page**,
**interrogate** it now, **test the connection**, **edit its management settings**,
or **stop managing** it.

**Add device** adds to the list: give the device type, management address,
username and password, and the platform connects and fills in the rest. If it
can't connect, the form says why and lets you add the device by hand.

> **Stop managing is not delete.** It removes the management configuration and its
> credentials. The asset stays in Inventory with everything ever discovered about
> it. An asset discovered through a cloud integration has no management
> credentials, so interrogate and test are unavailable on it.

See [Device Interrogation](../features/device-interrogation.md) and the
[Device Interrogation Guide](./device-interrogation-user-guide.md).

### Active Scan

**Discovery → Active Scan** lists assets that have **never been actively
scanned** — typically ones that arrived by import, by SBOM, or from a CMDB. Run a
TLS probe to catalogue and verify their cryptography; the results flow back
through the normal discovery pipeline.

Click **Scan** on a row, or **Scan all** in the header. When every active asset
has been scanned at least once, the page says so and stays empty until something
new arrives.

### Scheduled Scans

**Discovery → Scheduled Scans** turns interrogation into a recurring job. Click
**New schedule** and give it:

- a **Name** and optional **Description**,
- a **Cron expression** — standard five fields, for example `0 2 * * *` for daily
  at 02:00,
- a **Target type** and target: a specific device, or a cloud integration.

From the list you can **run a schedule now**, **edit** it, toggle it on and off,
or **delete** it. The target is fixed once a schedule is created — to point at
something else, create a new one.

### Approvals

**Discovery → Approvals** is the hinge between Discovery and Inventory, and it is
the **one queue for every proposal**. Nothing waits for review anywhere else.

A **Source** facet across the top says where each item came from, which is the
first thing worth knowing because it decides how much scrutiny is owed:
**Discovered** (a sensor or scan saw it), **Imported** (spreadsheet),
**Declared from SBOM upload**, **Pulled from CMDB**, **Proposed by matcher**,
**Proposed by classifier**, **Proposed by assistant**. Click a chip to filter;
**Clear** removes the filter.

Four kinds of row can be waiting:

**Discovered assets.** A table of things found but not yet admitted: name,
address, class, segment, source, confidence, when it was found. **Accept** admits
it — and materializes its deferred certificates and crypto configurations into
Inventory. **Reject** denies it and suppresses rediscovery. **Accept all** (or
"Accept these *n*" when a source filter is on) decides the whole visible set at
once.

**Merge proposals.** "This looks like something you already have." The matcher
thinks a new sighting and an existing asset are the same thing, and shows you the
candidates with a match percentage and the identifiers they share. Pick the
surviving asset and click **Merge** — the survivor's History records what was
merged in. **Keep separate** says they are different things; the matcher will not
propose it again, and the discovery goes back to waiting for ordinary approval.

**Relationship proposals.** A claim that two assets are connected in a particular
way, read left to right: this → relationship → that, with a confidence bar and how
many times it was observed. **Accept** confirms it, and it starts counting in
impact analysis. **Reject** records the decision so the same claim is not proposed
again. See [Relationships](../features/relationships.md).

**Class proposals.** A claim about what an asset *is*: current class → proposed
class. Where the evidence was ambiguous you get **Candidates** to choose between
before accepting. Accepting sets the class and records which rule — or which
model — decided it. Rejecting stops that class being proposed again.

**Auto-merged by the matcher.** If your organization has raised the auto-accept
threshold above zero, this section lists merges that already happened inside the
recent window, each with its score and the matcher's reasons. It is deliberately
not a queue: there is nothing to decide, no buttons, and **no way to reverse one
from here**. A **Change the threshold** link goes to the setting that allowed it.
On the default threshold of zero the section does not appear at all.

> If one of these reads fails, the page tells you so instead of showing an empty
> section. "Nothing awaiting review" is a claim about the whole queue, and it is
> only made when every read succeeded.

Full detail: [Asset Approval](../features/asset-approval.md).

### Job Logs

**Discovery → Job Logs** is the run stream: every job with its short id, status,
when it started, what type it was, what it was pointed at, what it found, and how
long it took. Failures show their error message inline. Click any entry for the
full run detail.

### Sources

**Sources** is a group in the rail, not a page. Three ways to bring data in that
are not a sensor:

#### Cloud

**Discovery → Cloud** connects AWS, Azure and GCP accounts and discovers the
cryptographic assets in them. Add an integration, then from its row: **run
discovery now**, **test connection**, **edit**, or **remove**.

Each provider asks for its own credentials — for AWS, a role to assume or an
access key; for Azure, its tenant and client details; for GCP, a project and
service-account key. See [AWS](../features/aws-cloud-discovery.md),
[Azure](../features/azure-cloud-discovery.md) and
[GCP](../features/gcp-cloud-discovery.md).

#### PCAP Upload

**Discovery → PCAP Upload** takes a packet capture and extracts cryptographic
configurations from the handshakes in it. Drop a `.pcap` or `.pcapng` file on the
zone, or click **Choose file**. **Recent uploads** underneath shows each file with
its size, packet count, how many discoveries it produced, and when.

This is the route for a segment no sensor covers — a capture taken elsewhere
becomes inventory. See [PCAP Ingestion](../features/pcap-ingestion.md).

#### SBOM Upload

**Discovery → SBOM Upload** takes a bill of materials — CycloneDX JSON 1.4–1.7 or
SPDX JSON 2.2/2.3, up to 32 MB — and turns its components into software inventory.
The format is read from inside the document, not from the filename.

First say **where the document belongs**:

- **An existing asset** — the host, container or application this software runs
  on. Search for it by name and pick it.
- **Create an application asset from the document** — the artefact the document is
  about becomes an application asset, waiting for approval. Uploading the same
  artefact again lands on the same asset rather than making a second one.

Then drop the file or click **Choose a document**. When it finishes you get a
summary, a link to the asset's **Software** tab, and — if the upload created an
asset — a link to Approvals. Anything skipped is listed with the reason.

See [SBOM Upload](../features/sbom.md).

---

## Inventory

**Inventory** is one list of everything, reshaped by **lenses**. The lenses are
grouped in the rail exactly as they are here.

| Group | Lenses |
|---|---|
| **Assets** | All assets · Map · Software |
| **Cryptography** | Certificates · Keys · Configuration · TLS · SSH · Data Protection · 3rd Party |
| **Lifecycle** | Stale · Pending (a cross-link to Discovery → Approvals) |

**Pending** carries an arrow because it leaves the section: pending assets are
reviewed in Approvals, and a second queue here would be a second inbox.

Reference: [Inventory & Lenses](../features/inventory-and-lenses.md).

### All assets

The default lens, and the one that answers "what is out there". It has three
controls above the table and a facet rail beside it.

**The filter rail** (left) builds the query for you. Facets: **Class**,
**Status**, **Environment**, **Site**, **Segment**, **Owner**, **Business unit**,
**Tag**, **Risk**, **Provenance**, and a findings toggle. Each value carries its
own count.

- **Class** is a tree. Picking *Hardware* selects everything beneath it; drill
  down to *Server* to narrow. Only one class at a time — the taxonomy is a
  hierarchy, and a multi-select over it reads as nonsense.
- **Status** is Monitoring / Pending approval / Denied / Archived.
- **Risk** bands are Critical, High, Medium, Low, Informational and **Not
  assessed** — a separate band, because "we have not scored this" is not the same
  claim as "this is fine".
- **Provenance** is how the class was decided: **Discovered** (something measured
  it), **Declared**, **Imported**, **Proposed**.

Values within one facet are OR-ed; different facets are AND-ed.

**The query box** (top) holds the same thing the rail writes, in one readable
line. You can type in it directly: it autocompletes fields, operators and values,
and a query it cannot parse tells you *where* it is wrong and what to write
instead, rather than just "invalid". The rail and the box are never two different
filters — the query is the state, and the rail is a way of writing it.

**Query applied.** Under the box, the predicate the *server* actually ran. It is
often not identical to what you typed, because the read path adds its own default
scope — `status:monitoring`, which steps aside as soon as your query names a
status itself. When the two differ you get a **not what you typed** marker
explaining why. This is how you find out that the asset you expected is missing
because it is still pending approval.

**Saved views** (the **Views** button) name a query so you can come back to it, or
share it. Build a filter, open the menu, and choose **Save current query…** — give
it a name and decide whether to share it with your organization. Shared views
carry a marker; only the owner can delete one. Only a query that parses can be
saved: a saved view is a predicate other people will run.

The language is documented in full at [Query](../features/query.md).

**Other controls.** **New asset** (top right) creates one by hand. The header
strip shows the running count, and a warning band appears above the table
whenever items are awaiting review, with a **Review** button into Approvals.

The empty state differs on purpose: a filtered no-match offers to clear the query,
while a genuinely empty inventory offers the three ways to get some — run a
discovery, import a spreadsheet, or add one by hand.

### The asset page

Click any row to open the asset. Overview lives at the bare URL and each other tab
deep-links, so the link you copy off the first tab is the short one. Seven tabs:

1. **Overview** — **Identity** (what this thing is called), **Identifiers** (every
   way it is known, each with its kind, value, source, confidence and when it was
   last seen), the **class attributes** for its class, **Risk**, **Context**
   (environment, business unit, owner, support group, location, segment),
   **Status**, and **Tags**.
2. **Services & Endpoints** — every network face it has: address, port, transport,
   service, exposure, status and last seen. An asset with no network face simply
   has none, rather than a fabricated port.
3. **Relationships** — what it is attached to, where each edge came from, and what
   is affected if it changes.
4. **Cryptography** — its cryptographic configurations, each drilling through to
   the protocol, cipher suite and certificate behind it.
5. **Findings** — what is open against it, and what was not assessed.
6. **Software** — what is installed, from a host agent or an uploaded SBOM.
7. **History** — reclassification, context edits, merges and approvals, recorded
   as they happen.

### The drawer

Clicking a row in a cryptography lens opens a **drawer** — the peek, rather than
the whole record — and the drawers stack: configuration → asset → certificate, so
you can drill in and close back out one layer at a time.

The asset drawer shows a risk gauge, the asset's identity and primary address,
its cryptographic configurations, and its details. **Open full page** is the way
out of the peek and into the asset page.

### Acting on an asset

From the asset drawer:

- **Active Scan** — probe this asset now and catalogue its TLS cryptography.
  Results arrive once the probe completes.
- **Edit** — open the asset form.
- **Delete** — soft-delete. It leaves active inventory and can be restored.
- **Restore** — brings a deleted or archived asset back.

These need the matching permission; without it the button is simply not there.

### Adding an asset by hand

**New asset** opens a form whose shape is decided by the class you pick, so pick
that first.

1. **Class** — an indented list of the whole taxonomy. What you choose decides
   which attributes the asset has.
2. **Display name** — what a person calls it. Usually optional, because the
   platform derives one from the identifiers. For a **service** class it is
   **required**: a service identifies by its name, having no address or serial to
   be known by.
3. **Identifiers** — the ways this thing can be recognised later, so a future
   sighting updates it rather than creating a second copy. You can enter
   hostnames, FQDNs, IP addresses, MAC addresses, serial numbers, CMDB sys ids,
   SSH host key fingerprints and names. Two kinds are **collector-minted** —
   agent id and cloud resource id — and cannot be typed: they are identities the
   platform assigns, and being able to type one would let two real assets be
   merged into one by hand with nothing to review.
4. **Class attributes** — the fields that class declares.
5. **Context** — Environment, Support group, Business unit, Owner email.
6. **Description**, **Tags**, and optional **Metadata (JSON)** for anything the
   class schema does not cover.

Click **Create asset**. If you ask to remove an identifier the platform must keep,
it is kept and you are told which and why, rather than the removal quietly failing.

Editing an existing asset uses the same form, and the class is changeable —
reclassifying something that was wrongly classed is an ordinary correction, and
the History tab records it.

### Uploading a certificate

**Upload cert** (in the header of the cryptography lenses) adds an X.509
certificate by PEM — useful when no sensor covers the thing that presents it.
Switch between **Upload file** and **Paste PEM**, drop or paste the certificate
(a chain, leaf first, is accepted; 1 MiB maximum), set its ownership, and upload.
The certificate is authoritative: its cryptographic details are extracted from it
server-side rather than typed.

An uploaded certificate shows as **Unassigned** in the Certificates lens until it
is linked to an asset. See
[Certificate Chain Management](../features/certificate-chain-management.md).

### The cryptography lenses

Each has its own shape, a search box, and an **Export** button for the current
view.

- **Certificates** — every certificate, including ones uploaded by hand, with an
  **Ownership** filter (3rd-party / Internal / Unknown).
- **Keys** — the key inventory: key, algorithm, state, expiry, and **Used by**,
  which counts the assets using it ("Unlinked" when none). The drawer drills
  through to the using asset. See
  [Cryptographic Keys](../features/cryptographic-keys.md).
- **Configuration** — negotiated cryptographic configurations, grouped by the
  numeric risk bands Critical, High, Medium, Low and Informational, with **Not
  assessed** as its own group when no numeric evidence establishes a score.
  Filters for Environment and Risk band. The catalogue's qualitative strength
  is separate evidence and is not derived from the numeric score.
- **TLS** and **SSH** — the same configuration lens, narrowed to one protocol.
- **Data Protection** — at-rest posture across the resources that store data,
  with **Resource type**, **Assessment** and **Risk** filters. Each row names the
  key-custody rung it sits on.
- **3rd Party** — outbound connections your assets make to SaaS, partners and
  APIs. A connection you decide to track like an internal asset can be
  **promoted**: click the promote control, confirm **Elevate to managed?**, and it
  joins managed inventory. See
  [Third-Party & External Connections](../features/third-party-and-external-connections.md).

### Map and Software

**Map** has two views, switched at the top of the page:

- **Neighbourhood** — an interactive graph around one focus asset, up to three
  hops, with the impact overlay and a GraphML/Cytoscape export. It also opens full
  screen, which returns you to the lens carrying your depth and selection rather
  than resetting.
- **Topology** — the tenant-wide "where is everything", as a site → segment →
  class tree with counts.

**Software** is anchored on the *product*, not the asset: it answers "who runs
this version of this thing?" Columns for product, vendor, version, end of life,
vulnerabilities, identifier, licence, last checked, and the number of assets. Sort
by any of them, search across name, vendor, Package URL and CPE, and click through
to the assets. An **Upload SBOM** link sits in its header.

See [The Map](../features/map.md) and [SBOM Upload](../features/sbom.md).

### Stale

**Inventory → Stale** lists assets not observed for more than **30 days**. That
number is the product's one definition of stale: the lens, the hygiene finding and
the compliance control all mean the same thing by the word.

Per row: **Rescan** (queue a revalidation job for that asset) and **Archive** (set
its lifecycle to archived). A header bar acts on the whole current page —
**Revalidate all** and **Archive all**, the latter behind a confirmation that says
what archiving does: archived assets drop out of active inventory and reporting,
discovery can resurface them, and you can restore one individually from its
drawer.

Thresholds and auto-archive behaviour are set by a Tenant Admin under
**Settings → Policies → Asset Lifecycle**. See
[Asset Lifecycle Management](../features/asset-lifecycle-management.md).

### Exporting what you are looking at

Every lens has an **Export** button that writes the rows currently on screen to
CSV, built in your browser from what is already loaded — no round trip, no
template.

> **A page export is convenience, not evidence.** For audit-grade output with
> provenance, a content hash and a fixed scope, generate a bill of materials
> instead (see below). Detail: [Page-Local Exports](../features/page-local-exports.md).

---

## Risk & Compliance

### Posture

**Risk & Compliance → Posture** carries three views, switched from the rail:
**Overview**, **Frameworks** and **Algorithm Reference**. The last two exist so a
verdict is never a black box — you can always read why the platform rates
something the way it does.

#### Overview

A gauge for the share of assets at high risk, **Posture trend · 30 days**,
per-framework standing for each framework you have activated, a **Control posture
grid**, and **Highest-priority exposures** ranked for you.

#### Reading a control result

On the control grid — and on each group under **Findings → By Control** — every
control shows one of three results:

- **PASS** — the control was checked and nothing in scope violated it.
- **FAIL** — the control was checked and something violated it. One violation is
  enough, whatever its severity.
- **Not assessed** — the control was not checked, so no claim is made either way.
  Hover it to see why: no measurement rule configured, nothing in scope to check,
  or the check itself failed.

Severity (Critical / High / Medium / Low) rates *how much a failure matters* — it
labels each finding and weights the score — but it never decides pass or fail.
Scores cover assessed controls only and are shown with a coverage line such as
*"8 of 11 controls assessed"*. A framework with nothing assessed shows **—**,
never 100%. Controls that could not be evaluated are left out of the score
entirely: they neither reward nor punish you.

#### Frameworks

Browse compliance frameworks and, crucially, what each one actually measures. The
view opens on **My frameworks** — the ones you have activated, which drive your
compliance score — and an **All published** toggle reveals the full catalogue,
each with a preview score showing what you would score against it today. Open a
framework to see its controls; expand a control to read its measurement in plain
language (for example, *"Passes when RSA key size is at least 2,048 bits"*).
Nothing is marked failing without a rule you can read here.

Activating and deactivating frameworks is a Tenant Admin job, under
**Settings → Policies → Compliance Frameworks**.


#### Algorithm Reference

A read-only catalogue of every cryptographic algorithm the platform knows about,
with our assessment of each. Search or filter by **strength** (recommended /
strong / acceptable / weak), **status** (current / deprecated / obsolete), or
**quantum** (post-quantum vs classical). Click an algorithm for its strength,
deprecation and post-quantum status, risk score, migration guidance, and the
specific alternatives to move to. This is the same rating used to flag risk across
your inventory — so when something is marked "weak", this is where you see why.

See [Algorithm Reference](../features/algorithm-reference.md) and
[Framework Transparency](../features/framework-transparency.md).

### Findings

**Risk & Compliance → Findings** is every open problem, from every producer.

#### Lenses

The rail groups the lenses by what they read:

**Platform findings** — the one findings table, every producer:

- **By Producer** *(the default)* — the only lens that shows every producer's
  findings without a framework in the way, and therefore the home of end-of-life
  and vulnerability findings. The producers are **Compliance**, **Cryptography**,
  **End of life**, **Vulnerability**, **Configuration**, **Inventory hygiene** and
  **Drift**.
- **By Framework** — grouped by the frameworks you have activated.
- **By Control** — grouped by control, with each control's pass/fail/not-assessed
  result.

**Crypto findings** — the cryptographic-risk stream, a different data set:

- **By Severity**, **By Asset**, **By Category** (protocol / algorithm / key size
  / certificate), **By Date Observed**.

> The two scopes are counted separately and labelled, because switching between
> them changes the number on screen. That is not a counting bug: they are
> different sets.

#### Filtering

Above the list: a filter box, and segment chips for **Open**, **Critical +
High**, **Mine** and **Unassigned**. A **producer facet** gives one chip per
registered producer with its count under the current filters — a producer with no
findings shows a zero rather than disappearing, because zero is an answer.
**Export** writes the current view to CSV.

Arriving from a link that narrows to one subject or severity shows a banner saying
so, with a way to clear it — a page that is filtered always says it is filtered.

#### The inspector

Click a finding to open the inspector. It carries the finding's evidence and, for
some kinds, the same issue found elsewhere on your network, with a way to raise
tickets for the set at once. Advisories and, for drift findings, a
**Baseline / Observed** comparison appear where they apply.

The **Workflow** block is where you act:

- **Status** — **New**, **Notified**, **Resolved** or **Suppressed**. Choosing
  Suppressed asks for a suppression reason before it is applied.
- **Assignee** — assign the finding to a member of your organization, or leave it
  unassigned.
- **Create ticket** — opens a remediation ticket pre-filled from the finding. It
  lands in **Remediation → Queue**.
- **Add to plan** — attach it to an existing remediation plan, or create a plan
  and add it in one step.
- **Override control (justified exception)** — for compliance findings only.
  Disregards that control in future evaluations. A rationale is required and is
  audited.

The **Remediation** block above it always shows the standard guidance for that
kind of finding — in every edition, with no model involved.


Full reference: [Findings](../features/findings.md).

### Bills of Materials

**Risk & Compliance → Bills of Materials** produces the documents you hand an
auditor: immutable, dated, content-hashed snapshots of what matched a scope at the
moment of generation.

#### The four kinds

| Kind | What it contains |
|---|---|
| **Cryptographic (CBOM)** | Certificates, algorithms, protocols, keys and crypto libraries |
| **Software (SBOM)** | Every distinct software product installed, and the assets it was found on |
| **Hardware (HBOM)** | Every hardware asset, with vendor, model, serial and firmware |
| **Full inventory** | Every asset with its endpoints, relationships, facts and open vulnerabilities |

All four share one pipeline: the same scope, the same content hash, the same
comparison.

#### Generating one

Click **Generate** and choose:

- **Kind** — one of the four above.
- **Scope** — the boundary the artifact attests to. Scopes are named, versioned
  asset definitions managed under **Settings → Policies → Scopes**; see
  [Scopes](../features/scopes.md).
- **Name** — optional. For an audit submission, name it after the engagement.

The artifact captures the scope's exact version, so it stays reproducible even
after the scope is later edited.

#### The list

Each row shows name, scope, kind, when it was generated, entry count and size.
Filters for kind and scope sit above. Click a row for the artifact drawer.

#### Downloading

**Download** offers the formats that kind supports:

- **CycloneDX 1.7** — the canonical bytes, and what the content hash covers.
  Available for every kind.
- **OCSF 1.9 events** — JSON Lines for a SIEM: one Device Inventory Info per
  asset, one Vulnerability Finding per CVE. Offered for the **full inventory**
  kind only, because it is the only one with devices and CVEs to project.


#### Verifying

**Verify** in the artifact drawer recomputes the content hash (and the signature,
where there is one) and reports the verdict. This is how you prove an artifact you
were handed is the one that was generated.

#### Deleting

**Delete** soft-deletes an artifact. The row stays, so a comparison that referenced
it shows "deleted" rather than a dead end.


Reference: [Bills of Materials](../cbom/xbom.md) and
[CBOM Artifacts](../cbom/cbom-artifacts.md).

---

## Remediation

### Alerts

**Remediation → Alerts** is the inbox. Summary cards count **Acknowledged**,
**Snoozed** and the rest; a severity filter and status filters narrow the list.

Each row names the alert, its type, its severity, and its **subject** — the thing
the alert is about. Where the subject has a page of its own, it is a link: an
asset goes to the asset page; a software install or a crypto configuration goes to
Findings narrowed to exactly that subject; a control goes to the control lens; a
certificate goes to the Certificates lens. Where there is no honest destination
the subject is plain text, because a link that lands on an empty page reads as
"nothing is wrong here" — the one thing it must never say.

**Working an alert.** Per row:

- **Acknowledge** — you have seen it.
- **Snooze** — put it aside until a time you choose, with a reason.
- **Unsnooze** — bring it back now.
- **Resolve** — close it, with a resolution note.
- **Create ticket** — turn it into remediation work in the Queue. A row whose
  ticket already exists links straight to it.

Click a row for the detail panel: the full message, the subject, and who
acknowledged, snoozed or resolved it and when.

**What raises an alert.** These are the types that can open against your
organization:

| Alert | Raised when |
|---|---|
| **Certificate expiring** | A certificate is approaching, or past, expiry. One alert per certificate, escalating as expiry nears. Activated compliance policies can add earlier rungs. |
| **Control noncompliant** | A control in an activated framework went noncompliant. One alert per control, with the affected-asset count — not one per asset. |
| **Compliance score drop** | A framework's score fell more than 10 points in 24 hours. |
| **Hygiene score drop** | Your Inventory Hygiene score fell more than 10 points in 24 hours. Split out from the above because data quality is worth routing — and silencing — separately from security posture. |
| **Known vulnerability** | An installed software product matched the vulnerability catalogue. |
| **End of life** | Something on an asset passed, or is approaching, the date its vendor stops shipping fixes — its operating system, its hardware, or an installed package. |
| **Drift detected** | Something about a subject changed relative to its recent baseline: a new device class on its segment, a protocol it has not spoken before, a different set of listening ports, a certificate from an unfamiliar issuer. Drift is not automatically bad — most are planned changes, and resolving the finding is how you tell the baseline so. |
| **Sensor offline** | A sensor stopped reporting, or registered and never reported at all (after a 15-minute dwell — measured from the last heartbeat, or from registration if there has never been one, so a sensor whose install silently failed is not invisible). Sensors marked air-gapped, pending or inactive are not expected to check in and do not raise this. |
| **Discovery agent offline** | A discovery agent stopped reporting, or registered and never reported at all (same dwell, measured the same way). Agents switched to inactive do not raise this. |
| **Discovery job failed** | A discovery job failed. |
| **Failed login burst** | Multiple failed sign-in attempts in a short window. |
| **Asset limit approaching** | Asset usage is nearing your plan limit. |

Most resolve themselves when the condition clears — a renewed certificate is
observed, a heartbeat arrives, the next run succeeds, the finding stops being
detected.

Which alert types are enabled, and where they are delivered, is configured by a
Tenant Admin under **Settings → Notifications & Alerts**.

### Queue

**Remediation → Queue** is the single ticket queue: every remediation ticket in
your organization, whatever raised it.

Five cards across the top double as filters: **Open work**, **Overdue**, **Due
soon**, **Resolved**, and **Keeping pace** — the share of open work still on track.
Click a card to filter to it, click again to clear.

The table lists ticket, category, external reference, SLA state and due date.
Click a ticket for its drawer: description, due date, assignee, what it is linked
to, and a threaded **Comments** section (⌘/Ctrl + Enter posts). Status changes are
made from the drawer.

Categories are compliance, certificate, remediation, vulnerability, operational
and general — each able to link back to the asset, certificate, configuration or
finding it came from.

### Plans

**Remediation → Plans** groups related work into one initiative — a post-quantum
migration, a protocol deprecation, a certificate replacement programme — and
tracks it as a whole. Click **New plan**, give it a title, and add findings to it
from the findings inspector (**Add to plan**). A plan's detail view shows its
steps and its progress.

See [Remediation](../features/remediation.md).

---

## Global Search and Ask

Press **⌘K** (Mac) or **Ctrl+K** (Windows/Linux) anywhere, or click the search
icon in the header, to open the command palette.

**Search** is the default. Type two or more characters to search assets,
certificates, devices and sensors at once; results are grouped by type. With the
box empty it lists the pages you can jump to. Navigate with ↑↓, open with
**Enter**, close with **Esc**, and ⌘K toggles it.


Full reference: [Global search](../features/global-search.md).

---

## Notifications

### The bell

The bell in the header carries a count of unread notifications. Open it for the
recent list, mark one read by clicking it, or **Mark all read**. Two links at the
bottom go to **View alerts** and **View delivery history**.

### Your own preferences

**My Profile → Notifications** controls what reaches *you*, within what your
organization has configured.

**What you're notified about** — per-category switches: Security findings &
alerts, Sensors & discovery, Billing & subscription, System & maintenance, CBOM &
compliance evidence, Members & access changes.

**How it reaches you** — **In-app** and **Email** switches, plus a **Frequency**:
Immediate, Hourly digest, or Daily digest.

Click **Save changes** to apply.

> You choose *what* and *how often*. The channels themselves — Slack, email,
> PagerDuty, a webhook — are configured for the whole organization, as are the
> routing rules that decide which events reach which channel and the alert rules
> that decide what raises an alert in the first place. Those live under
> **Settings → Integrations** and **Settings → Notifications & Alerts**, and are
> covered in the [Tenant Admin Guide](./tenant-admin-guide.md).

---

## Organization Settings at a Glance

Reached from the profile chip → **Organization Settings**. What you see depends on
your permissions and your edition; the detail for each is in the
[Tenant Admin Guide](./tenant-admin-guide.md).

| Group | Pages | In one line |
|---|---|---|
| **Organization** | Overview, Branding | Organization metadata, and white-labelling the console |
| **Account** | Usage & Limits, Billing | Consumption against plan limits, and (on the commercial editions) the subscription itself |
| **People & Access** | Members, Roles & Permissions, Security & SSO | Who is in the organization, what each role grants, and how people sign in |
| **Integrations** | Integrations, AI assistant | Connected systems — CMDB/ITSM, messaging, storage, SIEM — and which AI capabilities are on |
| **Notifications & Alerts** | Routing Rules, Alert Rules, Delivery History | Which events reach which channel, what raises an alert, and what was actually sent |
| **Policies** | Compliance Frameworks, Custom Policies, Asset Lifecycle, Scopes, Classes, Identification rules | The rules the platform applies to your data |
| **Audit** | Audit | Search and export the full trail of who did what, when |
| **Infrastructure** | Locations, Network Segments | The physical/cloud location registry and the network boundaries discovery scopes against |

Some of these belong to the commercial editions and are simply absent from the
rail on a Core deployment: **Billing**, **Security & SSO**, **Custom Policies**,
and SIEM export among the integrations. Core has local users, invitations, roles
and the free frameworks, with no subscription to manage.

Three pages are worth knowing about as a user even though you may not administer
them:

- **Policies → Scopes** defines the asset boundaries a bill of materials attests
  to ([Scopes](../features/scopes.md)).
- **Policies → Classes** browses the asset class taxonomy and the attributes each
  class carries — which is what the New asset form is built from.
- **Policies → Identification rules** shows how a new sighting is matched to an
  existing asset, and whether a high enough match may be accepted without you.
  That setting is what fills the **Auto-merged by the matcher** section in
  Approvals.

Billing, retention, locations and network segments are administrator work; the
[Tenant Admin Guide](./tenant-admin-guide.md) covers each.

---

## My Profile

Reached from the profile chip → **My Profile**. Six pages.

### Personal

Your identity. Edit **First name**, **Last name** and **Timezone**, and **Save
changes**. **Upload photo** takes a JPEG, PNG, GIF or WebP up to 5 MB and applies
it immediately.

**Email** and **Role** are shown but not directly editable: changing your email
requires confirming a link sent to the new address, and your role is assigned by
your organization's admins under **Settings → Members**.

**Your data → Export** downloads everything the platform holds about you, as a
file you can keep.

### Security

**Password** — enter your current password, a new one (8 characters minimum) and
the confirmation, then **Change password**. You may be signed out afterwards and
have to sign in again.

**Multi-factor authentication** — an authenticator app with backup codes is on the
roadmap and will be enrolled from here. It is not available yet, and the page says
so rather than offering a control that does nothing.

**Account status** — whether your account is active, when you joined, and your
last sign-in.

### Notifications

Covered under [Notifications](#notifications) above.

### Sessions & Devices

Every active session: device, IP address, last active, and when it was signed in.
Your current session is marked. **Revoke** ends one session; **Revoke other
sessions** ends every session except the one you are using — the right move after
signing in somewhere you do not control.

### Connected Accounts


On a Core deployment there are no providers to link, so this page has nothing to
show.

### API Tokens

Personal access tokens for scripts and for the read-only MCP server. **New token**
creates one: name it, choose its scopes, and copy the value — **the full value is
shown only once**, so put it in a secret manager immediately.

The table lists name, prefix, scopes, created, expires, last used and status.
**Revoke** kills a token. Tokens carry a subset of read-only scopes, are owned by
you, and you may hold up to 25 active at a time. See
[API Tokens & MCP Server](../features/api-tokens-and-mcp.md).

> **Preferences** and **Accessibility** appear in the design but are not in this
> build, so they are not listed in the profile rail. Theme is switched from the
> profile chip menu in the meantime.

---

## Troubleshooting

**"I ran a discovery and the inventory did not change."**
New discoveries wait in **Discovery → Approvals** and are invisible to every lens
until accepted. Check the pending count on the Inventory header, or **Pending
approval** on the Dashboard's Inventory Health hero.

**"An asset I know exists is not in the list."**
Look at the **Query applied** line under the query box. The default scope is
`status:monitoring`, so anything pending, denied or archived is excluded until
your query names a status itself. Add `status:pending_approval` (or archived, or
denied) to see it.

**"Two records exist for the same thing."**
That is what merge proposals are for — check **Approvals**. If no proposal was
raised, the two records may share no identifier the matcher can compare; add one
to each from the asset form, and the next sighting should link them. See
[Asset Approval](../features/asset-approval.md).

**"An asset was merged and I did not approve it."**
Check **Approvals → Auto-merged by the matcher**. If the section is there, your
organization's auto-accept threshold is above zero. The **Change the threshold**
link goes to the setting. There is no way to reverse a completed auto-merge from
that page.

**"A sensor shows offline but the process is running."**
Offline is decided by the heartbeat, not by the stored status. Check the sensor
drawer's **Health** tab for the last heartbeat and the reporting interval, and
confirm the host can reach the platform.

**"Host observations show a large *Shed* count."**
The segment is busier than the sensor is sized for, so observations are being
dropped rather than emitted. That is a capacity signal.

**"A compliance control says Not assessed."**
Nothing was claimed either way. Hover the result for the reason: no measurement
rule configured, nothing in scope to check, or the check failed. Not-assessed
controls are excluded from the score entirely.

**"My compliance score has not moved after fixing something."**
Evaluation is continuous but not instantaneous, and catalogue rule changes take a
few minutes to propagate. Check **Findings** for whether the finding cleared
before assuming the score is wrong.

**"A risk score reads 0."**
Zero means **not assessed** — nothing resolved against the algorithm catalogue and
no size or lifecycle rule fired. It is not a claim that the thing is safe. The
**Unscored assets** tile on the Dashboard lists these.

**"My saved views will not load."**
The menu says so and offers a retry; your views have not been deleted. If the
query box shows an error, a view can only be saved when the query parses — fix the
query and save again.

**"I cannot see a page or a button that the documentation describes."**
Two possibilities. It may be gated by **permission** — your role does not grant
it, and your administrator assigns roles under Settings → Members. Or it may be
gated by **edition** — the capability belongs to Enterprise, in which case a deep
link shows an upgrade card rather than a broken page.

---

## Support

- **In-product** — **About** (profile chip) reports the exact version and build
  you are running. Quote it in any report.
- **Concepts** — [Concepts](../concepts.md) defines every term this guide uses.
- **Feature guides** — the [documentation index](../README.md) lists a page per
  feature; each goes deeper than this guide does.
- **Administrator tasks** — [Tenant Admin Guide](./tenant-admin-guide.md), and
  your organization's administrators for access, roles, connected systems,
  notification channels and anything else under Organization Settings.

When reporting a problem, include what you clicked, what you expected, what you
saw, and the version from the About page.
