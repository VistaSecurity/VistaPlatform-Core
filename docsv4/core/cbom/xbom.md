# Bills of Materials — the four kinds

A bill of materials is a frozen, dated, content-hashed snapshot of everything
matching a [Scope](../features/scopes.md) at the moment you generate it. It is
what you hand an auditor, attach to a vendor questionnaire, or submit alongside
a regulatory filing.

The **CBOM** — the cryptographic one — was the first. There are now four, and
they are the same thing pointed at different parts of your inventory:

| Kind | What it contains |
|---|---|
| **Cryptographic (CBOM)** | Certificates, algorithms, protocols, keys and crypto libraries. See [CBOM Artifacts](./cbom-artifacts.md) for the detail. |
| **Software (SBOM)** | Every distinct software product installed on the assets in scope, and the assets each one was found on. |
| **Hardware (HBOM)** | Every hardware asset in scope, with its vendor, model, serial, UUID and firmware version. |
| **Full inventory** | Every asset in scope — typed by its class — with its network endpoints, its relationships to other assets, its collected facts, and its open vulnerabilities. |

All four share one pipeline: the same scope, the same content hash, the same
signature, the same comparison, the same CycloneDX format. Only the assembled
contents differ. That is deliberate — a separate document format per kind would
have meant four things to verify instead of one.

## Where to find them

**Risk & Compliance → Bills of Materials** in the primary nav, or directly at
`/risk-compliance/cbom`.

One list holds every kind. The **Kind** column says which each row is, and the
**Kind** filter narrows the list. The filter starts on "All kinds" on purpose —
an SBOM you just generated should not be hidden behind a filter you never set.

## Generating one

1. Click **Generate**.
2. Pick a **Kind**. Each card says in one line what that kind contains.
3. Pick a [Scope](../features/scopes.md) — the boundary the artifact attests to.
   Every artifact lives against exactly one, and records which *version* of it
   was in force.
4. Optionally name it. For an audit submission, name it after the engagement.
5. Click **Generate**. The snapshot is taken immediately and a new row appears.

The scope applies identically to every kind, so a CBOM and a full inventory of
the same scope always describe the same set of assets.

## What each kind contains, precisely

### Cryptographic (CBOM)

The crypto components discovered on the scope's assets: certificates with their
lifecycle state and extensions, the algorithms and cipher suites in use, the
protocol versions negotiated, the keys, and the crypto libraries that provide
them. This is the kind [CBOM Artifacts](./cbom-artifacts.md) documents in full.

### Software (SBOM)

One CycloneDX `library` component per distinct software **product**, not per
installation. A fleet of 500 hosts running the same OpenSSL is one component to
patch, not 500 rows — the hosts appear underneath it as
`evidence.occurrences`, one per (asset, install path).

Each component carries what the collector reported: name, version, vendor,
Package URL (`purl`), CPE, and licence.

An SBOM carries **no `dependencies` graph**. An installation record says a
product is present on a host; it says nothing about anything depending on it,
and an invented edge inside a signed document is worse than an absent one. If
you ingest a supplier's SBOM with real dependency data, that document keeps its
own graph — this is our inventory's view, not a replacement for it.

### Hardware (HBOM)

One CycloneDX `device` component per hardware-class asset. Membership is decided
by the asset's **class**, so what counts as hardware here is exactly what counts
as hardware everywhere else in the product.

Each component carries the asset's hardware facts (`hw.vendor`, `hw.model`,
`hw.serial`, `hw.uuid`, `hw.firmware_version`) and its identifiers. The
component's `version` is the firmware version, because on an appliance or an OT
device the firmware *is* the software and it is what a vendor advisory names.

An HBOM carries hardware facts only. Operating-system and software facts belong
to the other two kinds; including them would make an HBOM a full inventory
under a narrower name.

### Full inventory

Every asset in scope, as a CycloneDX component typed by its class — `device` for
a server or a switch, `platform` for a VM or a cloud resource, `application` for
an application or a managed database, `data` for an object store, and so on.

It also carries:

- **Endpoints as `services`.** Each reachable (address, port, transport) face of
  an asset becomes a CycloneDX service with the identified service name and
  version where one was measured. An endpoint with no identified service is
  named by its address and port — *not* by guessing a service from the port
  number, which is a convention rather than a measurement.
- **Relationships as the `dependencies` graph.** One entry per asset that has
  approved, active edges to other assets in scope. A proposed edge awaiting
  review is not included: signed evidence is not where a proposal becomes a
  fact. An edge pointing at an asset outside the scope is dropped rather than
  emitted as a reference the reader cannot resolve.
- **Facts and identifiers as `properties`**, under a `vista:` prefix. Where two
  sources disagree about the same fact, **both** are carried, each tagged with
  its source — the disagreement is real and flattening it would publish a
  reconciliation nobody performed.
- **Open vulnerabilities as `vulnerabilities`.**

### What is *not* in the vulnerabilities list

Only findings from the **vulnerability** producer become CycloneDX
`vulnerabilities` entries. Compliance control failures, end-of-life findings,
hygiene gaps, configuration findings and drift are all findings — none of them
is a CVE, and every tool that reads a CycloneDX document treats that array as
CVEs. A missing asset owner listed there would be read as a remote code
execution.

A vulnerability whose CVE the catalogue has not scored carries **no rating** —
not a score of 0.0. A zero in a ratings array reads as "scored, and harmless",
which is a different and much worse claim than "we have not scored this yet".

## Downloading

The **Download** control offers only the formats that artifact's kind can
actually produce:

| Format | Available for | Edition |
|---|---|---|
| **CycloneDX 1.7** (`.cyclonedx.json`) | every kind | Core |
| **OCSF 1.9 events** (`.ocsf.ndjson`) | full inventory only | Core |
| **SPDX 2.3**, **PDF** | CBOM only | Enterprise |

CycloneDX is the canonical form: it is the byte stream the content hash and any
signature cover, so a re-download always verifies.

Requesting a format a kind does not define returns a clear error naming the
kind, rather than an empty file. An empty OCSF stream for a CBOM would read as
"this tenant has no assets", which is a far worse answer than a refusal.

## OCSF export (full inventory)

The OCSF download turns a **full inventory** artifact into an event stream a
SIEM can ingest directly. It is **[OCSF](https://schema.ocsf.io) 1.9.0**, as
JSON Lines (`application/x-ndjson`, one event per line), and it is included in
every edition — a SIEM is where an operations team already works, and an export
that could not reach them would not be much of an export.

It is a projection of the **stored artifact**, not a fresh query. What your SIEM
ingests is exactly what the artifact's content hash covers and exactly what an
auditor verifying that artifact would see. Every event carries the artifact's
own generation timestamp — not the moment you clicked Download — so
re-downloading a snapshot does not look like a fresh observation.

Two event classes:

### Device Inventory Info — `class_uid` 5001

One per asset the artifact records as a CycloneDX *component* — which is every
asset except those whose class is a service (a business service, a technical
service). Those are in the artifact's `services` array, and OCSF 1.9.0 has no
inventory class for them: a business service is not a device, and reporting one
as `Device Inventory Info` with an unknown device type would put a category
error into a document your SIEM correlates on. They are in the CycloneDX
download.

| OCSF field | Source |
|---|---|
| `activity_id` / `activity_name` | `2` / `Collect` — a scope-driven snapshot is a collection, not a log |
| `category_uid` / `class_uid` / `type_uid` | `5` / `5001` / `500102` |
| `severity_id` / `severity` | `1` / `Informational` — an inventory record is not an alert |
| `time`, `metadata.original_time` | the artifact's generation time |
| `metadata.version` | `1.9.0` |
| `metadata.product` | `Vista Platform` / `Vista Security` |
| `metadata.correlation_uid` | the artifact's serial number — every event from one artifact shares it, so a SIEM can group a whole snapshot |
| `device.type_id` / `device.type` | the asset's class, mapped onto the OCSF device enumeration |
| `device.uid` | the asset id |
| `device.name` | the asset's display name |
| `device.hostname` | the asset's FQDN identifier, or its hostname identifier |
| `device.ip` | the asset's IP-address identifier |
| `device.mac` | the asset's MAC-address identifier |
| `device.domain` | the parent of the FQDN — only when the FQDN actually has one |
| `device.vendor_name` / `device.model` | `hw.vendor` / `hw.model` |
| `device.region` / `device.zone` | the asset's region / zone |
| `device.risk_score` | the asset's risk score |
| `device.first_seen_time` / `device.last_seen_time` | first discovered / last seen |
| `device.os.{name, version, kernel_release, cpe_name}` | `os.name`, `os.version`, `os.kernel`, `sw.cpe` |
| `device.os.type_id` | the OS name mapped onto the OCSF OS enumeration |

### Vulnerability Finding — `class_uid` 2002

One per vulnerability the artifact records.

| OCSF field | Source |
|---|---|
| `activity_id` / `activity_name` | `1` / `Create` |
| `category_uid` / `class_uid` / `type_uid` | `2` / `2002` / `200201` |
| `severity_id` / `severity` | the finding's severity, on the OCSF ladder |
| `status_id` / `status` | `1` / `New` |
| `finding_info.uid` | the finding id |
| `finding_info.title` | the CVE id |
| `finding_info.desc` | the advisory description, or the finding's summary |
| `finding_info.types` | the finding kind |
| `finding_info.{first_seen_time, last_seen_time}` | when the condition was first and last observed |
| `finding_info.src_url` | the advisory URL |
| `vulnerabilities[].cve.uid` | the CVE id |
| `vulnerabilities[].cve.cvss[]` | version, base score, vector and severity, from the mirrored catalogue |
| `vulnerabilities[].severity` | the finding's severity |
| `resources[]` | the affected asset — uid, name, class, hostname, IP |

### What OCSF export will never do

**An absent answer stays absent.** Where OCSF defines a field and the platform
has not measured it, the field is *not present* — not `""`, not `0`, not
`"Unknown"`. A SIEM rule correlating on `device.mac` cannot tell an empty string
from a value nobody observed, and a rule that fires on a measurement nobody made
is worse than one that never fires.

The one field that is always present is `device.type_id`, which OCSF requires.
An asset whose class has no counterpart in the OCSF device enumeration gets
`0` (**Unknown**) — not `99` (Other). "Unknown" says *we do not know*, which is
a statement about us and a true one. "Other" would say *OCSF does not model this
kind*, which is a statement about OCSF we are not entitled to make from a class
we simply have no mapping for.

The same rule governs the OS mapping: an operating system we do not recognise is
`0`/Unknown, never a guess. A firewall running PAN-OS or FortiOS has a real
operating system; reporting it as Linux because the name looks similar would put
a fabricated platform attribution into a document your SIEM correlates on.

## Comparing artifacts

Comparison is part of the Enterprise evidence layer; on Core the endpoint
answers **402 Payment Required** and the page shows an upgrade card.

It works for **every kind**, and it compares **like with like**: base and head
must be the same kind. The picker enforces it, and the API refuses a cross-kind
request. Two kinds identify their contents in completely different ways — a
certificate by fingerprint, an asset by its id — so a cross-kind comparison
would align nothing and report the entire base as removed and the entire head as
added. That output would be precise, confident and meaningless.

## Page exports are not evidence; artifacts are

The **Export** button on the Inventory page writes a CSV of the rows currently on
screen. It is a convenience: no provenance, no hash, no scope record, no date
beyond the file's own timestamp, and it contains whatever the page happened to be
filtering on.

An artifact is the opposite of all of that. It records the scope *and the scope
version* that were in force, the moment the inventory was read, a SHA-256 over
its exact bytes, and — on Enterprise — a signature over that hash. It is
immutable; regenerating tomorrow produces a second artifact and you keep both.

When someone asks you to prove what you had and when, generate an artifact. Do
not send a CSV.

## Frequently asked

**Does the kind change how the scope is applied?**
No. All four kinds resolve the scope through the same query, so a CBOM and a
full inventory of the same scope always cover the same assets.

**Why does my SBOM show fewer components than I have installed packages?**
Components are per *product*, not per installation. Open a component's
`evidence.occurrences` to see every asset it was found on.

**My HBOM is empty.**
An HBOM contains hardware-class assets. A scope made entirely of cloud
resources, applications or business services has none — which is a true answer,
not a fault. The full-inventory kind will show them.

**My inventory artifact has no vulnerabilities.**
Only the vulnerability producer's findings appear there. If the vulnerability
catalogue has not been mirrored yet, or no installed software matched an
advisory, the array is legitimately absent.

**Can I compare a CBOM against a full inventory of the same scope?**
No — see "Comparing artifacts" above. Generate the same kind at two points in
time instead.
