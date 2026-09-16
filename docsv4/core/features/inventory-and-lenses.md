# Inventory and Lenses

The **Inventory** page is the heart of Vista Platform. It's where every asset, certificate, cryptographic key, crypto configuration, and third-party connection your environment has discovered comes together in one place.

There is **one inventory** — a single dataset — and **lenses** reshape it. A lens doesn't take you to a different page or a different copy of the data; it re-angles the same underlying inventory so you see it the way the task in front of you needs. Auditing certificate expiry? Switch to the Certificates lens. Checking weak ciphers? Switch to Configuration. Tracking down assets that have gone quiet? Switch to Stale. Same data, different angle.

## Where to find it

**Inventory** in the left navigation rail. Its lenses are grouped into three:

| Group | Lenses |
|---|---|
| **Assets** | All assets · Map · Software |
| **Cryptography** | Certificates · Keys · Configuration · TLS · SSH · Data Protection · 3rd Party |
| **Lifecycle** | Stale · Pending (a link across to Discovery → Approvals) |

The active lens is in the page address (`/inventory?lens=…`), so a lens view is bookmarkable and shareable.

Every lens in that table is live. **Map** draws the neighbourhood around one
asset and **Software** answers "who is running this product, at this version?" —
both have their own pages ([The Map](./map.md), [SBOM upload](./sbom.md)) because
neither is a table with different columns.

**Pending** is a link, not a second list. Everything awaiting your review — discovered assets, imports, CMDB pulls and merge proposals — lives in one queue at **Discovery → Approvals**, and Inventory points at it rather than keeping a copy.

## All assets

The default view, and the general inventory. Every row is one **asset** — one *thing*, not one address or one open port. A host running five services is one row here, with its five endpoints on its own page.

### The class facet

Every asset has exactly one **class** — Server, Switch, Object storage, Web application, Business service, and so on — from a fixed taxonomy. The left rail shows that taxonomy as a tree with a count beside each class.

The tree is **hierarchical**, and picking a parent selects everything beneath it: click **Hardware** and you get servers, switches, firewalls and printers together; drill to **Server** and you get only servers. That is why there is one asset list rather than one page per class.

**The columns follow the class you pick.** Choose Server and you get operating system and model; choose Object storage and you get provider and account. Pick a parent class, or none at all, and the columns fall back to what everything shares — because a list mixing servers and switches has no common operating-system column to show.

To browse the taxonomy itself — every class, the attributes it carries, and what a class decides — see [Asset Classes & Identification Rules](./asset-classes.md).

### The other filters

Beneath the class tree: **Risk**, **Status**, **Provenance**, **Environment**, **Site**, **Segment**, **Owner**, **Business unit**, **Tag**, and **Findings**. Selections within one filter are combined with *or*; across filters with *and*.

Two of them deserve a note, because both are about the difference between "we looked and found nothing" and "nobody looked":

- **Risk → Not assessed** finds assets no producer has scored. That is not a low risk — it is the absence of a risk assessment, and on a fresh tenant it is usually the most useful slice on the page.
- **Findings → No open findings** finds assets that *were* assessed and came back clean. If you want the ones nobody has looked at, that is Risk → Not assessed, not this.

### The query box

Every filter you click writes into the **query box** at the top of the page, and the query is what actually runs. This is deliberate: the box shows you, in the platform's query language, exactly what your clicks mean — so you learn the language by watching the filters produce it.

You can also type in it directly, which is how you ask for things the checkboxes cannot express:

```
class:server and risk >= high and environment:production
class:hardware and risk:not_assessed
endpoint:(port:443 and protocol:tls)
tag.tier:gold and last_seen < now-30d
```

As you type, it suggests the fields and values that exist — it will only ever offer you something the platform accepts. If a query is wrong it underlines the exact word and says what is wrong with it, often with the correction:

```
environment:production and hostnaem:web-1
                           ^^^^^^^^
unknown_field: no field "hostnaem" on assets. did you mean "hostname"?
```

The query lives in the page address, so a filtered view is shareable: send someone the link and they see the same rows.

If you type something the filters can't represent — a relationship traversal, say — the rail tells you so and **keeps it**. Clicking a checkbox afterwards does not throw away what you typed.

### Adding something by hand

**New asset** (top right) records a thing you already know about — an appliance
nothing can scan, a business service with no address at all. The form asks for
the class first, because the class decides which fields it then offers you. See
[Adding assets manually](./adding-assets-manually.md).

On the Certificates lens the same corner also carries **Upload cert**, for
pasting or uploading a PEM.

### Saved views

**Views** (beside the query box) saves the current query under a name, for you and your team. A view is nothing more than its query, so applying one puts that query in the box where you can see it, adjust it, and save the result as another view.

### The Address column, and blanks in it

The **Address** column shows the asset's primary endpoint — its address, and its port when it has one.

Some assets have **no address at all**, and the column is genuinely blank for them. An object store or a declared business service has nothing to connect to. A blank here means "this thing has no network endpoint", not "we failed to find one" — and it is why you will never see a made-up port beside one.

## Opening an asset

From **All assets** and from **Stale**, clicking a row opens the **asset page** at
its own address (`/inventory/assets/…`), which you can link to. It has tabs:

| Tab | What's on it |
|---|---|
| **Overview** | Class and how it was decided; every identifier with its kind, source, confidence and when it was last seen; the class's attributes; ownership and context; status; and risk — with **who assessed it**, or an explicit *Not assessed*. |
| **Services & Endpoints** | Every network face of the asset: address, port, transport, the identified service and how confidently it was identified, and when it was last seen. |
| **Relationships** | What this asset is attached to — each edge with its type, its direction, where it came from, and whether it is confirmed or still proposed — plus the impact closure: what else is affected if this goes away. |
| **Cryptography** | The crypto configurations discovered on the asset. Click one for the full configuration drawer. |
| **Findings** | Cryptographic findings on this asset, with the configuration each was found on. |
| **Software** | The products installed on this asset — name, vendor, version, end-of-life state, known vulnerabilities, identifier, source, last seen and status. A product that has been removed is shown muted rather than dropped, because "it was here and is gone" is an answer. |
| **History** | Two lists. **Class history** first — every class this asset has held, what moved it, and who decided — then the general change log: context edits, merges, approvals, newest first. |

From the cryptography lenses — where the row is a certificate, a key or a
configuration rather than an asset — clicking through to an asset opens the
quick-look **drawer** instead, so you keep your place in the list you were
working. The asset drawer carries an **Open full page** button when the peek is
not enough.

### Class history: was this ever something else?

An asset's class decides a great deal — which findings apply to it, which
approval rules match it, which compliance measurements it is in scope for. So
when the class changes, everything recorded before the change was recorded about
a different kind of thing, and the question "was this reclassified?" is usually
the first one worth asking about a surprising result.

**Inventory → an asset → History** answers it. The *Class history* panel lists
every class the asset has held, newest first, and each entry says:

- **what moved** — the class before and the class after. The oldest entry has no
  "before": it is the class the asset was given when it was first discovered.
- **how** — *Set at discovery* (the classification rules or a collector decided
  it), *Accepted in Approvals* (a reviewer took a proposed class), *Edited by a
  person*, or *Stated by an import*.
- **who**, when a person was involved. Entries with no person were made by the
  platform; the panel names the mechanism rather than guessing at a user.
- **why** — the rules that argued for it, or the classifier and how confident it
  was.

An **empty panel does not mean the class has never changed.** It means nothing
has been recorded — which is what you will see for assets discovered before this
record existed. The panel says so rather than showing a clean timeline.

Nothing here can be edited. To change an asset's class, edit the asset, or accept
a class proposal in **Discovery → Approvals**; either way the change turns up in
this panel.

### Identifiers, and why they matter

The Overview tab lists the asset's **identifiers** — its FQDN, hostname, addresses, MAC, serial number, cloud resource id, and so on. These are what make one thing one asset: when a sensor sees a host, your CMDB exports it, and someone types it in by hand, the platform matches all three on their identifiers and keeps **one** record rather than three.

Each identifier shows where it came from and how confident the platform is. When the evidence is ambiguous, you get a **merge proposal** in Discovery → Approvals rather than a silent guess. The order the platform tries identifiers in is documented, read-only, at **Settings → Policies → Identification rules**.

## The cryptography lenses

### Certificates

Every certificate in your inventory, one per row — common name, issuer, key algorithm and size, expiry, and how many places it's deployed. This lens lists **all** certificates, including ones you've uploaded manually (shown as unassigned until they're linked to an asset), not just certificates discovered by a sensor. It's sorted by expiry so the certificates closest to expiring float to the top, and an **Ownership** filter lets you narrow to internal vs. third-party certificates.

**Use it when** you're managing certificate lifecycle — renewals, expiry sweeps, finding weak key sizes, or confirming an uploaded certificate landed.

### Keys

A dedicated inventory of every cryptographic key discovered across your environment — key type and size (or curve), lifecycle state, expiry, and how many assets use each key. A key marked **Unlinked** is in inventory but isn't (yet) referenced by any discovered configuration — expected for imported or newly-catalogued key material, and tracked here so nothing is invisible.

**Use it when** you're running a key-length policy audit, reviewing lifecycle state, or tracing the blast radius of a weak or compromised key. (See the dedicated [Cryptographic Keys](./cryptographic-keys.md) guide for the full column reference.)

### Configuration

Every discovered **Crypto Configuration**, grouped by strength — Weak, Acceptable, Strong — with the weak group expanded first so the riskiest crypto is in front of you. Each row shows the host, protocol and version, cipher suite, key details, and hash. An additional **Strength** filter (on top of Environment and Risk) lets you isolate exactly the band you care about.

**Use it when** you're hunting for weak or deprecated crypto — outdated TLS versions, weak ciphers, small key sizes — across everything at once.

### 3rd Party

Outbound connections your assets make to **external** endpoints — SaaS providers, partners, APIs. This is its own dataset (not your internal assets): each row is a destination your environment talks to over TLS, with the protocol, cipher suite, crypto strength, certificate expiry, and when it was last seen. Where you have the right permission, you can **Elevate** a connection to bring it into managed inventory, after which it's tracked like an internal asset and the row shows an "Elevated" badge.

**Use it when** you're assessing third-party crypto exposure — are the vendors and services we depend on using strong TLS? (See [Third-Party and External Connections](./third-party-and-external-connections.md) for detail.)

### Data Protection

At-rest encryption posture across every resource that stores data — object
stores, managed databases. It is a *property* lens rather than a family of
things: the question is "is this data protected, and by whose key?", and the
answer is the same shape whether the resource is a bucket or a database.

Each row shows the resource, its type, its encryption state, **key custody** (who
holds the key — the provider, or you), the origin of the answer, and whether it
was verified. Encryption state has **three** values, not two: Encrypted, Not
encrypted, and **Not assessed** — drawn deliberately neutral so it can never be
read as either verdict. Filters for resource type, assessment and risk sit in the
toolbar.

An empty lens means nothing has been inventoried, not that everything is
encrypted. Object stores and databases arrive here from a cloud discovery.

**Use it when** you are answering "is our data encrypted at rest, and who holds
the keys?" — for a questionnaire, an audit, or your own peace of mind.

### Stale

Assets nothing has observed for more than **30 days**. Each row shows the asset,
its class, its segment, its status and how many days it has been quiet, with
per-row **Rescan** and **Archive** actions on the right and a bar above the table
that acts on the whole page at once. The staleness cut runs across the whole
inventory, so the count and pagination reflect every stale asset, not just the
current page.

Staleness is a property of the asset — of when the *host* was last seen — and it
is a claim that nothing has looked recently, not that the thing is gone.
Individual **endpoints** go stale on the same 30-day boundary and are marked so on
the asset's Services & Endpoints tab; an endpoint is only ever marked *closed* by
something that actually looked and found nothing listening.

**Use it when** you're cleaning up — retiring decommissioned hosts, investigating
assets that dropped off the radar, or keeping your inventory honest. See
[Asset lifecycle management](./asset-lifecycle-management.md) for the actions and
the thresholds behind them.

### TLS and SSH

Two protocol sub-lenses beneath Configuration. They show the same flat Configuration view, pre-narrowed to a single protocol — **TLS** or **SSH** — so you can focus on one without setting a filter.

**Use it when** you want a clean, protocol-specific list — e.g. reviewing every SSH configuration in one shot.

## Drilling into a row: the detail drawer

Click any row to slide open a **detail drawer** with the full record. Drawers **stack** — you can drill from one record into a related one without losing your place, and each drawer paints on top of the last. The top drawer closes first (press Esc or click the dimmed background), peeling back one layer at a time:

- From a **key**, jump to the asset that uses it.
- From a **certificate**, jump to the asset it's deployed on.
- From a **crypto configuration**, jump to its asset or its certificate.
- From an **asset**, expand into its configurations.

This is how you answer "what depends on this?" questions: start anywhere and follow the relationships, with every step you took stacked behind you.

### Why a configuration scored what it did

A crypto configuration's drawer carries a **Why this score** section under its
Assessment rows. It names the component that set the score, shows each
component's catalogue assessment, marks whether the component was **observed in
use** or only **offered, not observed**, and surfaces the catalogue's migration
guidance for the offending one. When nothing resolved against the catalogue it
says **not assessed** — which is not the same as safe. See
[Crypto Risks → Seeing why a configuration scored what it did](./crypto-risks.md#seeing-why-a-configuration-scored-what-it-did).

## Exporting the current view

The **Export** button in the toolbar downloads exactly what you're looking at — the current lens, with your active filters and search applied — as a CSV. Each lens exports the columns that make sense for it: certificates export issuers and expiry; keys export sizes and fingerprints; configurations export cipher suites and algorithms; Stale exports class, segment, status and last seen. The file is built right in your browser from the rows already on screen, so there's no waiting.

You will find it on the **Certificates, Keys, Configuration, TLS, SSH, Data
Protection, 3rd Party** and **Stale** lenses. **Map** has its own export — a
graph, in GraphML or Cytoscape JSON, rather than a table.

**Exports are convenience, not evidence.** A page-local CSV is perfect for a quick spreadsheet pivot, a key-length sweep, or sharing a snapshot with a teammate. It is **not** an audit-grade artifact: it has no provenance, no content hash, and no fixed scope boundary. When you need something an auditor can rely on — reproducible, hashed, and tied to a defined boundary — generate a **CBOM artifact** instead. (See [Page-Local Exports](./page-local-exports.md) for the distinction, and [CBOM Artifacts](../cbom/cbom-artifacts.md) for audit-grade output.)

## Where the old lenses went

Two lenses were absorbed by the class facet on All assets, and their bookmarks redirect there:

| Was | Ask for it now |
|---|---|
| **Infrastructure** | All assets — it *is* the asset list, with a class facet on top |
| **Network** | All assets, filtered by **Segment** in the rail (or `segment_id:` in the query) |

## See also

- [Assets and Crypto Configurations](./assets-and-crypto-configurations.md) — what an asset, an endpoint and a configuration each are
- [Adding assets manually](./adding-assets-manually.md) — the New asset form and the class picker
- [Asset Lifecycle Management](./asset-lifecycle-management.md) — the Stale lens, archiving and deletion
- [Cryptographic Keys](./cryptographic-keys.md) — the Keys lens in depth
- [Third-Party and External Connections](./third-party-and-external-connections.md) — the 3rd Party lens in depth
- [Query](./query.md) — the language the query box and the filter rail share
- [Page-Local Exports](./page-local-exports.md) — what the Export button is (and isn't) for
- [CBOM Artifacts](../cbom/cbom-artifacts.md) — audit-grade, hashed, scoped evidence
