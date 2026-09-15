# SBOM Upload

## Overview

A **software bill of materials** (SBOM) lists the components inside a piece of
software: the libraries a build pulled in, their versions, and the identifiers a
vulnerability feed matches on. If you build software, your pipeline almost
certainly already produces one.

Vista Platform accepts those documents as an inventory source. Their components
become **software inventory** on your assets: a per-tenant product catalogue and
a record of which asset carries what. The platform already emits CycloneDX as an
output (see [CBOM Artifacts](../cbom/cbom-artifacts.md)); this makes it an input
as well.

| | |
|---|---|
| **Formats** | CycloneDX JSON 1.4 – 1.7, SPDX JSON 2.2 and 2.3 |
| **Maximum size** | 32 MB |
| **Maximum components** | 100,000 |
| **Where** | Discovery → Sources → **SBOM Upload** |
| **Permission** | `assets.update` for an upload against an existing asset; `assets.create` to create one from the document |

The format is detected **from inside the document** — CycloneDX's `bomFormat` /
`specVersion`, SPDX's `spdxVersion` — never from the filename or the
Content-Type. Rename `bom.json` to `bom.txt` and it still works.

## Uploading

1. Go to **Discovery → Sources → SBOM Upload**.
2. Choose where the document belongs:
   - **An existing asset** — the host, container or application this software
     runs on. Search for it by name.
   - **Create an application asset from the document** — for a document about an
     artefact you have not recorded yet. See [Creating an asset from a
     document](#creating-an-asset-from-a-document).
3. Drop the file, or click **Choose a document**.

The result card tells you what the upload did:

> **412 of 480 components ingested · 68 excluded by the document.**
> Software recorded against web-01.

That denominator is deliberate. "412 imported" on its own is a number you cannot
check against your build output; "412 of 480, 68 excluded" is one you can. Under
it, **What was skipped** lists everything the parse dropped and why.

### Uploading from CI

The endpoint takes the raw document as well as a form upload, so a pipeline does
not need a multipart encoder:

```bash
curl -X POST \
  "https://<your-host>/api/v2/inventory-service/infrastructure-assets/<asset-id>/sbom?filename=build-1234.cdx.json" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <api token>" \
  --data-binary @bom.cdx.json
```

See [API Tokens & MCP](api-tokens-and-mcp.md) for issuing a token.

## Where the software appears

**On one asset** — open the asset and choose the **Software** tab. Name, vendor,
version, its **end-of-life** and **vulnerability** state, purl or CPE, where the
claim came from, when it was last seen, and its status. Search and filter by
status.

**Across the tenant** — **Inventory → Software** is the product catalogue: every
distinct product with how many assets carry it, and the same two state columns
rolled up across its installs. Click the asset count to see them. This is where
"who runs log4j 2.14?" is answered.

**In a query** — the software collection is part of the [query
language](query.md):

```
software:(name:openssl and version < 3.0)
class:hardware.computer.server software:(purl="pkg:npm/left-pad@1.3.0")
```

**To an AI agent** — `vistaplatform_list_asset_software` over MCP.

## End of life and vulnerabilities

Two columns on both surfaces, filled in by the platform's own checks rather than
by anything in your document. They run nightly, and again after an upload.

### Vulnerabilities

| It says | It means |
|---|---|
| **12 · CVSS 9.8** | Twelve advisories match this version; the worst scores 9.8. Click through for the CVE list. |
| **3 · not scored** | Three advisories match, and the catalogue published no CVSS for any of them. That is "we could not grade this", not "harmless". |
| **None known** | This product carries a purl or a CPE, the advisory catalogue was searched for it, and nothing matched this version. |
| **Not assessed** | This product carries **neither** a purl nor a CPE. There is nothing to match against, so nothing was checked. |

The last two are different answers and only one of them is reassuring. Matching
is by purl and CPE only — a name is not an identifier a vulnerability feed can
be searched by — so a component your document named without one is reported as
unchecked rather than as clean.

If you see a lot of **Not assessed**, the fix is upstream: have whatever
generates your bills of materials emit purls. Most tools do by default.

### End of life

| It says | It means |
|---|---|
| **Ended 2023-09-11** | The lifecycle catalogue's end-of-life date for this version has passed. |
| **Ends 2027-01-31** | It has not passed yet, but it is inside the warning window. |
| **Supported until 2028-04-01** | The catalogue resolved this version to a support cycle whose end-of-life date is further out than the warning window. |
| **No date published** | The catalogue has this version but publishes no end-of-life date — the vendor has not announced one, or support ended on a date nobody recorded. Neither "supported" nor "end of life" can be claimed. |
| **Not in catalogue** | The catalogue has no entry for this product, so its support status is unknown. The gap is recorded for the catalogue's curators. |
| **Not assessed** | No lifecycle answer has been recorded for this install. |

Every answer but the last is one the platform actually recorded, per install,
when it last checked the catalogue. A supported package says so and gets its
credit; a package the catalogue has never heard of says that instead, rather
than looking the same.

### How current is the answer?

On **Inventory → Software** a **Last checked** column shows when the lifecycle
catalogue was last consulted for each product, and turns amber once that is
more than about three months ago — the catalogue moves, so an older answer is a
claim about a world that has changed underneath it. A product no completed
check has ever recorded an answer for reads **Never** rather than a dash: a
dash would read as "nothing to report".

Sort by **Least recently checked** (the sort dropdown, or the column header) to
bring the stale corner of the catalogue to the top. **Never** sorts first,
ahead of the oldest dates, because "nobody has looked" is the weaker of the two
answers, not a missing one.

**"Not assessed" is still not "supported".** It now means one of three narrower
things: the check has not run since this install was first seen (it runs
nightly and after an upload), the install is no longer present and so was not
checked, or its end-of-life finding was closed by a person. Rather than pick
the reassuring one, the column says it does not know, and the hover text says
which.

### Clicking through

A cell is a link when there is a finding behind it. On the asset's Software tab
it opens [Findings](findings.md) narrowed to **that install**; on the catalogue
it opens the findings from that producer, searched by product name — a product
installed on forty assets has forty findings rather than one.

## How products are deduplicated

A product is identified by the **strongest identifier the document supplied**:

1. Its **purl** (`pkg:npm/left-pad@1.3.0`) — names a specific artefact.
2. Its **CPE** (`cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*`) — names a
   product line, and is what a vulnerability feed matches on.
3. Its **name and version** — what is left when a document supplies neither.

Two documents that name the same purl produce one catalogue row and two
installs, which is what makes "how many assets run this?" answerable. CPE
attribute values are stored lowercase, because CPE 2.3 makes them
case-insensitive and NVD publishes them that way — `OpenSSL` and `openssl` are
one product, not two.

Versions are ordered by a normalised key, not as text. A product whose version
has no numeric part (`"latest"`, `"stable"`) has **no** ordering key, and a
comparison like `version < 3.0` returns neither true nor false for it. That is
deliberate: sorting versions as text puts `1.10` below `1.9` and inverts every
answer built on it.

## Re-uploading: what changes

**An upload replaces the imported software list for its asset.** Anything the
new document does not list is marked **No longer listed** — the row is kept, not
deleted, so:

- Its **first seen** date survives, and "this library was here in March" stays
  answerable.
- A later document that lists it again makes it current once more.

The Software tab shows removed rows by default, muted, for that reason. Filter
to **Present now** for the current picture.

Two consequences worth knowing:

- **Uploading a second document that describes a different part of the same
  asset will mark the first document's components as no longer listed.** There
  is no way for the platform to tell "a new build of the same thing" from "a
  different thing on the same host": CycloneDX mints a fresh serial number on
  every export, so two builds of one artefact carry two unrelated serials. If
  you have two documents for one asset, merge them before uploading.
- **Nothing a sensor or agent measured is touched.** The replacement applies
  only to software the platform was *told* about, never to software it observed.

## Creating an asset from a document

If the document describes an application you have not recorded, choose **Create
an application asset from the document**. The platform reads the document's own
subject — CycloneDX's `metadata.component`, or the package an SPDX `DESCRIBES`
relationship names — and creates an **Application** from it.

Uploading the same artefact again lands on the **same asset**, because the asset
is identified by the subject's own software identity (its purl, else its CPE,
else its name and version).

### The new asset waits for approval

It appears in **Discovery → Approvals** labelled *Declared from SBOM upload*,
and is not in your inventory until someone accepts it.

That is not an oversight. An asset you create in the UI is approved because a
person decided, in front of the inventory, that it belongs there. An upload is a
file arriving at an endpoint, possibly from a build pipeline nobody is watching.
The queue is where those two get told apart.

### What cannot become an asset

Only an **application** subject can. The platform will refuse, and say why:

| Subject type | What happens |
|---|---|
| `application`, `framework`, or no type given | Becomes an Application asset. |
| `library` | **Refused.** A library is a component *of* an asset. Upload the document against the asset the library is installed on and it appears in its Software tab. |
| `container` | **Refused.** A container-image bill of materials says nothing about a running container, and a running container is identified by its agent, cloud resource id or hostname — none of which a document carries. Upload it against the container or host asset it runs on. |
| `operating-system`, `platform`, `device`, `firmware`, and the rest | **Refused.** These are identified by hardware or platform facts a bill of materials does not carry. Upload against the asset they describe. |

An asset created from a name alone, in a class that cannot be *matched* by name,
could never be recognised on a second upload — every upload after the first
would create a duplicate or open a review request against the asset it already
was. Refusing up front is the honest answer.

## What is skipped, and why

A parse with warnings is a **successful** parse. Everything below is reported in
**What was skipped** on the result card and in the asset's History.

| Skipped | Why |
|---|---|
| **Cryptographic components** (CycloneDX `cryptographic-asset`, anything with `cryptoProperties`) | They belong to the CBOM side of the platform, which has its own model and its own algorithm catalogue. A library nested under one is still ingested. |
| **Components marked `scope: excluded`** | The document says they are *not* in the artefact. Recording one as installed would be a false positive. |
| **SPDX `files`** | Files are not products. A mid-size SPDX document has tens of thousands of them. |
| **Free-text licence names** | The licence column holds SPDX identifiers and expressions. "Apache 2.0", "Apache License v2" and "BSD-like" in it would be indistinguishable from a real identifier. |
| **Document-local licence references** (`LicenseRef-…`) | They mean something only inside the document that defines them. Two build systems both emit `LicenseRef-0` for unrelated licences. |
| **Unparseable purls and CPEs** | Keeping one would key the catalogue on a string no vulnerability feed can match. The component is still ingested — only the bad identifier is dropped. |
| **Components with no name** | There is nothing to call the row, and inventing a name would be worse. |
| **Dependency relationships** | See below. |

### The dependency graph is not stored

A document's `dependencies` are edges between *components* — "this jar is on the
classpath of that war". Vista Platform's relationship model connects **assets**
to assets, and a component is not an asset. There is nowhere to put these edges
that would not mean inventing a relationship the document never claimed.

They are **counted** on the result card ("56 dependency edges not kept") rather
than dropped in silence, so you know the graph did not come across.

## Refusals

| What you see | What happened |
|---|---|
| *This looks like XML…* | Only JSON is parsed, for both formats. Re-export as JSON. |
| *SPDX-3.0 is a JSON-LD model…* | SPDX 3.0 is a different model, not a revision of 2.x. Parsing it on the 2.x shape would succeed and return nothing, which is worse than refusing. Export SPDX 2.2 or 2.3. |
| *…exceeds the size cap* | Over 32 MB. The document is refused rather than truncated: a half-ingested SBOM shows a software list that looks complete, and the missing half is invisible. |
| *430,000 components (limit 100,000)* | Same reasoning, for the component count. The message names both numbers. |
| *Asset not found* | The asset id does not exist in your tenant. |

## What this does not do yet

- **No scheduled or automatic re-import.** Each upload is a deliberate act (or a
  call from your own pipeline).
- **No per-install record on the vulnerability axis.** The end-of-life column
  now reads a per-install record of what the catalogue resolved; the
  vulnerability column still derives "nothing matched" from "nothing to match
  on" through the identifiers alone, which is enough for its three values.

## Related

- [Inventory & Lenses](inventory-and-lenses.md) — where the Software lens sits
- [Asset Approval](asset-approval.md) — the queue a created asset lands in
- [Query](query.md) — the `software:(…)` predicate
- [CBOM Artifacts](../cbom/cbom-artifacts.md) — the platform's own CycloneDX output
- [API Tokens & MCP](api-tokens-and-mcp.md) — uploading from a pipeline, and the MCP tool
- [Findings](findings.md) — the end-of-life and vulnerability findings the two columns read
