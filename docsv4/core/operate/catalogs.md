# Platform catalogues and their feeds

Vista Platform evaluates every tenant's inventory against **platform
catalogues** — curated reference data that carries no `tenant_id` and is the
same for everyone on the deployment. There are five:

| Catalogue | Table | Where it comes from | Console |
|---|---|---|---|
| Algorithms | `algorithms` | Shipped in the seed, hand-curated | Catalog ▸ Algorithms |
| Compliance frameworks | `platform_frameworks` | Shipped in the seed (+ the Enterprise content bundle) | Catalog ▸ Frameworks |
| **End-of-life** | `eol_catalogue` | Mirrored from [endoflife.date](https://endoflife.date) | Catalog ▸ End-of-life |
| **Vulnerability** | `vulnerability_catalogue`, `vulnerability_matches` | Mirrored from [NVD](https://nvd.nist.gov) and [OSV](https://osv.dev) | Catalog ▸ Vulnerability feed |
| **Classification rules** | `classification_rules` | Shipped in the seed, curated in the console | Catalog ▸ Classification rules |

This page covers the last three: how the mirrors work, how to run them, what
their sources ask of you, how to fill them on a deployment with no internet, and
how to curate the classification rules that decide what a newly discovered asset
is proposed as.

All five are **Core** — free, present in every edition, with no entitlement to
check.

> **What these catalogues do today.** They hold reference data and nothing reads
> them against your inventory yet. Matching an asset's OS and installed software
> against these rows — and raising end-of-life and known-vulnerability findings
> from the match — is the next slice of work. Until it lands, the pages below are
> a browsing and operations surface, not a source of findings.

## Who can see and change them

All three pages are gated on the platform permission **`catalogs.manage`**, granted to
`super_admin` and `platform_admin` by the seed. It is separate from
`algorithms.manage` on purpose: curating crypto ratings and re-pointing the
platform at a vulnerability source are different trust decisions, even though the
same two roles hold both today.

The routes live under the admin plane (`/api/v1/admin-service/admin/catalogs/**`),
so they are served on the admin host only — never on the tenant host.

## The feeds

Three mirror jobs run inside `admin-service`, on a schedule and on demand:

| Feed | Source | Fills | Incremental by |
|---|---|---|---|
| `eol` | `https://endoflife.date/api` | `eol_catalogue` | Nothing — a full pass each run |
| `nvd` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | `vulnerability_catalogue` + CPE match rules | Last-modified window |
| `osv` | `https://osv-vulnerabilities.storage.googleapis.com/<ecosystem>/all.zip` | `vulnerability_catalogue` + PURL match rules | Per-ecosystem watermark, plus `If-Modified-Since` |

Each run records its outcome in `catalog_feed_state` — last run, status, rows
written, the error if it failed, and a bookmark — which is what the console
shows. **A feed error is recorded, never fatal.** A mirror that cannot reach NVD
does not take the admin console down with it, and the failure is visible on the
page rather than inferred from a catalogue that stopped growing.

**The bookmark only advances on success.** A run that fails retries the same
window next time rather than skipping it.

### Configuration

| Variable | Default | What it does |
|---|---|---|
| `CATALOG_FEEDS_ENABLED` | `true` | Kill switch. `false` stops the scheduled passes **and** refuses Sync now (409). Bundle import still works. |
| `CATALOG_FEEDS_INTERVAL` | `24h` | Time between scheduled passes. |
| `CATALOG_FEEDS_STARTUP_DELAY` | `2m` | Delay before the first pass after a pod starts, so a rolling restart is not N simultaneous passes. |
| `NVD_API_KEY` | empty | Raises the NVD rate limit from 5 to 50 requests per 30 seconds. |
| `OSV_ECOSYSTEMS` | `Debian,Ubuntu,Alpine` | Comma-separated osv.dev bucket names to mirror. |

On Kubernetes, set them through the chart's per-backend `extraEnv`:

```yaml
backends:
  admin-service:
    extraEnv:
      - name: CATALOG_FEEDS_ENABLED
        value: "false"
```

Only one replica runs a given feed at a time: each run takes a Postgres advisory
lock keyed on the feed name, so scaling `admin-service` up does not multiply the
requests going to NVD.

### Rate limits, and why the first NVD run is not the whole database

NVD allows **5 requests per rolling 30 seconds** without an API key and **50**
with one, and answers **403** — not 429 — when you exceed it. NIST's published
guidance is to sleep 6 seconds between unkeyed requests, which the mirror does.

Because 403 means "slow down" here rather than "you may not", a rate-limited
page is **waited out and retried** — up to three attempts, backing off from the
length of NVD's own rolling window (or from a `Retry-After` header when one is
sent), with the retries counting against the run's request budget. Only once
those are exhausted does the run fail, and the error it records says *rate
limit*, not just "403", so nobody goes hunting for an authentication problem
that isn't there. A status that is a genuine refusal (404, 401) is not retried.

Because of that, the first NVD run does **not** pull the entire history. It
reaches back 90 days by default and advances from there, a window at a time, with
a per-run request budget so a cold start cannot loop for a day. To get the full
back catalogue, either let it run for several days or — much faster — import an
offline bundle built on an install that already has it.

Get a key (free) at <https://nvd.nist.gov/developers/request-an-api-key> and set
`NVD_API_KEY`.

### What the vulnerability catalogue does not contain

`vulnerability_catalogue` is keyed on **CVE id**. OSV advisories are keyed on OSV
ids (`GHSA-…`, `DSA-…`, `PYSEC-…`) and only some carry a CVE alias; the mirror
imports the ones that do and **skips the rest**, counting the skips in the
service log. A GitHub advisory with no CVE assigned is therefore not in this
catalogue. That is a real coverage gap, stated here rather than papered over by
minting synthetic ids.

Similarly, a CVE mirrored only from OSV has a CVSS **vector** and no base score:
OSV publishes no number, and this platform does not compute one from the vector.
The console shows "vector only" rather than a `0.0` that would read as "not
serious". When NVD later mirrors the same CVE, the score fills in.

## Running a feed now

Catalog ▸ End-of-life (or ▸ Vulnerability feed) → the feed card at the top of the
page → **Sync now**.

The button answers immediately — the run is *started*, not finished. A pass takes
minutes (NVD's rate limit alone guarantees it), so the page polls the feed status
and the result appears there when the run completes. A second click while a run
is in flight is refused.

If Sync now is greyed out, either a run is already going or this deployment has
`CATALOG_FEEDS_ENABLED=false`; the card says which.

## Air-gapped installs: the offline bundle

A disconnected deployment cannot reach endoflife.date, NVD or osv.dev. Fill its
catalogues from a bundle built on a connected install.

**1. Build it** (on the connected install, or any machine that can reach its
database):

```bash
make build-catalog-bundle DATABASE_URL=postgres://user:pass@host:5432/crypto_inventory
```

This writes `catalog-bundle-<YYYY-MM-DD>.tar.gz` and prints a SHA-256 and row
count per file. Optionally pass `CATALOG_BUNDLE_OUT=/path/to/bundle.tar.gz`.

**2. Carry it across the gap** by whatever means your policy allows.

**3. Import it** in the disconnected install: Catalog ▸ End-of-life → **Import
bundle** → choose the file. (Either catalogue page imports the whole bundle; it
is one file covering both.)

### What is in a bundle, and what is checked

A gzipped tar of:

- `manifest.json` — format, version, generation time, and per file a **SHA-256**,
  a **row count** and a byte length;
- `ATTRIBUTION.md` — the upstream sources' attribution, carried **with** the data
  rather than only in the product's `NOTICE`, because a bundle is a file you may
  hand on (see "Attribution and terms" below);
- `eol_catalogue.jsonl` — one end-of-life row per line;
- `vulnerability_catalogue.jsonl` — one CVE per line, with its match rules inline.

On import, **every file's hash and row count is verified before a single row is
written**. A corrupt transfer is refused with a message naming the file and the
mismatch, and nothing is applied — the alternative, verifying as you go, leaves a
half-imported catalogue behind a corruption error, which is precisely the failure
an air-gap transfer is most likely to produce.

A bundle carries each file **once**, and one that repeats a name is refused. That
is not tidiness: the verification records one digest per name, so a second member
under a name already seen would be checked while the first was silently applied
alongside it — which would defeat the manifest entirely.

The one failure that is *not* "nothing was applied" is a fault that happens after
verification passed — a dropped database connection partway through. The console
labels that case differently and names the rows already written, because telling
an operator their catalogue is untouched when it is half-written is worse than
telling them nothing. Re-import the same bundle; import is idempotent.

Import is idempotent: re-importing the same bundle leaves the catalogue exactly
where it was.

### Reading the numbers an import reports

The three counts answer slightly different questions, and the second import of a
bundle is where the difference shows:

| Count | Statement | On a re-import of the same bundle |
|---|---|---|
| End-of-life rows | `ON CONFLICT DO UPDATE` | the **same number again** — every row was applied |
| Vulnerabilities | `ON CONFLICT DO UPDATE` | the **same number again** |
| Match rules | `ON CONFLICT DO NOTHING` | **0** — the rules were already there |

All three are what the database reported affected, not what the file contained.
A second import showing "0 match rules" is the correct answer, not a failure.

### What is recorded

Both actions on these pages are written to the platform audit trail
(Security ▸ audit logs): running a feed records which feed and who started it,
and importing a bundle records the operator, the manifest's **SHA-256 per file**
and the rows actually written. The hash is the part worth having — after a bad
bundle the question is not whether an import happened but *which bytes* were
applied, and only the hash settles it. A bundle refused by verification wrote
nothing and is not recorded; one that failed partway through is, with what it
managed to write.

### Hash, not signature — and why

The Enterprise content bundle (regulated compliance frameworks) is signed with an
ECDSA key, because it carries licensed content and the signature is what makes it
revocable by non-renewal.

These catalogues are Core. There is nothing to revoke and no entitlement to
prove, so the bundle carries **integrity** rather than provenance: a hash per
file, checked before use. That is what answers the question an air-gap transfer
actually raises — "did this file arrive whole?".

If your policy also requires provenance, sign the tarball with your own key
before it leaves the connected side and verify it before import. The format does
not prevent that; it just does not require a key this platform would then have to
manage for you.

## Classification rules

**Catalog ▸ Classification rules** is the fifth platform catalogue, and the one
you can write to. It holds the evidence behind every **class proposal**: what
kind of thing a newly discovered asset is.

When a collector sees something new, it has facts but no identity — a MAC
address, an SNMP `sysObjectID`, a cloud resource type, an HTTP `Server:` header,
a set of open ports, a model string. A classification rule maps one of those
onto a **vendor** and, where the mapping is unambiguous, an **asset class**.

Every rule produces a *proposal* that goes through Approvals. Nothing on this
page classifies anything on its own.

> **What this page does today.** The rules that ship with the platform are
> already used — the collectors consult them when an interrogation identifies a
> device. Rules you **add or edit here do not take effect yet**: the classifier
> reads the shipped set, and reading your curated rows back at run time is the
> next slice of work, landing alongside class proposals in Approvals. Until it
> does, treat this page as the place to *review* what the platform believes and
> to stage your own rules, not as a live control.

### What a rule looks like

| Field | Meaning |
|---|---|
| Kind | How the pattern is matched — see the table below. |
| Pattern | The thing matched, in that kind's own syntax. |
| Class | The asset class to propose. **Optional**, and often deliberately empty. |
| Vendor | The manufacturer the pattern identifies. Optional. |
| Model | The specific model, where the pattern pins one. Rarely set. |
| Confidence | 0.50–0.95. What the rule *asserts*. |
| Source | Where the mapping comes from. Required for a rule that ships. |

| Kind | Pattern is | Example |
|---|---|---|
| MAC OUI | The 24-bit IEEE assignment, 6 uppercase hex digits | `00000C` |
| SNMP sysObjectID | An OID under `1.3.6.1.4.1`; longest prefix wins | `1.3.6.1.4.1.9` |
| EtherNet/IP vendor | An ODVA vendor id in decimal | `1` |
| Cloud resource type | The provider's own type | `aws_s3_bucket` |
| Service banner | A regular expression over a captured banner | `(?i)^server:\s*nginx` |
| Port profile | Ports that must **all** be open | `631,9100` |
| Model prefix | A prefix of the stated model; longest wins | `C9300` |
| Collector platform | The management API the device answered | `fortios` |

The MAC OUI rules are **derived**, not written by hand: the platform keeps one
manufacturer table (the same one the sensor uses to name a vendor from a
captured frame), and each shipped OUI rule pairs a prefix from it with the class
that manufacturer's products are — where there is one. That is why most of them
say *vendor only*: two thirds of the manufacturers in the table sell more than
one kind of thing.

### "Vendor only" is the normal answer

Most of the shipped OUI rules name a vendor and **no class**, and the table says
"vendor only" rather than showing a gap. That is deliberate.

Dell, HP, Netgear, Ubiquiti and MikroTik each sell servers, switches, access
points and printers under the same IEEE assignment. There is no majority worth
guessing at, so the rule stops at the vendor and something with better evidence —
an SNMP walk, a model string, an agent on the host — narrows it later.

> **A wrong class is worse than no class.** An absent class shows as
> unclassified, which reads as "we have not worked this out yet" and invites
> someone to look. A wrong class shows as a fact, and a plausible-looking wrong
> proposal is the one that gets approved without a second thought.

Follow the same instinct when you add a rule: leave the class empty whenever the
pattern covers more than one kind of thing, and prefer a broad class that is
certainly right (`network_device`) over a narrow one that is probably right
(`switch`).

### When two rules disagree

If two rules propose different, unrelated classes at similar confidence, the
classifier proposes **no** class and records both. That is the intended
behaviour, not a failure — it means the catalogue contradicts itself, and the
fix is to correct one of the two rules rather than to let a coin-flip decide.

A rule proposing `switch` and another proposing `network_device` is *not* a
disagreement: one is a refinement of the other, and the more specific class wins.

### Adding, editing and deleting

**Add rule** opens the form. The pattern box shows what that kind expects, and
the server validates against exactly the rules the classifier applies — so a
rule that saves is a well-formed rule, not one the engine will later refuse. (It
will not fire until the classifier reads this table at run time; see the note
above.) If it is rejected, the message names what to change.

Two things are worth knowing before you edit or delete:

* **Editing a shipped rule does not last.** The rules that come with the
  platform are restated on every upgrade, so an edit to one is overwritten by
  the next release. To override a shipped answer durably, **add a more specific
  rule** instead — a longer `sysObjectID` prefix, a longer model prefix. It wins
  on its own merits and survives every upgrade. Rules *you* add are never
  touched.
* **Deleting does not rewrite history.** Class proposals already made from a
  rule keep their own copy of it, so past decisions stay reviewable. Deleting a
  shipped rule also only lasts until the next upgrade.

Adding, editing and deleting a rule are all recorded in the audit trail with who
did it and what the rule was.

## Attribution and terms

These are third-party datasets. Mirroring them into your deployment is a
redistribution, and the sources ask for different things:

- **endoflife.date** — a community-maintained dataset. The mirror identifies
  itself with a `User-Agent`, paces itself to roughly 4 requests per second, and
  runs once a day. Rows are stored with the upstream product page as their
  `source_url`, and the console links to it. See
  <https://endoflife.date/docs/api> for their current terms.
- **NVD (NIST)** — a U.S. government work. **This product uses data from the NVD
  API but is not endorsed or certified by the NVD.** NIST asks that you do not
  imply endorsement and that you identify your client; the mirror sets a
  `User-Agent` and honours the published rate limits. See
  <https://nvd.nist.gov/developers/terms-of-use>.
- **OSV (osv.dev)** — the aggregated database is published under **CC-BY-4.0**,
  attributed to OSV (<https://osv.dev>) and to the upstream database named on each
  record. See also <https://github.com/google/osv.dev>.

**The offline bundle carries this wording with it.** Every bundle built by
`make build-catalog-bundle` includes an `ATTRIBUTION.md` member stating exactly
the three points above, so the obligations do not stay behind in the product's
`NOTICE` when the file is carried across an air gap or handed on. The same text is
in `NOTICE`, under "Third-party data".

> **Operator responsibility.** If you redistribute a bundle built from this
> platform beyond your own organization, the attribution obligations of the
> upstream sources travel with it — which is what `ATTRIBUTION.md` is for.
> Redistribution itself is permitted by both sources; the review of their terms
> for this bundle is complete, and what it found was owed is the attribution
> wording above. Nothing here should be read as legal advice.

## Filling gaps in the end-of-life catalogue

The mirrors only know what their upstream sources publish. endoflife.date is
excellent on mainstream operating systems and language runtimes and thin on
appliances, network hardware and vendor-specific firmware trains — so the
catalogue will not answer for everything your inventory contains.

**Catalog ▸ End-of-life** has three views of the same catalogue, listed under
**End-of-life** in the left nav:

| View | What it is |
|---|---|
| **Catalogue** | The rows you have, with a badge saying how each one got there (`mirrored`, `AI-proposed`, `declared`). |
| **Proposals** | A review queue. Nothing in it is in the catalogue yet. |
| **Gaps** | The products the platform has been asked about and could not answer for, ordered by how often. |

### Check a product

On the **Gaps** view, "Check a product" asks the platform what it knows about a
vendor, product and version. There are four answers, and they are deliberately
different from each other:

- **A date, with its provenance.** Each fact carries the catalogue row it came
  from and the page that cites it.
- **"The catalogue has this product but publishes no end-of-life date."** The
  release train is known and the vendor has not announced a date — including the
  case where the upstream source says support has ended without saying when.
  This is *not* a gap, and nothing is added to the gap list: there is nothing
  for anyone, model or person, to fill in.
- **"Nothing for this product — added to the gap list."** The catalogue has
  never heard of it. This is the answer that puts it on the list a proposal run
  works from, which is how you deliberately queue a product up.
- **"…and the gap list could not be updated."** The lookup worked and the
  bookkeeping write did not. Said plainly rather than reported as the previous
  answer, because "it is on the list now" would be false.

The matching is deliberately exact. A version whose release train is not in the
catalogue resolves to **nothing**, not to the nearest cycle: the support date of
the release beside yours is not your support date, and answering with it would
be wrong in the direction that reassures. When both the question and a catalogue
row name a vendor they must agree.

### Where the gaps come from

Most rows on this list are not put there by hand. Every tenant's end-of-life
pass resolves each asset's operating system, its hardware and every installed
package against this catalogue, and each lookup it cannot answer is counted
here. So the top of the list is, literally, the products costing your tenants
the most answers.

Two things follow from that, and both are deliberate:

- **A gap is a silence, not a clean bill of health.** A product the catalogue has
  never heard of produces no end-of-life finding for anybody running it. Filling
  the gap is what makes those findings appear.
- **One pass records at most 500 new gaps.** A tenant with tens of thousands of
  distinct unrecognised packages would otherwise fill this list in one night and
  bury the row worth working on. The next pass records the next slice, and
  anything common reappears immediately.

### Working the gap list by hand

Without a provider, the Gaps view is still useful on its own: it is the list to
work through by hand, ordered by how much each gap costs you, and any row you
add by hand is a row the mirrors will not overwrite unless the upstream source
starts publishing it.

Adding a row has an effect you can see: the next end-of-life pass resolves the
products that were missing it, and their findings appear on the assets running
them — citing the row you just added. See
[Findings](../features/findings.md) for what those look like to a tenant.


## Troubleshooting

**"Never run" and Sync now does nothing.** Check `CATALOG_FEEDS_ENABLED`. The
card shows a banner when the deployment has feeds switched off.

**NVD keeps failing with 403.** That is the rate limit, not authentication — and
the mirror already retried it three times before recording the failure, so this
means the limit is being hit persistently. Set `NVD_API_KEY`, or check whether
something else on the same egress IP is also calling NVD.

**The catalogue is not growing after a successful NVD run.** Look at the
bookmark on the feed card. A run that reaches its per-run request budget stops
early and records the window it *did* finish; the next run resumes from there.
Repeated runs walk forward through the history.

**An import was refused.** The message names the file and the check that failed.
A SHA-256 mismatch means the file changed in transit — rebuild or re-copy it. A
row-count mismatch usually means the manifest was edited. Nothing was applied in
either case; the card says "Bundle refused".

**An import says "Bundle partly applied".** That is the other outcome: the
manifest verified and the write then failed (most often a database connection
dropping under a large import). Some rows are in. Import the same bundle again —
it is idempotent, so the repair is a retry, not a cleanup.

**An OSV ecosystem is missing.** Check the name against the bucket listing at
<https://osv-vulnerabilities.storage.googleapis.com> — `OSV_ECOSYSTEMS` uses the
exact upstream spelling, spaces included (`Rocky Linux`).
