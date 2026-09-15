# Findings

A **finding** is a judgement the platform makes about something in your
inventory: *this control fails on that server*, *this certificate uses a weak
signature algorithm*, *this operating system is past end of life*.

It is not the same thing as a **fact** (something observed, with provenance —
"this endpoint negotiated TLS 1.2 at 09:14"), and it is not the same thing as an
**alert** (a notification that chases you until somebody deals with it). A fact
is what we saw; a finding is what we make of it; an alert is us telling you
about it.

## One list, several producers

Every finding lives in one list, whoever made the judgement. Each carries a
**producer** — the part of the platform that judged it — and a **kind**, which
is the specific thing it is claiming.

| Producer | What it judges | Judged against |
|---|---|---|
| **Compliance** | Controls in the frameworks you have activated | The framework |
| **Cryptography** | Negotiated configurations, certificates and their algorithms | The algorithm catalogue |
| **End of life** | Operating systems, software and hardware | The end-of-life catalogue |
| **Vulnerability** | Installed software, by CPE and Package URL | The vulnerability catalogue |
| **Configuration** | How a device is managed and what it exposes | The configuration rules |
| **Inventory hygiene** | Gaps in the inventory itself — no owner, no class, stale records | Nothing; this is data quality |
| **Drift** | What changed against a recent baseline | Recent history |

Producers arrive in stages. **Compliance, Cryptography, End of life,
Vulnerability, Configuration, Inventory hygiene and Drift write findings
today**; the rest land as their catalogues and collectors ship. Where the
product can tell you which producers have actually looked at something, it does
— because "we found nothing" and "nobody looked" are different answers, and only
one of them is good news.

### Cryptography findings

Every cryptographic configuration in your inventory, and every certificate
reachable from one, is judged against the algorithm catalogue.

- **Weak cryptographic configuration** — the configuration negotiates a
  protocol version, cipher suite, key exchange, signature, symmetric cipher or
  hash the catalogue rates as weak or deprecated. The score is the worst of
  them: a service is only as strong as the weakest thing it will agree to, so
  an AES-256 cipher does not offset a TLS 1.0 protocol version. The finding
  lists every component that was looked at, worst first, with the catalogue's
  rating of each — so the number always has its working attached.
- **Certificate uses weak cryptography** — the certificate's key algorithm,
  key size or signature algorithm is rated weak, or the key falls below the
  NIST SP 800-131A floor (2048 bits for RSA, 256 for an elliptic curve). The
  floor is applied per algorithm FAMILY: a 256-bit elliptic-curve key is
  healthy and is not measured against the RSA floor.
- **Vulnerable to quantum attack** — the subject uses a classical asymmetric
  algorithm that Shor's algorithm breaks (a signature, a key-establishment or
  a public-key encryption primitive), per **NIST IR 8547**, which deprecates
  them after 2030 and disallows them after 2035. Nothing here is broken today;
  it is inventory-led migration work, and the finding says so.

  The subject can be a crypto configuration, a certificate **or a key** from
  [the key inventory](cryptographic-keys.md). The key form is usually the one to
  plan from: a public key is recorded once and shared by every certificate and
  service presenting it, so one RSA key deployed across forty hosts is one
  migration rather than forty. Key findings appear on every asset that uses the
  key, and only keys that are actually in use on an asset are judged — a key
  linked to nothing raises nothing. A symmetric key raises nothing either:
  Grover's algorithm weakens symmetric ciphers but does not break them, and they
  are not migration targets.

A configuration whose components resolve to **nothing** in the catalogue raises
no finding — and does not count as assessed either. That is the difference
between "we checked and it is fine" and "we could not check", and the product
keeps them apart rather than showing you the reassuring one.

### End-of-life findings

An asset's operating system and hardware, and every piece of software installed
on it, are checked against the end-of-life catalogue. A finding is raised once
the support date is **within 90 days** (180 for hardware, because replacing a
box takes longer than upgrading a package), and escalates as the date recedes:
past the date, and then past it by more than a year.

A product whose support ends further out than that raises **no finding** — but
the date is still recorded on the asset, so you can plan the upgrade before it
becomes a problem.

Software end-of-life findings are about the **installation**, not the host. A
server running four end-of-life packages has four findings, one per package,
because each one is a separate upgrade — and all four show on the server's
Findings tab, because a finding on something under an asset is a finding on the
asset.

### Vulnerability findings

Installed software is matched against the mirrored advisory catalogue by CPE and
by Package URL, using the version ranges each advisory publishes. One finding is
raised per **installation**, carrying every CVE that matched it, worst first.

One finding rather than one per CVE, because the fix is one action: you cannot
patch a single CVE in openssl 3.0.6 without moving off openssl 3.0.6. Twelve rows
for one upgrade would be twelve times the triage for one decision, so the twelve
CVEs are listed *on* the finding instead.

Severity is the worst matching CVE's CVSS score. **A CVE the catalogue has never
scored still raises a finding**, marked as not scored — it is reported as
ungraded, never as harmless.

Software with neither a CPE nor a Package URL **cannot be checked at all**, and
the platform counts those separately rather than reporting them as clean.

### Configuration findings

These are about **how a device is managed and what it leaves open**, judged from
what the platform has actually observed — an interrogation's own record of the
protocol it used, and the services identified on an asset's endpoints.

**Managed over a plaintext protocol.** When an interrogation records that the
management plane has no transport encryption — Telnet, HTTP, FTP, SNMP v1 or
v2c — the finding is raised on the **asset**. When a specific socket is the
plaintext management service, it is raised on that **endpoint** instead. Both
can be open at once, because they say different things: one is "this device is
managed in the clear", the other is "port 23 on this address answers Telnet".

**An insecure service exposed.** An endpoint running something the platform
rates as unsafe to leave reachable: a datastore whose shipped default is no
authentication (Redis, memcached, MongoDB, Elasticsearch, etcd, CouchDB), a
control interface that is remote code execution for whoever reaches it (the
plaintext Docker daemon API, the kubelet read-only port), a legacy remote shell
(rsh, rlogin, rexec) or legacy file sharing (NFS, rpcbind, TFTP).

Three things this producer deliberately does **not** do:

- **It does not fire on a port when something measured the service and it was
  not that one.** If the host reports that the process on 6379 is HAProxy, it is
  not Redis. Where nothing has identified the service, the port may fire on its
  own — but only for ports registered to a single service, and the finding says
  it was the port rather than a measurement. Look for **Matched by** in the
  finding's Configuration block.
- **It does not fire on a service it measured behind TLS or SSH.** An
  Elasticsearch behind transport security, an etcd behind client certificates —
  those are configurations somebody made on purpose, and reporting them as the
  insecure default would be the rule overruling the measurement.
- **It does not fire on a socket bound to loopback.** A Redis on 127.0.0.1 is
  the recommended configuration, not a finding. Where nobody established whether
  a socket is reachable — which is every endpoint a network scan found, since a
  scan can only see what answers — the finding says **not established** rather
  than claiming a measurement.

**Default credentials are not reported, because nothing tries them.** The
platform authenticates to your devices with credentials *you* supply and records
whether that worked; it never tries a vendor default. Until an explicitly
authorised default-credential probe exists, no finding of that kind is raised —
an empty list here means "not checked", not "none found".

### Inventory hygiene findings

These are about the **record**, not the thing the record describes. A missing
owner does not make a host less secure, so nothing in this producer contributes
to an asset's risk score — it is reported beside risk, never inside it.

| Kind | Raised when |
|---|---|
| **No owner** | The asset records neither an owner email nor a support group. |
| **Unclassified** | The asset is still on the `unknown_host` placeholder. A coarse but real class (`hardware`, say) is a classification, not a gap. |
| **No location** | No site, region, zone or location record. |
| **Duplicate suspected** | A merge proposal is waiting in Approvals. Raised on **both** records, because a suspected duplicate is a statement about a pair — showing it on only one leaves the other looking fine from its own page. Deciding the proposal closes both. |
| **Stale** | Nothing has observed the subject for **30**, **90** or **180** days — escalating rungs, on assets, endpoints and installed software alike. |
| **Orphan relationship** | A relationship points at an asset that has been archived or deleted. The edge is kept so the history stays readable; the finding is how you find it. |

The first four and stale apply to assets you have **approved into the
inventory**; something still waiting in Approvals is not yet a record anybody
has accepted. Archived assets are judged for nothing at all — you took them out
of the queue, and a producer putting fresh work back in would undo that.
Suspected duplicates are the exception: the newly-seen half of a contested pair
is by definition still awaiting approval, and that is precisely the record in
question.

**Where orphan relationships appear.** A relationship is not "under" either of
the assets it joins, but it is still somebody's work — so an orphan-relationship
finding is listed on **Risk & Compliance → Findings** *and* on the Findings tab
of each asset the edge touches. The finding names the edge, says which end went
missing and why, and links to the end that is still there. The Inventory Hygiene
control that counts them reaches them the same way, so the *score* and the list
agree.

**One meaning of "stale".** A record is stale when nothing has observed it for
more than **30 days**. That one number drives all of it: the Inventory → Stale
lens, the Stale finding's first rung, the Inventory Hygiene control IH-004 that
measures it, and the `stale` status an endpoint carries once it goes quiet. A
record in the Stale lens therefore has a Stale finding, and a Stale finding
means the record is in the lens.

*Changed in the current release.* The Stale lens used to cut at 14 days while
every judgement started at 30, so a record could be listed as stale with nothing
else anywhere agreeing. The lens now shows the same set the rest of the product
calls stale — expect it to list fewer records than before.

The Inventory Hygiene framework scores exactly these conditions, so activating
it turns this producer's output into a score and a worklist. Its two **counting**
controls — suspected duplicates and orphan relationships — report **not
assessed** until the producer has actually evaluated an asset, and a real number
(including a real zero) afterwards. "Nobody has looked yet" and "we looked and
found none" are different answers and the framework keeps them apart.
### Drift findings

Drift is the one producer that judges you against **yourself**. It has no
catalogue: it compares what your inventory looks like now against what it looked
like over a recent window, and reports the differences.

Four things are watched:

| Finding | Raised when |
|---|---|
| **First of its class on a segment** | A kind of device turns up on a network segment that has never held one — a printer on a server VLAN, an OT device on a corporate VLAN. |
| **Started speaking a new protocol** | A host begins using a protocol it was not using before. A newly-appearing plaintext or remote-access protocol is the case worth chasing. |
| **Listening ports changed** | The set of ports a host answers on moved. Ports **opening** is the signal to chase first, but a port closing unexpectedly can mean a service has failed rather than been removed. |
| **Certificate from a new issuer** | A host presents a certificate from a CA it has not used before. Either a planned migration, or what an interception looks like. |

#### The baseline window

The window is set under **Settings → Asset Lifecycle → Drift baseline**, and it
defaults to **30 days**. Everything first observed inside the window is a
candidate for a drift finding; everything older is the baseline it is compared
against.

That one number decides two things at once. It is how far back "new" reaches —
and it is also how long a change stays reported. **A drift finding closes on its
own once the change has been there for a full window**, because at that point it
is part of how your estate looks rather than a change to it. Nothing is lost: the
port, the protocol and the certificate are all still in your inventory, and the
finding keeps its history.

#### Nothing is drift until there is something to compare against

Two rules, and both exist so that "we have not been watching long enough to tell"
is never reported as "this is new":

- **A new organization gets no drift findings at all** until it has been observed
  for a full window. On day one everything you own is new, and a list saying so
  is not information.
- **An individual asset is only judged where it has its own history.** A host
  first seen last week has no protocol, port or certificate baseline of its own,
  so the first thing it does is not a *change*. The same goes for a network
  segment newer than the window.

#### Reading one

Opening a drift finding shows the two sides of the comparison — what the baseline
held, and what was seen — with the window it was judged under. Findings about a
new issuer carry the certificate's fingerprint, never its contents.

If you confirm a change was planned, resolve the finding. **The next pass will
not re-open it**, and once the change has aged into the baseline it closes on its
own. A *different* change on the same host — another new protocol, another new CA
— does re-open it, because that is a question you have not answered yet.

### Citations

An end-of-life or vulnerability finding is a judgement made against a catalogue,
so it says which catalogue entry it read and links to the page that published it
— the vendor's lifecycle page, or the CVE's NVD record. If you disagree with a
date or a match, that link is where you check it. The link is on the finding
wherever the finding is: in the inspector on the Findings page, and on the
asset's Findings tab.

Opening an end-of-life finding shows the catalogue product and cycle, the
end-of-life date, any extended-support date, and how far past (or short of) it
you are. Opening a vulnerability finding lists **every** CVE that matched, worst
first, each with its CVSS score and a link to its NVD record — all of them, not
just the one in the headline.

Opening a cryptography finding shows **why this score**: the number, the
components the catalogue rated (worst first, with each one's rating), and — when
the two disagree — the catalogue's score beside the one recorded when the
service was last observed, with a note that the worse of the two wins. The two
are shown apart because they are fixed in different places: a catalogue score
changes when an administrator edits the algorithm's catalogue row, and an
observed score changes when the service is scanned again.

A catalogue entry the platform has never heard of is **not** silently treated as
safe: the lookup is recorded as a gap, and a platform administrator can see and
fill it under **Catalog → End-of-life → Gaps**.

## What a finding is about

A finding names its **subject**: the thing the judgement is about. That is often
not the host — most compliance findings today are about a certificate — and as
more producers arrive, subjects will also include installed software, network
endpoints and individual cryptographic configurations.

A compliance finding about how a host negotiates cryptography names the **host**
as its subject, because that is what was measured: the check runs across
everything the host serves. The specific configurations that failed are listed
on the finding, so you can still get to them.

That matters when you are reading a count. "Assets with open findings" means the
asset **or anything under it**: its endpoints, the certificates and
configurations at those endpoints, its software. A server with a weak
certificate has an open finding, even though nothing is wrong with the server
itself.

## Severity and score

Severity is one ladder everywhere in the product: **Critical, High, Medium, Low,
Informational**. The bands are the CVSS qualitative ratings, so a High here
means what a High means elsewhere in your security tooling.

Compliance findings deliberately contribute **nothing** to an asset's risk
score. A framework is scored by its own score; counting one failing control
across every asset it touches would swamp the per-asset number and tell you
less, not more.

A score of **0** means *not assessed* — nothing resolved against a catalogue and
no rule fired. It does not mean safe.

## How an asset's risk score is made

An asset's risk score is the **highest score among its open findings** — the
ones on the asset itself, and the ones on everything under it: its endpoints,
the certificates and cryptographic configurations at those endpoints, and its
installed software. Highest, not a sum: one critical problem is a critical
problem whether or not there are three medium ones beside it, and adding them
up would let a pile of small things outrank a single serious one.

It is **recomputed**, not accumulated. When the last weak configuration on an
asset is fixed and its finding closes, the asset's score comes back down. The
number always describes the findings that are open right now.

Not every kind of finding feeds it. **Inventory hygiene findings contribute
nothing** — an asset with no owner is a gap in your records, not a security
weakness, and letting it inflate a security score would make the score mean less.
Hygiene is reported separately, as data quality. **Compliance findings
contribute nothing** either, for the reason above.

**Drift findings do** feed it, at deliberately modest weights. A change worth
looking at is not the same as a weakness, and an estate that moves a lot should
not out-score one running obsolete cryptography.

### "Assessed by", and the score that means nothing yet

Beside the score, an asset says **who has evaluated it**: *Assessed by crypto,
drift, eol, vulnerability*. A producer's name appears there once it has
completed a pass over that asset, whether or not it found anything — and it
appears *only* then. A pass that failed part way records nothing, so it can
never leave behind a claim that something was checked when it was not.

**Drift** is stricter with itself than the others have to be, because it judges
you against your own history: it names an asset only where that asset had a
history to be compared against. A host first seen last week, and every asset of
an organization still inside its first baseline window, are not claimed — there
was nothing to compare them to, and saying otherwise would turn "we could not
tell yet" into "we looked and it is fine".

Only producers that can actually **move the score** are named there. Inventory
hygiene is not one of them: it reports gaps in your records, not security
weaknesses, so an asset it has looked at and nothing else has still reads *Not
assessed* for risk — which is true. Its work shows up in the hygiene controls
instead.

That turns a score of 0 into two different answers, and the page tells you which:

| What you see | What it means |
|---|---|
| **0, assessed by crypto, drift, eol** | Those producers looked at this asset and found nothing to score. A clean bill of health, from the parts of the platform that can give you one. |
| **Not assessed** | Nobody has evaluated this asset yet. There is no finding *and* no reassurance. |

An unassessed asset is not a low-risk asset. Filter for them with **Inventory →
the facet rail → Risk → Not assessed**, and give the discovery that reaches them
a nudge — an active scan, a sensor, or an inventory upload, depending on what is
missing.

Where the score comes from is on the asset page too: the **Overview** tab names
the single finding the score came from, and clicking it opens the **Findings**
tab with that finding highlighted, alongside the rest of them.

## The two states a finding has

Findings carry two independent states, and both are needed to answer "is this
still my problem?".

**Detection state** is the platform's: is the condition still there?

| State | Meaning |
|---|---|
| **Active** | Still detected on the most recent evaluation. |
| **Inactive** | The condition went away. The row is kept, with its history. |
| **Archived** | Retired. It no longer appears anywhere. |

**Workflow status** is yours: has anybody dealt with it?

| Status | Meaning |
|---|---|
| **New** | Nobody has looked at it yet. |
| **Notified** | Someone has been told. |
| **Resolved** | Closed by a person. |
| **Suppressed** | Muted, with a reason and optionally an expiry. |

A finding is **open** when both agree: still detected, and not closed by a
person. That is what the counts and the "has open findings" filter mean.

### When a condition comes back

If a finding goes Inactive and the condition later returns, the platform
**reuses the same finding** rather than opening a new one. Its first-seen date,
its occurrence count and its history stay intact, and it records when it
resurfaced — so you can see that this is the third time this quarter, not three
unrelated problems.

One exception is deliberate: a returning finding that you had **Resolved** goes
back to **New**, because it is outstanding again. A finding you **Suppressed**
stays suppressed — you muted the condition, not that particular sighting of it.

## Where to find them

- **Risk & Compliance → Findings** — every open finding for your organization,
  from every producer. This is where you triage: assign an owner, change status,
  suppress with a reason, or raise a ticket.

  The lens picker chooses how they are grouped. **By Producer** shows all of
  them, banded by who judged what; **By Framework** and **By Control** group
  compliance findings by the control they failed, and show only those — an
  end-of-life finding has no control, so there is nowhere on those two lenses to
  put it. The producer chips along the top filter any of the three, and each one
  carries its own count so you can see at a glance which producer is raising
  what.

  The framework picker narrows to one framework's controls, so it also narrows
  to compliance findings. That is the filter meaning what it says.

  The **search box** searches your whole findings list, not the page on screen:
  the term goes to the server, which matches it against each finding's summary,
  the thing it is about, the kind as it is written on the row, and the host the
  row names underneath it — so typing `end of life` finds the end-of-life
  findings, `openssl` finds every finding about openssl, and `web-01` finds
  every finding on web-01, however many findings your organization has. The count
  beside each producer chip narrows with it, so the chips and the list always
  describe the same set. `%` and `_` are ordinary characters here, not
  wildcards.

  A link can carry the search: `?q=openssl` on this page opens it already
  filtered. That is what the software surfaces use when a product is installed
  on too many assets to name a single one.
- **Inventory → any asset → Overview** — the risk score, the one finding it came
  from, and which producers have evaluated the asset.
- **Inventory → any asset → Findings** — the open findings on one asset and on
  everything under it, plus the producers that assessed it and had nothing to
  report.
- **Inventory → the facet rail → Findings** — filter the asset list to assets
  that have open findings, or to assets that have none. "No open findings" means
  a producer looked and found nothing; for assets nobody has assessed, use
  **Risk → Not assessed** instead.
- **Risk & Compliance → Posture** — findings rolled up by control and by
  framework.

In the query language, `finding:(…)` selects assets by their findings:

```
finding:(severity >= high) and environment:production
finding:(producer:compliance and workflow_status:NEW)
finding:(producer:eol and kind:os_end_of_life)
finding:(producer:vulnerability and severity:critical)
finding:(producer:crypto and kind:pqc_vulnerable)
finding:(producer:configuration and kind:plaintext_management)
finding:(producer:hygiene and kind:no_owner) and environment:production
finding:(producer:drift and kind:port_profile_changed)
not finding:(detection_state:ACTIVE and workflow_status not in (RESOLVED, SUPPRESSED))
```

The last one is exactly what the "No open findings" filter writes — the rail
shows you the query it built, so the language is learned by reading.

## Remediation guidance

Every finding kind carries **standard remediation guidance**: what a person does
about a finding of that kind, written once and shown on every finding of it. You
will find it in the **Remediation** block of the finding inspector, under
**Risk & Compliance → Findings**.

It is generic to the kind, on purpose. "Reissue the certificate with a key and
signature algorithm the catalogue rates acceptable" is true of every weak
certificate, so it does not need a model, a provider or an edition to say — it
is simply there, in every deployment, whether or not anyone has configured AI.


## Findings and tickets

A finding is the platform's judgement; a **ticket** is your work on it. Raising
a ticket from a finding links the two, and the ticket carries a link to the
finding's subject — the asset or the certificate — so the person who picks it up
knows what they are looking at. Where the finding names exactly one
cryptographic configuration, the ticket links that too; where it names several,
it does not pick one, because guessing would be worse than leaving the question
open.

Tickets outlive findings. If a finding is archived, the ticket stays, because
the work was yours.
