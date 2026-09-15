# Concepts

Vista Platform is becoming a general asset inventory and map, with
cryptographic posture as its first specialized module. As new kinds of
assets, relationships, and posture checks are added, they all use the same
small set of ideas described on this page. The vocabulary here is used
consistently across the rest of the documentation and the product — skim it
once and the rest will read consistently too.

## Asset

An asset is a thing you manage: a server, a switch, a virtual machine, a
cloud database, an application, a business service. Every one of these gets
exactly one record, no matter how many addresses or ports it answers on. A
web server that serves HTTPS, accepts SSH, and exposes a management
interface is one asset with three exposed points — not three separate
entries competing for your attention.

*Example:* `web-01` is a single asset, even though it listens on both port
443 (HTTPS) and port 22 (SSH).

## Endpoint

An endpoint is an address and a port that an asset exposes — where it can be
reached, and over what. This is where TLS and SSH configurations actually
live, because a protocol is negotiated at a specific address and port, not
by the asset as a whole.

*Example:* `web-01` has two endpoints: `10.0.1.15:443` (TLS 1.3) and
`10.0.1.15:22` (SSH). Each carries its own protocol details and its own
risk; the asset rolls them up.

## Class

Every asset has a class — the kind of thing it is, drawn from a fixed tree.
The top-level classes are **hardware** (computers, network devices, storage,
printers, OT and IoT devices), **virtual** (virtual machines, containers,
hypervisors), **cloud resource** (compute instances, managed databases,
object storage, and similar), **application**, and **service** (a declared
business or technical capability, like "Checkout"). Two more classes exist
for things you've spotted but don't fully know yet: **external**, someone
else's endpoint your assets talk to, and **unknown host**, an address inside
your own space you haven't identified further.

The top level is fixed platform-wide, so a filter, a report, or the map
means the same thing for every tenant. Tenant admins can add their own
subclasses underneath any of these — a "Dell PowerEdge" subclass under
server, say — to capture detail specific to their environment, without
touching the shared taxonomy everyone else relies on.

## Identifier

An identifier is a fact that helps establish which real-world thing an asset
record actually refers to: a serial number, a cloud resource ID, a MAC
address, a fully qualified domain name, and so on. Vista Platform trusts
identifiers in a fixed order — things that rarely change and are hard to
fake (a cloud resource ID, a serial number) outrank things that are easy to
observe but also easy to reassign.

An IP address is deliberately the weakest identifier. DHCP leases expire,
NAT hides many hosts behind one address, and cloud instances get a new IP on
every restart, so the same address can belong to different assets at
different times. Matching on IP alone would quietly merge or split records
that shouldn't be. IP is used to identify an asset only when nothing
stronger is available, and only within a network that isn't known to hand
addresses out dynamically.

## Relationship

Assets are connected by typed, directional relationships: runs on, hosted
on, depends on, connects to, member of, and a handful of others. An
application *runs on* a server; a virtual machine is *hosted on* a
hypervisor; a checkout service *depends on* a database.

These relationships are what the map is built from. Pick an asset and see
everything connected to it a few hops out in either direction, so you can
answer "if I take this down, what else is affected?" without hunting
through separate lists by hand.

## Fact, finding, risk, and alert

**Fact.** A plain statement about something, with a record of where it came
from and when — *this server runs Ubuntu 22.04, measured by a sensor on
Tuesday.* Facts aren't judgments; they carry no verdict of good or bad, just
what was observed.

**Finding.** A judgment made from facts against a rule or a catalogue —
*this operating system is end of life,* *this certificate uses a weak
signature algorithm,* *this control fails.* A finding carries a severity and
the evidence behind it.

**Risk.** A single 0–100 score, and a plain-language band (Low, Medium,
High, Critical), rolled up from the worst finding on an asset. It isn't only
a crypto score — vulnerabilities, end-of-life software, and configuration
problems all feed the same number.

Here's the honesty rule, in plain terms: a score of zero, by itself, doesn't
mean "safe." It can just as easily mean nothing has looked at this asset
yet. Vista Platform tracks which kinds of checks have actually run against
each asset, and the UI always distinguishes "checked, and clean" from "not
checked." A blank is a blank, never a pass.

**Alert.** A notification that something changed and needs attention — a
certificate about to expire, a new critical finding, an asset that's gone
quiet. Alerts are deduplicated and escalated automatically, so the same
problem doesn't page you twice; they're what turns a finding into something
you actually see.

## Provenance

Every fact, identifier, and relationship carries provenance — where it came
from. There are four kinds: **measured** (an agent or a scanner observed it
directly), **declared** (a person typed it in), **imported** (a connected
CMDB or a spreadsheet supplied it), and **inferred** (a model or a rule
guessed it from a pattern).

Provenance decides what wins when two sources disagree, and the rule is
simple: an inferred value — a best guess — never overwrites something that
was actually measured or that a person declared. A guess can fill a gap, but it
can't overrule a fact. This is the same principle that already governs your
certificate and configuration data, extended to cover everything else the
platform tracks.

## Approval and proposals

Nothing enters your inventory unannounced. A newly discovered asset, a
suggestion that two records describe the same thing and should merge, a
proposed reclassification, or a proposed relationship — all of these wait in
[**Approvals**](./features/asset-approval.md) until a person accepts them, or until a rule you've configured
admits them automatically (by network segment, for example).

This applies equally to anything an AI-assisted part of the platform
suggests. A model proposing that two assets are duplicates, or that a newly
seen device is probably a switch, produces exactly the same kind of row in
Approvals as a rule would — a proposal with its reasoning attached, never a
fact written straight into your inventory. You always decide what becomes
real.

## Query

Every list you filter, every scope you define, and every rule you write
reduces to the same thing underneath: a query, written in one small
language. `class:server and environment:production` finds every production
server. `certificate:(expires < now+30d)` finds anything with a certificate
expiring within the month. Terms combine with `and`, `or`, and `not`, group
with parentheses, and can reach across a relationship to filter by what an
asset is connected to.

You'll rarely type this by hand — the filter panel on any list builds the
query for you as you click through options, and shows you the query it
wrote so you can pick it up by reading. The full syntax has its own
reference page; this is just enough to recognize it when you see it.

## Scope and snapshot

A **scope** is a saved query — a named definition of "these assets, and not
those," reusable anywhere a boundary is needed: a compliance report, a
signed artifact, an approval rule. Instead of re-describing "our
PCI-in-scope production systems" every time, you define it once and pick it
by name.

A **snapshot** is a signed, dated record of everything that matched a scope
at a specific moment — proof you can hand to an auditor that says "this is
what was true, and here is the evidence." Today, the snapshot you generate
is a Cryptographic Bill of Materials (CBOM), covering certificates, keys,
and crypto configurations. As the inventory grows beyond crypto, the same
signed-snapshot mechanism extends to cover the full asset inventory too. See
[Scopes](./features/scopes.md) and [CBOM Artifacts](./cbom/cbom-artifacts.md).

## Cryptographic posture

Cryptographic posture — the state of your certificates, keys, crypto
configurations, and data protection — used to be the whole product. It's now
the first of what will become several posture modules sitting on top of the
general inventory, and nothing about how it works changes: certificates,
keys, and crypto configurations are still their own well-understood objects,
linked to the assets and endpoints that use them. See [Certificate Chain
Management](./features/certificate-chain-management.md), [Cryptographic
Keys](./features/cryptographic-keys.md), and [Crypto
Risks](./features/crypto-risks.md) for the detail. What changes is the frame
around it: crypto posture now sits beside asset identity and relationships,
one module among several, rather than being the only lens the inventory has.
