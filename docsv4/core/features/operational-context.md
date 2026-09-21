# Operational Context

A discovery tells you an address answered. It does not tell you *whose* address,
*where* it is, or whether anyone should be worried about it. Operational context
is the small amount of information you supply once — where your networks are and
what they are for — that turns every subsequent discovery from a fact into
something actionable.

Two registries carry it: **Locations** and **Network Segments**. Both live under
**Settings → Infrastructure**.

## Locations

A hierarchical registry of the places your estate physically or logically sits:
a region, a datacenter, a rack; a cloud provider and region.

**Settings → Infrastructure → Locations** lists them with their type, cloud
provider and region where relevant, timezone, and how many assets each holds.
**New location** creates one; the row actions edit or delete. A location can
record a physical address, a cloud provider and region, and a timezone.

Creating, editing and deleting need the **update settings** permission. Everyone
with settings access can see the list.

Locations exist mainly to give network segments somewhere to live — every
segment names one.

## Network Segments

A segment is a piece of your network described in a way the platform can match an
address against:

| Type | What you give it |
|---|---|
| **CIDR** | `10.4.0.0/16` |
| **IP range** | a first and last address |
| **Domain** | a domain pattern |
| **Cloud VPC** | a VPC identifier |

**Settings → Infrastructure → Network Segments** lists them with their type,
value, environment, location and whether they are active. **New segment** creates
one and **Import** brings a batch in from a spreadsheet. Each segment carries an
**environment** (production, staging, development, test) and a **location**, plus
optional description, business unit, owner email, tags, and an **auto-approve**
switch.

Same permission rule as Locations: anyone with settings access can look; changing
anything needs **update settings**.

### What segments decide

Defining your segments is not bookkeeping. Four things fall out of it:

1. **Environment and location on every asset.** An asset inherits both from the
   segment its address falls in. That is where `environment:production` in a
   query gets its answer, and how the inventory can be sliced by site.
2. **Internal versus third party.** An address inside one of your segments is
   *yours*. An address outside them is somebody else's — which is what the
   3rd Party lens is a list of, and what the ownership filters on the
   Certificates lens sort by. With no segments defined, that distinction is a
   guess. See
   [Third-party and external connections](./third-party-and-external-connections.md).
3. **What gets approved without you.** A segment with **auto-approve** on is
   the way a newly *discovered* asset joins active inventory without a person
   accepting it. The one other automatic path is a host your own device agent
   is installed on, which its first host inventory admits. Everything else waits
   in **Discovery → Approvals** — including assets you type in by hand. See
   [Asset approval](./asset-approval.md).
4. **What discovery scans.** Segments are what a scan is scoped against.

Define your segments before your first discovery. Running one first works, but
you will spend the afternoon approving things and re-tagging them afterwards.

## Service identification

Separately from the two registries, the platform tries to name the service behind
each endpoint it finds — and it says how sure it is, which is the part that
matters.

An endpoint's service name on the **Services & Endpoints** tab is labelled with
how it was determined. A name read directly out of a service banner reads as
**Confirmed**; a name deduced from the port number alone reads as a **best
guess**. Port 8443 is *probably* HTTPS and might be anything; the label is what
stops that guess being quoted back at you later as a finding.

## History

**Network Spaces** was the earlier name for this idea, and the segments registry
replaced it. Assets classified under the old model carried over; the segment a
given asset matches is recomputed against the current registry, so editing a
segment reclassifies what falls inside it rather than leaving old answers behind.
The earlier `network-spaces` API endpoints still answer, for integrations written
against them, and proxy to the segment model — new integrations should use the
network-segments API instead.

## Related

- [Asset approval](./asset-approval.md) — the two auto-approval rules, and the queue
- [Third-party and external connections](./third-party-and-external-connections.md) — what internal-versus-external buys you
- [Discovery](./discovery.md) — what segments scope
- [Inventory and lenses](./inventory-and-lenses.md) — the Segment, Site and Environment filters
- [Spreadsheet import](./spreadsheet-import.md) — importing segments in bulk
