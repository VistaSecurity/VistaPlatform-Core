# Adding Assets Manually

Most of your inventory arrives on its own — sensors find it, cloud connectors
pull it, a spreadsheet or a CMDB export brings it in. But some things you simply
know about: an appliance nothing can scan, a business service that has no
address at all, a host that is behind a firewall your sensors cannot reach.

**Inventory → All assets → New asset** is where you record those.

## Where the button is

Open **Inventory** in the left rail. On **All assets** — and on the Certificates,
Keys, Configuration, TLS, SSH, Data Protection, 3rd Party and Stale lenses too —
the **New asset** button sits at the top right of the page.

You need the **create assets** permission to see it. Without that permission the
button is not shown at all, rather than shown and then refused.

## Pick the class first

The form opens on a single field: **Class**.

That order is deliberate. An asset's class is what kind of thing it is — Server,
Switch, Virtual machine, Object storage, Business service — and the class decides
which fields the rest of the form offers you. A server has an operating system
and a serial number; an object store has a provider, a region and a bucket name.
Neither list would make sense on the other.

The picker is the whole class taxonomy as one indented list, so you can see where
a class sits in the tree while you choose it. Pick the most specific class that
is true. If you are not sure, a parent class is a better answer than a wrong
child — you can reclassify later, and the asset's **History** tab records that
you did.

Once you pick one, a short description of that class appears under the field, and
the **Class attributes** section fills in with the fields that class declares.
Leave any of them blank; blank means "not recorded", which is a different and
more honest thing than an empty value.

## The rest of the form

| Section | What goes in it |
|---|---|
| **Display name** | What a person calls this thing. Optional — the platform derives one from the identifiers if you leave it empty. For a **service** class it is *required*, because a service has no address or serial to be known by: its name is its identity. |
| **Identifiers** | How this thing is known. See below — this is the important one. |
| **Class attributes** | Whatever the class declares. Some classes declare none, and the form says so instead of showing an empty box. |
| **Context** | Environment, support group, business unit, owner email. "Who do I page about this?" is usually the first question anyone asks of an asset, so there is a field for the answer. |
| **Description** | One line, free text. |
| **Tags** | Key/value pairs of your own. |
| **Metadata** | An optional JSON object for anything the class schema does not declare. |

## Which identifiers you may type

An identifier is a fact that says *which real thing* this record is about. They
are what let two sightings of one machine become one asset instead of two — so
the form will not let you save a new asset with none at all. (The one exception
is a declared service, which identifies by its name.)

You may enter:

- **FQDN**, **Hostname**, **IP address**, **MAC address**
- **Serial number**
- **SSH host key fingerprint**
- **CMDB sys_id**
- **Name** (for service classes)

Two kinds are **minted by a collector and can never be typed**:

- **Agent ID** — issued by the platform to a running sensor or agent
- **Cloud resource ID** — the provider's own name for a resource

Both mean "this is the thing that agent is" or "this is that exact cloud
resource", and only the platform can know either. If a person could type one,
they could claim an identity the platform assigns — which is how two genuinely
different assets get merged by hand, with no proposal and nothing to review.

A serial number you type is worth exactly as much as one a scanner read. What
differs is the **source**, which the platform records against the identifier
either way.

### Editing an existing asset

When you reopen the form on an asset that already exists, you will see identifier
rows with a padlock beside them. Those were recorded by a collector, not typed by
a person, and the form will not retire them. They are shown rather than hidden:
an asset that is matched on an agent ID the form never mentioned is confusing in
a way that showing the locked row fixes.

If you remove an editable identifier and save, and the platform keeps it anyway,
it tells you which one and why rather than reporting a silent success.

## What happens when you save

The asset is not simply inserted. It goes through the same **identification
engine** every discovery goes through, which asks first whether this is something
you already have:

- **No match** — a new asset is created.
- **Match** — your entry is folded into the existing asset, which gains whatever
  identifiers, attributes and context you supplied. This is the point of running
  a manual entry through the engine: typing in a host a sensor already found
  updates that host rather than creating a duplicate beside it.
- **Conflict** — your identifiers belong to more than one existing asset and
  nothing can settle which. Nothing is created or changed; a **merge proposal**
  is opened and the form tells you to review it in **Discovery → Approvals**.

## Does it go straight into inventory, or into Approvals?

That is decided by your own approval policy, not by the fact that you typed it.

An asset — however it arrives — joins active inventory immediately only when it
falls inside a **network segment you defined with auto-approve turned on**
(**Settings → Infrastructure → Network Segments**). Anything else waits in
**Discovery → Approvals** for a person.

So in practice:

- A host inside an auto-approving segment: **monitored straight away**, and it
  shows up in All assets on your next refresh.
- Everything else — including anything with no address to match a segment against,
  such as a business service or an object store: **pending approval**. It will not
  appear in the asset list until you accept it, and All assets shows a banner with
  the pending count and a link into the queue.

This is on purpose. The approval policy is the tenant's, and letting a
hand-entered asset step around it would make the policy advisory. If you
regularly add assets by hand and want them monitored immediately, define the
segment they live in and mark it auto-approve.

An asset in conflict always waits for a human, whatever the segment rule says —
there is a merge to settle first.

## Certificates are a separate button

A certificate is not an asset, and it has its own path in: **Upload cert**, beside
**New asset** on the Certificates lens. Paste a PEM or pick a file (leaf first;
a chain is fine). The certificate's contents are read out of the PEM rather than
typed, so nothing about it is taken on trust. It appears in the Certificates lens
straight away, shown as unassigned until something links it to an asset.

Uploading needs the **manage assets** permission.

## Related

- [Inventory and lenses](./inventory-and-lenses.md) — where the asset lands, and how to find it again
- [Asset approval](./asset-approval.md) — the queue, merge proposals, class proposals, and the one auto-approval rule
- [Assets and crypto configurations](./assets-and-crypto-configurations.md) — what an asset, an endpoint and a configuration each are
- [Spreadsheet import](./spreadsheet-import.md) — the same job for many assets at once
- [Operational context](./operational-context.md) — locations and network segments
