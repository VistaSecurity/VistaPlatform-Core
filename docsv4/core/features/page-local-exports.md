# Page-local Export

When you're looking at the Inventory page, the **Export** button in the toolbar downloads whatever's currently on screen as a CSV. That's it. No template selection, no parameter dialog, no waiting on a server-side generation job — just the rows you see, in your spreadsheet.

This is the right tool for: filtering down to a few hundred rows, dropping the result into Excel, emailing it to a colleague, pasting it into a ticket. Anything where "I just want this list in CSV form" is the whole task.

## What it isn't

It's not evidence. The CSV doesn't carry a content hash, a signature, or a provenance record. If you regenerate the same view tomorrow, you'll get different rows (new assets, expired certs, edited tags) — that's expected for a working view, but it means a CSV from this button is a snapshot in a notebook, not a snapshot in a vault.

For audit submissions, vendor questionnaires, or anything where the recipient needs to verify the artifact later, **generate a CBOM instead** (Risk & Compliance → Bills of Materials in the sidebar). A CBOM:

- Locks the rows by content hash so the recipient can verify integrity.
- Records the exact version of the scope it was generated against, so the
  boundary is reproducible rather than remembered.
- Stays retrievable later from the Bills of Materials list.


## Where the Export button lives

**Inventory** (`/inventory`) → the toolbar at the top of the page, beside the
count. It exports the lens you are on, with whichever filters and search you have
applied, and greys out when there is nothing to export.

It is on the **Certificates, Keys, Configuration, TLS, SSH, Data Protection,
3rd Party** and **Stale** lenses.

**Map** has an export of its own, in the same spirit and with the same caveat: it
downloads the graph you are looking at as GraphML or Cytoscape JSON, for opening
in a graph tool. Convenience, not evidence.

## What's in the CSV

Whatever the page is showing — the columns the active lens shows. Switch lenses
(Certificates → Keys → Configuration → Data Protection → 3rd Party → …) and the
next click exports the new layout. Certificates export issuers and expiry, keys
export sizes and fingerprints, configurations export cipher suites and
algorithms, Stale exports class, segment, status and last seen.

The filename names the view and the date — for example
`vista-inventory-certificates-2026-09-16.csv`.

Values that a spreadsheet would try to evaluate as a formula are escaped on the
way out, so a hostname a scanner picked up can't execute in anyone's Excel.

## Why it works this way

Earlier versions offered a set of templated reports that produced PDFs of the
same data the page was already showing, each behind its own parameter dialog and
its own wait. They were retired, because "export this view" and "produce
verifiable evidence" are two different jobs and one surface was doing neither
well.

They are now separate and each is good at its half. **Export** is the no-ceremony
one: the view you are looking at, as a CSV, immediately. **Bills of Materials**
(`/risk-compliance/cbom`) is the one with ceremony, and the ceremony is the
point — a fixed boundary, a content hash, and something a recipient can check.

## Related

- [Inventory and lenses](./inventory-and-lenses.md) — the views you can export
- [CBOM artifacts](../cbom/cbom-artifacts.md) — the audit-grade alternative
- [Scopes](./scopes.md) — the named boundary a CBOM attests to
