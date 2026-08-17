# Page-local Export

When you're looking at the Inventory page, the **Export** button at the top right downloads whatever's currently on screen as a CSV. That's it. No template selection, no parameter dialog, no waiting on a server-side generation job — just the rows you see, in your spreadsheet.

This is the right tool for: filtering down to a few hundred rows, dropping the result into Excel, emailing it to a colleague, pasting it into a ticket. Anything where "I just want this list in CSV form" is the whole task.

## What it isn't

It's not evidence. The CSV doesn't carry a content hash, a signature, or a provenance record. If you regenerate the same view tomorrow, you'll get different rows (new assets, expired certs, edited tags) — that's expected for a working view, but it means a CSV from this button is a snapshot in a notebook, not a snapshot in a vault.

For audit submissions, vendor questionnaires, or anything where the recipient needs to verify the artifact later, **generate a CBOM instead** (Risk & Compliance → CBOM in the sidebar). A CBOM:

- Locks the rows by content hash so the recipient can verify integrity.
- Captures `scope_version` so the boundary is reproducible.
- Stays retrievable later from the CBOM list.


## Where the Export button lives

- **Inventory** (`/inventory`) → top right of the page, next to "Discover Assets." Exports the current lens view (whichever lens is active, with whichever filters are applied).

That is the only one. The button greys out when there's nothing to export, with a tooltip pointing you at the CBOM page for audit-grade output.

## What's in the CSV

Whatever the page is showing — the columns the active lens shows. Switch lenses (Infrastructure → Certificates → Configuration → …) and the next click exports the new layout.

The filename is `<view>-<YYYY-MM-DD>.csv` (e.g. `inventory-certificate-2026-06-08.csv`). The date is the local date at the moment you clicked.

## Why this exists (Phase 5 background)

The legacy reporting surface had eight separate "lens reports" that produced PDFs of the same data you were already looking at. Each was a templated server-side generation job with its own filter dialog. We retired the whole thing in Phase 5 of the CBOM-centric reporting redesign — the surface was 90% redundant with the page itself.

This button is the replacement. It does exactly the job that wasn't worth a templated report: a CSV of the view you're already looking at, with zero ceremony.

For the part that *did* need ceremony — evidence-grade artifacts with provenance — that's now first-class at Risk & Compliance → CBOM (`/risk-compliance/cbom`), and the affordance is much better than the old "Generate Lens Report PDF" workflow.
