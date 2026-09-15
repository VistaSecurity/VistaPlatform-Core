// Package catalogs is the platform catalogue LOOKUP — the one code path that
// resolves a vendor/product/version against `eol_catalogue` and
// `vulnerability_matches`, and records the questions it could not answer.
//
// # Why it is here and not in a service
//
// It was in admin-service, because the platform admin console is what curates
// these tables and the Enricher seam's rule default lives beside them
// (workstream 4.5b). Then the `eol` producer arrived in inventory-service
// (3.3 part 2) needing to resolve exactly the same subjects against exactly the
// same rows — and there were only three ways to arrange that: an HTTP hop to
// admin-service, a second implementation, or one package both import.
//
// An HTTP hop would put a service boundary inside a per-asset loop and make the
// producer's answer depend on another deployment being up. A second
// implementation is the fork this repository has paid for twice already (the
// sensor and cluster-sensor-service; the device-agent and
// device-interrogation-service). So: one package, Core, pure Go plus
// database/sql, imported by both.
//
// The consequence worth stating plainly is that the enricher's answer and the
// producer's finding CANNOT disagree about which catalogue row applies, because
// there is one [LookupEnricher.ResolveEOL] and they both call it. A date shown
// on the asset page as a fact and the end-of-life finding beside it are the
// same row.
//
// # What stayed in admin-service
//
// Everything that is a console rather than a lookup: the proposal queue
// (`eol_catalogue_proposals`) and its review workflow, the gap pass that feeds
// a generative enricher, citation validation, and pagination for the admin
// tables. Those have one consumer, and moving them would widen this package's
// surface without giving anything a second caller.
//
// # Two rules this package holds itself to
//
//  1. **It will not return the nearest row.** "Ubuntu 22.04" does not answer a
//     question about "Ubuntu 24.04", and a lookup that falls back to a
//     neighbouring cycle produces a support date that is wrong in the direction
//     of reassurance. A question it cannot answer exactly is recorded on the gap
//     list and answered with nothing.
//  2. **Cite or refuse** (ADR-0008 D4.4). Every fact it emits carries the
//     catalogue row id it came from and the URL that row cites. A catalogue row
//     with no source_url is one somebody hand-entered without one, and it is not
//     evidence.
package catalogs
