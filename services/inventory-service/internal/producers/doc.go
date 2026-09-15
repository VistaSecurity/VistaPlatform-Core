// Package producers holds inventory-service's finding producers: the passes
// that read a tenant's facts and software, judge them against a platform
// catalogue, and write `findings` through the shared writer
// (shared/findings/producer).
//
// Four of them today — `eol` (workstream 3.3 part 2), `vulnerability` (3.4
// part 2), `configuration` and `hygiene` (both 3.5). They share one three-phase
// shape, and the shape is the design:
//
//	READ     one short tenant transaction: assets, their facts, their software,
//	         their endpoints, their edges
//	RESOLVE  no transaction at all: the platform catalogues carry no tenant_id
//	         and this phase makes no tenant-scoped query, so holding a
//	         transaction open across thousands of catalogue lookups would pin a
//	         connection and a snapshot for no isolation benefit. The two 3.5
//	         producers have no catalogue to read — theirs is a Go rule table and
//	         the inventory record itself — so their middle phase is pure
//	         computation and is called `plan` rather than `resolve`.
//	WRITE    one tenant transaction: every finding, every fact, then the sweep
//
// The write phase is one transaction because the sweep is the dangerous half. A
// producer's run is a FULL STATEMENT of what it currently sees — everything it
// no longer asserts goes INACTIVE — so the upserts and the sweep have to commit
// together. A run that wrote its findings, failed, and swept anyway would
// inactivate live findings and re-raise them on the next pass, resetting
// workflow status and re-notifying each time.
//
// And a run that FAILS does not sweep at all. A partial answer is not a full
// statement about anything, and sweeping on one would be the same damage
// arrived at by a different route. Every producer here returns an error rather
// than a partial [Run] when its read or resolve phase fails.
//
// # What these producers do not do
//
// They do not compute severity. The registry's ladders and the CVSS convention
// decide it (see `ladder.go` and `cvss.go`), and the writer refuses a pair that
// is not one of the registry's rungs — so a producer that invented a number
// fails loudly rather than quietly disagreeing with the YAML that documents it.
//
// They do not resolve catalogue rows themselves. `shared/catalogs` does, and it
// is the SAME code path the Enricher seam's rule default uses — which is what
// makes the `eol.os.date` fact shown on an asset page and the end-of-life
// finding beside it two readings of one catalogue row rather than two opinions.
//
// They do not decide risk, and they do not write `assets`. `risk_score` and
// `risk_assessed_by` are the generic post-pass rollup's (internal/riskrollup,
// workstream 3.2), derived from the findings and from the coverage record; a
// producer that wrote either would be a second opinion about a number the
// rollup owns.
//
// What each producer DOES owe is its coverage claim: `Writer.MarkAssessed`,
// called from inside its own write transaction, naming the assets it actually
// EXAMINED. That is the record of who has looked, and it is what keeps "no
// findings" from reading as "nothing wrong" for an asset nobody evaluated. It
// is narrower than "every asset read": the vulnerability pass claims only
// assets with identifiable software, and the configuration pass only assets
// with a management fact or an endpoint. Marking generously is the failure
// mode — an unclaimed asset reads "not assessed", which is true and visible;
// an over-claimed one reads "assessed clean", which is false and silent.
package producers
