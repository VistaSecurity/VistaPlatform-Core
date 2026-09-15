// Package producer is the writer every finding producer shares (ADR-0005 D3,
// workstreams 3.3/3.4 part 2).
//
// One table, one set of lifecycle rules. The compliance producer wrote those
// rules first, inline in compliance-engine; this package is the same semantics
// as a Core dependency any service can import, so the eol, vulnerability,
// configuration, hygiene and drift producers do not each re-derive them. It
// deliberately does NOT import compliance-engine — compliance-engine is a
// service, and a service is not a library.
//
// # The contract, in five sentences
//
//  1. A producer's run is a FULL STATEMENT of what it currently sees. Every
//     condition it still observes is [Writer.Upsert]ed; everything it no longer
//     asserts is swept ([Writer.Sweep]) to INACTIVE.
//  2. There is never a second OPEN row for one (producer, kind, subject). The
//     partial unique index `findings_open_subject_uniq` guarantees it and
//     Upsert's ON CONFLICT is written against that exact index.
//  3. A condition that goes away keeps its row (INACTIVE, not deleted), and a
//     condition that RETURNS reuses that row — bumping occurrence_count and
//     stamping resurfaced_at — so first_seen and occurrence_count describe the
//     whole history rather than the latest episode.
//  4. `producer`, `kind` and `subject_type` are validated against the generated
//     registry (standards/findings-registry.yaml). The table has no CHECK on
//     any of them; [findings.Validate] is the enforcement point.
//  5. Severity and score come from the registry too — a ladder kind must write
//     one of its rungs verbatim, and a kind whose `feeds_risk` is false must
//     write score 0, because a score that feeds nothing but reads as a number
//     is the "0 means not assessed" distinction thrown away.
//
// # What it is not
//
// It is not a queue, a batcher or a transaction owner. Every method takes the
// caller's `*sql.Tx`, because a producer's run is one unit of work: the writes,
// the sweep and whatever facts the producer also stores have to commit or roll
// back together, and a writer that opened its own transaction would make a
// half-swept run possible. The caller is responsible for running that
// transaction under the tenant's RLS session — [database.WithTenantTx] — and
// every statement here also carries an explicit `tenant_id` predicate, which is
// the same belt-and-braces every other tenant-scoped query in this codebase
// uses.
//
// # Adding a producer
//
// See docsv4/internal/developer/standards/FINDINGS.md, "Producers". The short
// version: add the producer and its kinds to the registry YAML, run
// `make generate`, construct a [Writer] with [New], and run the contract suite
// in [producertest] against your producer's key so the lifecycle is proven
// rather than assumed.
package producer
