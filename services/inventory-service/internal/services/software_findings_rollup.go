package services

// The software EOL / vulnerability rollup (workstream 3.8).
//
// The Software tab on the asset page and the Inventory `software` lens both
// answer "is this package end of life, and does it have CVEs?" — and both would
// otherwise have to ask compliance-engine once per row. Fifty installs is fifty
// subject-filtered calls, which is the N+1 this file exists to avoid: the state
// rides on the list the page already fetches.
//
// Everything here is a READ of what the `eol` and `vulnerability` producers
// wrote: the one `findings` table, and — for end of life — the `eol`
// producer's per-install record on `software_install_lifecycle`. Nothing
// re-decides whether a package is end of life or vulnerable. That resolution
// runs against catalogues this query cannot see, and a second opinion about it
// — the shape this codebase keeps paying for — would be worse than no column at
// all.
//
// # Many-valued on both axes, and the last value is the point
//
// "No finding" is not "clean":
//
//   - vulnerability: a product with NEITHER a CPE nor a PURL is skipped by the
//     producer, in its own words, because "'this install has no known
//     vulnerabilities' and 'this install could not be checked' are different
//     answers and only one of them is reassuring." That distinction is
//     reproducible here from the product's own columns, so the column can draw
//     it honestly.
//   - end of life: the producer resolves a name/vendor/version against the
//     lifecycle catalogue, and a miss, a dateless row and a date beyond the
//     warning window all produce no finding. They used to be indistinguishable
//     from the outside (BUILD_PLAN row 3.8, deviation 1). Now the producer
//     RECORDS what each install resolved to, in the same transaction as its
//     findings, and this file reads the word off that record: `supported`,
//     `no_date`, `not_in_catalogue`. What is left in `not_assessed` is exactly
//     "no completed pass has recorded an answer for this install" — the pass
//     has not run since the install was seen, the install is not active and
//     was skipped (the sweep removes its record), or the finding the record
//     points at has been closed by a person. That last one is deliberate: a
//     record saying `end_of_life` beside a finding somebody suppressed must not
//     read as "supported", and reading it as a problem would report a finding
//     somebody closed, so it reads as the honest third thing.

import (
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/software"
)

// softwareLifecycleJoin puts the `eol` producer's per-install record beside
// the install's row. A plain LEFT JOIN on the record's primary key, so it is
// one row per install by construction in both the per-asset list and the
// catalogue aggregate — no LATERAL, no LIMIT, and no reliance on a partial
// unique index the way the findings joins have.
func softwareLifecycleJoin(alias, installExpr, tenantExpr string) string {
	return `
		LEFT JOIN software_install_lifecycle ` + alias + `
		       ON ` + alias + `.tenant_id = ` + tenantExpr + `
		      AND ` + alias + `.install_id = ` + installExpr
}

// softwareFindingJoin is the LATERAL join that puts one producer's open finding
// for an install beside the install's row.
//
// LATERAL with `ORDER BY … LIMIT 1` rather than a plain LEFT JOIN: the identity
// index permits exactly one OPEN row per (producer, kind, subject), but nothing
// stops an INACTIVE one sitting beside it — a sweep inactivates rather than
// deletes — and a join that matched two would DOUBLE the install's row in the
// list. Worst-first so that if the invariant ever bends, the row shown is the
// one that matters.
//
// `findings` carries an index on (tenant_id, subject_type, subject_id), so this
// is a lookup per row rather than a scan.
//
// Nothing interpolated here comes from a request: producerKey and kind are
// registry constants named by the caller, the aliases are literals in this
// file, and the two expressions are column references. The tenant id is a bound
// parameter, and the whole read runs inside `database.WithTenantTx`, so RLS on
// `findings` is the isolation boundary either way.
func softwareFindingJoin(alias, producerKey, kind, subjectExpr, tenantExpr string) string {
	return `
		LEFT JOIN LATERAL (
			SELECT f.id, f.severity, f.score, f.evidence
			  FROM findings f
			 WHERE f.tenant_id = ` + tenantExpr + `
			   AND f.producer = '` + producerKey + `'
			   AND f.kind = '` + kind + `'
			   AND f.subject_type = '` + sharedfindings.SubjectSoftwareInstall + `'
			   AND f.subject_id = ` + subjectExpr + `
			   AND ` + sharedfindings.OpenSQL("f") + `
			 ORDER BY f.score DESC, f.last_seen DESC
			 LIMIT 1
		) ` + alias + ` ON true`
}

// softwareFindingAggregateJoin is the same match as [softwareFindingJoin],
// written as a plain LEFT JOIN for the one caller that folds EVERY install of a
// tenant rather than one page of one asset's.
//
// # Why a second shape rather than one
//
// A LATERAL is evaluated once per driving row. On the asset page that is at
// most a page of installs and costs nothing; the catalogue list aggregates the
// tenant's whole install set on every page it serves, so the same helper became
// two index probes per install — 120,000 of them on a 60,000-install tenant.
// Measured against Postgres 17 with that shape, page one of
// Inventory → Software went from 55ms (before the rollup existed) to 702ms.
// The join below is the identical match, planned as two hash joins: 101ms.
//
// # Why one row is still guaranteed
//
// The LATERAL's `LIMIT 1` is what stops a second matching finding DOUBLING an
// install inside the aggregate and inflating `eol_install_count`. A plain join
// has no such clamp, so it needs the database to provide one — and it does:
// `findings_open_subject_uniq` is UNIQUE on
// (tenant_id, producer, kind, subject_type, subject_id, control_id) with
// NULLS NOT DISTINCT over every row that is not ARCHIVED. `detection_state =
// 'ACTIVE'` (inside OpenSQL) is a subset of that, and `control_id` is NULL for
// every producer but `compliance` — a CHECK, not a habit — so at most one row
// can match. That is a constraint Postgres enforces, not an invariant this file
// hopes for, and TestIntegration_SoftwareRollup_OneOpenFindingPerSubjectIsEnforced
// fails if it is ever weakened.
func softwareFindingAggregateJoin(alias, producerKey, kind, subjectExpr, tenantExpr string) string {
	return `
		LEFT JOIN findings ` + alias + `
		       ON ` + alias + `.tenant_id = ` + tenantExpr + `
		      AND ` + alias + `.producer = '` + producerKey + `'
		      AND ` + alias + `.kind = '` + kind + `'
		      AND ` + alias + `.subject_type = '` + sharedfindings.SubjectSoftwareInstall + `'
		      AND ` + alias + `.subject_id = ` + subjectExpr + `
		      AND ` + sharedfindings.OpenSQL(alias)
}

// jsonInt reads an integer out of a finding's free-shaped evidence WITHOUT a
// cast that can abort the whole query.
//
// `evidence` is JSONB with no schema — deliberately, because every producer
// puts something different in it — so `(evidence->>'cve_count')::int` is a
// runtime error waiting for the first producer that writes a string there. One
// malformed document would 500 the whole Software tab rather than leave one
// number blank. The regex guard makes a bad value read as ABSENT, which is
// what it is.
func jsonInt(expr, key string) string {
	return `CASE WHEN ` + expr + ` ->> '` + key + `' ~ '^-?[0-9]+$'
	             THEN (` + expr + ` ->> '` + key + `')::int END`
}

// eolStateSQL is the end-of-life ladder for ONE install: the open finding
// first, then the word the producer recorded, then the honest fallback. See
// the file comment for why a record saying `end_of_life` beside a closed
// finding lands on the fallback rather than on either neighbour.
func eolStateSQL(findingAlias, lifecycleAlias string) string {
	return `CASE WHEN ` + findingAlias + `.id IS NOT NULL THEN '` + SoftwareEOLEndOfLife + `'
	             WHEN ` + lifecycleAlias + `.assessment = '` + software.LifecycleSupported + `' THEN '` + SoftwareEOLSupported + `'
	             WHEN ` + lifecycleAlias + `.assessment = '` + software.LifecycleNoDate + `' THEN '` + SoftwareEOLNoDate + `'
	             WHEN ` + lifecycleAlias + `.assessment = '` + software.LifecycleNotInCatalogue + `' THEN '` + SoftwareEOLNotInCatalogue + `'
	             ELSE '` + SoftwareEOLNotAssessed + `' END`
}

// eolDateSQL is the date beside the state: the finding's when there is an
// open finding, the record's when the install is supported, NULL otherwise —
// so a `not_assessed` cell carries no date it would then have to explain.
func eolDateSQL(findingAlias, lifecycleAlias string) string {
	return `CASE WHEN ` + findingAlias + `.id IS NOT NULL THEN ` + findingAlias + `.evidence ->> 'eol_date'
	             WHEN ` + lifecycleAlias + `.assessment = '` + software.LifecycleSupported + `'
	                  THEN to_char(` + lifecycleAlias + `.eol_date, 'YYYY-MM-DD') END`
}

// eolLifecycleAggregatesSQL folds the per-install records of one product's
// active installs into the counts the catalogue-row state is derived from.
// Emitted as a fragment of the aggregate sub-select's column list; the
// aliases it defines are what eolProductStateSQL and eolProductDateSQL read.
func eolLifecycleAggregatesSQL(lifecycleAlias string) string {
	return `count(*) FILTER (WHERE ` + lifecycleAlias + `.assessment = '` + software.LifecycleSupported + `')      AS supported_install_count,
			               count(*) FILTER (WHERE ` + lifecycleAlias + `.assessment = '` + software.LifecycleNoDate + `')         AS no_date_install_count,
			               count(*) FILTER (WHERE ` + lifecycleAlias + `.assessment = '` + software.LifecycleNotInCatalogue + `') AS uncatalogued_install_count,
			               to_char(min(` + lifecycleAlias + `.eol_date) FILTER (WHERE ` + lifecycleAlias + `.assessment = '` + software.LifecycleSupported + `'), 'YYYY-MM-DD') AS supported_until,
			               max(` + lifecycleAlias + `.assessed_at) AS eol_assessed_at`
}

// eolProductStateSQL is the catalogue row's state, worst-then-most-informative
// over the counts eolLifecycleAggregatesSQL produced: an open finding on any
// active install, else any supported record, else any no-date record, else
// any recorded miss, else not assessed. `countsAlias` is the aggregate
// sub-select's alias.
func eolProductStateSQL(countsAlias string) string {
	return `CASE WHEN coalesce(` + countsAlias + `.eol_install_count, 0) > 0          THEN '` + SoftwareEOLEndOfLife + `'
			            WHEN coalesce(` + countsAlias + `.supported_install_count, 0) > 0    THEN '` + SoftwareEOLSupported + `'
			            WHEN coalesce(` + countsAlias + `.no_date_install_count, 0) > 0      THEN '` + SoftwareEOLNoDate + `'
			            WHEN coalesce(` + countsAlias + `.uncatalogued_install_count, 0) > 0 THEN '` + SoftwareEOLNotInCatalogue + `'
			            ELSE '` + SoftwareEOLNotAssessed + `' END`
}

// eolProductDateSQL is the date beside the catalogue row's state, following
// the same precedence: the findings' date when any install has an open
// finding, else the soonest supported-until date, else NULL.
func eolProductDateSQL(countsAlias string) string {
	return `CASE WHEN coalesce(` + countsAlias + `.eol_install_count, 0) > 0 THEN ` + countsAlias + `.eol_date
			            WHEN coalesce(` + countsAlias + `.supported_install_count, 0) > 0 THEN ` + countsAlias + `.supported_until END`
}

// vulnStateSQL takes the PRODUCT alias as well, because "could this have been
// checked at all?" is a question about the product's identifiers rather than
// about the install: a product with neither a CPE nor a PURL is what the
// vulnerability producer counts as unidentifiable and skips.
func vulnStateSQL(findingAlias, productAlias string) string {
	return `CASE WHEN ` + findingAlias + `.id IS NOT NULL THEN '` + SoftwareVulnVulnerable + `'
	             WHEN coalesce(` + productAlias + `.purl, '') <> ''
	               OR coalesce(` + productAlias + `.cpe, '') <> '' THEN '` + SoftwareVulnNoneKnown + `'
	             ELSE '` + SoftwareVulnNotAssessed + `' END`
}

// worstCVSSSQL turns the finding's score back into a CVSS base score.
//
// `score` is the CVSS base score x10 (the convention models.RiskBands is
// anchored to), so the reverse is a divide. It is NULL — never 0.0 — when the
// catalogue scored none of the matching CVEs: the producer states that
// explicitly with `worst_cvss_scored: false`, and 0.0 on screen reads as
// "harmless" for something nobody has graded.
func worstCVSSSQL(findingAlias string) string {
	return `CASE WHEN ` + findingAlias + `.evidence ->> 'worst_cvss_scored' = 'true'
	             THEN round(` + findingAlias + `.score::numeric / 10, 1) END`
}
