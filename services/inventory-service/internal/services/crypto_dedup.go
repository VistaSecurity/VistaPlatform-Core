// Package services: idempotent materialization of crypto configurations.
//
// Ingest used to be non-idempotent. The only production INSERT into
// crypto_implementations minted a fresh uuid every time, the table has no
// unique key beyond its (tenant_id, id) primary key, and nothing looked for an
// existing row — so every re-observation of the same endpoint appended another
// identical Crypto Configuration. An asset a sensor sees hourly accrued ~168
// duplicate rows a week, on BOTH the approved path and the deferred
// (pending_approval) replay.
//
// That is not merely cosmetic. Those rows are denominators:
//
//   - PQC readiness classifies each implementation exactly once into four
//     mutually exclusive buckets and divides by the total, so N copies of one
//     vulnerable endpoint drown out the rest of the estate.
//   - Risk aggregation rolls up per asset (MAX over its implementations) before
//     banding, which survives duplication — but the per-configuration lists,
//     counts and drawers do not.
//
// The fix is at the application layer, deliberately: giving the table a unique
// index would have to choose a survivor among the duplicates every existing
// install already holds, and each of those rows carries junction dependents
// (algorithms, certificates, keys) and compliance findings. That is a data
// migration with its own spec, not a side effect of this change. Existing
// duplicates therefore stay; this stops new ones.
package services

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// cryptoImplementationKey is the natural key of a crypto configuration —
// the identity that decides whether a finding describes a configuration we
// already hold or a new one.
//
// Shape: asset + protocol + the negotiated component fingerprint + provenance.
//
//   - The audit's suggested shape named a PORT. There is no port column on
//     crypto_implementations, and there does not need to be: IngestFindings
//     resolves a finding to an asset by (hostname OR ip_address) AND port, so
//     two ports on one host are already two assets. asset_id subsumes port.
//   - certificate_id is deliberately NOT in the key. A certificate renewal does
//     not change what the endpoint negotiates; it is the same configuration
//     presenting a new leaf. Keying on it would make every renewal a duplicate
//     configuration. The row's certificate_id is refreshed instead, and the
//     junction keeps the full chain history.
//   - source_sensor_id is likewise NOT in the key. A sensor is a vantage point,
//     not a property of the configuration; two sensors observing one endpoint
//     describe one configuration.
//   - discovery_method IS in the key. It is a persisted, user-visible,
//     documented filter (?discovery_method=passive|active|manual|…). Merging a
//     passively observed row with an actively probed one would destroy that
//     attribution and make the filter's results flap with ingest order. The
//     cost of keeping it is bounded — at most one row per method per
//     configuration — and it errs toward under-deduping, which is the safe
//     direction.
//
// # Subset absorption
//
// Equality on the component fingerprint is not the whole story, because the
// same configuration is routinely observed at two levels of completeness. A
// passive sensor that sees a handshake it cannot fully decode writes a row
// with protocol='TLS' and every other component NULL; the active probe that
// follows (automatic on first observation and daily, since the auto active
// scan shipped) measures the full handshake — version, suite, key exchange,
// signature, symmetric, hash. Those two fingerprints differ on six columns, so
// under pure equality the second observation INSERTED a second row and the
// refresh path, which only bumps timestamps, never completed the first. In
// the observed deployment that was 2 of 247 endpoints carrying exactly that partial+complete
// pair, and with the automatic scan it becomes the steady state for every
// passive-first endpoint: the asset page shows two rows under one endpoint,
// `total_crypto` counts both, and the CBOM ships an empty component beside a
// real one.
//
// The rule, applied on the same (tenant, asset, endpoint, protocol) after the
// exact-key lookup misses:
//
//  1. A live row whose non-NULL components all EQUAL the observation's, and
//     which is NULL somewhere the observation is not, is the same
//     configuration observed less completely. It is ENRICHED in place — the
//     NULLs are filled from the observation, first_discovered_at is kept — and
//     the caller re-links and re-scores it exactly as it would a fresh row.
//  2. The converse — every non-NULL component of the observation equals the
//     row's, and the row knows strictly more — is a less complete
//     re-observation of a configuration already held. The row is refreshed;
//     nothing is inserted, and the observation's components change nothing.
//  3. Any non-NULL component that CONFLICTS (passive saw TLS 1.2, active saw
//     TLS 1.3) is a genuine second configuration — a change between the two
//     observations, or a downgrade surface — and stays a second row.
//
// Equal fingerprints under DIFFERENT methods are deliberately outside the rule
// (neither is a strict subset of the other), so the attribution argument above
// holds unchanged and the observed data — zero such pairs — is not what this is
// for. Provenance is kept explicitly instead: `discovery_methods` accumulates
// every method that has contributed to a row, `discovery_method` stays the
// first, and the exact-key lookup treats a method already in the array as a
// match — otherwise a row enriched by an active probe would gain a fresh
// duplicate on the very next active probe, which is the defect re-created one
// observation later.
type cryptoImplementationKey struct {
	AssetID uuid.UUID
	// EndpointID is the face the configuration was measured on, and it IS part
	// of the key: the same protocol and cipher suite on :443 and on :8443 are
	// two configurations of one asset, and merging them would lose the
	// distinction the old port-as-asset model kept by accident (they were two
	// assets then). uuid.Nil means no endpoint — an at-rest resource — and the
	// null-safe comparison below keeps those matching each other.
	EndpointID      uuid.UUID
	Protocol        string
	ProtocolVersion *string
	CipherSuite     *string
	KeyExchange     *string
	Signature       *string
	Symmetric       *string
	Hash            *string
	KeySize         *int
	DiscoveryMethod string
}

// findCryptoImplementationSQL locates an existing configuration matching the
// natural key.
//
// Six of the ten key columns are nullable and NULL never equals NULL, so every
// nullable comparison is `IS NOT DISTINCT FROM` — the null-safe equality. A
// plain `=` would match nothing whenever a component was not measured, which is
// the common case (a passive observation frequently carries only a protocol),
// and the fix would silently do nothing for exactly the rows that duplicate
// most.
//
// `IS NOT DISTINCT FROM` is not an indexable operator. That is fine here and
// only here: tenant_id and asset_id are both indexed and applied with plain
// `=`, so the planner has already narrowed to one asset's handful of
// configurations before the null-safe predicates are evaluated. (Contrast the
// asset lookup in IngestFindings, where the same operator degraded a
// tenant-wide scan and was removed for that reason.)
//
// ORDER BY first_discovered_at picks the OLDEST match. On an install that
// already holds duplicates that means ingest converges on the earliest row —
// the one whose first_discovered_at is actually true — rather than picking an
// arbitrary survivor or, worse, a different one each run.
//
// The method predicate accepts a row whose `discovery_methods` provenance
// already contains the observation's method, not only one whose primary
// `discovery_method` equals it. A row first written by a passive sensor and
// then enriched by an active probe carries {passive, active}; the next active
// probe must land on it, and under a primary-only predicate it would miss,
// fall through the subset lookups (equal fingerprints are not strict
// subsets) and INSERT — re-creating the duplicate this file exists to stop,
// one observation later.
const findCryptoImplementationSQL = `
		SELECT id FROM crypto_implementations
		 WHERE tenant_id = $1
		   AND asset_id = $2
		   AND deleted_at IS NULL
		   AND endpoint_id IS NOT DISTINCT FROM $12::uuid
		   AND protocol = $3::public.protocol_type
		   AND protocol_version       IS NOT DISTINCT FROM $4::text
		   AND cipher_suite           IS NOT DISTINCT FROM $5::text
		   AND key_exchange_algorithm IS NOT DISTINCT FROM $6::text
		   AND signature_algorithm    IS NOT DISTINCT FROM $7::text
		   AND symmetric_encryption   IS NOT DISTINCT FROM $8::text
		   AND hash_algorithm         IS NOT DISTINCT FROM $9::text
		   AND key_size               IS NOT DISTINCT FROM $10::integer
		   AND ($11::public.discovery_method = discovery_method
		        OR $11::public.discovery_method = ANY(discovery_methods))
		 ORDER BY first_discovered_at ASC, id ASC
		 LIMIT 1`

// cryptoComponentCountSQL is how many of the seven component columns a row
// has measured. It is the strictness half of both subset lookups below: the
// per-column predicates establish "compatible", and comparing this count to
// the observation's establishes "and one side knows strictly more". Equal
// counts under compatible columns means equal fingerprints, which is the
// exact-key lookup's business, not the subset lookups'.
const cryptoComponentCountSQL = `(
		    (protocol_version       IS NOT NULL)::int
		  + (cipher_suite           IS NOT NULL)::int
		  + (key_exchange_algorithm IS NOT NULL)::int
		  + (signature_algorithm    IS NOT NULL)::int
		  + (symmetric_encryption   IS NOT NULL)::int
		  + (hash_algorithm         IS NOT NULL)::int
		  + (key_size               IS NOT NULL)::int)`

// findPartialCryptoImplementationSQL locates a live row that is a STRICT
// component-subset of the observation on the same (tenant, asset, endpoint,
// protocol): every component the row has measured equals the observation's,
// and the observation has measured at least one the row has not. That row is
// the same configuration seen less completely, and the caller enriches it.
//
// `col IS NULL OR col = $n` is the per-column "compatible" test, and it is
// deliberately NOT null-safe on the right-hand side: when the observation's
// value is NULL, `col = NULL` is NULL, so the disjunction is true only when
// the row's column is NULL too. That is the subset relation exactly — a row
// may know less than the observation, never more, and never differently.
//
// Oldest first, for the same reason as the exact lookup: on an install that
// already holds several partial rows for one endpoint, every enrichment
// converges on the earliest, whose first_discovered_at is the true one.
const findPartialCryptoImplementationSQL = `
		SELECT id FROM crypto_implementations
		 WHERE tenant_id = $1
		   AND asset_id = $2
		   AND deleted_at IS NULL
		   AND endpoint_id IS NOT DISTINCT FROM $11::uuid
		   AND protocol = $3::public.protocol_type
		   AND (protocol_version       IS NULL OR protocol_version       = $4::text)
		   AND (cipher_suite           IS NULL OR cipher_suite           = $5::text)
		   AND (key_exchange_algorithm IS NULL OR key_exchange_algorithm = $6::text)
		   AND (signature_algorithm    IS NULL OR signature_algorithm    = $7::text)
		   AND (symmetric_encryption   IS NULL OR symmetric_encryption   = $8::text)
		   AND (hash_algorithm         IS NULL OR hash_algorithm         = $9::text)
		   AND (key_size               IS NULL OR key_size               = $10::integer)
		   AND ` + cryptoComponentCountSQL + ` < $12::integer
		 ORDER BY first_discovered_at ASC, id ASC
		 LIMIT 1`

// findSupersetCryptoImplementationSQL is the converse: a live row of which the
// observation is a STRICT component-subset. Every component the observation
// has measured equals the row's, and the row has measured at least one more.
// The observation is then a less complete re-observation of a configuration
// already held, and the caller refreshes that row instead of inserting.
//
// Same per-column shape as above with the sides swapped: `$n IS NULL OR col =
// $n` is true when the observation did not measure the column (whatever the
// row holds) or when both measured it identically.
const findSupersetCryptoImplementationSQL = `
		SELECT id FROM crypto_implementations
		 WHERE tenant_id = $1
		   AND asset_id = $2
		   AND deleted_at IS NULL
		   AND endpoint_id IS NOT DISTINCT FROM $11::uuid
		   AND protocol = $3::public.protocol_type
		   AND ($4::text     IS NULL OR protocol_version       = $4::text)
		   AND ($5::text     IS NULL OR cipher_suite           = $5::text)
		   AND ($6::text     IS NULL OR key_exchange_algorithm = $6::text)
		   AND ($7::text     IS NULL OR signature_algorithm    = $7::text)
		   AND ($8::text     IS NULL OR symmetric_encryption   = $8::text)
		   AND ($9::text     IS NULL OR hash_algorithm         = $9::text)
		   AND ($10::integer IS NULL OR key_size               = $10::integer)
		   AND ` + cryptoComponentCountSQL + ` > $12::integer
		 ORDER BY first_discovered_at ASC, id ASC
		 LIMIT 1`

// recordDiscoveryMethodSQL is the provenance append every write path shares:
// the observation's method joins `discovery_methods` once. Written as a CASE
// rather than an unconditional array_append so a re-observation under a
// method already recorded does not grow the array on every pass.
const recordDiscoveryMethodSQL = `CASE
		           WHEN $5::public.discovery_method = ANY(discovery_methods) THEN discovery_methods
		           ELSE array_append(discovery_methods, $5::public.discovery_method)
		         END`

// refreshCryptoImplementationSQL re-observes an existing configuration.
//
// first_discovered_at is deliberately untouched and last_verified_at is
// refreshed: the two are a genuine first-seen/last-seen pair, both exposed by
// the API and both offered as sort keys on the crypto-configuration list
// (last_verified_at is the default sort). Collapsing them would make a
// long-standing configuration look newly discovered.
//
// certificate_id and source_sensor_id are COALESCEd so a later observation that
// captured no chain, or arrived from a sensor-less path, cannot erase a link an
// earlier one established. raw_data is replaced outright — it is the latest
// measurement's evidence (quality flags, enumerated versions), and stale
// evidence is worse than none.
const refreshCryptoImplementationSQL = `
		UPDATE crypto_implementations
		   SET certificate_id    = COALESCE($2::uuid, certificate_id),
		       source_sensor_id  = COALESCE($3::uuid, source_sensor_id),
		       raw_data          = $4::jsonb,
		       discovery_methods = ` + recordDiscoveryMethodSQL + `,
		       last_verified_at  = NOW(),
		       updated_at        = NOW()
		 WHERE id = $1`

// reobserveCryptoImplementationSQL is the refresh for a LESS complete
// re-observation (the observation is a strict subset of the row). It differs
// from refreshCryptoImplementationSQL in one clause: raw_data is MERGED, the
// observation's keys over the row's, rather than replaced. A passive glimpse
// that decoded only the protocol carries no `tls_versions` enumeration and no
// quality flags; replacing the active probe's evidence with it would erase the
// "server still accepts TLS 1.0" signal that AnalyzeCryptoRisk reads from
// raw_data, on every passive re-observation, until the next probe. What the
// observation did measure still wins on its own keys.
const reobserveCryptoImplementationSQL = `
		UPDATE crypto_implementations
		   SET certificate_id    = COALESCE($2::uuid, certificate_id),
		       source_sensor_id  = COALESCE($3::uuid, source_sensor_id),
		       raw_data          = COALESCE(raw_data, '{}'::jsonb) || $4::jsonb,
		       discovery_methods = ` + recordDiscoveryMethodSQL + `,
		       last_verified_at  = NOW(),
		       updated_at        = NOW()
		 WHERE id = $1`

// enrichCryptoImplementationSQL completes a partial row from a fuller
// observation of the same configuration. Every component is COALESCEd —
// the row's value if it has one, else the observation's — which, given the
// lookup that selected the row guarantees the two agree wherever both are
// measured, fills exactly the NULLs and changes nothing else.
//
// first_discovered_at is kept: the configuration was first seen when the
// partial row was written, and completing the picture is not a new discovery.
// raw_data is merged the same way as reobserveCryptoImplementationSQL, with
// the fuller observation's keys winning, so nothing the partial observation
// alone recorded is lost.
//
// What this statement does NOT do is score. The caller re-links the
// components and recomputes risk for the returned row exactly as it would for
// a freshly inserted one, so an enriched row ends at the same score and the
// same junction rows a fresh insert of the same observation would get.
const enrichCryptoImplementationSQL = `
		UPDATE crypto_implementations
		   SET protocol_version       = COALESCE(protocol_version,       $6::text),
		       cipher_suite           = COALESCE(cipher_suite,           $7::text),
		       key_exchange_algorithm = COALESCE(key_exchange_algorithm, $8::text),
		       signature_algorithm    = COALESCE(signature_algorithm,    $9::text),
		       symmetric_encryption   = COALESCE(symmetric_encryption,   $10::text),
		       hash_algorithm         = COALESCE(hash_algorithm,         $11::text),
		       key_size               = COALESCE(key_size,               $12::integer),
		       certificate_id         = COALESCE($2::uuid, certificate_id),
		       source_sensor_id       = COALESCE($3::uuid, source_sensor_id),
		       raw_data               = COALESCE(raw_data, '{}'::jsonb) || $4::jsonb,
		       discovery_methods      = ` + recordDiscoveryMethodSQL + `,
		       last_verified_at       = NOW(),
		       updated_at             = NOW()
		 WHERE id = $1`

// setCryptoRiskScoreSQL writes a configuration's risk score.
//
// Note what refreshCryptoImplementationSQL above does NOT touch: risk_score.
// A re-observation refreshes the evidence and the last-seen stamp, and the
// score is recomputed separately from the components the same pass just linked
// — see persistCryptoRiskScore.
const setCryptoRiskScoreSQL = `
		UPDATE crypto_implementations
		   SET risk_score = $1,
		       updated_at = NOW()
		 WHERE id = $2`

// persistCryptoRiskScore writes the score of a configuration that was ASSESSED,
// including a score of zero.
//
// The caller decides "assessed"; this decides nothing. The split matters because
// the two states a zero can mean are settled before the write, not by it.
//
// # What this fixes
//
// The write used to be guarded by `if score > 0`, with the reasoning that a
// persisted 0 is indistinguishable from "nobody looked". The reasoning is right
// and the guard was the wrong place to act on it, because the column it guards
// is a LAST-WRITE, not an accumulator: a configuration first observed
// negotiating TLS 1.0 with SHA-1 scored 75 and kept 75 for ever, even after the
// operator fixed the server and every later observation resolved to a clean
// set. Re-observation could raise a score and, at the bottom of the range,
// could not lower it. The product therefore reported remediation as unfinished
// precisely when it had been finished.
//
// The score can move DOWN for two reasons and both are legitimate: the
// configuration now resolves to better components, or the catalogue row that
// scored it was corrected — which is the whole promise of "edit the catalogue
// row, not Go code" (CLAUDE.md, "The catalogue drives risk scoring"). Nothing
// about either says the number may only ever climb.
//
// # And zero still means two things
//
// The three-valued honesty is kept, just not by refusing to write. For a
// configuration, ASSESSED is a derived fact with a home of its own: at least one
// catalogue component linked in a `cryptoassess.CatalogueRiskRoles` role, in
// `crypto_implementation_algorithms`. That is exactly the predicate the `crypto`
// finding producer already reads (its `cat.linked` count) to decide whether an
// asset's crypto was judged at all, so there is one definition rather than two,
// and no new column on a table that is one partitioned parent plus eight
// partitions.
//
//	risk_score 0, no linked component  → NOT ASSESSED
//	risk_score 0, linked components    → assessed, and clean
//	risk_score N > 0                   → assessed, and not clean
//
// A pass that resolved nothing therefore writes nothing at all and leaves the
// row exactly as it was — which is the honest outcome: it has no opinion to
// record, and overwriting a real earlier verdict with a 0 it cannot justify
// would be a worse lie than the stale score this change removes.
func persistCryptoRiskScore(tx *sqlx.Tx, implID uuid.UUID, score int) error {
	if _, err := tx.Exec(setCryptoRiskScoreSQL, score, implID); err != nil {
		return fmt.Errorf("set risk score on crypto implementation %s: %w", implID, err)
	}
	return nil
}

// linkLeafCertificateSQL writes the `leaf` row of the certificate↔configuration
// junction for a configuration that names a certificate.
//
// The junction is the ONE source of truth for that link: every reader that asks
// "which certificates belong to this asset / endpoint / configuration" walks it
// — `shared/findings.AssetSubjects` (the certificate descendant path behind
// `finding:(…)` and the `has_findings` facet), the `asset/cert`,
// `endpoint/cert`, `crypto_configuration/cert` and `certificate/asset` shapes in
// `shared/query/sql`, the location roll-up, and the crypto-risk certificate
// expiry bands. `crypto_implementations.certificate_id` stays as the LEAF
// denormalisation those few readers that want one certificate use directly
// (the crypto-configuration list, the asset↔certificate links endpoint).
//
// Writing it here, in the caller's transaction, is the whole point. The two
// used to be written apart: the column by the INSERT/UPDATE below and the
// junction by a later, separate, best-effort `LinkCertificateToImplementation`
// call that only logged on failure. They diverged in production — the original
// `valid_certificate_role` CHECK rejected the literal 'leaf', so on every
// sensor-discovered certificate the column was set, the junction insert was
// refused, and the certificate became invisible from its own asset while ingest
// reported success. Same transaction means that cannot recur: either both land
// or neither does.
//
// The certificate is SELECTed back out of the row rather than bound from the
// caller, so the junction cannot name a different certificate from the column —
// and so a re-observation of a legacy row converges it, even when this
// observation carried no chain of its own.
const linkLeafCertificateSQL = `
		INSERT INTO crypto_implementation_certificates (
			crypto_implementation_id, certificate_id, certificate_role, certificate_order
		)
		SELECT id, certificate_id, 'leaf', 0
		  FROM crypto_implementations
		 WHERE id = $1 AND certificate_id IS NOT NULL
		ON CONFLICT (crypto_implementation_id, certificate_id) DO NOTHING`

// lockAssetMaterializationSQL serializes concurrent materialization for one
// asset.
//
// Without a unique constraint a SELECT-then-INSERT can race: two ingest
// workers handling the same endpoint can both miss and both insert. There is no
// DB-level arbiter to fall back on, so this takes a transaction-scoped advisory
// lock keyed on (tenant, asset) instead. It is cluster-wide (so it holds across
// service replicas, not just goroutines), it is released automatically on
// commit OR rollback, and it costs one hash lookup. It serializes only per
// asset, so unrelated findings in the same batch still proceed in parallel.
//
// hashtextextended is a Postgres built-in, so the key derivation lives in one
// place rather than being duplicated in Go.
const lockAssetMaterializationSQL = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`

// assetMaterializationLockKey namespaces the advisory lock so it cannot collide
// with an unrelated advisory lock elsewhere in the platform.
func assetMaterializationLockKey(tenantID, assetID uuid.UUID) string {
	return "vistaplatform:crypto_materialization:" + tenantID.String() + ":" + assetID.String()
}

// cryptoKeyForFinding builds the natural key a finding materializes to.
//
// It is the single place the key is derived, and it MUST stay the only one:
// the values it produces are the values bound into both the lookup and the
// INSERT, so a key derived one way and written another would never match itself
// on the next observation — a dedup that silently never dedups.
//
// The second return is false when the finding names no protocol the enum
// models — a transport, an explicit "no encryption", or something unrecognised.
// The key is then unusable and Protocol is left EMPTY rather than filled with a
// guess: an empty enum value fails the INSERT loudly, where the old "default to
// TLS" fabricated a negotiated-TLS row that nothing downstream could tell from
// a measured one. Callers that write must check it; the fingerprint path below
// does not write and substitutes its own identity string.
func (s *AssetService) cryptoKeyForFinding(assetID uuid.UUID, f IngestFinding) (cryptoImplementationKey, bool) {
	return s.cryptoKeyForFindingOnEndpoint(assetID, uuid.Nil, f)
}

// cryptoKeyForFindingOnEndpoint is cryptoKeyForFinding with the endpoint the
// observation was measured on. The two-argument form exists because the
// fingerprint path (deferredFindingFingerprint) has no asset yet, let alone an
// endpoint, and must not pretend otherwise.
func (s *AssetService) cryptoKeyForFindingOnEndpoint(assetID, endpointID uuid.UUID, f IngestFinding) (cryptoImplementationKey, bool) {
	protocol, verdict := resolveProtocol(f.Protocol)
	derived := s.deriveCipherComponents(f)
	return cryptoImplementationKey{
		AssetID:         assetID,
		EndpointID:      endpointID,
		Protocol:        protocol,
		ProtocolVersion: derived.ProtocolVersion,
		CipherSuite:     f.CipherSuite,
		KeyExchange:     derived.KeyExchange,
		Signature:       derived.Signature,
		Symmetric:       derived.Symmetric,
		Hash:            derived.Hash,
		KeySize:         f.KeySize,
		DiscoveryMethod: findingDiscoveryMethod(f),
	}, verdict == protocolEnum
}

// cryptoUpsertOutcome says what upsertCryptoImplementation did with an
// observation. The caller needs more than created/not-created: an enriched row
// must be re-scored like a fresh one, and a less complete re-observation must
// NOT be — see processDiscoveryCryptoData.
type cryptoUpsertOutcome int

const (
	// cryptoUpsertCreated: no compatible row existed; a new one was inserted.
	cryptoUpsertCreated cryptoUpsertOutcome = iota
	// cryptoUpsertRefreshed: the exact key matched; timestamps and evidence
	// were refreshed.
	cryptoUpsertRefreshed
	// cryptoUpsertEnriched: a live row that was a strict component-subset of
	// the observation had its NULL components filled from it.
	cryptoUpsertEnriched
	// cryptoUpsertPartialReobserved: the observation is a strict
	// component-subset of a live row; that row was refreshed and the
	// observation's components changed nothing.
	cryptoUpsertPartialReobserved
)

// componentCount is how many of the seven component columns the observation
// measured — the observation-side half of the strictness test the two subset
// lookups apply against cryptoComponentCountSQL.
func (k cryptoImplementationKey) componentCount() int {
	n := 0
	for _, p := range []*string{k.ProtocolVersion, k.CipherSuite, k.KeyExchange, k.Signature, k.Symmetric, k.Hash} {
		if p != nil {
			n++
		}
	}
	if k.KeySize != nil {
		n++
	}
	return n
}

// upsertCryptoImplementation finds the configuration matching k and refreshes
// it, enriches or re-observes a compatible one, or inserts a new one. Returns
// the row's id and which of those happened.
//
// The order is load-bearing: exact key, then a partial row this observation
// completes, then a fuller row this observation partially re-observes, then
// insert. Only the last branch creates a row, and it is reached only when
// every live row on the same (asset, endpoint, protocol) either conflicts
// with the observation on a measured component or carries an equal
// fingerprint under a method not yet in its provenance — both of which are
// genuinely second rows (see the package doc on cryptoImplementationKey).
//
// The caller supplies the transaction; it must already have taken the
// per-asset advisory lock (see lockAssetMaterializationSQL), and the bound
// values MUST be the same ones the key was built from — a key normalized
// differently from what the INSERT writes would never match itself on the next
// observation.
func upsertCryptoImplementation(
	tx *sqlx.Tx,
	tenantID uuid.UUID,
	k cryptoImplementationKey,
	certificateID interface{},
	sourceSensorID interface{},
	rawJSON []byte,
) (uuid.UUID, cryptoUpsertOutcome, error) {
	endpoint := nullUUIDValue(k.EndpointID)

	var existing uuid.UUID
	err := tx.QueryRow(
		findCryptoImplementationSQL,
		tenantID, k.AssetID, k.Protocol,
		k.ProtocolVersion, k.CipherSuite, k.KeyExchange, k.Signature,
		k.Symmetric, k.Hash, k.KeySize, k.DiscoveryMethod,
		endpoint,
	).Scan(&existing)
	if err == nil {
		if _, e := tx.Exec(refreshCryptoImplementationSQL, existing, certificateID, sourceSensorID, rawJSON, k.DiscoveryMethod); e != nil {
			return uuid.Nil, cryptoUpsertRefreshed, fmt.Errorf("refresh crypto implementation %s: %w", existing, e)
		}
		if e := linkLeafCertificate(tx, existing); e != nil {
			return uuid.Nil, cryptoUpsertRefreshed, e
		}
		return existing, cryptoUpsertRefreshed, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, cryptoUpsertCreated, fmt.Errorf("look up crypto implementation: %w", err)
	}

	// The subset lookups bind the same values in the same order; only the
	// strictness comparison differs.
	subsetArgs := []interface{}{
		tenantID, k.AssetID, k.Protocol,
		k.ProtocolVersion, k.CipherSuite, k.KeyExchange, k.Signature,
		k.Symmetric, k.Hash, k.KeySize,
		endpoint, k.componentCount(),
	}

	var partial uuid.UUID
	err = tx.QueryRow(findPartialCryptoImplementationSQL, subsetArgs...).Scan(&partial)
	if err == nil {
		if _, e := tx.Exec(
			enrichCryptoImplementationSQL,
			partial, certificateID, sourceSensorID, rawJSON, k.DiscoveryMethod,
			k.ProtocolVersion, k.CipherSuite, k.KeyExchange, k.Signature,
			k.Symmetric, k.Hash, k.KeySize,
		); e != nil {
			return uuid.Nil, cryptoUpsertEnriched, fmt.Errorf("enrich crypto implementation %s: %w", partial, e)
		}
		if e := linkLeafCertificate(tx, partial); e != nil {
			return uuid.Nil, cryptoUpsertEnriched, e
		}
		return partial, cryptoUpsertEnriched, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, cryptoUpsertCreated, fmt.Errorf("look up partial crypto implementation: %w", err)
	}

	var superset uuid.UUID
	err = tx.QueryRow(findSupersetCryptoImplementationSQL, subsetArgs...).Scan(&superset)
	if err == nil {
		if _, e := tx.Exec(reobserveCryptoImplementationSQL, superset, certificateID, sourceSensorID, rawJSON, k.DiscoveryMethod); e != nil {
			return uuid.Nil, cryptoUpsertPartialReobserved, fmt.Errorf("re-observe crypto implementation %s: %w", superset, e)
		}
		if e := linkLeafCertificate(tx, superset); e != nil {
			return uuid.Nil, cryptoUpsertPartialReobserved, e
		}
		return superset, cryptoUpsertPartialReobserved, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, cryptoUpsertCreated, fmt.Errorf("look up superset crypto implementation: %w", err)
	}

	id := uuid.New()
	if _, e := tx.Exec(
		insertCryptoImplementationSQL,
		id, tenantID, k.AssetID, k.Protocol, k.ProtocolVersion, k.CipherSuite,
		k.Hash, k.KeySize, certificateID, sourceSensorID, rawJSON,
		k.KeyExchange, k.Signature, k.Symmetric,
		k.DiscoveryMethod, endpoint,
	); e != nil {
		return uuid.Nil, cryptoUpsertCreated, fmt.Errorf("insert crypto implementation: %w", e)
	}
	if e := linkLeafCertificate(tx, id); e != nil {
		return uuid.Nil, cryptoUpsertCreated, e
	}
	return id, cryptoUpsertCreated, nil
}

// linkLeafCertificate is the one call site shape of linkLeafCertificateSQL, so
// the insert and refresh branches above cannot drift apart.
//
// It is deliberately FATAL rather than best-effort. Its predecessor logged and
// carried on, which is precisely how a configuration came to name a certificate
// that no reader could reach from the asset — a silent hole, reported as a
// successful ingest. Rolling the transaction back leaves no configuration at
// all, which is the honest outcome: the certificate link is not decoration, it
// is how the certificate is found.
func linkLeafCertificate(tx *sqlx.Tx, implID uuid.UUID) error {
	if _, err := tx.Exec(linkLeafCertificateSQL, implID); err != nil {
		return fmt.Errorf("link leaf certificate for crypto implementation %s: %w", implID, err)
	}
	return nil
}

// deferredFindingFingerprint identifies a deferred finding for dedup purposes.
//
// It fingerprints the IDENTIFYING fields, never the raw blob. Several producers
// stamp per-observation timestamps into RawData (capture time, probe time,
// batch id), so comparing whole findings — or hashing RawData wholesale — never
// matches and the array grows regardless. What identifies a deferred finding is
// what it will materialize: the crypto configuration's natural key, plus the
// certificates it carries (a renewal observed while the asset is still pending
// is genuinely new evidence and must survive), plus the at-rest resource it
// describes if it is one.
//
// Deliberately excluded: everything that varies per observation without
// changing what gets written — timestamps, batch ids, sensor ids, and the
// posture VALUES of an at-rest resource. A flapping posture must not grow the
// array; the newest observation replaces the older one, which is exactly what
// the at-rest producer (an upsert of current state) wants.
func (s *AssetService) deferredFindingFingerprint(f IngestFinding) string {
	k, recordable := s.cryptoKeyForFinding(uuid.Nil, f)

	// A finding whose protocol the enum does not model still needs a STABLE,
	// DISTINCT fingerprint — it is deferred and replayed like any other, and
	// two different unmodelled protocols on one pending asset must not collapse
	// into one entry. The key's Protocol is empty in that case, so fingerprint
	// on what was actually observed instead.
	protocolPart := k.Protocol
	if !recordable {
		protocolPart = "unmodelled:" + strings.ToUpper(strings.TrimSpace(f.Protocol))
	}

	parts := []string{
		"protocol=" + protocolPart,
		"version=" + derefStr(k.ProtocolVersion),
		"suite=" + derefStr(k.CipherSuite),
		"kex=" + derefStr(k.KeyExchange),
		"sig=" + derefStr(k.Signature),
		"sym=" + derefStr(k.Symmetric),
		"hash=" + derefStr(k.Hash),
		"keysize=" + derefInt(k.KeySize),
		"method=" + k.DiscoveryMethod,
	}

	// The at-rest identity (which resource), not its posture (what the
	// posture currently is).
	if f.RawData != nil {
		if rt, ok := f.RawData["resource_type"].(string); ok {
			parts = append(parts, "resource_type="+strings.TrimSpace(rt))
		}
		if arn, ok := f.RawData["arn"].(string); ok {
			parts = append(parts, "arn="+strings.TrimSpace(arn))
		}
	}

	// Certificates, order-independent: the same chain reported in a different
	// order is the same evidence.
	var fps []string
	for _, c := range s.extractCertificatesFromFinding(f) {
		fp := strings.TrimSpace(c.FingerprintSHA256)
		if fp == "" {
			// No fingerprint to compare on — fall back to the subject so two
			// different partial-data certificates still separate.
			fp = "subject:" + strings.TrimSpace(c.SubjectDN)
		}
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	parts = append(parts, "certs="+strings.Join(fps, "|"))

	sum := sha256.Sum256([]byte(strings.Join(parts, "\x1f")))
	return hex.EncodeToString(sum[:])
}

func derefStr(p *string) string {
	if p == nil {
		return "\x00"
	}
	return *p
}

func derefInt(p *int) string {
	if p == nil {
		return "\x00"
	}
	return strconv.Itoa(*p)
}

// nullUUIDValue binds uuid.Nil as SQL NULL. The zero uuid is not an id — it
// names no row — and binding it literally would make every at-rest
// configuration collide on one fictional endpoint.
func nullUUIDValue(id uuid.UUID) interface{} {
	if id == uuid.Nil {
		return nil
	}
	return id
}
