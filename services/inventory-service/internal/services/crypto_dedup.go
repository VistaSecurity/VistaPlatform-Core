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
type cryptoImplementationKey struct {
	AssetID         uuid.UUID
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
const findCryptoImplementationSQL = `
		SELECT id FROM crypto_implementations
		 WHERE tenant_id = $1
		   AND asset_id = $2
		   AND deleted_at IS NULL
		   AND protocol = $3::public.protocol_type
		   AND protocol_version       IS NOT DISTINCT FROM $4::text
		   AND cipher_suite           IS NOT DISTINCT FROM $5::text
		   AND key_exchange_algorithm IS NOT DISTINCT FROM $6::text
		   AND signature_algorithm    IS NOT DISTINCT FROM $7::text
		   AND symmetric_encryption   IS NOT DISTINCT FROM $8::text
		   AND hash_algorithm         IS NOT DISTINCT FROM $9::text
		   AND key_size               IS NOT DISTINCT FROM $10::integer
		   AND discovery_method = $11::public.discovery_method
		 ORDER BY first_discovered_at ASC, id ASC
		 LIMIT 1`

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
		   SET certificate_id   = COALESCE($2::uuid, certificate_id),
		       source_sensor_id = COALESCE($3::uuid, source_sensor_id),
		       raw_data         = $4::jsonb,
		       last_verified_at = NOW(),
		       updated_at       = NOW()
		 WHERE id = $1`

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
	protocol, verdict := resolveProtocol(f.Protocol)
	derived := s.deriveCipherComponents(f)
	return cryptoImplementationKey{
		AssetID:         assetID,
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

// upsertCryptoImplementation finds the configuration matching k and refreshes
// it, or inserts a new one. Returns the row's id and whether it was created.
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
) (uuid.UUID, bool, error) {
	var existing uuid.UUID
	err := tx.QueryRow(
		findCryptoImplementationSQL,
		tenantID, k.AssetID, k.Protocol,
		k.ProtocolVersion, k.CipherSuite, k.KeyExchange, k.Signature,
		k.Symmetric, k.Hash, k.KeySize, k.DiscoveryMethod,
	).Scan(&existing)
	if err == nil {
		if _, e := tx.Exec(refreshCryptoImplementationSQL, existing, certificateID, sourceSensorID, rawJSON); e != nil {
			return uuid.Nil, false, fmt.Errorf("refresh crypto implementation %s: %w", existing, e)
		}
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, false, fmt.Errorf("look up crypto implementation: %w", err)
	}

	id := uuid.New()
	if _, e := tx.Exec(
		insertCryptoImplementationSQL,
		id, tenantID, k.AssetID, k.Protocol, k.ProtocolVersion, k.CipherSuite,
		k.Hash, k.KeySize, certificateID, sourceSensorID, rawJSON,
		k.KeyExchange, k.Signature, k.Symmetric,
		k.DiscoveryMethod,
	); e != nil {
		return uuid.Nil, false, fmt.Errorf("insert crypto implementation: %w", e)
	}
	return id, true, nil
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
