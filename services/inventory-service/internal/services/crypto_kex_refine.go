package services

// Key-exchange refinement: one endpoint, observed at two levels of precision.
//
// A TLS key exchange reaches ingest in two vocabularies. A cipher-suite parse
// yields a FAMILY LABEL — "ECDHE", read from a TLS 1.2 suite name or simply
// assumed for every TLS 1.3 suite, whose name carries no key exchange at all.
// A live handshake yields the NEGOTIATED GROUP — X25519, DH-ECP-256,
// X25519MLKEM768 (shared/discovery.TLSKeyExchangeGroupName). The group is a
// more precise statement of the same fact: which ephemeral (EC)DH the
// endpoint ran.
//
// The natural key compares the key_exchange column with equality, so the two
// vocabularies read as a CONFLICT (package doc on cryptoImplementationKey,
// rule 3) and a passive observation (label) beside an active probe (group) of
// one endpoint became two permanent configurations. The label row was kept
// alive by passive traffic, every existing active / cloud / interrogated row
// re-keyed on upgrade and left its label row behind, and a hybrid endpoint
// could never read better than half PQC-ready.
//
// refineCryptoKeyExchange runs before the natural-key lookups, inside the same
// locked transaction, and makes the two vocabularies meet:
//
//   - An observation carrying a measured group REFINES every live row of the
//     same (asset, endpoint) TLS configuration whose key exchange is a family
//     label and whose other components are compatible: the row's key_exchange
//     becomes the group, and its now-stale label link is deleted — links are
//     insert-only (ON CONFLICT DO NOTHING), so without the delete the row would
//     carry the classical label beside the hybrid group and the PQC
//     classifier's "any classical component makes it vulnerable" rule would
//     still fire. Rows that already carry the group are REPAIRED the same way
//     (idempotently): a label link can reach such a row after its refinement —
//     a passive observation's link step runs after its transaction commits,
//     outside the lock, and an uncatalogued group could not remove it — and
//     without the repair it would stay there for ever.
//   - An observation carrying only a family label, on an endpoint that already
//     has a row with a measured group, ADOPTS that group for its key — the
//     most recently verified one, so after a downgrade passive traffic keeps
//     the current configuration fresh rather than the superseded one. The
//     label is the less precise reading of a configuration already held, and
//     the lookups then treat it as the same configuration (a re-observation or
//     an enrichment), never a conflict. The adopted group is linked as INFERRED
//     by the caller: this observation did not measure it.
//
// Only TLS. The group names are TLS NamedGroups, but three of them
// (DH-ECP-256/384/521) are also the catalogue codes of IKE groups, so an IPsec
// configuration must never be rewritten or adopted here. And only an
// ephemeral-EC family label is refinable, and only by a group a live TLS
// handshake records: a static "ECDH" suite, a finite-field "DHE", an SSH
// key-exchange name or a vendor's free-text value is left exactly as it was.

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

// refinableProtocol is the one protocol whose key exchange is refined.
const refinableProtocol = "TLS"

// suiteKeyExchangeLabels are the family labels a measured TLS group refines.
// "ECDHE" is what the cipher-suite parser emits (and assumes for TLS 1.3); the
// two _RSA/_ECDSA spellings are the passive capture's suite-prefix labels,
// listed so that a producer forwarding them is handled the same way.
var suiteKeyExchangeLabels = []string{"ECDHE", "ECDHE_RSA", "ECDHE_ECDSA"}

// isSuiteKeyExchangeLabel reports whether v is a family label a measured group
// refines.
func isSuiteKeyExchangeLabel(v *string) bool {
	if v == nil {
		return false
	}
	for _, l := range suiteKeyExchangeLabels {
		if strings.EqualFold(strings.TrimSpace(*v), l) {
			return true
		}
	}
	return false
}

// isMeasuredTLSGroup reports whether v is a negotiated group a live handshake
// recorded.
func isMeasuredTLSGroup(v *string) bool {
	return v != nil && discovery.IsTLSKeyExchangeGroupName(*v)
}

// kexCompatibleRowsSQL selects the live rows of the observation's (asset,
// endpoint, protocol) whose six non-key-exchange components are COMPATIBLE with
// it — equal wherever both are measured — together with each row's key
// exchange and when it was last verified. Compatibility is two-sided on
// purpose: a passive row that never measured a key size and an active
// observation that did describe the same configuration, in either order.
//
// Oldest first, matching the natural-key lookups.
const kexCompatibleRowsSQL = `
		SELECT id, key_exchange_algorithm, last_verified_at FROM crypto_implementations
		 WHERE tenant_id = $1
		   AND asset_id = $2
		   AND deleted_at IS NULL
		   AND endpoint_id IS NOT DISTINCT FROM $3::uuid
		   AND protocol = $4::public.protocol_type
		   AND key_exchange_algorithm IS NOT NULL
		   AND (protocol_version     IS NULL OR $5::text     IS NULL OR protocol_version     = $5::text)
		   AND (cipher_suite         IS NULL OR $6::text     IS NULL OR cipher_suite         = $6::text)
		   AND (signature_algorithm  IS NULL OR $7::text     IS NULL OR signature_algorithm  = $7::text)
		   AND (symmetric_encryption IS NULL OR $8::text     IS NULL OR symmetric_encryption = $8::text)
		   AND (hash_algorithm       IS NULL OR $9::text     IS NULL OR hash_algorithm       = $9::text)
		   AND (key_size             IS NULL OR $10::integer IS NULL OR key_size             = $10::integer)
		 ORDER BY first_discovered_at ASC, id ASC`

// refineKeyExchangeSQL replaces a row's family-label key exchange with the
// measured group.
const refineKeyExchangeSQL = `
		UPDATE crypto_implementations
		   SET key_exchange_algorithm = $2::text,
		       updated_at = NOW()
		 WHERE id = $1`

// linkMeasuredGroupSQL links a configuration to the catalogue row of its
// measured group, as a measured (not inferred) component. The group names
// shared/discovery records ARE catalogue codes (pinned by
// TestIntegration_TLSKeyExchangeGroup_EveryRecordedNameIsCatalogued), so an
// exact, case-insensitive code match is the whole resolution.
const linkMeasuredGroupSQL = `
		INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
		SELECT $1, a.id, 'key_exchange', false
		  FROM algorithms a
		 WHERE a.category = 'key_exchange' AND lower(a.code) = lower($2::text)
		ON CONFLICT (crypto_implementation_id, algorithm_id, algorithm_type) DO NOTHING`

// deleteSupersededKeyExchangeLinksSQL removes a configuration's key_exchange
// links to family-label catalogue rows (in practice the "ECDHE" row) once it
// carries a measured group. Only labels: an SSH configuration's offered key
// exchanges are also inferred key_exchange links, and they are evidence that
// must stay.
//
// Guarded on the measured group resolving in the catalogue. A group with no
// row yet (one a future crypto/tls adds before the catalogue follows) would
// otherwise leave the configuration with no key_exchange link at all, and a
// configuration whose only links are a symmetric cipher and a hash is classed
// symmetric-safe — a worse wrong answer than the label. Once the row exists,
// the next observation of the endpoint repairs it (see the file doc).
const deleteSupersededKeyExchangeLinksSQL = `
		DELETE FROM crypto_implementation_algorithms cia
		 USING algorithms a
		 WHERE cia.crypto_implementation_id = $1
		   AND cia.algorithm_type = 'key_exchange'
		   AND a.id = cia.algorithm_id
		   AND upper(a.code) = ANY($2::text[])
		   AND EXISTS (SELECT 1 FROM algorithms g
		                WHERE g.category = 'key_exchange' AND lower(g.code) = lower($3::text))`

// refineCryptoKeyExchange reconciles the observation's key exchange with the
// rows already held for the same endpoint (see the file doc). It may rewrite
// k.KeyExchange to the held measured group when the observation carries only a
// family label; it then returns adopted=true, and the caller must link that
// group — as inferred — rather than the label.
//
// Runs inside the caller's transaction, after the per-asset advisory lock.
func refineCryptoKeyExchange(tx *sqlx.Tx, tenantID uuid.UUID, k *cryptoImplementationKey) (adopted bool, err error) {
	if k.Protocol != refinableProtocol {
		return false, nil
	}
	observedGroup := isMeasuredTLSGroup(k.KeyExchange)
	observedLabel := isSuiteKeyExchangeLabel(k.KeyExchange)
	if !observedGroup && !observedLabel {
		return false, nil
	}

	rows, err := tx.Query(kexCompatibleRowsSQL,
		tenantID, k.AssetID, nullUUIDValue(k.EndpointID), k.Protocol,
		k.ProtocolVersion, k.CipherSuite, k.Signature, k.Symmetric, k.Hash, k.KeySize)
	if err != nil {
		return false, fmt.Errorf("look up key-exchange-compatible crypto implementations: %w", err)
	}
	type candidate struct {
		id           uuid.UUID
		kex          string
		lastVerified time.Time
	}
	var candidates []candidate
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.id, &c.kex, &c.lastVerified); err != nil {
			_ = rows.Close()
			return false, fmt.Errorf("scan key-exchange-compatible crypto implementation: %w", err)
		}
		candidates = append(candidates, c)
	}
	if err := rows.Close(); err != nil {
		return false, err
	}
	if err := rows.Err(); err != nil {
		return false, err
	}

	if observedGroup {
		group := *k.KeyExchange
		for _, c := range candidates {
			kex := c.kex
			switch {
			case isSuiteKeyExchangeLabel(&kex):
				if _, err := tx.Exec(refineKeyExchangeSQL, c.id, group); err != nil {
					return false, fmt.Errorf("refine key exchange of crypto implementation %s: %w", c.id, err)
				}
			case strings.EqualFold(kex, group):
				// Already refined: repair a label link that reached it later.
			default:
				continue
			}
			// A row other than the one this observation lands on is never
			// re-linked by the caller, so it gets its group link here.
			if _, err := tx.Exec(linkMeasuredGroupSQL, c.id, group); err != nil {
				return false, fmt.Errorf("link measured key exchange of crypto implementation %s: %w", c.id, err)
			}
			if err := deleteSupersededKeyExchangeLinks(tx, c.id, group); err != nil {
				return false, err
			}
		}
		return false, nil
	}

	// A family label only: adopt the measured group of the most recently
	// verified row already held.
	var best *candidate
	for i := range candidates {
		kex := candidates[i].kex
		if !isMeasuredTLSGroup(&kex) {
			continue
		}
		if best == nil || candidates[i].lastVerified.After(best.lastVerified) {
			best = &candidates[i]
		}
	}
	if best == nil {
		return false, nil
	}
	group := best.kex
	k.KeyExchange = &group
	// The row carries a measured group; a label link on it is stale however it
	// got there.
	if err := deleteSupersededKeyExchangeLinks(tx, best.id, group); err != nil {
		return false, err
	}
	return true, nil
}

// deleteSupersededKeyExchangeLinks drops implID's family-label key_exchange
// links now that it carries the measured group. See
// deleteSupersededKeyExchangeLinksSQL for why it is guarded on group.
func deleteSupersededKeyExchangeLinks(q interface {
	Exec(string, ...interface{}) (sql.Result, error)
}, implID uuid.UUID, group string) error {
	if _, err := q.Exec(deleteSupersededKeyExchangeLinksSQL, implID, pq.Array(suiteKeyExchangeLabels), group); err != nil {
		return fmt.Errorf("delete superseded key-exchange links of crypto implementation %s: %w", implID, err)
	}
	return nil
}
