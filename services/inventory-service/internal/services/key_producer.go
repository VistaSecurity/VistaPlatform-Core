// Package services: cryptographic-key inventory producer.
//
// This file is the producer half of the Keys lens (Inventory > Keys). The read
// side (ListKeys / GetKeyByID / GetKeyImplementations + the lens UI) shipped in
///; this derives the rows it reads. See feature spec
// docsv4/internal/developer/standards/features/cryptographic-keys-producer.md.
package services

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedcerts "github.com/vistasecurity/vistaplatform/shared/certificates"
)

// producedCertRef pairs a stored certificate with the extraction data that still
// carries its PEM and public-key fields, so the key producer can run after the
// crypto implementation row exists.
type producedCertRef struct {
	cert *models.Certificate
	data models.CertificateData
}

// produceKeyFromCertificate derives a public-key row in the cryptographic-key
// inventory from a discovered certificate and links it to the crypto
// implementation via implementation_keys.
//
// METADATA ONLY — no key material is ever stored. A certificate's public key is
// public by definition, and even so this persists only its SPKI fingerprint,
// algorithm, size, curve, key-usage, and lifecycle dates — never raw key bytes.
// Private and secret material never enter this table (material_type is always
// "public-key").
//
// Idempotent: keys are upserted on (tenant_id, public_fingerprint), so the same
// public key seen across many certificates or assets collapses to a single row —
// exactly what the Keys lens "used by N assets" count is built on. Any failure
// is logged and swallowed; it must never fail crypto ingest.
func (s *AssetService) produceKeyFromCertificate(tenantID, cryptoID uuid.UUID, cert *models.Certificate, data models.CertificateData) {
	if cert == nil {
		return
	}

	// key_type from the extraction (already "RSA"/"ECDSA"/"Ed25519" via
	// x509.PublicKeyAlgorithm.String()).
	keyType := strings.TrimSpace(data.PublicKeyAlgorithm)

	// Prefer the SPKI (public-key) fingerprint + curve by parsing the PEM; fall
	// back to the whole-certificate SHA-256 only when the PEM is unavailable
	// (partial-data certs). The SPKI fingerprint is what makes the same key
	// across renewals/hosts dedup to one row.
	pubFP := ""
	var curvePtr *string
	if x, err := sharedcerts.ParseCertificatePEM(data.CertificatePEM); err == nil && x != nil {
		pubFP = sharedcerts.PublicKeyFingerprintSHA256(x)
		if c := sharedcerts.PublicKeyCurve(x.PublicKey); c != "" {
			curvePtr = &c
		}
		if keyType == "" {
			keyType = x.PublicKeyAlgorithm.String()
		}
	}
	if pubFP == "" {
		pubFP = data.FingerprintSHA256
	}
	if pubFP == "" {
		// Nothing stable to dedup on — skip rather than write an anonymous row.
		return
	}
	if keyType == "" {
		keyType = "unknown"
	}

	var sizeBits *int
	if data.PublicKeySize > 0 {
		sz := data.PublicKeySize
		sizeBits = &sz
	}

	var activation, expires *time.Time
	if !data.NotBefore.IsZero() {
		t := data.NotBefore
		activation = &t
	}
	if !data.NotAfter.IsZero() {
		t := data.NotAfter
		expires = &t
	}

	// Best-effort resolution of algorithm_id against the algorithms catalogue so
	// the lens "Algorithm" column (alg.name via keys.algorithm_id) populates.
	// A miss leaves it NULL (the read path LEFT JOINs), which is harmless.
	algoCode := algorithmCodeForKey(keyType, data.PublicKeySize)

	meta := map[string]interface{}{
		"source":                         "certificate",
		"certificate_id":                 cert.ID.String(),
		"certificate_fingerprint_sha256": data.FingerprintSHA256,
	}
	if cert.CommonName != nil && *cert.CommonName != "" {
		meta["certificate_common_name"] = *cert.CommonName
	}
	metaJSON, _ := json.Marshal(meta)

	keyUsage := pq.StringArray(data.KeyUsage)
	state := mapCertStateToKeyState(cert.CertificateState)

	const upsertKey = `
		INSERT INTO keys (
			tenant_id, key_type, key_usage, public_fingerprint, size_bits, curve,
			material_type, state, algorithm_id, provenance, metadata,
			fingerprint_algorithm, fingerprint_value,
			created_at, activation_date, expires_at
		) VALUES (
			$1, $2, $3, $4::text, $5, $6,
			'public-key', $7,
			(SELECT id FROM algorithms WHERE code ILIKE $8 ORDER BY code LIMIT 1),
			'certificate', $9,
			'SHA-256', $4::text,
			NOW(), $10, $11
		)
		ON CONFLICT (tenant_id, public_fingerprint) WHERE public_fingerprint IS NOT NULL
		DO UPDATE SET
			key_type        = EXCLUDED.key_type,
			key_usage       = EXCLUDED.key_usage,
			size_bits       = EXCLUDED.size_bits,
			curve           = EXCLUDED.curve,
			state           = EXCLUDED.state,
			algorithm_id    = COALESCE(EXCLUDED.algorithm_id, keys.algorithm_id),
			activation_date = EXCLUDED.activation_date,
			expires_at      = EXCLUDED.expires_at,
			metadata        = EXCLUDED.metadata
		RETURNING id`

	const linkKey = `
		INSERT INTO implementation_keys (implementation_id, key_id)
		SELECT $1, $2
		WHERE EXISTS (SELECT 1 FROM crypto_implementations WHERE id = $1 AND tenant_id = $3 AND deleted_at IS NULL)
		  AND EXISTS (SELECT 1 FROM keys WHERE id = $2 AND tenant_id = $3)
		ON CONFLICT DO NOTHING`

	// RLS-scoped write over keys + implementation_keys, atomically.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		var keyID uuid.UUID
		if e := tx.QueryRow(
			upsertKey,
			tenantID, keyType, keyUsage, pubFP, sizeBits, curvePtr,
			state, algoCode, string(metaJSON), activation, expires,
		).Scan(&keyID); e != nil {
			return fmt.Errorf("upsert key: %w", e)
		}
		if _, e := tx.Exec(linkKey, cryptoID, keyID, tenantID); e != nil {
			return fmt.Errorf("link key to implementation: %w", e)
		}
		return nil
	})
	if err != nil {
		log.Printf("[AssetService] Warning: failed to produce key from certificate %s (impl %s): %v",
			cert.ID, cryptoID, err)
	}
}

// mapCertStateToKeyState maps a certificate lifecycle state onto the key state
// enum (valid_key_state: pre-activation, active, suspended, deactivated,
// compromised, destroyed). Certificate-only states have no direct key analogue:
// a revoked cert implies its key is no longer trusted (compromised); an expired
// cert implies its key is no longer in service (deactivated).
func mapCertStateToKeyState(certState string) string {
	switch certState {
	case "pre-activation", "active", "suspended", "deactivated", "destroyed":
		return certState
	case "revoked":
		return "compromised"
	case "expired":
		return "deactivated"
	default:
		return "active"
	}
}

// algorithmCodeForKey returns the algorithms.code to look up for a given public
// key type/size (e.g. RSA-2048), or "" when there's no useful match. Matching is
// case-insensitive (ILIKE) at the call site; "" simply matches nothing.
func algorithmCodeForKey(keyType string, sizeBits int) string {
	switch strings.ToUpper(keyType) {
	case "RSA":
		if sizeBits > 0 {
			return fmt.Sprintf("RSA-%d", sizeBits)
		}
		return "RSA"
	case "ECDSA", "EC":
		return "ECDSA"
	case "ED25519":
		return "Ed25519"
	case "DSA":
		return "DSA"
	default:
		return ""
	}
}
