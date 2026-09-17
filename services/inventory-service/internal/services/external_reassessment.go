package services

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// ReassessBatch recomputes current ratings from persisted facts without creating
// observations or rewriting history. The UUID cursor is resumable; retrying a
// committed batch is harmless. The scheduler starts from zero on every pass so
// later catalogue edits apply to existing rows too.
func (s *ExternalConnectionsService) ReassessBatch(ctx context.Context, tenant uuid.UUID, after uuid.UUID, limit int) (last uuid.UUID, processed int, err error) {
	if limit < 1 || limit > 200 {
		return after, 0, fmt.Errorf("reassessment batch limit must be 1..200")
	}
	last = after
	err = database.WithTenantTx(ctx, s.db, tenant, func(tx *sqlx.Tx) error {
		rows, e := tx.QueryContext(ctx, `SELECT to_jsonb(ec) FROM external_connections ec WHERE tenant_id=$1 AND id>$2 ORDER BY id LIMIT $3 FOR UPDATE`, tenant, after, limit)
		if e != nil {
			return e
		}
		var payloads [][]byte
		for rows.Next() {
			var payload []byte
			if e := rows.Scan(&payload); e != nil {
				_ = rows.Close()
				return e
			}
			payloads = append(payloads, payload)
		}
		e = rows.Err()
		_ = rows.Close()
		if e != nil {
			return e
		}
		for _, payload := range payloads {
			var current models.ExternalConnection
			var facts models.ExternalConnectionUpsert
			var stored struct {
				Strength *string `json:"crypto_strength"`
			}
			if e := json.Unmarshal(payload, &current); e != nil {
				return e
			}
			if e := json.Unmarshal(payload, &facts); e != nil {
				return e
			}
			if e := json.Unmarshal(payload, &stored); e != nil {
				return e
			}
			assessmentInput, priorReasons := prepareExternalAssessment(facts, current.WeakReasons, false)
			rating, pqcRating, _, reasons, hygiene := assessExternalCryptoTx(ctx, tx, assessmentInput)
			rating, reasons = preserveExternalAssessment(rating, reasons, stored.Strength, priorReasons, false)
			next := nullableStrength(rating)
			if _, e := tx.ExecContext(ctx, `UPDATE external_connections SET crypto_strength=$1,is_pqc_resistant=$2,weak_reasons=$3,cert_hygiene_flags=$4,cert_is_expired=$5,updated_at=NOW() WHERE tenant_id=$6 AND id=$7`, next, pqcRating, pq.StringArray(reasons), pq.StringArray(appendUnique(hygiene, current.CertHygieneFlags...)), facts.CertNotAfter != nil && facts.CertNotAfter.Before(time.Now()), tenant, current.ID); e != nil {
				return e
			}
			if stringValue(stored.Strength) != rating {
				if _, e := tx.ExecContext(ctx, `INSERT INTO external_connection_history(external_connection_id,tenant_id,change_type,previous_protocol_version,previous_cipher_suite,previous_crypto_strength,previous_is_pqc_resistant,previous_cert_fingerprint_sha256,previous_cert_not_after,new_protocol_version,new_cipher_suite,new_crypto_strength,new_is_pqc_resistant,new_cert_fingerprint_sha256,new_cert_not_after,strength_vocabulary_version) VALUES($1,$2,'crypto_strength_changed',$3,$4,$5,$6,$7,$8,$3,$4,$9,$10,$7,$8,2)`, current.ID, tenant, current.ProtocolVersion, current.CipherSuite, stored.Strength, current.IsPQCResistant, current.CertFingerprintSHA256, current.CertNotAfter, next, pqcRating); e != nil {
					return e
				}
			}
			last = current.ID
			processed++
		}
		return nil
	})
	if err != nil {
		return after, 0, err
	}
	return last, processed, nil
}
