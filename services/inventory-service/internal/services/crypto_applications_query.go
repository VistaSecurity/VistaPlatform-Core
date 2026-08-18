package services

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// CryptoApplicationFilter is the read filter behind
// GET /crypto-applications (the Data Protection lens).
type CryptoApplicationFilter struct {
	// EncryptionContext defaults to "at_rest" at the handler; empty here means
	// "every context".
	EncryptionContext string
	ResourceType      string
	// Determined filters on whether the posture could be measured at all.
	// nil = no filter; the tri-state matters, because "could not determine" is
	// its own answer and the lens needs to isolate it.
	Determined *bool
	// RiskAtLeast is a band LABEL (Critical/High/Medium/Low/Informational),
	// resolved through models.RiskAtLeastSQL. Never a raw threshold — CLAUDE.md
	// forbids hand-written `risk_score >= N` predicates.
	RiskAtLeast string
	Search      string
	Limit       int
	Offset      int
}

// cryptoApplicationRow scans the projection below. configuration_data fields
// are extracted in SQL (->>) rather than unmarshalled, so filtering and
// projection use the same expressions.
type cryptoApplicationRow struct {
	ID                   string     `db:"id"`
	AssetID              *string    `db:"asset_id"`
	ResourceType         string     `db:"resource_type"`
	ResourceName         *string    `db:"resource_name"`
	ResourceIdentifier   string     `db:"resource_identifier"`
	EncryptionContext    string     `db:"encryption_context"`
	Encrypted            *bool      `db:"encrypted"`
	EncryptionDetermined *bool      `db:"encryption_determined"`
	EncryptionType       *string    `db:"encryption_type"`
	Algorithm            *string    `db:"algorithm"`
	KeyManager           *string    `db:"key_manager"`
	KMSKeyID             *string    `db:"kms_key_id"`
	CloudProvider        *string    `db:"cloud_provider"`
	CloudRegion          *string    `db:"cloud_region"`
	RiskScore            int        `db:"risk_score"`
	LastVerifiedAt       *time.Time `db:"last_verified_at"`
}

const cryptoApplicationColumns = `
	ca.id::text AS id,
	ca.asset_id::text AS asset_id,
	ca.resource_type,
	ca.resource_name,
	ca.resource_identifier,
	ca.encryption_context,
	(ca.configuration_data->>'encrypted')::boolean AS encrypted,
	(ca.configuration_data->>'encryption_determined')::boolean AS encryption_determined,
	NULLIF(ca.configuration_data->>'encryption_type', '') AS encryption_type,
	COALESCE(alg.name, NULLIF(ca.configuration_data->>'algorithm', '')) AS algorithm,
	NULLIF(ca.configuration_data->>'key_manager', '') AS key_manager,
	NULLIF(ca.configuration_data->>'kms_key_id', '') AS kms_key_id,
	NULLIF(ca.configuration_data->>'cloud_provider', '') AS cloud_provider,
	NULLIF(ca.configuration_data->>'cloud_region', '') AS cloud_region,
	COALESCE(ca.risk_score, 0) AS risk_score,
	ca.last_verified_at`

// determinedSQL is the single expression for "was the posture measured at all".
// A row written before the producer existed has no encryption_determined key;
// COALESCE to false keeps it out of the "measured" bucket rather than
// promoting an unknown to an answer.
const determinedSQL = `COALESCE((ca.configuration_data->>'encryption_determined')::boolean, false)`

// ListCryptoApplications returns a tenant's cryptographic-application posture
// rows, newest-verified first, plus the unpaginated total.
func (s *AssetService) ListCryptoApplications(tenantID uuid.UUID, f CryptoApplicationFilter) ([]models.CryptoApplication, int, error) {
	where := []string{"ca.tenant_id = $1", "ca.deleted_at IS NULL"}
	args := []interface{}{tenantID}
	next := func(v interface{}) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}

	if f.EncryptionContext != "" {
		where = append(where, "ca.encryption_context = "+next(f.EncryptionContext))
	}
	if f.ResourceType != "" {
		where = append(where, "ca.resource_type = "+next(f.ResourceType))
	}
	if f.Determined != nil {
		if *f.Determined {
			where = append(where, determinedSQL)
		} else {
			where = append(where, "NOT "+determinedSQL)
		}
	}
	if f.RiskAtLeast != "" {
		// Unknown band labels are ignored rather than silently matching
		// nothing — RiskAtLeastSQL reports the miss.
		if cond, ok := models.RiskAtLeastSQL("COALESCE(ca.risk_score, 0)", f.RiskAtLeast); ok {
			where = append(where, cond)
		}
	}
	if term := strings.TrimSpace(f.Search); term != "" {
		p := next("%" + term + "%")
		where = append(where, "(ca.resource_name ILIKE "+p+" OR ca.resource_identifier ILIKE "+p+")")
	}

	whereSQL := strings.Join(where, " AND ")
	const join = ` FROM crypto_applications ca LEFT JOIN algorithms alg ON alg.id = ca.algorithm_id WHERE `

	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	listSQL := `SELECT ` + cryptoApplicationColumns + join + whereSQL +
		` ORDER BY COALESCE(ca.risk_score, 0) DESC, ca.last_verified_at DESC NULLS LAST` +
		` LIMIT ` + next(limit) + ` OFFSET ` + next(offset)
	countSQL := `SELECT COUNT(*)` + join + whereSQL

	var rows []cryptoApplicationRow
	var total int
	// RLS-scoped read over crypto_applications (LEFT JOIN algorithms, a global
	// catalogue table with no tenant column).
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if e := tx.Select(&rows, listSQL, args...); e != nil {
			return e
		}
		// The count reuses every filter arg but not LIMIT/OFFSET (the last two).
		return tx.Get(&total, countSQL, args[:len(args)-2]...)
	}); err != nil {
		return nil, 0, fmt.Errorf("failed to list crypto applications: %w", err)
	}

	out := make([]models.CryptoApplication, 0, len(rows))
	for _, r := range rows {
		item := models.CryptoApplication{
			ID:                 r.ID,
			AssetID:            r.AssetID,
			ResourceType:       r.ResourceType,
			ResourceIdentifier: r.ResourceIdentifier,
			EncryptionContext:  r.EncryptionContext,
			Algorithm:          r.Algorithm,
			KeyManager:         r.KeyManager,
			KMSKeyID:           r.KMSKeyID,
			CloudProvider:      r.CloudProvider,
			CloudRegion:        r.CloudRegion,
			RiskScore:          r.RiskScore,
			// Single source for the band. Never a second ladder.
			RiskLevel:      models.GetRiskLevel(r.RiskScore),
			LastVerifiedAt: r.LastVerifiedAt,
		}
		if r.ResourceName != nil {
			item.ResourceName = *r.ResourceName
		}
		if r.Encrypted != nil {
			item.Encrypted = *r.Encrypted
		}
		if r.EncryptionDetermined != nil {
			item.EncryptionDetermined = *r.EncryptionDetermined
		}
		if r.EncryptionType != nil {
			item.EncryptionType = *r.EncryptionType
		}
		out = append(out, item)
	}
	return out, total, nil
}
