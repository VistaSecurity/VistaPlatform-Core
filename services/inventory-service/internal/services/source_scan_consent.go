package services

// Per-source scan consent (platform ADR-0002 D10): whether assets known only
// from one imported source may be actively scanned by automatic scanning. The
// rule that reads it is shared/autoscan ImportedWithoutConsentSQL, used by the
// auto-scan planner here and by the dispatch guard at every later stage. The
// row is written only through the signed internal source route, by the
// service that owns the connection — which records the tenant's choice on the
// connection and here, and refuses the change when this write fails.

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// SourceScanConsent is one source's consent as stored.
type SourceScanConsent struct {
	SourceRef       string `json:"source_ref"`
	AllowActiveScan bool   `json:"allow_active_scan"`
}

// SetScanConsent records whether assets from source may be actively scanned by
// automatic scanning. actor is the person who changed it (uuid.Nil when
// unknown).
func (s *SourceImportService) SetScanConsent(ctx context.Context, tenantID uuid.UUID, source identity.Source, allow bool, actor uuid.UUID) (SourceScanConsent, error) {
	var actorArg any
	if actor != uuid.Nil {
		actorArg = actor
	}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO source_scan_consents (tenant_id, source_ref, allow_active_scan, updated_by, updated_at)
			VALUES ($1, $2, $3, $4::uuid, NOW())
			ON CONFLICT (tenant_id, source_ref)
			DO UPDATE SET allow_active_scan = EXCLUDED.allow_active_scan,
			              updated_by = EXCLUDED.updated_by, updated_at = NOW()`,
			tenantID, source.Ref, allow, actorArg)
		return err
	})
	if err != nil {
		return SourceScanConsent{}, fmt.Errorf("record scan consent: %w", err)
	}
	return SourceScanConsent{SourceRef: source.Ref, AllowActiveScan: allow}, nil
}
