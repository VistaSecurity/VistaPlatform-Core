package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/alertcatalog"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// AlertCatalogService serves the tenant alert catalog: registry entries
// overlaid with per-tenant settings (enable/disable + preference rung) and,
// for ladder types, the effective rung ladder including policy rungs
// projected from the tenant's activated compliance frameworks (§8.3).
type AlertCatalogService struct {
	db *sqlx.DB
}

func NewAlertCatalogService(db *sqlx.DB) *AlertCatalogService {
	return &AlertCatalogService{db: db}
}

// CatalogEntry is one row of the tenant-facing catalog.
type CatalogEntry struct {
	alertcatalog.Entry
	Enabled        bool                `json:"enabled"`
	PreferenceRung map[string]int      `json:"preference_rung,omitempty"`
	Ladder         []alertcatalog.Rung `json:"ladder,omitempty"`
}

type tenantAlertSetting struct {
	Enabled        bool
	PreferenceRung map[string]int
}

// GetCatalog returns the tenant-track catalog with settings + ladders applied.
func (s *AlertCatalogService) GetCatalog(ctx context.Context, tenantID uuid.UUID) ([]CatalogEntry, error) {
	settings, err := s.loadSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	var certPolicyRungs []alertcatalog.Rung
	// Only the cert ladder consumes policy rungs today; compute once.
	certPolicyRungs, err = s.CertPolicyRungs(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("project policy rungs: %w", err)
	}

	out := []CatalogEntry{}
	for _, entry := range alertcatalog.Registry {
		if entry.Track != "tenant" {
			continue
		}
		ce := CatalogEntry{Entry: entry, Enabled: entry.EnabledByDefault}
		if st, ok := settings[entry.ID]; ok {
			ce.Enabled = st.Enabled
			ce.PreferenceRung = st.PreferenceRung
		}
		if entry.SeverityModel == "ladder" && entry.BaselineDays > 0 {
			baseline := &alertcatalog.Rung{Days: entry.BaselineDays, Severity: entry.BaselineSeverity}
			var pref *alertcatalog.Rung
			if d, ok := ce.PreferenceRung["days"]; ok && d > 0 {
				pref = &alertcatalog.Rung{Days: d, Severity: entry.BaselineSeverity}
			}
			var policy []alertcatalog.Rung
			if entry.ID == "certificate_expiring" {
				policy = certPolicyRungs
			}
			ce.Ladder = alertcatalog.BuildLadder(baseline, pref, policy, ce.Enabled)
		}
		out = append(out, ce)
	}
	return out, nil
}

// UpdateSetting upserts the tenant's enable/preference state for one type.
func (s *AlertCatalogService) UpdateSetting(ctx context.Context, tenantID uuid.UUID, alertType string,
	enabled bool, preferenceRung map[string]int, updatedBy uuid.UUID) error {

	if _, ok := alertcatalog.Get(alertType); !ok {
		return fmt.Errorf("unknown alert type: %s", alertType)
	}
	if d, ok := preferenceRung["days"]; ok && (d < 1 || d > 3650) {
		return fmt.Errorf("preference rung days must be 1–3650")
	}
	var rungJSON interface{}
	if len(preferenceRung) > 0 {
		b, _ := json.Marshal(preferenceRung)
		rungJSON = b
	}
	return shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO tenant_alert_settings (tenant_id, alert_type, enabled, preference_rung, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, NOW())
			ON CONFLICT (tenant_id, alert_type) DO UPDATE SET
			  enabled = EXCLUDED.enabled,
			  preference_rung = EXCLUDED.preference_rung,
			  updated_by = EXCLUDED.updated_by,
			  updated_at = NOW()
		`, tenantID, alertType, enabled, rungJSON, updatedBy)
		return err
	})
}

// CertLadder returns the tenant's effective certificate-expiry ladder.
func (s *AlertCatalogService) CertLadder(ctx context.Context, tenantID uuid.UUID) ([]alertcatalog.Rung, error) {
	entry, ok := alertcatalog.Get("certificate_expiring")
	if !ok {
		return nil, fmt.Errorf("certificate_expiring missing from registry")
	}
	settings, err := s.loadSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	enabled := entry.EnabledByDefault
	var pref *alertcatalog.Rung
	if st, ok := settings[entry.ID]; ok {
		enabled = st.Enabled
		if d, dok := st.PreferenceRung["days"]; dok && d > 0 {
			pref = &alertcatalog.Rung{Days: d, Severity: entry.BaselineSeverity}
		}
	}
	policy, err := s.CertPolicyRungs(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	baseline := &alertcatalog.Rung{Days: entry.BaselineDays, Severity: entry.BaselineSeverity}
	return alertcatalog.BuildLadder(baseline, pref, policy, enabled), nil
}

// CertPolicyRungs projects rungs from the tenant's ACTIVE framework licenses:
// every cert_expiration_days threshold measurement contributes a rung at its
// predicate value, carrying the control's severity (measurement override
// first, then control baseline), with the tenant's premium measurement
// override (predicate_override/severity_override) taking precedence.
func (s *AlertCatalogService) CertPolicyRungs(ctx context.Context, tenantID uuid.UUID) ([]alertcatalog.Rung, error) {
	query := `
		SELECT
		  COALESCE(tmo.predicate_override, cm.predicate) AS predicate,
		  COALESCE(tmo.severity_override, cm.severity_override, pfc.baseline_severity) AS severity,
		  pf.name
		FROM tenant_framework_licenses tfl
		JOIN platform_frameworks pf ON pf.id = tfl.platform_framework_id
		JOIN platform_framework_controls pfc ON pfc.framework_id = pf.id
		JOIN control_measurements cm ON cm.control_id = pfc.id AND cm.framework_type = 'platform'
		JOIN measurement_types mt ON mt.id = cm.measurement_type_id
		LEFT JOIN tenant_measurement_overrides tmo
		  ON tmo.control_measurement_id = cm.id AND tmo.tenant_id = $1
		WHERE tfl.tenant_id = $1
		  AND tfl.subscription_status = 'active'
		  AND mt.code = 'cert_expiration_days'
		  AND cm.rule_type = 'threshold'
	`
	rungs := []alertcatalog.Rung{}
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, tenantID)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var predicateJSON []byte
			var severity, frameworkName string
			if err := rows.Scan(&predicateJSON, &severity, &frameworkName); err != nil {
				return err
			}
			var predicate struct {
				Operator string  `json:"operator"`
				Value    float64 `json:"value"`
			}
			if err := json.Unmarshal(predicateJSON, &predicate); err != nil {
				continue
			}
			// "must have >= N days remaining" → warn when remaining <= N.
			if predicate.Operator != ">=" && predicate.Operator != ">" {
				continue
			}
			rungs = append(rungs, alertcatalog.Rung{
				Days:     int(predicate.Value),
				Severity: alertcatalog.NormalizeControlSeverity(severity),
				Source:   "policy:" + frameworkName,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return rungs, nil
}

func (s *AlertCatalogService) loadSettings(ctx context.Context, tenantID uuid.UUID) (map[string]tenantAlertSetting, error) {
	out := map[string]tenantAlertSetting{}
	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx,
			`SELECT alert_type, enabled, preference_rung FROM tenant_alert_settings WHERE tenant_id = $1`, tenantID)
		if qErr != nil {
			return qErr
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var alertType string
			var st tenantAlertSetting
			var rung []byte
			if err := rows.Scan(&alertType, &st.Enabled, &rung); err != nil {
				return err
			}
			if len(rung) > 0 {
				_ = json.Unmarshal(rung, &st.PreferenceRung)
			}
			out[alertType] = st
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// IsTypeEnabled reports whether a tenant has the alert type enabled
// (registry default when unset). Used by the raise path for operational
// types; policy-rung raises bypass this by design (§8.3 disable semantics).
func (s *AlertCatalogService) IsTypeEnabled(ctx context.Context, tenantID uuid.UUID, alertType string) bool {
	entry, ok := alertcatalog.Get(alertType)
	enabled := true
	if ok {
		enabled = entry.EnabledByDefault
	}
	_ = shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		var e bool
		err := tx.QueryRowContext(ctx,
			`SELECT enabled FROM tenant_alert_settings WHERE tenant_id = $1 AND alert_type = $2`,
			tenantID, alertType).Scan(&e)
		if err == nil {
			enabled = e
		}
		return nil
	})
	return enabled
}
