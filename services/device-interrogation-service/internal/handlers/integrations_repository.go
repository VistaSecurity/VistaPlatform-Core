package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// integrationStore is the persistence surface the integration handlers depend
// on. Declaring it as an interface (the concrete integrationRepository
// satisfies it) is what makes the handlers exercisable from the contract test
// with an in-memory stub — no database — per the spec-first contract recipe
// (ADR-0001). The inline SQL the handlers used to run was relocated VERBATIM
// into integrationRepository below; the per-field credential
// encrypt/decrypt/mask logic stays in the handler (it never touched SQL).
type integrationStore interface {
	List(ctx context.Context, tenantID uuid.UUID, providerFilter string) ([]CloudIntegration, error)
	Get(ctx context.Context, id, tenantID uuid.UUID) (*CloudIntegration, error)
	Create(ctx context.Context, p CreateIntegrationParams) error
	// GetConfigForUpdate / GetConfigForTest report a row's encrypted config + type;
	// found=false when no such row exists for the tenant. They differ only in
	// whether shared (tenant_id IS NULL) rows are visible.
	GetConfigForUpdate(ctx context.Context, id, tenantID uuid.UUID) (configJSON, integrationType string, found bool, err error)
	GetConfigForTest(ctx context.Context, id, tenantID uuid.UUID) (configJSON, integrationType string, found bool, err error)
	Update(ctx context.Context, id, tenantID uuid.UUID, fields map[string]interface{}) (rowsAffected int64, err error)
	Delete(ctx context.Context, id, tenantID uuid.UUID) (rowsAffected int64, err error)
	// UpdateTestStatus is keyed by id; tenantID is threaded from the caller so the
	// write is RLS-scoped.
	UpdateTestStatus(ctx context.Context, tenantID, id uuid.UUID, status string, statusMessage *string) error
}

// CreateIntegrationParams carries the columns for an integration INSERT. config
// is already encrypted by the handler; tags is a JSON array string.
type CreateIntegrationParams struct {
	ID              uuid.UUID
	TenantID        uuid.UUID
	IntegrationType string
	IntegrationName string
	Provider        string
	ConfigJSON      string
	AccountID       *string
	Region          *string
	Environment     *string
	Description     *string
	TagsJSON        string
	IsEnabled       bool
	Status          string
	CreatedAt       time.Time
}

// integrationRepository is the SQL-backed integrationStore. The queries here
// are moved verbatim from the former inline handler SQL.
type integrationRepository struct {
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) connection used by the read paths
	// that intentionally include SHARED platform integrations (tenant_id IS NULL,
	// is_shared = true): the RLS policy `tenant_id = NULLIF(current_setting(...), '')::uuid`
	// excludes NULL-tenant rows, so List/Get/GetConfigForTest run on bypass to keep
	// shared integrations visible. The tenant-owned write paths (Create/Update/
	// Delete/GetConfigForUpdate/UpdateTestStatus) use WithTenantTx. Pre-flip it
	// resolves to the same connection as db.
	bypassDB *sql.DB
}

func newIntegrationRepository(db, bypassDB *sql.DB) *integrationRepository {
	return &integrationRepository{db: db, bypassDB: bypassDB}
}

const integrationSelectColumns = `
	SELECT id, tenant_id, integration_type, integration_name, provider, config,
		   account_id, region, environment, description, tags, is_enabled,
		   COALESCE(is_shared, false) as is_shared, status, status_message,
		   last_tested_at, created_at, updated_at
	FROM platform_integrations
`

// scanIntegration scans one row into a CloudIntegration, parsing the (still
// encrypted) config and the tags JSON. The caller decrypts/masks Config.
func scanIntegration(scan func(dest ...any) error) (CloudIntegration, error) {
	var integ CloudIntegration
	var configJSON string
	var tagsJSON sql.NullString
	var tenantIDNull sql.NullString
	if err := scan(
		&integ.ID, &tenantIDNull, &integ.IntegrationType,
		&integ.IntegrationName, &integ.Provider, &configJSON,
		&integ.AccountID, &integ.Region, &integ.Environment,
		&integ.Description, &tagsJSON, &integ.IsEnabled,
		&integ.IsShared, &integ.Status, &integ.StatusMessage,
		&integ.LastTestedAt, &integ.CreatedAt, &integ.UpdatedAt,
	); err != nil {
		return CloudIntegration{}, err
	}
	if tenantIDNull.Valid {
		integ.TenantID, _ = uuid.Parse(tenantIDNull.String)
	}
	if configJSON != "" {
		_ = json.Unmarshal([]byte(configJSON), &integ.Config)
	}
	if tagsJSON.Valid {
		_ = json.Unmarshal([]byte(tagsJSON.String), &integ.Tags)
	}
	return integ, nil
}

func (r *integrationRepository) List(ctx context.Context, tenantID uuid.UUID, providerFilter string) ([]CloudIntegration, error) {
	query := integrationSelectColumns + `
		WHERE (tenant_id = $1 OR (tenant_id IS NULL AND is_shared = true))
		  AND deleted_at IS NULL
		  AND is_active = true
	`
	args := []interface{}{tenantID}
	if providerFilter != "" {
		query += " AND integration_type = $2"
		args = append(args, providerFilter)
	}
	query += " ORDER BY created_at DESC"

	// RLS: this read intentionally includes SHARED (tenant_id IS NULL) integrations
	// which the RLS policy would hide → bypass role. The explicit
	// `tenant_id = $1 OR (tenant_id IS NULL AND is_shared)` WHERE is the isolation
	// control.
	rows, err := r.bypassDB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	integrations := make([]CloudIntegration, 0)
	for rows.Next() {
		integ, err := scanIntegration(rows.Scan)
		if err != nil {
			continue
		}
		integrations = append(integrations, integ)
	}
	return integrations, nil
}

func (r *integrationRepository) Get(ctx context.Context, id, tenantID uuid.UUID) (*CloudIntegration, error) {
	query := integrationSelectColumns + `
		WHERE id = $1
		  AND (tenant_id = $2 OR (tenant_id IS NULL AND is_shared = true))
		  AND deleted_at IS NULL
	`
	// RLS: includes SHARED (tenant_id IS NULL) integrations → bypass role; the
	// explicit WHERE is the isolation control.
	integ, err := scanIntegration(r.bypassDB.QueryRowContext(ctx, query, id, tenantID).Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &integ, nil
}

func (r *integrationRepository) Create(ctx context.Context, p CreateIntegrationParams) error {
	query := `
		INSERT INTO platform_integrations (
			id, tenant_id, integration_type, integration_name, provider, config,
			account_id, region, environment, description, tags, is_enabled,
			status, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
	`
	// RLS-scoped write on `platform_integrations`: tenant-owned row → WithTenantTx.
	return shareddatabase.WithTenantTx(ctx, r.db, p.TenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, query,
			p.ID, p.TenantID, p.IntegrationType, p.IntegrationName,
			p.Provider, p.ConfigJSON, p.AccountID, p.Region, p.Environment,
			p.Description, p.TagsJSON, p.IsEnabled, p.Status, p.CreatedAt, p.CreatedAt,
		)
		return err
	})
}

func (r *integrationRepository) GetConfigForUpdate(ctx context.Context, id, tenantID uuid.UUID) (string, string, bool, error) {
	// Tenant-owned row only (tenant_id = $2) → WithTenantTx.
	var configJSON, integrationType string
	found := false
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		scanErr := tx.QueryRowContext(ctx,
			"SELECT config, integration_type FROM platform_integrations WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
			id, tenantID,
		).Scan(&configJSON, &integrationType)
		if scanErr == sql.ErrNoRows {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		found = true
		return nil
	})
	if err != nil {
		return "", "", false, err
	}
	return configJSON, integrationType, found, nil
}

func (r *integrationRepository) GetConfigForTest(ctx context.Context, id, tenantID uuid.UUID) (string, string, bool, error) {
	// RLS: includes SHARED (tenant_id IS NULL) integrations → bypass role; the
	// explicit WHERE is the isolation control.
	var configJSON, integrationType string
	err := r.bypassDB.QueryRowContext(ctx,
		"SELECT config, integration_type FROM platform_integrations WHERE id = $1 AND (tenant_id = $2 OR (tenant_id IS NULL AND is_shared = true)) AND deleted_at IS NULL",
		id, tenantID,
	).Scan(&configJSON, &integrationType)
	if err == sql.ErrNoRows {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return configJSON, integrationType, true, nil
}

func (r *integrationRepository) Update(ctx context.Context, id, tenantID uuid.UUID, fields map[string]interface{}) (int64, error) {
	if len(fields) == 0 {
		return 0, nil
	}

	// Deterministic column order (callers pass a fixed allowlist of columns).
	cols := make([]string, 0, len(fields))
	for k := range fields {
		cols = append(cols, k)
	}
	sort.Strings(cols)

	setClauses := make([]string, 0, len(cols)+1)
	args := make([]interface{}, 0, len(cols)+3)
	argNum := 1
	for _, col := range cols {
		setClauses = append(setClauses, fmt.Sprintf("%s = $%d", col, argNum))
		args = append(args, fields[col])
		argNum++
	}
	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argNum))
	args = append(args, time.Now())
	argNum++

	args = append(args, id, tenantID)
	//nolint:gosec // column names come from a fixed handler-controlled allowlist; values are parameterized via args
	query := fmt.Sprintf(
		"UPDATE platform_integrations SET %s WHERE id = $%d AND tenant_id = $%d",
		joinStrings(setClauses, ", "), argNum, argNum+1,
	)
	var rowsAffected int64
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		res, e := tx.ExecContext(ctx, query, args...)
		if e != nil {
			return e
		}
		rowsAffected, e = res.RowsAffected()
		return e
	})
	if err != nil {
		return 0, err
	}
	return rowsAffected, nil
}

func (r *integrationRepository) Delete(ctx context.Context, id, tenantID uuid.UUID) (int64, error) {
	var rowsAffected int64
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		res, e := tx.ExecContext(ctx,
			"UPDATE platform_integrations SET deleted_at = NOW(), is_active = false WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL",
			id, tenantID,
		)
		if e != nil {
			return e
		}
		rowsAffected, e = res.RowsAffected()
		return e
	})
	if err != nil {
		return 0, err
	}
	return rowsAffected, nil
}

func (r *integrationRepository) UpdateTestStatus(ctx context.Context, tenantID, id uuid.UUID, status string, statusMessage *string) error {
	return shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx,
			"UPDATE platform_integrations SET last_tested_at = NOW(), status = $1, status_message = $2 WHERE id = $3 AND tenant_id = $4",
			status, statusMessage, id, tenantID,
		)
		return err
	})
}
