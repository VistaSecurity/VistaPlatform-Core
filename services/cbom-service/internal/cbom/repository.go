package cbom

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/database"
)

// ErrNotFound is returned when an artifact lookup misses (truly missing or
// not visible to the current tenant under RLS).
var ErrNotFound = errors.New("cbom artifact not found")

// Repository encapsulates cbom_artifacts persistence.
type Repository struct {
	db *database.DB
}

// NewRepository constructs a Repository over the given DB connection.
func NewRepository(db *database.DB) *Repository {
	return &Repository{db: db}
}

func (r *Repository) withTenantSession(ctx context.Context, tenantID uuid.UUID, fn func(*sql.Tx) error) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cbom: begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("cbom: set tenant_id: %w", err)
	}

	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// insertParams bundles everything the builder needs to persist.
type insertParams struct {
	TenantID          uuid.UUID
	ScopeID           uuid.UUID
	ScopeVersion      int
	ScopeNameSnapshot string
	Name              string
	StorageKey        string // either StorageKey or InlineContent (exclusive)
	InlineContent     []byte
	// InternalContent is the private CBOMData view of the same snapshot, kept
	// so the Enterprise diff can read fields CycloneDX has no home for. Never
	// served, never hashed, and not subject to the storage/inline CHECK.
	InternalContent      []byte
	ContentHash          string
	SizeBytes            int64
	ComponentCount       int
	CycloneDXSpecVersion string
	InputDataFreshnessAt interface{} // time.Time
	GeneratedBy          uuid.UUID
	Provenance           Provenance
	// Phase 4: optional attestation layer + signature. When nil/empty the
	// columns stay empty and the artifact is unsigned + unattested.
	Layers        []Layer
	SignatureHMAC string
	SignatureKID  string
}

// Create inserts a new artifact row. Either StorageKey or InlineContent must
// be set (enforced by a CHECK constraint at the DB level).
func (r *Repository) Create(ctx context.Context, p insertParams) (*Artifact, error) {
	provBytes, err := json.Marshal(p.Provenance)
	if err != nil {
		return nil, fmt.Errorf("cbom: marshal provenance: %w", err)
	}

	// Layers default to an empty array (not null) so JSONB queries don't
	// have to NULL-check. Same for the column default in schema.sql.
	layers := p.Layers
	if layers == nil {
		layers = []Layer{}
	}
	layersBytes, err := json.Marshal(layers)
	if err != nil {
		return nil, fmt.Errorf("cbom: marshal layers: %w", err)
	}

	var (
		storageKey    sql.NullString
		inlineContent []byte
	)
	if p.StorageKey != "" {
		storageKey = sql.NullString{String: p.StorageKey, Valid: true}
	} else {
		inlineContent = p.InlineContent
	}

	// internal_content is independent of the storage_key/inline_content split.
	// That CHECK constraint governs where the CANONICAL bytes live; this is the
	// private diff view, which always lives in the DB so a comparison works the
	// same whether or not the deployment has S3 configured.
	internalContent := p.InternalContent

	var a Artifact
	a.Provenance = p.Provenance
	a.Layers = layers
	a.SignatureHMAC = p.SignatureHMAC
	a.SignatureKID = p.SignatureKID
	err = r.withTenantSession(ctx, p.TenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			INSERT INTO public.cbom_artifacts
				(tenant_id, scope_id, scope_version, scope_name_snapshot, name,
				 storage_key, inline_content, internal_content,
				 content_hash, size_bytes, component_count,
				 cyclonedx_spec_version, input_data_freshness_at,
				 generated_by, provenance, layers,
				 signature_hmac, signature_kid)
			VALUES ($1, $2, $3, $4, $5,
				$6, $7, $8,
				$9, $10, $11,
				$12, $13,
				$14, $15, $16,
				$17, $18)
			RETURNING id, generated_at, created_at
		`,
			p.TenantID, p.ScopeID, p.ScopeVersion, p.ScopeNameSnapshot, nullableString(p.Name),
			storageKey, inlineContent, internalContent,
			p.ContentHash, p.SizeBytes, p.ComponentCount,
			p.CycloneDXSpecVersion, p.InputDataFreshnessAt,
			p.GeneratedBy, provBytes, layersBytes,
			nullableString(p.SignatureHMAC), nullableString(p.SignatureKID),
		).Scan(&a.ID, &a.GeneratedAt, &a.CreatedAt)
	})
	if err != nil {
		return nil, err
	}

	a.TenantID = p.TenantID
	a.ScopeID = p.ScopeID
	a.ScopeVersion = p.ScopeVersion
	a.ScopeNameSnapshot = p.ScopeNameSnapshot
	a.Name = p.Name
	a.StorageKey = p.StorageKey
	a.HasInlineContent = inlineContent != nil
	a.ContentHash = p.ContentHash
	a.SizeBytes = p.SizeBytes
	a.ComponentCount = p.ComponentCount
	a.CycloneDXSpecVersion = p.CycloneDXSpecVersion
	a.GeneratedBy = p.GeneratedBy
	if t, ok := p.InputDataFreshnessAt.(interface{ UTC() interface{} }); ok {
		_ = t // type narrowing left for callers; we only need it stored
	}
	return &a, nil
}

// List returns non-deleted artifacts for the tenant ordered by generated_at DESC.
// Pagination is intentional follow-up — Phase 2 expects tens, not thousands.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID, scopeID *uuid.UUID, limit int) ([]Artifact, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	var artifacts []Artifact
	err := r.withTenantSession(ctx, tenantID, func(tx *sql.Tx) error {
		query := `
			SELECT id, tenant_id, scope_id, scope_version, scope_name_snapshot,
			       COALESCE(name, ''), COALESCE(storage_key, ''),
			       (inline_content IS NOT NULL),
			       content_hash, size_bytes, component_count,
			       cyclonedx_spec_version, input_data_freshness_at,
			       generated_at, generated_by,
			       COALESCE(signature_hmac, ''), COALESCE(signature_kid, ''),
			       provenance, layers, created_at
			FROM public.cbom_artifacts
			WHERE tenant_id = $1 AND deleted_at IS NULL
		`
		args := []interface{}{tenantID}
		if scopeID != nil {
			query += " AND scope_id = $2"
			args = append(args, *scopeID)
		}
		query += fmt.Sprintf(" ORDER BY generated_at DESC LIMIT %d", limit)

		rows, err := tx.QueryContext(ctx, query, args...)
		if err != nil {
			return fmt.Errorf("cbom: query list: %w", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			a, scanErr := scanArtifact(rows)
			if scanErr != nil {
				return scanErr
			}
			artifacts = append(artifacts, a)
		}
		return rows.Err()
	})
	return artifacts, err
}

// Get returns one artifact by id within the tenant's scope. The tenant_id
// predicate is the real isolation boundary — RLS is inert because the service
// connects as the table owner, so every by-id query must filter tenant_id
// explicitly.
func (r *Repository) Get(ctx context.Context, tenantID, artifactID uuid.UUID) (*Artifact, error) {
	var out *Artifact
	err := r.withTenantSession(ctx, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT id, tenant_id, scope_id, scope_version, scope_name_snapshot,
			       COALESCE(name, ''), COALESCE(storage_key, ''),
			       (inline_content IS NOT NULL),
			       content_hash, size_bytes, component_count,
			       cyclonedx_spec_version, input_data_freshness_at,
			       generated_at, generated_by,
			       COALESCE(signature_hmac, ''), COALESCE(signature_kid, ''),
			       provenance, layers, created_at
			FROM public.cbom_artifacts
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		`, artifactID, tenantID)
		a, scanErr := scanArtifact(row)
		if errors.Is(scanErr, sql.ErrNoRows) {
			return ErrNotFound
		}
		if scanErr != nil {
			return scanErr
		}
		out = &a
		return nil
	})
	return out, err
}

// GetDiffContent returns the shape a comparison should read for an artifact.
//
// Prefers internal_content, the private CBOMData view written alongside the
// canonical CycloneDX bytes. Falls back to inline_content for artifacts created
// before that column existed — for those rows inline_content IS the old
// internal shape, so the same parse works and old artifacts stay comparable.
//
// Returns ErrNotFound when neither is present, which is the S3-stored,
// pre-column case: the canonical bytes are in the bucket and there is no
// internal view to read.
func (r *Repository) GetDiffContent(ctx context.Context, tenantID, artifactID uuid.UUID) ([]byte, error) {
	var content []byte
	err := r.withTenantSession(ctx, tenantID, func(tx *sql.Tx) error {
		var internal, inline []byte
		err := tx.QueryRowContext(ctx, `
			SELECT internal_content, inline_content
			FROM public.cbom_artifacts
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		`, artifactID, tenantID).Scan(&internal, &inline)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		switch {
		case internal != nil:
			content = internal
		case inline != nil:
			content = inline
		default:
			return ErrNotFound
		}
		return nil
	})
	return content, err
}

// GetInlineContent returns the canonical CycloneDX bytes for an artifact
// stored in inline_content. Returns ErrNotFound if the artifact has no
// inline content (i.e. it's stored in S3 — caller should use storage path).
func (r *Repository) GetInlineContent(ctx context.Context, tenantID, artifactID uuid.UUID) ([]byte, error) {
	var content []byte
	err := r.withTenantSession(ctx, tenantID, func(tx *sql.Tx) error {
		// Scan into a plain []byte, not sql.RawBytes: database/sql's
		// (*Row).Scan rejects *sql.RawBytes outright ("sql: RawBytes isn't
		// allowed on Row.Scan"), which previously made every inline-stored
		// download/verify 500. []byte gets a copy owned by us.
		var raw []byte
		err := tx.QueryRowContext(ctx, `
			SELECT inline_content
			FROM public.cbom_artifacts
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		`, artifactID, tenantID).Scan(&raw)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if raw == nil {
			return ErrNotFound
		}
		content = raw
		return nil
	})
	return content, err
}

// SoftDelete marks an artifact deleted_at = now(). Soft delete only — we
// keep the row so dangling references from comparison runs surface
// meaningfully rather than 404.
func (r *Repository) SoftDelete(ctx context.Context, tenantID, artifactID uuid.UUID) error {
	return r.withTenantSession(ctx, tenantID, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `
			UPDATE public.cbom_artifacts
			SET deleted_at = now()
			WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		`, artifactID, tenantID)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func scanArtifact(r interface{ Scan(...interface{}) error }) (Artifact, error) {
	var (
		a           Artifact
		provBytes   []byte
		layersBytes []byte
	)
	err := r.Scan(
		&a.ID, &a.TenantID, &a.ScopeID, &a.ScopeVersion, &a.ScopeNameSnapshot,
		&a.Name, &a.StorageKey,
		&a.HasInlineContent,
		&a.ContentHash, &a.SizeBytes, &a.ComponentCount,
		&a.CycloneDXSpecVersion, &a.InputDataFreshnessAt,
		&a.GeneratedAt, &a.GeneratedBy,
		&a.SignatureHMAC, &a.SignatureKID,
		&provBytes, &layersBytes, &a.CreatedAt,
	)
	if err != nil {
		return Artifact{}, err
	}
	if len(provBytes) > 0 {
		_ = json.Unmarshal(provBytes, &a.Provenance)
	}
	if len(layersBytes) > 0 {
		_ = json.Unmarshal(layersBytes, &a.Layers)
	}
	if a.Layers == nil {
		a.Layers = []Layer{}
	}
	return a, nil
}

func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
