package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

type implementationKeyRow struct {
	ImplementationID  uuid.UUID      `db:"implementation_id"`
	ID                uuid.UUID      `db:"id"`
	TenantID          uuid.UUID      `db:"tenant_id"`
	KeyType           string         `db:"key_type"`
	KeyUsage          pq.StringArray `db:"key_usage"`
	PublicFingerprint *string        `db:"public_fingerprint"`
	JWKThumbprint     *string        `db:"jwk_thumbprint"`
	SizeBits          *int           `db:"size_bits"`
	Curve             *string        `db:"curve"`
	MaterialType      *string        `db:"material_type"`
	State             *string        `db:"state"`
	StateReason       *string        `db:"state_reason"`
	Format            *string        `db:"format"`
	SecuredBy         *string        `db:"secured_by_mechanism"`
	AlgorithmRef      *uuid.UUID     `db:"algorithm_id"`
	CreatedAt         sql.NullTime   `db:"created_at"`
	ActivationDate    sql.NullTime   `db:"activation_date"`
	RotatedAt         sql.NullTime   `db:"rotated_at"`
	DeactivationDate  sql.NullTime   `db:"deactivation_date"`
	ExpiresAt         sql.NullTime   `db:"expires_at"`
	DestructionDate   sql.NullTime   `db:"destruction_date"`
	Provenance        *string        `db:"provenance"`
	Metadata          []byte         `db:"metadata"`
}

type implementationLibraryRow struct {
	ImplementationID     uuid.UUID      `db:"implementation_id"`
	ID                   uuid.UUID      `db:"id"`
	TenantID             uuid.UUID      `db:"tenant_id"`
	Name                 string         `db:"name"`
	Version              string         `db:"version"`
	Vendor               *string        `db:"vendor"`
	CPE                  *string        `db:"cpe"`
	PURL                 *string        `db:"purl"`
	CertificationLevel   pq.StringArray `db:"certification_level"`
	BuildMetadata        []byte         `db:"build_metadata"`
	KnownVulnerabilities []byte         `db:"known_vulnerabilities"`
	CreatedAt            sql.NullTime   `db:"created_at"`
	UpdatedAt            sql.NullTime   `db:"updated_at"`
}

func enrichCryptoImplementationsWithRelations(db *database.DB, tenantID uuid.UUID, implementations []models.CryptoImplementation) error {
	if len(implementations) == 0 {
		return nil
	}

	implementationIDs := make([]uuid.UUID, 0, len(implementations))
	for _, implementation := range implementations {
		implementationIDs = append(implementationIDs, implementation.ID)
	}

	keysByImplementation, err := loadImplementationKeys(db, tenantID, implementationIDs)
	if err != nil {
		return err
	}

	librariesByImplementation, err := loadImplementationLibraries(db, tenantID, implementationIDs)
	if err != nil {
		return err
	}

	assignImplementationRelations(implementations, keysByImplementation, librariesByImplementation)
	return nil
}

func assignImplementationRelations(
	implementations []models.CryptoImplementation,
	keysByImplementation map[uuid.UUID][]models.Key,
	librariesByImplementation map[uuid.UUID][]models.CryptoLibrary,
) {
	for index := range implementations {
		implementation := &implementations[index]
		implementation.Keys = append([]models.Key(nil), keysByImplementation[implementation.ID]...)
		implementation.Libraries = append([]models.CryptoLibrary(nil), librariesByImplementation[implementation.ID]...)
	}
}

func loadImplementationKeys(db *database.DB, tenantID uuid.UUID, implementationIDs []uuid.UUID) (map[uuid.UUID][]models.Key, error) {
	if len(implementationIDs) == 0 {
		return map[uuid.UUID][]models.Key{}, nil
	}

	query, args, err := sqlx.In(`
		SELECT
			ik.implementation_id,
			k.id, k.tenant_id, k.key_type, k.key_usage, k.public_fingerprint,
			k.jwk_thumbprint, k.size_bits, k.curve, k.material_type, k.state,
			k.state_reason, k.format, k.secured_by_mechanism, k.algorithm_id,
			k.created_at, k.activation_date, k.rotated_at, k.deactivation_date,
			k.expires_at, k.destruction_date, k.provenance, k.metadata
		FROM implementation_keys ik
		INNER JOIN keys k ON k.id = ik.key_id
		WHERE ik.implementation_id IN (?) AND k.tenant_id = ?
		ORDER BY ik.implementation_id, k.created_at NULLS LAST, k.id
	`, implementationIDs, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to build implementation key query: %w", err)
	}

	query = db.Rebind(query)

	// RLS-scoped read over keys (JOIN implementation_keys).
	var rows []implementationKeyRow
	if err := database.WithTenantTx(context.Background(), db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&rows, query, args...)
	}); err != nil {
		return nil, fmt.Errorf("failed to load implementation keys: %w", err)
	}

	keysByImplementation := make(map[uuid.UUID][]models.Key, len(implementationIDs))
	for _, row := range rows {
		keysByImplementation[row.ImplementationID] = append(keysByImplementation[row.ImplementationID], row.toKey())
	}

	return keysByImplementation, nil
}

func loadImplementationLibraries(db *database.DB, tenantID uuid.UUID, implementationIDs []uuid.UUID) (map[uuid.UUID][]models.CryptoLibrary, error) {
	if len(implementationIDs) == 0 {
		return map[uuid.UUID][]models.CryptoLibrary{}, nil
	}

	query, args, err := sqlx.In(`
		SELECT
			il.implementation_id,
			cl.id, cl.tenant_id, cl.name, cl.version, cl.vendor, cl.cpe, cl.purl,
			cl.certification_level, cl.build_metadata, cl.known_vulnerabilities,
			cl.created_at, cl.updated_at
		FROM implementation_libraries il
		INNER JOIN crypto_libraries cl ON cl.id = il.library_id
		WHERE il.implementation_id IN (?) AND cl.tenant_id = ?
		ORDER BY il.implementation_id, cl.name, cl.version, cl.id
	`, implementationIDs, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to build implementation library query: %w", err)
	}

	query = db.Rebind(query)

	// RLS-scoped read over crypto_libraries (JOIN implementation_libraries).
	var rows []implementationLibraryRow
	if err := database.WithTenantTx(context.Background(), db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&rows, query, args...)
	}); err != nil {
		return nil, fmt.Errorf("failed to load implementation libraries: %w", err)
	}

	librariesByImplementation := make(map[uuid.UUID][]models.CryptoLibrary, len(implementationIDs))
	for _, row := range rows {
		librariesByImplementation[row.ImplementationID] = append(librariesByImplementation[row.ImplementationID], row.toLibrary())
	}

	return librariesByImplementation, nil
}

func (row implementationKeyRow) toKey() models.Key {
	key := models.Key{
		ID:                row.ID,
		TenantID:          row.TenantID,
		KeyType:           row.KeyType,
		KeyUsage:          []string(row.KeyUsage),
		PublicFingerprint: row.PublicFingerprint,
		JWKThumbprint:     row.JWKThumbprint,
		SizeBits:          row.SizeBits,
		Curve:             row.Curve,
		Provenance:        row.Provenance,
		State: func() string {
			if row.State != nil {
				return *row.State
			}
			return ""
		}(),
		StateReason: row.StateReason,
		Format:      row.Format,
		SecuredBy:   row.SecuredBy,
		Metadata:    map[string]interface{}{},
	}

	if row.MaterialType != nil {
		key.MaterialType = *row.MaterialType
	}

	if row.AlgorithmRef != nil {
		ref := row.AlgorithmRef.String()
		key.AlgorithmRef = &ref
	}

	if row.CreatedAt.Valid {
		key.CreatedAt = &row.CreatedAt.Time
	}
	if row.ActivationDate.Valid {
		key.ActivationDate = &row.ActivationDate.Time
	}
	if row.RotatedAt.Valid {
		key.RotatedAt = &row.RotatedAt.Time
	}
	if row.DeactivationDate.Valid {
		key.DeactivationDate = &row.DeactivationDate.Time
	}
	if row.ExpiresAt.Valid {
		key.ExpiresAt = &row.ExpiresAt.Time
	}
	if row.DestructionDate.Valid {
		key.DestructionDate = &row.DestructionDate.Time
	}
	if len(row.Metadata) > 0 {
		_ = json.Unmarshal(row.Metadata, &key.Metadata)
	}

	return key
}

func (row implementationLibraryRow) toLibrary() models.CryptoLibrary {
	library := models.CryptoLibrary{
		ID:                   row.ID,
		TenantID:             row.TenantID,
		Name:                 row.Name,
		Version:              row.Version,
		Vendor:               row.Vendor,
		CPE:                  row.CPE,
		PURL:                 row.PURL,
		CertificationLevel:   []string(row.CertificationLevel),
		BuildMetadata:        map[string]interface{}{},
		KnownVulnerabilities: []map[string]interface{}{},
	}

	if row.CreatedAt.Valid {
		library.CreatedAt = row.CreatedAt.Time
	}
	if row.UpdatedAt.Valid {
		library.UpdatedAt = row.UpdatedAt.Time
	}
	if len(row.BuildMetadata) > 0 {
		_ = json.Unmarshal(row.BuildMetadata, &library.BuildMetadata)
	}
	if len(row.KnownVulnerabilities) > 0 {
		_ = json.Unmarshal(row.KnownVulnerabilities, &library.KnownVulnerabilities)
	}

	return library
}
