package services

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func TestAssignImplementationRelations(t *testing.T) {
	implementationOne := uuid.New()
	implementationTwo := uuid.New()

	implementations := []models.CryptoImplementation{
		{ID: implementationOne},
		{ID: implementationTwo},
	}

	key := models.Key{ID: uuid.New(), KeyType: "rsa"}
	library := models.CryptoLibrary{ID: uuid.New(), Name: "OpenSSL", Version: "3.2.0"}

	assignImplementationRelations(
		implementations,
		map[uuid.UUID][]models.Key{
			implementationOne: {key},
		},
		map[uuid.UUID][]models.CryptoLibrary{
			implementationTwo: {library},
		},
	)

	require.Len(t, implementations[0].Keys, 1)
	assert.Equal(t, key.ID, implementations[0].Keys[0].ID)
	assert.Empty(t, implementations[0].Libraries)

	require.Len(t, implementations[1].Libraries, 1)
	assert.Equal(t, library.ID, implementations[1].Libraries[0].ID)
	assert.Empty(t, implementations[1].Keys)
}

func TestImplementationKeyRowToKey(t *testing.T) {
	createdAt := time.Date(2026, time.March, 1, 12, 0, 0, 0, time.UTC)
	expiresAt := createdAt.Add(24 * time.Hour)

	row := implementationKeyRow{
		ID:        uuid.New(),
		TenantID:  uuid.New(),
		KeyType:   "rsa",
		KeyUsage:  pq.StringArray{"tls_server", "code_signing"},
		SizeBits:  intPtr(3072),
		CreatedAt: sql.NullTime{Time: createdAt, Valid: true},
		ExpiresAt: sql.NullTime{Time: expiresAt, Valid: true},
		Metadata:  []byte(`{"source":"sensor","rotation":"quarterly"}`),
	}

	key := row.toKey()

	assert.Equal(t, "rsa", key.KeyType)
	assert.Equal(t, []string{"tls_server", "code_signing"}, key.KeyUsage)
	require.NotNil(t, key.CreatedAt)
	assert.Equal(t, createdAt, *key.CreatedAt)
	require.NotNil(t, key.ExpiresAt)
	assert.Equal(t, expiresAt, *key.ExpiresAt)
	assert.Equal(t, "sensor", key.Metadata["source"])
	assert.Equal(t, "quarterly", key.Metadata["rotation"])
}

func TestImplementationLibraryRowToLibrary(t *testing.T) {
	createdAt := time.Date(2026, time.March, 2, 8, 30, 0, 0, time.UTC)
	updatedAt := createdAt.Add(2 * time.Hour)

	row := implementationLibraryRow{
		ID:                   uuid.New(),
		TenantID:             uuid.New(),
		Name:                 "BoringSSL",
		Version:              "1.9.4",
		BuildMetadata:        []byte(`{"compiler":"clang","fips":true}`),
		KnownVulnerabilities: []byte(`[{"id":"CVE-2026-1234"}]`),
		CreatedAt:            sql.NullTime{Time: createdAt, Valid: true},
		UpdatedAt:            sql.NullTime{Time: updatedAt, Valid: true},
	}

	library := row.toLibrary()

	assert.Equal(t, "BoringSSL", library.Name)
	assert.Equal(t, "1.9.4", library.Version)
	assert.Equal(t, "clang", library.BuildMetadata["compiler"])
	assert.Equal(t, true, library.BuildMetadata["fips"])
	require.Len(t, library.KnownVulnerabilities, 1)
	assert.Equal(t, "CVE-2026-1234", library.KnownVulnerabilities[0]["id"])
	assert.Equal(t, createdAt, library.CreatedAt)
	assert.Equal(t, updatedAt, library.UpdatedAt)
}
