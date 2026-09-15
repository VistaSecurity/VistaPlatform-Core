package cbom

// Database-integration tests for `cbom_artifacts.artifact_kind`.
//
// The column is the whole point of workstream 3.7 and nothing above this file
// touches a real one. Three things are only observable against Postgres: that
// the column EXISTS on a database the schema was applied to (a column added to
// a `CREATE TABLE IF NOT EXISTS` body never reaches an existing database — the
// two-copy rule); that the CHECK constraint actually refuses a kind outside the
// vocabulary; and that the default makes a row written without one a `cbom`,
// which is the compatibility promise for every artifact already stored.
//
// They skip unless TEST_DATABASE_URL is set (see shared/testdb).

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newIntegrationRepo(t *testing.T) (*Repository, uuid.UUID) {
	t.Helper()
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	return NewRepository(&database.DB{DB: sqlx.NewDb(owner, "postgres")}), tenant
}

func insertOfKind(t *testing.T, repo *Repository, tenant uuid.UUID, kind ArtifactKind) *Artifact {
	t.Helper()
	a, err := repo.Create(context.Background(), insertParams{
		TenantID:             tenant,
		ScopeID:              uuid.New(),
		ScopeVersion:         1,
		ScopeNameSnapshot:    "All",
		ArtifactKind:         kind,
		InlineContent:        []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7","components":[]}`),
		ContentHash:          "deadbeef",
		SizeBytes:            10,
		ComponentCount:       0,
		CycloneDXSpecVersion: "1.7",
		InputDataFreshnessAt: time.Now().UTC(),
		GeneratedBy:          uuid.New(),
	})
	if err != nil {
		t.Fatalf("Create(%s): %v", kind, err)
	}
	return a
}

// TestIntegration_ArtifactKind_RoundTripsForEveryKind. Writing and reading back
// each kind proves the column is there, the CHECK accepts the whole vocabulary,
// and Get/List return what Create wrote.
func TestIntegration_ArtifactKind_RoundTripsForEveryKind(t *testing.T) {
	repo, tenant := newIntegrationRepo(t)
	ctx := context.Background()

	for _, kind := range AllArtifactKinds {
		t.Run(string(kind), func(t *testing.T) {
			created := insertOfKind(t, repo, tenant, kind)
			if created.ArtifactKind != kind {
				t.Errorf("Create returned kind %q, want %q", created.ArtifactKind, kind)
			}
			got, err := repo.Get(ctx, tenant, created.ID)
			if err != nil {
				t.Fatalf("Get: %v", err)
			}
			if got.ArtifactKind != kind {
				t.Errorf("Get returned kind %q, want %q", got.ArtifactKind, kind)
			}
		})
	}
}

// TestIntegration_ArtifactKind_ListFilters. An absent filter returns every
// kind — defaulting it to `cbom` would hide an SBOM behind a filter nobody set.
func TestIntegration_ArtifactKind_ListFilters(t *testing.T) {
	repo, tenant := newIntegrationRepo(t)
	ctx := context.Background()

	for _, kind := range AllArtifactKinds {
		insertOfKind(t, repo, tenant, kind)
	}

	all, err := repo.List(ctx, tenant, nil, "", 50)
	if err != nil {
		t.Fatalf("List(all): %v", err)
	}
	if len(all) != len(AllArtifactKinds) {
		t.Errorf("unfiltered list returned %d, want %d — an absent filter must mean every kind", len(all), len(AllArtifactKinds))
	}

	for _, kind := range AllArtifactKinds {
		got, err := repo.List(ctx, tenant, nil, kind, 50)
		if err != nil {
			t.Fatalf("List(%s): %v", kind, err)
		}
		if len(got) != 1 {
			t.Fatalf("List(%s) returned %d, want 1", kind, len(got))
		}
		if got[0].ArtifactKind != kind {
			t.Errorf("List(%s) returned a %s", kind, got[0].ArtifactKind)
		}
	}
}

// TestIntegration_ArtifactKind_CheckConstraintRefusesUnknown.
//
// The repository refuses an unknown kind before the database sees it, so this
// goes around it and INSERTs directly — the CHECK is the backstop, and a
// backstop nobody exercises is one of the inert guards CLAUDE.md warns about.
// Without it a future writer bypassing Create could store `xbom` and every
// reader would have to handle a kind that does not exist.
func TestIntegration_ArtifactKind_CheckConstraintRefusesUnknown(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)

	_, err := owner.Exec(`
		INSERT INTO public.cbom_artifacts
			(tenant_id, scope_id, scope_version, scope_name_snapshot, artifact_kind,
			 inline_content, content_hash, size_bytes, component_count,
			 cyclonedx_spec_version, input_data_freshness_at, generated_by)
		VALUES ($1, $2, 1, 'All', 'xbom', '{}', 'deadbeef', 2, 0, '1.7', now(), $3)
	`, tenant, uuid.New(), uuid.New())
	if err == nil {
		t.Fatal("the database accepted artifact_kind = 'xbom'; the CHECK constraint is not enforcing the vocabulary")
	}
}

// TestIntegration_ArtifactKind_DefaultsToCBOM is the compatibility promise: a
// row written without a kind — which is every artifact stored before this
// column existed — is a `cbom`, not an empty string.
func TestIntegration_ArtifactKind_DefaultsToCBOM(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	repo := NewRepository(&database.DB{DB: sqlx.NewDb(owner, "postgres")})

	id := uuid.New()
	if _, err := owner.Exec(`
		INSERT INTO public.cbom_artifacts
			(id, tenant_id, scope_id, scope_version, scope_name_snapshot,
			 inline_content, content_hash, size_bytes, component_count,
			 cyclonedx_spec_version, input_data_freshness_at, generated_by)
		VALUES ($1, $2, $3, 1, 'All', '{}', 'deadbeef', 2, 0, '1.7', now(), $4)
	`, id, tenant, uuid.New(), uuid.New()); err != nil {
		t.Fatalf("insert without a kind: %v", err)
	}

	got, err := repo.Get(context.Background(), tenant, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ArtifactKind != KindCBOM {
		t.Errorf("a row written with no kind reads back as %q, want %q", got.ArtifactKind, KindCBOM)
	}
}

// TestIntegration_ArtifactKind_RepositoryRefusesUnknownBeforeTheDatabase.
//
// The CHECK would catch it anyway, but as an opaque 23505/23514 with the caller
// long gone from the stack. Failing in Go names the value.
func TestIntegration_ArtifactKind_RepositoryRefusesUnknownBeforeTheDatabase(t *testing.T) {
	repo, tenant := newIntegrationRepo(t)
	_, err := repo.Create(context.Background(), insertParams{
		TenantID:             tenant,
		ScopeID:              uuid.New(),
		ScopeVersion:         1,
		ScopeNameSnapshot:    "All",
		ArtifactKind:         "xbom",
		InlineContent:        []byte(`{}`),
		ContentHash:          "deadbeef",
		CycloneDXSpecVersion: "1.7",
		InputDataFreshnessAt: time.Now().UTC(),
		GeneratedBy:          uuid.New(),
	})
	if err == nil {
		t.Fatal("Create accepted an unknown artifact_kind")
	}
}
