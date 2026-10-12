package cbom

// DB-integration tests for the hardening changes. Skipped without
// TEST_DATABASE_URL (see shared/testdb).

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/scopes"
	sharedstorage "github.com/vistasecurity/vistaplatform/shared/storage"
)

func TestIntegration_GetDiffContent_RefusesArtifactsWithoutInternalView(t *testing.T) {
	repo, tenant := newIntegrationRepo(t)
	ctx := context.Background()

	create := func(p insertParams) uuid.UUID {
		t.Helper()
		p.TenantID, p.ScopeID, p.ScopeVersion, p.ScopeNameSnapshot = tenant, uuid.New(), 1, "All"
		p.ArtifactKind, p.ContentHash, p.SizeBytes, p.CycloneDXSpecVersion = KindCBOM, "deadbeef", 2, "1.7"
		p.InputDataFreshnessAt, p.GeneratedBy = time.Now().UTC(), uuid.New()
		a, err := repo.Create(ctx, p)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		return a.ID
	}

	withInternal := create(insertParams{
		InlineContent:   []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`),
		InternalContent: []byte(`{"spec_version":"1.7","components":[]}`),
	})
	legacyInline := create(insertParams{InlineContent: []byte(`{"spec_version":"1.5","components":[]}`)})
	legacyS3 := create(insertParams{StorageKey: "cbom/legacy.cdx.json"})
	inlineIsCycloneDX := create(insertParams{InlineContent: []byte(`{"bomFormat":"CycloneDX","specVersion":"1.7"}`)})

	if got, err := repo.GetDiffContent(ctx, tenant, withInternal); err != nil || !bytes.Contains(got, []byte("spec_version")) {
		t.Errorf("artifact with an internal view: got %q, %v", got, err)
	}
	if got, err := repo.GetDiffContent(ctx, tenant, legacyInline); err != nil || !bytes.Contains(got, []byte("1.5")) {
		t.Errorf("legacy inline (old internal shape) must stay comparable: got %q, %v", got, err)
	}
	for name, id := range map[string]uuid.UUID{"object-stored legacy": legacyS3, "inline holding CycloneDX": inlineIsCycloneDX} {
		if _, err := repo.GetDiffContent(ctx, tenant, id); !errors.Is(err, ErrNoInternalView) {
			t.Errorf("%s: err = %v, want ErrNoInternalView", name, err)
		}
	}
	if _, err := repo.GetDiffContent(ctx, tenant, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing artifact: err = %v, want ErrNotFound", err)
	}
}

func TestIntegration_List_PagesWithTotal(t *testing.T) {
	repo, tenant := newIntegrationRepo(t)
	for i := 0; i < 5; i++ {
		insertOfKind(t, repo, tenant, KindCBOM)
	}
	page1, total, err := repo.List(context.Background(), tenant, nil, "", 2, 0)
	if err != nil || total != 5 || len(page1) != 2 {
		t.Fatalf("page 1: len=%d total=%d err=%v, want 2/5", len(page1), total, err)
	}
	page3, total, err := repo.List(context.Background(), tenant, nil, "", 2, 4)
	if err != nil || total != 5 || len(page3) != 1 {
		t.Fatalf("page 3: len=%d total=%d err=%v, want 1/5", len(page3), total, err)
	}
	if page1[0].ID == page3[0].ID || page1[1].ID == page3[0].ID {
		t.Errorf("pages overlap")
	}
}

// memStorage is an in-memory ArtifactStorageService for the orphan tests.
type memStorage struct {
	sharedstorage.ArtifactStorageService
	mu      sync.Mutex
	objects map[string]bool
	deleted []string
	// forceKey, when set, is the key every upload resolves to, modelling two
	// artifacts whose identical bytes share one content-addressed object.
	forceKey string
}

func newMemStorage() *memStorage { return &memStorage{objects: map[string]bool{}} }

func (m *memStorage) IsEnabled(sharedstorage.ArtifactType) bool { return true }
func (m *memStorage) Upload(_ context.Context, _ sharedstorage.ArtifactType, _ *uuid.UUID, filename string, r io.Reader, _ string, _ int64) (*sharedstorage.UploadResult, error) {
	_, _ = io.Copy(io.Discard, r)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.forceKey != "" {
		filename = m.forceKey
	}
	m.objects[filename] = true
	return &sharedstorage.UploadResult{Key: filename}, nil
}
func (m *memStorage) Delete(_ context.Context, _ sharedstorage.ArtifactType, key string, _ *uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.objects, key)
	m.deleted = append(m.deleted, key)
	return nil
}

func persistInput(tenant uuid.UUID, kind ArtifactKind) PersistInput {
	return PersistInput{
		Scope: &scopes.Scope{ID: uuid.New(), TenantID: tenant, Name: "All", Version: 1},
		Build: &BuildOutput{
			CanonicalBytes: []byte(`{"bomFormat":"CycloneDX"}`), InternalBytes: []byte(`{}`),
			ContentHash: "0123456789abcdef0123456789abcdef", CycloneDXSpecVersion: "1.7", Kind: kind,
		},
		GeneratedBy:          uuid.New(),
		InputDataFreshnessAt: time.Now().UTC(),
	}
}

// A failed row insert after a successful upload must not leave the object.
// An invalid kind makes Create fail after the upload has happened.
func TestIntegration_Persist_FailedCreateRemovesUploadedObject(t *testing.T) {
	repo, tenant := newIntegrationRepo(t)
	st := newMemStorage()
	p := NewPersister(repo, st)

	_, err := p.Persist(context.Background(), persistInput(tenant, ArtifactKind("bogus")))
	if err == nil {
		t.Fatal("Persist succeeded; the invalid kind should have failed the insert")
	}
	if len(st.objects) != 0 || len(st.deleted) != 1 {
		t.Errorf("orphan left behind: objects=%v deleted=%v", st.objects, st.deleted)
	}
}

// Keys are content-addressed, so the object may belong to another artifact.
func TestIntegration_Persist_FailedCreateKeepsObjectAnotherArtifactUses(t *testing.T) {
	repo, tenant := newIntegrationRepo(t)
	st := newMemStorage()
	p := NewPersister(repo, st)

	in := persistInput(tenant, KindCBOM)
	first, err := p.Persist(context.Background(), in)
	if err != nil {
		t.Fatalf("first persist: %v", err)
	}
	if first.StorageKey == "" {
		t.Fatal("expected an object-stored artifact")
	}

	st.forceKey = first.StorageKey // the failing create uploads to the SAME key
	bad := persistInput(tenant, ArtifactKind("bogus"))
	if _, err := p.Persist(context.Background(), bad); err == nil {
		t.Fatal("second persist should fail")
	}
	if !st.objects[first.StorageKey] || len(st.deleted) != 0 {
		t.Errorf("object belonging to a live artifact was deleted: objects=%v deleted=%v", st.objects, st.deleted)
	}
}

// Requested signing with no signer is refused BEFORE anything is written.
func TestIntegration_Persist_SignWithoutSignerWritesNothing(t *testing.T) {
	repo, tenant := newIntegrationRepo(t)
	st := newMemStorage()
	p := NewPersister(repo, st)

	in := persistInput(tenant, KindCBOM)
	in.Sign = true
	if _, err := p.Persist(context.Background(), in); !errors.Is(err, ErrSignerUnavailable) {
		t.Fatalf("err = %v, want ErrSignerUnavailable", err)
	}
	if len(st.objects) != 0 {
		t.Errorf("object uploaded for a refused request: %v", st.objects)
	}
	if _, total, _ := repo.List(context.Background(), tenant, nil, "", 10, 0); total != 0 {
		t.Errorf("row written for a refused request: total=%d", total)
	}
}
