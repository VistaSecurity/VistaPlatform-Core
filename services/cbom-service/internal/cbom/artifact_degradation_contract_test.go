package cbom

// Contract coverage for the three HTTP-surface fixes in WP-C: refusing a scope
// the generator cannot evaluate (422), reporting storage/attestation
// degradations to the caller, and honouring ?limit=.
//
// Shares the harness in artifact_contract_test.go (newEngine, do, loadSpec).

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// TestContract_GenerateCBOMArtifact_422OnUnsupportedPredicate covers the refusal
// path added with the scope-evaluation fix. A predicate the generator cannot
// evaluate must not produce an artifact: the row would be dated, hashed and
// possibly signed while covering more than the scope it names.
func TestContract_GenerateCBOMArtifact_422OnUnsupportedPredicate(t *testing.T) {
	sv := loadSpec(t)
	scope := sampleScope()
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{},
		scopes:    &stubScopeGetter{result: scope},
		builder:   &stubBuilder{err: &UnsupportedPredicateError{Fields: []string{"ip_subnet_cidr"}}},
		persister: &stubPersister{},
		features:  &stubFeatureChecker{allowed: false},
	})
	body := strings.NewReader(`{"scope_id":"` + scope.ID.String() + `"}`)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate", body)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "UnsupportedPredicateError", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), "ip_subnet_cidr") {
		t.Errorf("response should name the offending field: %s", w.Body.String())
	}
}

// TestContract_GenerateCBOMArtifact_ReportsDegradations pins CBOM-5(d): a
// storage fallback or a failed attestation used to be a server log line only,
// leaving the caller unable to tell a degraded artifact from a clean one.
func TestContract_GenerateCBOMArtifact_ReportsDegradations(t *testing.T) {
	sv := loadSpec(t)
	scope := sampleScope()
	persisted := sampleArtifact()
	persisted.StorageDegraded = "object-store upload failed, artifact stored inline: connection refused"
	persisted.AttestationError = "findings query timed out"
	eng := newEngine(handlerDeps{
		artifacts: &stubArtifactStore{},
		scopes:    &stubScopeGetter{result: scope},
		builder:   &stubBuilder{out: &BuildOutput{CanonicalBytes: []byte("{}"), ContentHash: "deadbeef"}},
		persister: &stubPersister{out: &persisted},
		features:  &stubFeatureChecker{allowed: true},
	})
	body := strings.NewReader(`{"scope_id":"` + scope.ID.String() + `"}`)
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/generate", body)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "GenerateCBOMResponse", w.Body.Bytes())

	var resp GenerateResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.StorageDegraded == "" {
		t.Error("storage fallback was not reported to the caller")
	}
	if resp.AttestationError == "" {
		t.Error("attestation failure was not reported to the caller")
	}
}

// TestListCBOMArtifacts_HonorsLimit pins CBOM-5(a): ?limit= was documented in
// the OpenAPI spec and hardcoded to 50 in the handler.
func TestListCBOMArtifacts_HonorsLimit(t *testing.T) {
	store := &limitCapturingStore{}
	eng := newEngine(handlerDeps{artifacts: store})

	cases := []struct {
		query string
		want  int
		code  int
	}{
		{"", defaultArtifactLimit, http.StatusOK},
		{"?limit=5", 5, http.StatusOK},
		{"?limit=1000", maxArtifactLimit, http.StatusOK},
		{"?limit=0", 0, http.StatusBadRequest},
		{"?limit=abc", 0, http.StatusBadRequest},
	}
	for _, c := range cases {
		store.limit = -1
		w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/artifacts"+c.query, nil)
		if w.Code != c.code {
			t.Fatalf("%q: status = %d, want %d; body=%s", c.query, w.Code, c.code, w.Body.String())
		}
		if c.code != http.StatusOK {
			continue
		}
		if store.limit != c.want {
			t.Errorf("%q: repository received limit %d, want %d", c.query, store.limit, c.want)
		}
	}
}

type limitCapturingStore struct {
	stubArtifactStore
	limit int
}

func (s *limitCapturingStore) List(_ context.Context, _ uuid.UUID, _ *uuid.UUID, limit int) ([]Artifact, error) {
	s.limit = limit
	return nil, nil
}
