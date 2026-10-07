package handlers

// POST /evaluate/multiple took `framework_ids` as an unbounded array: ~2.7
// million UUIDs fit inside the edge's 100 MiB body cap, and each one — even one
// that names no framework — cost the service two database round-trips. These
// tests drive the handler through the same route shape the service mounts and
// pin the three limits: the body ceiling, the per-request framework cap and the
// de-duplication of repeats.

import (
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
)

// recordingEvaluationStore is a stubEvaluationStore that remembers what
// EvaluateMultipleFrameworks was asked for.
type recordingEvaluationStore struct {
	stubEvaluationStore
	calls atomic.Int32
	asked []uuid.UUID
}

func (s *recordingEvaluationStore) EvaluateMultipleFrameworks(_ uuid.UUID, ids []uuid.UUID, _ map[string]string, _ models.ScenarioFilters, _ string) ([]services.MultiFrameworkEvaluationResult, error) {
	s.calls.Add(1)
	s.asked = append([]uuid.UUID(nil), ids...)
	return nil, nil
}

func idsJSON(n int) string {
	ids := make([]string, n)
	for i := range ids {
		ids[i] = `"` + uuid.NewString() + `"`
	}
	return `{"framework_ids":[` + strings.Join(ids, ",") + `]}`
}

func TestEvaluateMultiple_RefusesMoreFrameworksThanTheCap(t *testing.T) {
	store := &recordingEvaluationStore{}
	eng := newEvalEngine(store, &stubFrameworkContextStore{})

	w := do(eng, http.MethodPost, evalBase+"/evaluate/multiple", strings.NewReader(idsJSON(maxEvaluateFrameworks+1)))

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if store.calls.Load() != 0 {
		t.Fatal("the evaluation service was called for a request over the framework cap")
	}
}

func TestEvaluateMultiple_AcceptsExactlyTheCap(t *testing.T) {
	store := &recordingEvaluationStore{}
	eng := newEvalEngine(store, &stubFrameworkContextStore{})

	w := do(eng, http.MethodPost, evalBase+"/evaluate/multiple", strings.NewReader(idsJSON(maxEvaluateFrameworks)))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(store.asked) != maxEvaluateFrameworks {
		t.Fatalf("service asked for %d frameworks, want %d", len(store.asked), maxEvaluateFrameworks)
	}
}

func TestEvaluateMultiple_RefusesAnOversizeBody(t *testing.T) {
	store := &recordingEvaluationStore{}
	eng := newEvalEngine(store, &stubFrameworkContextStore{})

	// A valid-looking document that is mostly padding inside a version map: it
	// stays under the framework cap, so only the body ceiling can stop it.
	pad := strings.Repeat("a", maxEvaluateBodyBytes+1024)
	body := `{"framework_ids":["` + aUUID + `"],"framework_versions":{"x":"` + pad + `"}}`
	w := do(eng, http.MethodPost, evalBase+"/evaluate/multiple", strings.NewReader(body))

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413; body=%s", w.Code, w.Body.String())
	}
	if store.calls.Load() != 0 {
		t.Fatal("the evaluation service was called for an oversize body")
	}
}

func TestEvaluateMultiple_DropsRepeatedFrameworkIDs(t *testing.T) {
	store := &recordingEvaluationStore{}
	eng := newEvalEngine(store, &stubFrameworkContextStore{})

	other := uuid.NewString()
	body := `{"framework_ids":["` + aUUID + `","` + other + `","` + aUUID + `","` + strings.ToUpper(aUUID) + `"]}`
	w := do(eng, http.MethodPost, evalBase+"/evaluate/multiple", strings.NewReader(body))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	if len(store.asked) != 2 || store.asked[0].String() != aUUID || store.asked[1].String() != other {
		t.Fatalf("service asked for %v, want [%s %s] in request order", store.asked, aUUID, other)
	}
}
