package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/lib/pq"
)

// A create or rename that collides with another of the caller's integrations
// used to answer 500 "Failed to create integration" — which the Connect modal
// then showed verbatim, so the user had no way to learn the name was the
// problem. It is now 409 with the name, driven through the REAL handlers.

func nameTakenErr() error {
	return mapIntegrationWriteErr(&pq.Error{Code: "23505", Constraint: integrationNameUniqueIndex})
}

// MUTATION-VERIFIED: remove the errIntegrationNameTaken branch from
// CreateIntegration and this returns 500.
func TestContract_CreateIntegration_409_nameTaken(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{createErr: nameTakenErr()})
	w := do(eng, http.MethodPost, base+"/integrations", strings.NewReader(validIntegrationBody))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	var body struct{ Error string }
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Error != `An integration named "prod" already exists` {
		t.Errorf("error = %q", body.Error)
	}
}

// MUTATION-VERIFIED: remove the errIntegrationNameTaken branch from
// UpdateIntegration and this returns 500.
func TestContract_UpdateIntegration_409_nameTaken(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{updFound: true, updType: "aws", updConfig: "{}", updErr: nameTakenErr()})
	w := do(eng, http.MethodPut, base+"/integrations/"+aUUID, strings.NewReader(`{"integration_name":"renamed"}`))
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `renamed`) {
		t.Errorf("409 body does not name the integration: %s", w.Body.String())
	}
}

// Any other write failure is still a 500 — a different unique violation must
// not be reported to the user as a naming clash.
func TestContract_CreateIntegration_500_otherErrorsUnchanged(t *testing.T) {
	for _, err := range []error{
		errors.New("connection reset"),
		&pq.Error{Code: "23505", Constraint: "platform_integrations_pkey"},
	} {
		eng := newIntegrationEngine(&stubIntegrationStore{createErr: mapIntegrationWriteErr(err)})
		w := do(eng, http.MethodPost, base+"/integrations", strings.NewReader(validIntegrationBody))
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%v: status = %d, want 500", err, w.Code)
		}
	}
}

func TestMapIntegrationWriteErr(t *testing.T) {
	wrapped := fmt.Errorf("tx: %w", &pq.Error{Code: "23505", Constraint: integrationNameUniqueIndex})
	if !errors.Is(mapIntegrationWriteErr(wrapped), errIntegrationNameTaken) {
		t.Error("name-index violation not mapped")
	}
	if mapIntegrationWriteErr(nil) != nil {
		t.Error("nil must stay nil")
	}
	if errors.Is(mapIntegrationWriteErr(&pq.Error{Code: "23505", Constraint: "other_index"}), errIntegrationNameTaken) {
		t.Error("an unrelated unique violation was mapped to name-taken")
	}
}
