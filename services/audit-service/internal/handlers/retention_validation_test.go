package handlers

// Server-side validation of retention-policy ages (security-staff-16, admin-ui
// review decision 14). A 0 or negative hot/total age used to be accepted and
// stored; a total of 0 makes every matching log eligible for deletion on the
// next sweep. Both write routes now refuse such a policy with a 400 that names
// the field, before the service is called.
//
// Drives the real handler methods through the same engine the contract tests
// use (newRetentionEngine), with a stub that records whether the service was
// reached, and asserts every 400 body against the spec's LegacyError.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
)

// recordingRetentionService is stubRetentionService that remembers the
// policy each write received.
type recordingRetentionService struct {
	stubRetentionService
	created, updated *services.RetentionPolicy
}

func (s *recordingRetentionService) CreateRetentionPolicy(_ context.Context, p *services.RetentionPolicy) error {
	cp := *p
	s.created = &cp
	return nil
}

func (s *recordingRetentionService) UpdateRetentionPolicy(_ context.Context, p *services.RetentionPolicy) error {
	cp := *p
	s.updated = &cp
	return nil
}

func retentionBodyWith(hot, total string) string {
	return `{"policy_name":"X","hot_storage_days":` + hot + `,"total_retention_days":` + total + `,"is_active":true}`
}

func TestRetentionPolicy_RejectsNonPositiveOrInvertedAges(t *testing.T) {
	sv := loadSpec(t)
	cases := map[string]struct {
		body, field string
	}{
		"zero hot":               {retentionBodyWith("0", "365"), "hot_storage_days"},
		"negative hot":           {retentionBodyWith("-5", "365"), "hot_storage_days must be at least 1"},
		"zero total":             {retentionBodyWith("30", "0"), "total_retention_days must be at least 1"},
		"negative total":         {retentionBodyWith("30", "-1"), "total_retention_days must be at least 1"},
		"both zero":              {retentionBodyWith("0", "0"), "hot_storage_days"},
		"omitted ages":           {`{"policy_name":"X","is_active":true}`, "hot_storage_days"},
		"total shorter than hot": {retentionBodyWith("90", "30"), "cannot be shorter than hot_storage_days"},
	}
	for name, tc := range cases {
		for _, route := range []struct{ method, path string }{
			{http.MethodPost, base + "/retention-policies"},
			{http.MethodPut, base + "/retention-policies/" + aUUID},
		} {
			t.Run(route.method+" "+name, func(t *testing.T) {
				svc := &recordingRetentionService{}
				w := do(newRetentionEngine(svc), route.method, route.path, strings.NewReader(tc.body))
				if w.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
				}
				sv.assertConforms(t, "LegacyError", w.Body.Bytes())
				var got struct{ Error string }
				_ = json.Unmarshal(w.Body.Bytes(), &got)
				if !strings.Contains(got.Error, tc.field) {
					t.Fatalf("error %q should name %q", got.Error, tc.field)
				}
				if svc.created != nil || svc.updated != nil {
					t.Fatal("an invalid policy reached the service")
				}
			})
		}
	}
}

// The boundary is inclusive: a one-day policy, and a total equal to the hot
// period, are valid and reach the service unchanged.
func TestRetentionPolicy_AcceptsBoundaryAges(t *testing.T) {
	for name, body := range map[string]string{
		"one day each":     retentionBodyWith("1", "1"),
		"total equals hot": retentionBodyWith("30", "30"),
		"typical":          retentionBodyWith("30", "365"),
	} {
		t.Run(name, func(t *testing.T) {
			svc := &recordingRetentionService{}
			w := do(newRetentionEngine(svc), http.MethodPost, base+"/retention-policies", strings.NewReader(body))
			if w.Code != http.StatusCreated {
				t.Fatalf("create status = %d, want 201; body=%s", w.Code, w.Body.String())
			}
			if svc.created == nil {
				t.Fatal("a valid policy did not reach the service")
			}
			w = do(newRetentionEngine(svc), http.MethodPut, base+"/retention-policies/"+aUUID, strings.NewReader(body))
			if w.Code != http.StatusOK {
				t.Fatalf("update status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			if svc.updated == nil {
				t.Fatal("a valid update did not reach the service")
			}
		})
	}
}

// An older admin console still sends cold_storage_days. The field is gone;
// the request must still succeed and the response must not echo it.
func TestRetentionPolicy_IgnoresRemovedColdStorageDays(t *testing.T) {
	sv := loadSpec(t)
	body := `{"policy_name":"X","hot_storage_days":30,"cold_storage_days":90,"total_retention_days":365,"is_active":true}`
	w := do(newRetentionEngine(&recordingRetentionService{}), http.MethodPost, base+"/retention-policies", strings.NewReader(body))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RetentionPolicyResponse", w.Body.Bytes())
	if strings.Contains(w.Body.String(), "cold_storage_days") {
		t.Fatalf("response still carries cold_storage_days: %s", w.Body.String())
	}
}
