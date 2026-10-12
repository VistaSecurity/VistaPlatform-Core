package scopes

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lib/pq"
)

// A duplicate (tenant_id, name) is the caller's mistake, not a server fault.
func TestCreateAndUpdate_DuplicateNameIs409(t *testing.T) {
	dup := &pq.Error{Code: "23505", Message: `duplicate key value violates unique constraint "scopes_unique_name_per_tenant"`}
	store := &stubStore{createErr: dup, updateErr: dup}
	eng := newEngine(store)

	w := do(eng, http.MethodPost, "/api/v1/cbom-service/scopes", strings.NewReader(`{"name":"Prod","query":""}`))
	if w.Code != http.StatusConflict {
		t.Fatalf("create status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "already exists") || strings.Contains(w.Body.String(), "scopes_unique_name_per_tenant") {
		t.Errorf("409 should be a clear message without constraint internals: %s", w.Body.String())
	}

	w = do(eng, http.MethodPut, "/api/v1/cbom-service/scopes/"+aUUID, strings.NewReader(`{"name":"Prod","query":""}`))
	if w.Code != http.StatusConflict {
		t.Fatalf("update status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
}

func TestCreate_OtherStoreErrorStays500(t *testing.T) {
	eng := newEngine(&stubStore{createErr: errors.New("connection reset")})
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/scopes", strings.NewReader(`{"name":"Prod","query":""}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestCreateAndUpdate_OversizedTextIs400(t *testing.T) {
	eng := newEngine(&stubStore{updateResult: &Scope{}})
	cases := map[string]string{
		"description": `{"name":"Prod","description":"` + strings.Repeat("d", MaxDescriptionBytes+1) + `","query":""}`,
		"query":       `{"name":"Prod","query":"` + strings.Repeat("a", MaxQueryBytes+1) + `"}`,
	}
	for field, body := range cases {
		if w := do(eng, http.MethodPost, "/api/v1/cbom-service/scopes", strings.NewReader(body)); w.Code != http.StatusBadRequest {
			t.Errorf("create oversized %s: status = %d, want 400", field, w.Code)
		}
		if w := do(eng, http.MethodPut, "/api/v1/cbom-service/scopes/"+aUUID, strings.NewReader(body)); w.Code != http.StatusBadRequest {
			t.Errorf("update oversized %s: status = %d, want 400", field, w.Code)
		}
	}
}

// capturingCounter records the token the preview forwarded.
type capturingCounter struct{ token string }

func (c *capturingCounter) CountAssets(_ context.Context, token, _, _ string) (int64, error) {
	c.token = token
	return 7, nil
}

// Browser sessions authenticate by cookie; preview must forward it the way
// artifact generation does, instead of reporting "unavailable".
func TestPreview_ForwardsBearerOrCookieToken(t *testing.T) {
	sc := sampleScope()
	for name, tc := range map[string]struct {
		header, cookie, want string
	}{
		"bearer header": {header: "Bearer hdr-token", want: "hdr-token"},
		"cookie":        {cookie: "cookie-token", want: "cookie-token"},
		"header wins":   {header: "Bearer hdr-token", cookie: "cookie-token", want: "hdr-token"},
	} {
		t.Run(name, func(t *testing.T) {
			counter := &capturingCounter{}
			eng := newEngineWithCounter(&stubStore{getResult: &sc}, counter)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/cbom-service/scopes/"+aUUID+"/preview", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "access_token", Value: tc.cookie})
			}
			w := httptest.NewRecorder()
			eng.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
			}
			if counter.token != tc.want {
				t.Errorf("forwarded token = %q, want %q", counter.token, tc.want)
			}
		})
	}
}

// The handler test above cannot tell the length check from the query
// validator, which also rejects a 16 KB run of "a". Pin the limit itself.
func TestValidateRequestText_Limits(t *testing.T) {
	if err := ValidateRequestText("n", "", strings.Repeat("a", MaxQueryBytes)); err != nil {
		t.Errorf("a query at the limit must pass: %v", err)
	}
	if err := ValidateRequestText("n", "", strings.Repeat("a", MaxQueryBytes+1)); err == nil {
		t.Error("a query over the limit must be refused")
	}
	if err := ValidateRequestText("n", strings.Repeat("d", MaxDescriptionBytes), ""); err != nil {
		t.Errorf("a description at the limit must pass: %v", err)
	}
	if err := ValidateRequestText("n", strings.Repeat("d", MaxDescriptionBytes+1), ""); err == nil {
		t.Error("a description over the limit must be refused")
	}
}
