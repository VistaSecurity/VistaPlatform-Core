package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// A network segment too broad to be anybody's network is refused at save, with
// a message the person at the form can act on (owner decision on,
// W5.13), through the REAL handler and the REAL service over a real database —
// and a segment at the boundary still saves. Both polarities, both write
// routes.
//
// Mutation checks: drop the ErrSegmentTooBroad branch in either handler (the
// refusal becomes a 500 with a generic body); drop validateSegmentBreadth from
// Create or Update (the /0 is stored).
func TestIntegration_NetworkSegmentSave_RefusesTooBroadCIDR(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	segSvc := services.NewNetworkSegmentService(db, services.NewLocationService(db))

	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Next() })
	h := NewNetworkSegmentHandler(segSvc)
	grp.POST("/network-segments", h.CreateNetworkSegment)
	grp.PUT("/network-segments/:id", h.UpdateNetworkSegment)

	send := func(method, path, value string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]any{
			"name": "seg " + value, "segment_type": "cidr", "value": value,
			"network_type": "public", "environment": "production",
		})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/api/v2/inventory-service"+path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		return w
	}
	stored := func(value string) bool {
		t.Helper()
		var n int
		if err := raw.QueryRow(`SELECT count(*) FROM network_segments WHERE tenant_id = $1 AND value = $2`, tenant, value).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n > 0
	}

	// Refused on create, with the rule in the message.
	for _, value := range []string{"0.0.0.0/0", "192.0.0.0/7", "3ffe::/15"} {
		w := send(http.MethodPost, "/network-segments", value)
		if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "too broad") || !strings.Contains(w.Body.String(), "/8 or narrower") {
			t.Errorf("POST %s = %d %s, want 400 naming the rule", value, w.Code, w.Body.String())
		}
		if stored(value) {
			t.Errorf("%s was stored despite the refusal", value)
		}
	}

	// The boundary saves.
	w := send(http.MethodPost, "/network-segments", "192.0.0.0/8")
	if w.Code != http.StatusCreated {
		t.Fatalf("POST 192.0.0.0/8 = %d %s, want 201 — a /8 is at the floor, not below it", w.Code, w.Body.String())
	}
	var seg struct{ ID uuid.UUID }
	if err := json.Unmarshal(w.Body.Bytes(), &seg); err != nil {
		t.Fatal(err)
	}
	if w := send(http.MethodPost, "/network-segments", "3fff::/16"); w.Code != http.StatusCreated {
		t.Errorf("POST 3fff::/16 = %d %s, want 201", w.Code, w.Body.String())
	}

	// Widening an existing segment past the floor is refused too, and leaves
	// it as it was.
	if w := send(http.MethodPut, "/network-segments/"+seg.ID.String(), "0.0.0.0/0"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "too broad") {
		t.Errorf("PUT widening to 0.0.0.0/0 = %d %s, want 400 naming the rule", w.Code, w.Body.String())
	}
	if !stored("192.0.0.0/8") || stored("0.0.0.0/0") {
		t.Error("a refused update changed the stored segment")
	}
	if w := send(http.MethodPut, "/network-segments/"+seg.ID.String(), "192.0.2.0/24"); w.Code != http.StatusOK {
		t.Errorf("PUT narrowing to 192.0.2.0/24 = %d %s, want 200", w.Code, w.Body.String())
	}
}
