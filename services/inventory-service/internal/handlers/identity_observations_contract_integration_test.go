package handlers

// The Observations review table's responses as the REAL service produces them
//checked against the spec: a struct literal in a unit contract test
// can conform while the read path leaves `summary` null or a needs value off
// the enum. Application-role connection, so the reads run under RLS.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ContractObservationReviewResponses(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	app := testdb.ConnectAsAppRole(t, raw)
	spec := loadSpec(t)
	testdb.WithSchemaShareLock(t, raw, func() {
		actor := uuid.New()
		if _, err := raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, actor, tenant, "contract-"+actor.String()[:8]+"@example.com"); err != nil {
			t.Fatal(err)
		}
		segment, sensor := uuid.New(), uuid.New()
		if _, err := raw.Exec(`INSERT INTO network_segments (id, tenant_id, name, segment_type, value, environment) VALUES ($1,$2,'Office LAN','cidr','192.0.2.0/24','production')`, segment, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := raw.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status) VALUES($1,$2,'Office sensor','linux','1','datacenter_host','active')`, sensor, tenant); err != nil {
			t.Fatal(err)
		}
		fp := "SHA256:" + strings.Repeat("Zm9vYmFy", 5)
		var ids []uuid.UUID
		for i, reasons := range [][]string{
			{"dynamic_address_without_device_binding"}, {"network_scope_unresolved"},
			{"unverified_relayed_advertisement"}, {"no_device_or_address_binding"},
		} {
			addr := fmt.Sprintf("192.0.2.%d", 40+i)
			ev := fmt.Sprintf(`{"hostname":"host-%d","identifiers":[{"kind":"ip_address","value":%q},{"kind":"ssh_host_key_fingerprint","value":%q}],"endpoints":[{"address":%q,"port":22,"transport":"tcp","protocol":"ssh"}]}`, i, addr, fp, addr)
			var id uuid.UUID
			if err := raw.QueryRow(`INSERT INTO identity_observations(tenant_id,fingerprint,source_kind,source_ref,network_scope,evidence,admission_reasons,first_seen_at,last_seen_at)
			 VALUES($1,$2,'measured',$3,$4,$5,$6,$7,$7) RETURNING id`, tenant, uuid.NewString(), "sensor:"+sensor.String(), segment.String(), ev, pq.Array(reasons), time.Now().UTC().Add(-time.Hour)).Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		// Evidence with no identifiers at all: `summary` must still be an
		// array, which the spec requires and the UI maps over.
		if _, err := raw.Exec(`INSERT INTO identity_observations(tenant_id,fingerprint,source_kind,source_ref,evidence,admission_reasons,first_seen_at,last_seen_at)
		 VALUES($1,$2,'measured','scan','{}',ARRAY['no_device_or_address_binding'],now(),now())`, tenant, uuid.NewString()); err != nil {
			t.Fatal(err)
		}

		h := NewIdentityObservationHandler(services.NewAssetService(&database.DB{DB: sqlx.NewDb(app, "postgres")}))
		gin.SetMode(gin.TestMode)
		r := gin.New()
		r.Use(func(c *gin.Context) { c.Set("tenantID", tenant); c.Set("userID", actor); c.Next() })
		r.GET("/observations", h.List)
		r.GET("/observations/:id", h.Detail)
		r.POST("/observations/bulk", h.Bulk)

		get := func(path string) []byte {
			t.Helper()
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
			if w.Code != http.StatusOK {
				t.Fatalf("GET %s: %d %s", path, w.Code, w.Body.String())
			}
			return w.Body.Bytes()
		}
		page := get("/observations?sort=needs&needs=ready_to_confirm,needs_network&needs=needs_sensor&needs=likely_noise")
		spec.assertConforms(t, "IdentityObservationPage", page)
		var decoded services.IdentityObservationPage
		if err := json.Unmarshal(page, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded.Total != 5 || decoded.Counts == nil || decoded.Counts.All != 5 || decoded.Observations[0].Needs != services.NeedsReadyToConfirm {
			t.Fatalf("page %s", page)
		}
		first := decoded.Observations[0]
		if first.NetworkName == nil || *first.NetworkName != "Office LAN" || first.SourceName != "Office sensor" {
			t.Fatalf("names %v %q", first.NetworkName, first.SourceName)
		}
		// No UUID anywhere a person reads, and the host key is shortened for
		// display while the evidence keeps it whole.
		for _, o := range decoded.Observations {
			if o.SourceName == "Office sensor" && (!bytes.Contains(o.Evidence, []byte(fp)) || slices.Contains(summaryValues(o.Summary), fp)) {
				t.Fatalf("fingerprint: evidence keeps it=%v, summary shows it whole=%v", bytes.Contains(o.Evidence, []byte(fp)), slices.Contains(summaryValues(o.Summary), fp))
			}
			for _, text := range append([]string{o.SourceName, o.SuggestedReason}, summaryValues(o.Summary)...) {
				if strings.Contains(text, sensor.String()) || strings.Contains(text, segment.String()) {
					t.Fatalf("a UUID reached display text: %q", text)
				}
			}
		}
		spec.assertConforms(t, "IdentityObservation", get("/observations/"+ids[0].String()))

		body, _ := json.Marshal(map[string]any{"action": "dismiss", "ids": []uuid.UUID{ids[3], uuid.New()}, "reason": first.SuggestedReason})
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/observations/bulk", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("bulk %d %s", w.Code, w.Body.String())
		}
		spec.assertConforms(t, "BulkObservationDecisionResult", w.Body.Bytes())
	})
}

func summaryValues(s []services.ObservationIdentifierSummary) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		out = append(out, v.Value)
	}
	return out
}
