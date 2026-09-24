package main

// Catalog ▸ Frameworks "Update available" → Accept, through the REAL route
// table (decision 4, RC-12).
//
// The service-level tests in internal/services prove the database keeps an
// admin's edits and offers a new shipped version. This one proves the console
// can reach the accept: registerAdminRoutes — the function main() calls —
// mounted with the real handlers, a real platform token, a scratch database
// holding an offer, and a capturing audit-service. Deleting the route line,
// the handler wiring or the audit call fails it.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/handlers"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_SeededContentAccept_RealRouter(t *testing.T) {
	scratch := testdb.ScratchDatabase(t)

	// The admin edits a shipped control; a later release changes the same
	// control's shipped title.
	if _, err := scratch.Exec(`UPDATE platform_framework_controls SET title = 'Our TLS rule' WHERE control_id = 'BP-001'`); err != nil {
		t.Fatalf("admin edit: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(testdb.RepoRoot(t), "scripts", "database", "seed.sql"))
	if err != nil {
		t.Fatal(err)
	}
	const oldTitle, newTitle = "'TLS Version Requirements',", "'TLS Version Requirements (v2)',"
	if strings.Count(string(body), oldTitle) != 1 {
		t.Fatalf("fixture: %q no longer occurs exactly once in seed.sql", oldTitle)
	}
	if _, err := scratch.Exec(strings.Replace(string(body), oldTitle, newTitle, 1)); err != nil {
		t.Fatalf("apply next-release seed: %v", err)
	}
	var frameworkID, controlID uuid.UUID
	if err := scratch.QueryRow(`SELECT c.framework_id, c.id FROM platform_framework_controls c
		JOIN platform_frameworks f ON f.id = c.framework_id
		WHERE f.code = 'best-practices' AND c.control_id = 'BP-001'`).Scan(&frameworkID, &controlID); err != nil {
		t.Fatal(err)
	}

	// A capturing audit-service.
	events := make(chan map[string]interface{}, 16)
	auditSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var entry map[string]interface{}
		if json.Unmarshal(raw, &entry) == nil {
			events <- entry
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(auditSrv.Close)
	cfg := auditmiddleware.DefaultConfig()
	cfg.ServiceName = "compliance-engine"
	cfg.AuditServiceURL = auditSrv.URL
	cfg.BatchSize = 1
	cfg.FlushInterval = time.Hour
	cfg.RetryAttempts = 1
	mw := auditmiddleware.NewMiddleware(cfg)
	t.Cleanup(mw.Stop)

	svc := services.NewPlatformFrameworkService(sqlx.NewDb(scratch, "postgres"))
	h := handlers.NewPlatformFrameworkHandlers(svc)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("audit_middleware", mw); c.Next() })
	registerAdminRoutes(r.Group("/api/v1"), adminGateSecret, scratch, adminHandlers{
		reevaluateTenant: reached, listPlatformAlerts: reached,
		listFrameworks: reached, createFramework: reached, getFramework: h.GetFramework,
		updateFramework: reached, deleteFramework: reached, publishFramework: reached,
		unpublishFramework: reached, listFrameworkVersions: reached, getFrameworkVersion: reached,
		createControl: reached, updateControl: reached, deleteControl: reached,
		listControlMeasurements: reached, addControlMeasurement: reached,
		updateControlMeasurement: reached, deleteControlMeasurement: reached,
		acceptFrameworkUpdate:   h.AcceptFrameworkUpdate,
		acceptControlUpdate:     h.AcceptControlUpdate,
		acceptMeasurementUpdate: h.AcceptMeasurementUpdate,
		listTemplates:           reached, getTemplate: reached, createTemplate: reached,
		updateTemplate: reached, deleteTemplate: reached, applyTemplate: reached,
		provisionFramework: reached, listTenantSubscriptions: reached, cancelTenantSubscription: reached,
	})

	curator := testdb.NewPlatformUser(t, scratch, testdb.NewPlatformRole(t, scratch, rbac.PermissionCatalogsManage))
	token := testdb.SignPlatformToken(t, adminGateSecret, curator, "platform_admin")
	fw := adminPrefix + "/frameworks/" + frameworkID.String()
	accept := fw + "/controls/" + controlID.String() + "/accept-update"

	// The catalogue read shows the offer.
	w := testdb.DoPlatform(r, http.MethodGet, fw, token)
	if w.Code != http.StatusOK {
		t.Fatalf("GET framework: %d %s", w.Code, w.Body)
	}
	if !strings.Contains(w.Body.String(), `"update_available":true`) || !strings.Contains(w.Body.String(), `"offered_update":{"title":"TLS Version Requirements (v2)"}`) {
		t.Errorf("GET framework does not show BP-001's offer: %s", w.Body)
	}

	// Scoped to its framework.
	if w := testdb.DoPlatform(r, http.MethodPost, adminPrefix+"/frameworks/"+uuid.NewString()+"/controls/"+controlID.String()+"/accept-update", token); w.Code != http.StatusNotFound {
		t.Errorf("accept under another framework: %d %s, want 404", w.Code, w.Body)
	}

	w = testdb.DoPlatform(r, http.MethodPost, accept, token)
	if w.Code != http.StatusOK {
		t.Fatalf("accept: %d %s", w.Code, w.Body)
	}
	var resp struct {
		Control struct {
			Title           string `json:"title"`
			UpdateAvailable bool   `json:"update_available"`
			AdminModified   bool   `json:"admin_modified"`
			ContentOrigin   string `json:"content_origin"`
		} `json:"control"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode accept response: %v", err)
	}
	if resp.Control.Title != "TLS Version Requirements (v2)" || resp.Control.UpdateAvailable || !resp.Control.AdminModified || resp.Control.ContentOrigin != "vista" {
		t.Errorf("accept response control = %+v", resp.Control)
	}

	if w := testdb.DoPlatform(r, http.MethodPost, accept, token); w.Code != http.StatusConflict {
		t.Errorf("second accept: %d %s, want 409", w.Code, w.Body)
	}
	if w := testdb.DoPlatform(r, http.MethodPost, fw+"/accept-update", token); w.Code != http.StatusConflict {
		t.Errorf("accept on a framework with nothing on offer: %d %s, want 409", w.Code, w.Body)
	}

	// Audited, with what changed.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case e := <-events:
			if e["event_type"] != "platform_framework_control.seeded_update_accepted" {
				continue
			}
			nv, _ := e["new_values"].(map[string]interface{})
			ov, _ := e["old_values"].(map[string]interface{})
			if nv["title"] != "TLS Version Requirements (v2)" || ov["title"] != "Our TLS rule" {
				t.Errorf("audit entry old/new = %v / %v", ov, nv)
			}
			return
		case <-deadline:
			t.Fatal("no platform_framework_control.seeded_update_accepted audit entry reached audit-service")
		}
	}
}
