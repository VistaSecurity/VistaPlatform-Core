package main

// Wiring tests for the export feed's internal routes, on the REAL router.
//
// The feed is the whole platform's audit trail, every tenant's events, so the
// property that matters is WHO can reach it: HMAC-signed service calls only.
// A tenant token must not, and neither may a platform-admin token — no UI reads
// this, and a platform session is not a service. These drive newRouter (what
// main() serves) so that moving the two GETs onto the JWT group, or dropping
// the internal group's RequireInternalAuth, turns them red.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/database"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

const feedTestInternalSecret = "feed-test-internal-secret"

// stubFeed answers every read and records that it was reached.
type stubFeed struct{ reached int }

func (s *stubFeed) ExportPage(_ context.Context, after services.ExportCursor, _ int, _ time.Duration) (services.ExportPage, error) {
	s.reached++
	return services.ExportPage{Items: []services.ExportItem{}, Next: after}, nil
}

func (s *stubFeed) ExportHead(context.Context, time.Duration) (services.ExportCursor, error) {
	s.reached++
	return services.ExportCursor{CreatedAt: time.Now().UTC(), ID: uuid.Nil}, nil
}

func newFeedTestRouter(t *testing.T, feed *stubFeed) *gin.Engine {
	t.Helper()
	t.Setenv("DATABASE_URL", "")
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{
		JWT:                config.JWTConfig{Secret: testJWTSecret},
		InternalAuthSecret: feedTestInternalSecret,
	}
	return newRouter(cfg, &database.DB{}, newTestAuditMiddleware(t), routerHandlers{
		exportFeed: handlers.NewExportFeedHandlerFor(feed, 0),
	})
}

var feedPaths = []string{
	"/api/v1/audit-service/internal/export/events?after_created_at=2026-09-30T00:00:00Z&after_id=" + uuid.Nil.String(),
	"/api/v1/audit-service/internal/export/head",
}

func TestExportFeed_RefusesUserTokens(t *testing.T) {
	feed := &stubFeed{}
	r := newFeedTestRouter(t, feed)
	for _, tok := range []struct{ who, token string }{
		{"tenant admin", tenantAdminToken(t)},
		{"platform admin", platformAdminToken(t)},
	} {
		for _, path := range feedPaths {
			w := doWithToken(t, r, http.MethodGet, path, tok.token)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("%s GET %s = %d (%s); want 401 — the feed is for signed service calls only", tok.who, path, w.Code, w.Body.String())
			}
		}
	}
	if feed.reached != 0 {
		t.Fatalf("a user token reached the export feed %d time(s)", feed.reached)
	}
}

func TestExportFeed_RefusesAnUnsignedInternalHeader(t *testing.T) {
	feed := &stubFeed{}
	r := newFeedTestRouter(t, feed)
	for _, path := range feedPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Internal-Call", "true")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("unsigned GET %s = %d; want 401", path, w.Code)
		}
	}
	if feed.reached != 0 {
		t.Fatal("an unsigned call reached the export feed")
	}
}

func TestExportFeed_AcceptsASignedServiceCall(t *testing.T) {
	feed := &stubFeed{}
	r := newFeedTestRouter(t, feed)
	signer := serviceauth.NewSigner(feedTestInternalSecret)
	for _, path := range feedPaths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		signer.SignRequest(req)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("signed GET %s = %d (%s); want 200", path, w.Code, w.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode %s: %v", path, err)
		}
	}
	if feed.reached != len(feedPaths) {
		t.Fatalf("feed reached %d time(s); want %d", feed.reached, len(feedPaths))
	}
}
