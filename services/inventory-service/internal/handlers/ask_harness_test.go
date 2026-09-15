package handlers

// The shared harness for the ask endpoint's two polarities.
//
// Core's is in ask_core_contract_test.go (402, nothing downstream runs);
// Enterprise's is in ask_ee_contract_test.go, which only a `-tags ee` build
// compiles. Neither file can see the other's side, which is why there are two —
// and why the fixtures they share live here rather than being written twice.
//
// Everything below drives the REAL gin router and the REAL handler. The store
// is in-memory, but it is not inert: it COMPILES the predicate it is handed
// with the production translator and refuses one that does not translate, so a
// test that passes here has exercised the query language end to end rather than
// having a canned string handed back to it.

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
)

const (
	askAssetA = "550e8400-e29b-41d4-a716-446655440000"
	askAssetB = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	askBase   = "/api/v1/inventory-service"
)

// newAskEngine mounts POST /ask on a real router, behind a middleware that sets
// the tenant and user the way JWTMiddleware does.
//
// rawDB is nil: these cases do not exercise the tenant kill switch, which needs
// a real settings row. The handler says so in a log line, the boundary's second
// lock is the backstop, and the switch's own behaviour is pinned where it can be
// driven honestly — in the ee contract file, through ai.WithTenantControls.
func newAskEngine(seam seams.Query, assets askAssetStore, classes assetClassStore,
	tenantID, userID uuid.UUID,
) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(askBase)
	grp.Use(func(c *gin.Context) {
		if tenantID != uuid.Nil {
			c.Set("tenantID", tenantID)
		}
		if userID != uuid.Nil {
			c.Set("userID", userID.String())
		}
		c.Next()
	})
	h := NewAskHandlers(seam, assets, classes, nil, 0)
	grp.POST("/ask", h.Ask)
	return r
}

func askDo(engine *gin.Engine, body io.Reader) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, askBase+"/ask", body)
	req.Header.Set("Content-Type", "application/json")
	engine.ServeHTTP(w, req)
	return w
}

// --- stub stores -----------------------------------------------------------

// stubAskStore answers the three reads the tool layer makes.
//
// GetAssets COMPILES the predicate rather than ignoring it. That is the point:
// the seam validated the query against the production catalogue, and this
// proves the same string then survives the translator the list endpoint runs —
// which is where a catalogue the validator accepts and the compiler refuses
// would show up. A predicate that does not compile is returned as the real
// service's *services.QueryError, so the tool reports diagnostics rather than
// an empty inventory.
type stubAskStore struct {
	mu sync.Mutex

	rows      []models.Asset
	listErr   error
	byID      map[uuid.UUID]*models.Asset
	buckets   []models.AssetFacetBucket
	facetErr  error
	listCalls []models.AssetFilters
	facetCall []string
}

func (s *stubAskStore) GetAssets(_ uuid.UUID, filters models.AssetFilters) ([]models.Asset, int, error) {
	s.mu.Lock()
	s.listCalls = append(s.listCalls, filters)
	s.mu.Unlock()
	if s.listErr != nil {
		return nil, 0, s.listErr
	}
	if _, err := services.CompileAssetQuery(filters.Query, services.QueryTargetAsset, 1, "a"); err != nil {
		return nil, 0, err
	}
	return s.rows, len(s.rows), nil
}

func (s *stubAskStore) GetAssetByID(_ uuid.UUID, id uuid.UUID) (*models.Asset, error) {
	return s.byID[id], nil
}

func (s *stubAskStore) GetAssetFacets(_ uuid.UUID, filters models.AssetFilters, level string, _ int) ([]models.AssetFacetBucket, error) {
	s.mu.Lock()
	s.facetCall = append(s.facetCall, level)
	s.listCalls = append(s.listCalls, filters)
	s.mu.Unlock()
	if s.facetErr != nil {
		return nil, s.facetErr
	}
	return s.buckets, nil
}

func (s *stubAskStore) queries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.listCalls))
	for _, f := range s.listCalls {
		out = append(out, f.Query)
	}
	return out
}

// stubAskClasses is the taxonomy read. A nil *stubAskClasses is a deployment
// with no class store wired, which the tool layer reports by not offering the
// tool — so both halves are reachable from a test.
type stubAskClasses struct {
	classes []services.AssetClass
	calls   int
}

func (s *stubAskClasses) List(_ context.Context, _ uuid.UUID) ([]services.AssetClass, error) {
	s.calls++
	return s.classes, nil
}

// askSeededAssets is the tenant's seeded inventory: two monitored production
// servers, filled the way the real list path fills a row so the response
// conforms to the spec's Asset schema.
//
// Both carry risk score 0 with an EMPTY risk_assessed_by, which is NOT ASSESSED
// rather than "clean" — the honest state for a row nothing has scored, and the
// distinction the summary must not flatten.
func askSeededAssets() []models.Asset {
	now := time.Now().UTC()
	tenant := uuid.New()
	one := askSeededAsset(tenant, askAssetA, "web01", now)
	one.Hostname = askStr("web01.example.test")
	two := askSeededAsset(tenant, askAssetB, "web02", now)
	return []models.Asset{one, two}
}

func askSeededAsset(tenant uuid.UUID, id, name string, now time.Time) models.Asset {
	return models.Asset{
		ID:                uuid.MustParse(id),
		TenantID:          tenant,
		ClassKey:          "server",
		ClassPath:         "hardware.computer.server",
		ClassSourceKind:   "measured",
		DisplayName:       askStr(name),
		Environment:       askStr("production"),
		Attributes:        map[string]interface{}{},
		Tags:              map[string]interface{}{},
		Metadata:          map[string]interface{}{},
		AssetOwnership:    "owned",
		AssetStatus:       "monitoring",
		FirstDiscoveredAt: now,
		LastSeenAt:        now,
		CreatedAt:         now,
		UpdatedAt:         now,
		RiskScore:         0,
		RiskAssessedBy:    []string{},
		RiskLevel:         "Informational",
	}
}

func askStr(s string) *string { return &s }
