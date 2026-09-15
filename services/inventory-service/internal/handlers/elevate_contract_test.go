package handlers

// `POST /external-connections/{id}/elevate` — PARITY_LEDGER J6.
//
// The stub fields existed and nothing used them: the endpoint had no contract
// test at all, so nothing held its response to the schema and nothing pinned
// the not-found answer. It is the one intake path where a person promotes
// something the platform had deliberately kept OUT of inventory, which makes
// "what exactly comes back" a question worth pinning.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func newElevateEngine(assets *stubAssetStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := NewAssetHandler(assets, nil)
	grp.POST("/inventory-service/external-connections/:id/elevate", h.ElevateExternalConnection)
	return r
}

func TestContract_ElevateExternalConnection_200(t *testing.T) {
	sv := loadSpec(t)
	elevated := sampleAsset()
	elevated.AssetOwnership = "third_party"
	elevated.AssetStatus = "monitoring"
	eng := newElevateEngine(&stubAssetStore{elevatedAsset: &elevated})

	w := do(eng, http.MethodPost,
		"/api/v2/inventory-service/external-connections/"+uuid.New().String()+"/elevate", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetResponse", w.Body.Bytes())
}

// TestContract_ElevateExternalConnection_404: a connection that is not there is
// NOT a server error. The service returns (nil, nil) for it — a real answer —
// and flattening that into a 500 would tell the operator the platform had
// broken when the row simply does not exist.
func TestContract_ElevateExternalConnection_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newElevateEngine(&stubAssetStore{})

	w := do(eng, http.MethodPost,
		"/api/v2/inventory-service/external-connections/"+uuid.New().String()+"/elevate", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ElevateExternalConnection_400And500(t *testing.T) {
	eng := newElevateEngine(&stubAssetStore{elevateErr: errors.New("boom")})

	// An id that is not a uuid is the caller's mistake.
	w := do(eng, http.MethodPost,
		"/api/v2/inventory-service/external-connections/not-a-uuid/elevate", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed id: status = %d, want 400", w.Code)
	}

	// A genuine failure is a 500.
	w = do(eng, http.MethodPost,
		"/api/v2/inventory-service/external-connections/"+uuid.New().String()+"/elevate", nil)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("service failure: status = %d, want 500", w.Code)
	}
}

// TestContract_GetAsset_MergedTombstone is gate 1 I8.
//
// Accepting a merge ARCHIVES the observation rather than deleting it, so its id
// keeps resolving: `GET /assets/{merged-away-id}` answers 200 with
// `asset_status: archived` and `merged_into` naming the survivor, instead of a
// 404 that tells a stale bookmark nothing.
//
// Nothing observed that field. `sampleAsset` never set it, so no contract test
// exercised the projection, and no-op'ing `setMergedInto` left every handler
// test green — a pointer clients are told to FOLLOW, with nothing checking it
// was ever populated.
func TestContract_GetAsset_MergedTombstone(t *testing.T) {
	sv := loadSpec(t)
	survivor := uuid.New()
	tombstone := sampleAsset()
	tombstone.AssetStatus = "archived"
	tombstone.MergedInto = &survivor

	eng := newEngine(&stubAssetStore{getResult: &tombstone}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 — a merged-away id must resolve to a tombstone, not 404; body=%s",
			w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetResponse", w.Body.Bytes())

	var got struct {
		Asset struct {
			AssetStatus string `json:"asset_status"`
			MergedInto  string `json:"merged_into"`
		} `json:"asset"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Asset.AssetStatus != "archived" {
		t.Errorf("asset_status = %q, want archived", got.Asset.AssetStatus)
	}
	if got.Asset.MergedInto != survivor.String() {
		t.Errorf("merged_into = %q, want the survivor %s — a client is told to FOLLOW this pointer",
			got.Asset.MergedInto, survivor)
	}
}

// TestContract_GetAsset_LivingAssetHasNoMergedInto is the other polarity: the
// field must be ABSENT on an asset that was not merged away, not present and
// empty. A client that tested `"merged_into" in asset` would follow a pointer
// to nowhere.
func TestContract_GetAsset_LivingAssetHasNoMergedInto(t *testing.T) {
	living := sampleAsset()
	eng := newEngine(&stubAssetStore{getResult: &living}, &stubApprovalStore{})
	w := do(eng, http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if strings.Contains(w.Body.String(), "merged_into") {
		t.Errorf("a living asset carries merged_into; it must be absent, not empty:\n%s", w.Body.String())
	}
}
