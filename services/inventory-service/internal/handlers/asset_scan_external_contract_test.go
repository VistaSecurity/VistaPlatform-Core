package handlers

// POST /infrastructure-assets/scan for an asset outside the registered
// networks ( W5.13b, owner decision Q10): 422 asks, naming the assets; a
// confirmed resend needs discovery.create on top of the route's assets.update.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type stubPermissions struct {
	allow bool
	asked []string
}

func (p *stubPermissions) CheckPermission(_, _ uuid.UUID, permission string) (bool, error) {
	p.asked = append(p.asked, permission)
	return p.allow, nil
}

// countingRevalidation wraps the lifecycle stub to count scan calls.
type countingRevalidation struct {
	stubRevalidationStore
	calls int
	needs *services.ExternalConfirmationError
}

func (c *countingRevalidation) CreateActiveScanJob(t, u uuid.UUID, ids []uuid.UUID, auth string, rf services.RunFrom, confirmed bool) (services.ActiveScanResult, error) {
	c.calls++
	if c.needs != nil && !confirmed {
		return services.ActiveScanResult{}, c.needs
	}
	return c.stubRevalidationStore.CreateActiveScanJob(t, u, ids, auth, rf, confirmed)
}

func scanEngine(rv revalidationStore, perms PermissionChecker) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Set("userID", uuid.New())
		c.Next()
	})
	h := &AssetLifecycleHandler{revalidationService: rv}
	if perms != nil {
		h.SetPermissionChecker(perms)
	}
	r.POST("/scan", h.ScanAssets)
	return r
}

func postScan(t *testing.T, e *gin.Engine, body string) (int, []byte) {
	t.Helper()
	w := do(e, http.MethodPost, "/scan", bytes.NewBufferString(body))
	return w.Code, w.Body.Bytes()
}

func TestContract_ScanAssets_AsksAboutAssetsOutsideTheRegisteredNetworks(t *testing.T) {
	sv := loadSpec(t)
	asset := uuid.New()
	rv := &countingRevalidation{needs: &services.ExternalConfirmationError{Targets: []services.ActiveScanExternalTarget{
		{AssetID: asset, AssetName: "partner-portal", Target: "93.184.216.34", Addresses: []string{"93.184.216.34"}},
	}}}
	body := `{"asset_ids":["` + asset.String() + `"],"run_from":"platform"}`
	sv.assertConforms(t, "ActiveScanRequest", []byte(body))
	code, out := postScan(t, scanEngine(rv, &stubPermissions{allow: true}), body)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422; body=%s", code, out)
	}
	sv.assertConforms(t, "ActiveScanExternalTargetsError", out)
	var parsed struct {
		Error   string `json:"error"`
		Targets []struct {
			AssetID   string `json:"asset_id"`
			AssetName string `json:"asset_name"`
		} `json:"external_targets"`
	}
	_ = json.Unmarshal(out, &parsed)
	if parsed.Error != "external_targets_unconfirmed" || len(parsed.Targets) != 1 || parsed.Targets[0].AssetID != asset.String() || parsed.Targets[0].AssetName != "partner-portal" {
		t.Fatalf("422 body does not name the asset: %s", out)
	}
}

func TestScanAssets_ConfirmationNeedsDiscoveryCreate(t *testing.T) {
	sv := loadSpec(t)
	body := `{"asset_ids":["` + uuid.NewString() + `"],"external_targets_confirmed":true}`
	sv.assertConforms(t, "ActiveScanRequest", []byte(body))

	// No checker wired: fails closed.
	rv := &countingRevalidation{stubRevalidationStore: stubRevalidationStore{jobID: "j", scanned: 1}}
	if code, out := postScan(t, scanEngine(rv, nil), body); code != http.StatusForbidden || rv.calls != 0 {
		t.Fatalf("no permission checker: status=%d calls=%d body=%s, want 403 and nothing scanned", code, rv.calls, out)
	}
	// Checker says no.
	deny := &stubPermissions{allow: false}
	if code, _ := postScan(t, scanEngine(rv, deny), body); code != http.StatusForbidden || rv.calls != 0 {
		t.Fatalf("permission denied: status=%d calls=%d, want 403 and nothing scanned", code, rv.calls)
	}
	if len(deny.asked) != 1 || deny.asked[0] != "discovery.create" {
		t.Fatalf("asked for %v, want exactly discovery.create", deny.asked)
	}
	// Checker says yes: scanned, with the confirmation passed on.
	allow := &stubPermissions{allow: true}
	if code, out := postScan(t, scanEngine(rv, allow), body); code != http.StatusOK || rv.calls != 1 || !rv.gotConfirmed {
		t.Fatalf("permission held: status=%d calls=%d confirmed=%v body=%s", code, rv.calls, rv.gotConfirmed, out)
	}
	// An unconfirmed scan needs only the route's permission: no extra check.
	quiet := &stubPermissions{allow: false}
	if code, _ := postScan(t, scanEngine(rv, quiet), `{"asset_ids":["`+uuid.NewString()+`"]}`); code != http.StatusOK || len(quiet.asked) != 0 {
		t.Fatalf("unconfirmed scan: status=%d, extra permission checks=%v", code, quiet.asked)
	}
}
