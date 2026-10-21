package handlers

// Contract test for the IP Addresses tab's two server pieces: the list's
// asset_id filter (rows conform to IpAddressListResponse, including the
// asset flags) and PATCH /dcim/assets/{id}/primary-ips (conforms to
// AssetPrimaryIpsResponse; a wrong-family write is a 400 Error).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AssetPrimaryIPsContract(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	sv := loadSpec(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("tenantID", tenant)
		c.Set("userID", uuid.New())
		c.Set("email", "op@example.test")
	}, changes.Middleware())
	ipam := NewIPAMHandler(services.NewIPAMService(app))
	r.GET("/ipam/ip-addresses", ipam.List("ip-addresses"))
	r.POST("/ipam/ip-addresses", ipam.Create("ip-addresses"))
	r.PATCH("/dcim/assets/:id/primary-ips", NewAssetPrimaryIPHandler(services.NewAssetPrimaryIPService(app)).Update)

	var asset, ifc string
	if err := owner.QueryRow(`INSERT INTO assets (tenant_id, class_key, class_path, display_name)
		VALUES ($1, 'switch', 'hardware.network.switch', 'sw-01') RETURNING id`, tenant).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(`INSERT INTO interfaces (tenant_id, asset_id, name, type) VALUES ($1, $2, 'Vlan1', 'virtual') RETURNING id`, tenant, asset).Scan(&ifc); err != nil {
		t.Fatal(err)
	}
	mk := func(address string) string {
		w := do(r, http.MethodPost, "/ipam/ip-addresses", strings.NewReader(fmt.Sprintf(`{"address":%q,"assigned_kind":"interface","assigned_id":%q}`, address, ifc)))
		if w.Code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", address, w.Code, w.Body.String())
		}
		var env struct{ Data struct{ ID string } }
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		return env.Data.ID
	}
	v4, v6 := mk("10.80.0.1/24"), mk("2001:db8:80::1/64")

	w := do(r, http.MethodPatch, "/dcim/assets/"+asset+"/primary-ips", strings.NewReader(fmt.Sprintf(`{"primary_ip4_id":%q,"primary_ip6_id":%q}`, v4, v6)))
	if w.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AssetPrimaryIpsResponse", w.Body.Bytes())

	w = do(r, http.MethodPatch, "/dcim/assets/"+asset+"/primary-ips", strings.NewReader(fmt.Sprintf(`{"primary_ip4_id":%q}`, v6)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("an IPv6 address as primary_ip4: %d %s, want 400", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "Error", w.Body.Bytes())

	w = do(r, http.MethodGet, "/ipam/ip-addresses?asset_id="+asset, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("GET: %d %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "IpAddressListResponse", w.Body.Bytes())
	var list struct{ Data []map[string]any }
	_ = json.Unmarshal(w.Body.Bytes(), &list)
	if len(list.Data) != 2 {
		t.Fatalf("asset_id filter returned %d rows, want 2", len(list.Data))
	}
}
