package main

// DCIM row 1.5a: the intake seam through the REAL route. A collector that
// posts a sighting carrying interfaces, prefixes and VLANs to
// inventory-service's /internal/sightings gets interfaces, addresses,
// prefixes and VLANs written by the identity engine on the route's own
// transaction — no collector calls the interface or IPAM services.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Mutation: drop the recordObservedNetwork call in identity.Engine.Resolve —
// red (no MTU, no VLAN, no prefix; the interface exists only as the identity
// half filed it).
func TestIntegration_SightingRoute_WritesObservedInterfaces(t *testing.T) {
	gin.SetMode(gin.TestMode)
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	r := gin.New()
	mountSightingRoutes(r, handlers.NewSightingHandler(services.NewAssetService(db)), sourceTestSecret)

	mtu := 1500
	dhcp := true
	body, err := json.Marshal(map[string]any{"sightings": []identity.Sighting{{
		Source:  identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:route-it", Mode: identity.ModeActive},
		Channel: identity.ChannelAuthenticatedSession, ReceiptID: "sighting-route-ifaces-1",
		ClassHint: "switch",
		Identifiers: []identity.SightedIdentifier{
			{Kind: identity.KindSerialNumber, Value: "SW-ROUTE-IT"},
		},
		ManagementAddress: "10.61.0.2",
		Interfaces: []identity.ObservedInterface{
			{Name: "Gi0/1", MAC: "00:00:5e:00:53:61", MTU: &mtu, OperStatus: "up", Mode: "access", UntaggedVLAN: 61},
			{Name: "Vlan61", Addresses: []identity.ObservedAddress{{Address: "10.61.0.2", PrefixLen: 24}}},
		},
		VLANs:    []identity.ObservedVLAN{{VID: 61, Name: "lab"}},
		Prefixes: []identity.ObservedPrefix{{Prefix: "10.61.0.0/24", VLAN: 61, DHCPManaged: &dhcp}},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, sightingsPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(serviceauth.HeaderTenantID, tenant.String())
	serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sighting call = %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Results []services.SightingResult `json:"results"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Results) != 1 || resp.Results[0].AssetID == "" {
		t.Fatalf("response %s: %v", w.Body.String(), err)
	}
	asset := resp.Results[0].AssetID

	var (
		gotMTU   int
		vid      int
		mode     string
		svcAddr  string
		primary  string
		prefixes int
	)
	if err := raw.QueryRow(`
		SELECT coalesce(i.mtu, 0), coalesce(v.vid, 0), coalesce(i.mode, '')
		  FROM interfaces i LEFT JOIN vlans v ON v.tenant_id = i.tenant_id AND v.id = i.untagged_vlan_id
		 WHERE i.tenant_id = $1 AND i.asset_id = $2 AND i.name = 'GigabitEthernet0/1'`, tenant, asset).Scan(&gotMTU, &vid, &mode); err != nil {
		// The collector's `Gi0/1` is stored canonical (shared/dcim/ifnames).
		t.Fatalf("GigabitEthernet0/1: %v", err)
	}
	if gotMTU != 1500 || vid != 61 || mode != "access" {
		t.Errorf("GigabitEthernet0/1 mtu=%d untagged=%d mode=%q, want 1500, 61, access", gotMTU, vid, mode)
	}
	if err := raw.QueryRow(`
		SELECT host(ip.address) || '/' || masklen(ip.address) FROM ip_addresses ip
		  JOIN interfaces i ON i.tenant_id = ip.tenant_id AND i.id = ip.assigned_id
		 WHERE ip.tenant_id = $1 AND i.asset_id = $2 AND i.name = 'Vlan61'`, tenant, asset).Scan(&svcAddr); err != nil {
		t.Fatalf("Vlan61 address: %v", err)
	}
	if svcAddr != "10.61.0.2/24" {
		t.Errorf("Vlan61 address = %q, want 10.61.0.2/24", svcAddr)
	}
	if err := raw.QueryRow(`
		SELECT coalesce(host(ip.address), '') FROM assets a LEFT JOIN ip_addresses ip ON ip.tenant_id = a.tenant_id AND ip.id = a.primary_ip4_id
		 WHERE a.tenant_id = $1 AND a.id = $2`, tenant, asset).Scan(&primary); err != nil {
		t.Fatal(err)
	}
	if primary != "10.61.0.2" {
		t.Errorf("primary IPv4 = %q, want the management address 10.61.0.2", primary)
	}
	if err := raw.QueryRow(`SELECT count(*) FROM prefixes p JOIN vlans v ON v.tenant_id = p.tenant_id AND v.id = p.vlan_id
		WHERE p.tenant_id = $1 AND p.prefix = '10.61.0.0/24' AND v.vid = 61 AND p.dhcp_managed`, tenant).Scan(&prefixes); err != nil {
		t.Fatal(err)
	}
	if prefixes != 1 {
		t.Errorf("prefix 10.61.0.0/24 on VLAN 61, DHCP-managed: %d rows, want 1", prefixes)
	}
}
