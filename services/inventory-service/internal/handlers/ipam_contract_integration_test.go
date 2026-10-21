package handlers

// The real IPAM handlers over the real schema (as the app role), every body
// validated against the OpenAPI schema it claims. Complements the static
// parity test: that one holds the schema to the table, this one holds the
// served JSON (types, nullability, enums, the computed reads) to the schema.

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

func TestIntegration_IPAMContract_ResponsesConform(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	sv := loadSpec(t)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group("/api/v2/inventory-service/ipam")
	g.Use(func(c *gin.Context) {
		c.Set("tenantID", tenant)
		c.Set("userID", uuid.New())
		c.Set("email", "op@example.test")
	}, changes.Middleware())
	h := NewIPAMHandler(services.NewIPAMService(app))
	g.GET("/find", h.Find)
	g.GET("/prefixes/tree", h.PrefixTree)
	g.GET("/asn-ranges/:id/available-asns", h.AvailableASNs)
	for _, rt := range services.IPAMRoutes() {
		g.GET("/"+rt, h.List(rt))
		g.POST("/"+rt, h.Create(rt))
		if rt == "prefixes" {
			g.GET("/"+rt+"/:id", h.PrefixDetail)
		} else {
			g.GET("/"+rt+"/:id", h.Get(rt))
		}
		g.PATCH("/"+rt+"/:id", h.Update(rt))
		g.DELETE("/"+rt+"/:id", h.Delete(rt))
	}
	base := "/api/v2/inventory-service/ipam/"
	post := func(route, schema, body string) map[string]any {
		t.Helper()
		w := do(r, http.MethodPost, base+route, strings.NewReader(body))
		if w.Code != http.StatusCreated {
			t.Fatalf("POST %s: %d %s", route, w.Code, w.Body.String())
		}
		sv.assertConforms(t, schema+"Response", w.Body.Bytes())
		var env struct{ Data map[string]any }
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		return env.Data
	}
	var arin string
	if err := owner.QueryRow(`SELECT id FROM rirs WHERE slug = 'arin' AND tenant_id IS NULL`).Scan(&arin); err != nil {
		t.Fatal(err)
	}
	vrf := post("vrfs", "Vrf", `{"name":"blue","rd":"65000:7"}`)
	role := post("prefix-roles", "PrefixRole", `{"name":"Users"}`)
	grp := post("vlan-groups", "VlanGroup", `{"name":"campus","vid_ranges":[[1,999]]}`)
	vlan := post("vlans", "Vlan", fmt.Sprintf(`{"vid":20,"name":"users","group_id":%q}`, grp["id"]))
	pfx := post("prefixes", "Prefix", fmt.Sprintf(`{"prefix":"10.70.0.0/24","vrf_id":%q,"vlan_id":%q,"role_id":%q}`, vrf["id"], vlan["id"], role["id"]))
	post("prefixes", "Prefix", fmt.Sprintf(`{"prefix":"10.70.0.0/16","vrf_id":%q,"operational_status":"container"}`, vrf["id"]))
	post("ip-ranges", "IpRange", fmt.Sprintf(`{"start_address":"10.70.0.10","end_address":"10.70.0.20","vrf_id":%q}`, vrf["id"]))
	held := post("ip-addresses", "IpAddress", fmt.Sprintf(`{"address":"10.70.0.5/24","vrf_id":%q,"mac_address":"00:11:22:33:44:55"}`, vrf["id"]))
	// An asset holding the address, so the list's `asset` member is exercised.
	if _, err := owner.Exec(`INSERT INTO assets (tenant_id, class_key, class_path, display_name, primary_ip4_id)
		VALUES ($1, 'server', 'hardware.computer.server', 'pbx-01', $2)`, tenant, held["id"]); err != nil {
		t.Fatal(err)
	}
	post("ip-addresses", "IpAddress", `{"address":"2001:db8::5/64"}`)
	post("aggregates", "Aggregate", fmt.Sprintf(`{"prefix":"10.0.0.0/8","rir_id":%q}`, arin))
	post("route-targets", "RouteTarget", `{"name":"65000:7"}`)
	post("rirs", "Rir", `{"name":"Lab"}`)
	fg := post("fhrp-groups", "FhrpGroup", `{"protocol":"hsrp","group_id":1}`)
	// interface_id is a real interface since row 1.2 (tenant-paired FK); an
	// address assigned to it exercises the list's interface path to `asset`.
	var swID, ifaceID string
	if err := owner.QueryRow(`INSERT INTO assets (tenant_id, class_key, class_path, display_name)
		VALUES ($1, 'switch', 'hardware.network.switch', 'sw-01') RETURNING id`, tenant).Scan(&swID); err != nil {
		t.Fatal(err)
	}
	if err := owner.QueryRow(`INSERT INTO interfaces (tenant_id, asset_id, name, type) VALUES ($1, $2, 'Vlan20', 'virtual') RETURNING id`,
		tenant, swID).Scan(&ifaceID); err != nil {
		t.Fatal(err)
	}
	post("ip-addresses", "IpAddress", fmt.Sprintf(`{"address":"10.70.0.1/24","vrf_id":%q,"assigned_kind":"interface","assigned_id":%q}`, vrf["id"], ifaceID))
	post("fhrp-group-assignments", "FhrpGroupAssignment", fmt.Sprintf(`{"group_id":%q,"interface_id":%q}`, fg["id"], ifaceID))
	post("asns", "Asn", fmt.Sprintf(`{"asn":65010,"rir_id":%q}`, arin))
	// DCIM gap 10: an ASN range around that ASN, a VLAN translation policy
	// with a rule, applied to the interface.
	rng := post("asn-ranges", "AsnRange", fmt.Sprintf(`{"name":"Private 16-bit","rir_id":%q,"start":65008,"end":65012}`, arin))
	vtp := post("vlan-translation-policies", "VlanTranslationPolicy", `{"name":"customer-a"}`)
	post("vlan-translation-rules", "VlanTranslationRule", fmt.Sprintf(`{"policy_id":%q,"local_vid":100,"remote_vid":2100}`, vtp["id"]))
	if _, err := owner.Exec(`UPDATE interfaces SET vlan_translation_policy_id = $1 WHERE id = $2`, vtp["id"], ifaceID); err != nil {
		t.Fatal(err)
	}

	schemaOf := map[string]string{"rirs": "Rir", "aggregates": "Aggregate", "vrfs": "Vrf", "route-targets": "RouteTarget",
		"prefix-roles": "PrefixRole", "prefixes": "Prefix", "ip-ranges": "IpRange", "ip-addresses": "IpAddress",
		"vlan-groups": "VlanGroup", "vlans": "Vlan", "fhrp-groups": "FhrpGroup", "fhrp-group-assignments": "FhrpGroupAssignment", "asns": "Asn",
		"asn-ranges": "AsnRange", "vlan-translation-policies": "VlanTranslationPolicy", "vlan-translation-rules": "VlanTranslationRule"}
	for _, rt := range services.IPAMRoutes() {
		w := do(r, http.MethodGet, base+rt+"?limit=100", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("GET %s: %d %s", rt, w.Code, w.Body.String())
		}
		sv.assertConforms(t, schemaOf[rt]+"ListResponse", w.Body.Bytes())
	}
	w := do(r, http.MethodGet, base+"vlans/"+fmt.Sprint(vlan["id"]), nil)
	sv.assertConforms(t, "VlanResponse", w.Body.Bytes())
	w = do(r, http.MethodPatch, base+"vlans/"+fmt.Sprint(vlan["id"]), strings.NewReader(`{"description":"user access"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("PATCH: %d %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "VlanResponse", w.Body.Bytes())

	w = do(r, http.MethodGet, base+"prefixes/"+fmt.Sprint(pfx["id"])+"?length=26&limit=5", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("detail: %d %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PrefixDetailResponse", w.Body.Bytes())
	w = do(r, http.MethodGet, base+"prefixes/tree?vrf="+fmt.Sprint(vrf["id"]), nil)
	sv.assertConforms(t, "PrefixTreeResponse", w.Body.Bytes())
	w = do(r, http.MethodGet, base+"ip-addresses?parent=10.70.0.0/24&vrf_id="+fmt.Sprint(vrf["id"]), nil)
	sv.assertConforms(t, "IpAddressListResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"name":"pbx-01"`) {
		t.Fatalf("the address list does not name the asset holding the address: %s", w.Body.String())
	}
	w = do(r, http.MethodGet, base+"vlans", nil)
	if !strings.Contains(w.Body.String(), `"prefixes":["10.70.0.0/24"]`) {
		t.Fatalf("the VLAN list does not carry its prefixes: %s", w.Body.String())
	}
	// The ASN range's list row counts the ASN in it; its free numbers skip it.
	w = do(r, http.MethodGet, base+"asn-ranges", nil)
	if !strings.Contains(w.Body.String(), `"asn_count":1`) || !strings.Contains(w.Body.String(), `"available_count":4`) {
		t.Fatalf("the ASN range list does not count its ASNs: %s", w.Body.String())
	}
	w = do(r, http.MethodGet, base+"asn-ranges/"+fmt.Sprint(rng["id"])+"/available-asns?limit=3", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("available ASNs: %d %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "AvailableAsnsResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"asns":[65008,65009,65011]`) || !strings.Contains(w.Body.String(), `"available":4`) {
		t.Fatalf("available ASNs body: %s", w.Body.String())
	}
	w = do(r, http.MethodGet, base+"vlan-translation-policies", nil)
	if !strings.Contains(w.Body.String(), `"local_vid":100`) || !strings.Contains(w.Body.String(), `"interface_count":1`) {
		t.Fatalf("the policy list does not carry its rules and interfaces: %s", w.Body.String())
	}
	w = do(r, http.MethodGet, base+"find?address=10.70.0.5", nil)
	sv.assertConforms(t, "IpamFindResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"vrf_name":"blue"`) {
		t.Fatalf("find body: %s", w.Body.String())
	}

	// Error envelope.
	for _, c := range []struct {
		method, path, body string
		code               int
	}{
		{http.MethodPost, base + "prefixes", `{"prefix":"nope"}`, http.StatusBadRequest},
		{http.MethodPost, base + "vrfs", `{"name":"x","rd":"65000:7"}`, http.StatusConflict},
		{http.MethodGet, base + "vrfs/" + uuid.NewString(), "", http.StatusNotFound},
		{http.MethodDelete, base + "vrfs/" + fmt.Sprint(vrf["id"]), "", http.StatusConflict},
		{http.MethodPatch, base + "rirs/" + arin, `{"name":"x"}`, http.StatusForbidden},
		{http.MethodGet, base + "find?address=bogus", "", http.StatusBadRequest},
		{http.MethodPost, base + "asn-ranges", fmt.Sprintf(`{"name":"backwards","rir_id":%q,"start":65020,"end":65010}`, arin), http.StatusBadRequest},
		{http.MethodPost, base + "vlan-translation-rules", fmt.Sprintf(`{"policy_id":%q,"local_vid":100,"remote_vid":2200}`, vtp["id"]), http.StatusConflict},
		{http.MethodPost, base + "vlan-translation-rules", fmt.Sprintf(`{"policy_id":%q,"local_vid":101,"remote_vid":2100}`, vtp["id"]), http.StatusConflict},
		{http.MethodGet, base + "asn-ranges/" + uuid.NewString() + "/available-asns", "", http.StatusNotFound},
	} {
		var body *strings.Reader
		if c.body != "" {
			body = strings.NewReader(c.body)
		}
		var w2 = do(r, c.method, c.path, nil)
		if body != nil {
			w2 = do(r, c.method, c.path, body)
		}
		if w2.Code != c.code {
			t.Errorf("%s %s: %d, want %d (%s)", c.method, c.path, w2.Code, c.code, w2.Body.String())
			continue
		}
		sv.assertConforms(t, "Error", w2.Body.Bytes())
	}
}
