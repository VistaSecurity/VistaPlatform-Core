package services

// IPAM through the real service over the real schema as the app role (RLS on).
// Each test names the rule it holds; the mutation that must turn it red is in
// its comment.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ipam"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func ipamTestCtx() context.Context {
	return changes.WithSource(changes.WithActor(context.Background(),
		changes.Actor{UserID: uuid.New(), UserName: "op@example.test"}), changes.SourceUI)
}

type ipamFixture struct {
	owner, app *sql.DB
	svc        *IPAMService
	tenant     uuid.UUID
	ctx        context.Context
}

func newIPAMFixture(t *testing.T) *ipamFixture {
	t.Helper()
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	return &ipamFixture{owner: owner, app: app, svc: NewIPAMService(app), tenant: testdb.NewTenant(t, owner), ctx: ipamTestCtx()}
}

func (f *ipamFixture) create(t *testing.T, route string, body any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(body)
	raw, err := f.svc.Create(f.ctx, f.tenant, route, b)
	if err != nil {
		t.Fatalf("create %s %s: %v", route, b, err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (f *ipamFixture) tryCreate(route string, body any) error {
	b, _ := json.Marshal(body)
	_, err := f.svc.Create(f.ctx, f.tenant, route, b)
	return err
}

func idOf(m map[string]any) uuid.UUID { return uuid.MustParse(fmt.Sprint(m["id"])) }

func TestIntegration_IPAM_CRUDEveryObjectRecordsChanges(t *testing.T) {
	f := newIPAMFixture(t)
	var arin string
	if err := f.owner.QueryRow(`SELECT id FROM rirs WHERE slug = 'arin' AND tenant_id IS NULL`).Scan(&arin); err != nil {
		t.Fatal(err)
	}
	rir := f.create(t, "rirs", map[string]any{"name": "Internal Registry", "is_private": true})
	if rir["slug"] != "internal-registry" {
		t.Fatalf("slug not derived: %v", rir["slug"])
	}
	role := f.create(t, "prefix-roles", map[string]any{"name": "Voice", "weight": 50})
	vrf := f.create(t, "vrfs", map[string]any{"name": "blue", "rd": "65000:1"})
	rt := f.create(t, "route-targets", map[string]any{"name": "65000:100"})
	agg := f.create(t, "aggregates", map[string]any{"prefix": "10.1.2.3/8", "rir_id": arin})
	if agg["prefix"] != "10.0.0.0/8" {
		t.Fatalf("aggregate prefix not normalised: %v", agg["prefix"])
	}
	grp := f.create(t, "vlan-groups", map[string]any{"name": "Campus", "vid_ranges": [][2]int{{100, 199}}})
	if fmt.Sprint(grp["vid_ranges"]) != "[[100 199]]" {
		t.Fatalf("vid_ranges round trip: %v", grp["vid_ranges"])
	}
	vlan := f.create(t, "vlans", map[string]any{"vid": 110, "name": "voice", "group_id": grp["id"], "role_id": role["id"]})
	pfx := f.create(t, "prefixes", map[string]any{"prefix": "10.20.0.0/24", "vrf_id": vrf["id"], "vlan_id": vlan["id"], "role_id": role["id"], "dhcp_managed": true})
	rng := f.create(t, "ip-ranges", map[string]any{"start_address": "10.20.0.100/24", "end_address": "10.20.0.150/24", "vrf_id": vrf["id"], "mark_utilized": true})
	if rng["size"] != "51" {
		t.Fatalf("range size = %v", rng["size"])
	}
	ip := f.create(t, "ip-addresses", map[string]any{"address": "10.20.0.5/24", "vrf_id": vrf["id"], "dns_name": "pbx.example.test", "mac_address": "00:11:22:33:44:55"})
	if ip["mac_address"] != "00:11:22:33:44:55" {
		t.Fatalf("mac not presented as EUI-48: %v", ip["mac_address"])
	}
	fg := f.create(t, "fhrp-groups", map[string]any{"protocol": "vrrp2", "group_id": 10})
	// interface_id is a real interface since row 1.2 (tenant-paired FK).
	fhrpAsset := ifaceSeedAsset(t, f.owner, f.tenant, "monitoring")
	var fhrpIface string
	if err := f.owner.QueryRow(`INSERT INTO interfaces (tenant_id, asset_id, name, type) VALUES ($1, $2, 'Vlan110', 'virtual') RETURNING id`,
		f.tenant, fhrpAsset).Scan(&fhrpIface); err != nil {
		t.Fatal(err)
	}
	fga := f.create(t, "fhrp-group-assignments", map[string]any{"group_id": fg["id"], "interface_id": fhrpIface, "priority": 200})
	asn := f.create(t, "asns", map[string]any{"asn": 4200000000, "rir_id": arin})

	// Patch + list + get.
	if _, err := f.svc.Update(f.ctx, f.tenant, "prefixes", idOf(pfx), []byte(`{"description":"voice LAN"}`)); err != nil {
		t.Fatal(err)
	}
	rows, total, err := f.svc.List(f.ctx, f.tenant, "prefixes", IPAMListParams{Filters: map[string]string{"vrf_id": fmt.Sprint(vrf["id"])}, Limit: 10})
	if err != nil || total != 1 || len(rows) != 1 {
		t.Fatalf("list = %d/%d %v", len(rows), total, err)
	}
	if _, err := f.svc.Get(f.ctx, f.tenant, "asns", idOf(asn)); err != nil {
		t.Fatal(err)
	}
	// Platform catalogue rows are read-only.
	if _, err := f.svc.Update(f.ctx, f.tenant, "rirs", uuid.MustParse(arin), []byte(`{"name":"x"}`)); !errors.Is(err, ErrIPAMReadOnly) {
		t.Fatalf("platform RIR edit: %v", err)
	}
	// Unknown fields are refused, not ignored.
	if err := f.tryCreate("vrfs", map[string]any{"name": "x", "colour": "red"}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("unknown field: %v", err)
	}
	// Enumerations are the schema's.
	if err := f.tryCreate("prefixes", map[string]any{"prefix": "10.9.0.0/16", "operational_status": "bogus"}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("bad status: %v", err)
	}
	// In use → 409.
	if err := f.svc.Delete(f.ctx, f.tenant, "vrfs", idOf(vrf)); !errors.Is(err, ErrIPAMInUse) {
		t.Fatalf("delete VRF in use: %v", err)
	}
	for _, d := range []struct {
		route string
		m     map[string]any
	}{{"fhrp-group-assignments", fga}, {"fhrp-groups", fg}, {"ip-addresses", ip}, {"ip-ranges", rng}, {"prefixes", pfx}, {"vlans", vlan}, {"vlan-groups", grp},
		{"aggregates", agg}, {"route-targets", rt}, {"vrfs", vrf}, {"prefix-roles", role}, {"rirs", rir}, {"asns", asn}} {
		if err := f.svc.Delete(f.ctx, f.tenant, d.route, idOf(d.m)); err != nil {
			t.Fatalf("delete %s: %v", d.route, err)
		}
	}
	// Every create, the prefix update and every delete are in the change log,
	// attributed to the actor.
	var n, kinds int
	if err := f.owner.QueryRow(`SELECT count(*), count(DISTINCT object_kind) FROM object_changes WHERE tenant_id = $1 AND user_id IS NOT NULL`, f.tenant).Scan(&n, &kinds); err != nil {
		t.Fatal(err)
	}
	if n != 13+1+13 || kinds != 13 {
		t.Fatalf("object_changes = %d rows over %d kinds, want 27 over 13", n, kinds)
	}
}

// Mutation: invert the enforce_unique test or drop the role exemption in
// ipAddressUniqueness → red.
func TestIntegration_IPAddresses_DuplicateAllowedWhenVRFNotEnforceUnique_OrAnycast(t *testing.T) {
	f := newIPAMFixture(t)
	strict := f.create(t, "vrfs", map[string]any{"name": "strict"})
	loose := f.create(t, "vrfs", map[string]any{"name": "loose", "enforce_unique": false})

	f.create(t, "ip-addresses", map[string]any{"address": "10.0.0.5/24", "vrf_id": strict["id"]})
	// Same host, different mask: still the same address.
	if err := f.tryCreate("ip-addresses", map[string]any{"address": "10.0.0.5/32", "vrf_id": strict["id"]}); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("duplicate in an enforcing VRF: %v", err)
	}
	// Global table enforces.
	f.create(t, "ip-addresses", map[string]any{"address": "10.0.0.5/24"})
	if err := f.tryCreate("ip-addresses", map[string]any{"address": "10.0.0.5/24"}); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("duplicate in the global table: %v", err)
	}
	// A VRF without enforce_unique allows it.
	f.create(t, "ip-addresses", map[string]any{"address": "10.0.0.5/24", "vrf_id": loose["id"]})
	f.create(t, "ip-addresses", map[string]any{"address": "10.0.0.5/24", "vrf_id": loose["id"]})
	// An anycast/VIP address may repeat even where uniqueness is enforced.
	f.create(t, "ip-addresses", map[string]any{"address": "10.0.0.9/24", "vrf_id": strict["id"], "role": "anycast"})
	f.create(t, "ip-addresses", map[string]any{"address": "10.0.0.9/24", "vrf_id": strict["id"], "role": "anycast"})
	f.create(t, "ip-addresses", map[string]any{"address": "10.0.0.9/24", "vrf_id": strict["id"], "role": "vip"})
	// …but a plain address may not join them (NetBox: a unique-role address
	// conflicts with ANY duplicate), and an anycast one may not join a plain one.
	if err := f.tryCreate("ip-addresses", map[string]any{"address": "10.0.0.9/24", "vrf_id": strict["id"]}); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("plain address next to anycast ones: %v", err)
	}
	if err := f.tryCreate("ip-addresses", map[string]any{"address": "10.0.0.5/24", "vrf_id": strict["id"], "role": "anycast"}); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("anycast address next to a plain one: %v", err)
	}
	// A zoned address is stored without its zone.
	z := f.create(t, "ip-addresses", map[string]any{"address": "fe80::1%eth0/64"})
	if z["address"] != "fe80::1/64" {
		t.Fatalf("zone kept: %v", z["address"])
	}
}

// The tree from the DB equals the arithmetic on the same set.
func TestIntegration_PrefixTree_MatchesArithmetic(t *testing.T) {
	f := newIPAMFixture(t)
	vrf := f.create(t, "vrfs", map[string]any{"name": "tree"})
	set := []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "10.1.2.0/24", "10.1.1.128/25", "10.2.0.0/16", "192.168.0.0/16", "2001:db8::/32", "2001:db8:1::/48"}
	var ps []netip.Prefix
	for _, p := range set {
		f.create(t, "prefixes", map[string]any{"prefix": p, "vrf_id": vrf["id"]})
		ps = append(ps, netip.MustParsePrefix(p))
	}
	// A global prefix that must not appear in the VRF's tree.
	f.create(t, "prefixes", map[string]any{"prefix": "10.1.1.0/26"})
	vid := idOf(vrf)
	nodes, total, err := f.svc.PrefixTree(f.ctx, f.tenant, &vid)
	if err != nil || total != len(set) {
		t.Fatalf("tree: %d %v", total, err)
	}
	var walk func(ns []*PrefixTreeNode)
	seen := 0
	walk = func(ns []*PrefixTreeNode) {
		for _, n := range ns {
			seen++
			var m map[string]any
			_ = json.Unmarshal(n.Prefix, &m)
			p := netip.MustParsePrefix(fmt.Sprint(m["prefix"]))
			var kids []netip.Prefix
			for _, c := range n.Children {
				var cm map[string]any
				_ = json.Unmarshal(c.Prefix, &cm)
				kids = append(kids, netip.MustParsePrefix(fmt.Sprint(cm["prefix"])))
			}
			want := ipam.ChildPrefixes(p, ps)
			if !slices.Equal(kids, want) {
				t.Errorf("%s children = %v; arithmetic says %v", p, kids, want)
			}
			if n.Depth != ipam.Depth(p, ps) {
				t.Errorf("%s depth %d; arithmetic %d", p, n.Depth, ipam.Depth(p, ps))
			}
			walk(n.Children)
		}
	}
	walk(nodes)
	if seen != len(set) || len(nodes) != 3 {
		t.Fatalf("tree has %d nodes, %d roots", seen, len(nodes))
	}
}

func cachedUtil(t *testing.T, db *sql.DB, id uuid.UUID) (float64, int, int) {
	t.Helper()
	var u float64
	var ips, kids int
	if err := db.QueryRow(`SELECT utilization, ip_count, child_count FROM prefix_utilization WHERE prefix_id = $1`, id).Scan(&u, &ips, &kids); err != nil {
		t.Fatalf("utilisation cache row for %s: %v", id, err)
	}
	return u, ips, kids
}

// Mutation: remove AfterWrite from the ip-addresses spec (or make
// refreshChain a no-op) → red.
func TestIntegration_Utilization_RefreshedOnWrite(t *testing.T) {
	f := newIPAMFixture(t)
	parent := f.create(t, "prefixes", map[string]any{"prefix": "10.50.0.0/16", "operational_status": "container"})
	child := f.create(t, "prefixes", map[string]any{"prefix": "10.50.1.0/30"})
	if u, ips, _ := cachedUtil(t, f.owner, idOf(child)); u != 0 || ips != 0 {
		t.Fatalf("empty /30 = %v%% %d ips, want 0", u, ips)
	}
	ip := f.create(t, "ip-addresses", map[string]any{"address": "10.50.1.1/30"})
	if u, ips, _ := cachedUtil(t, f.owner, idOf(child)); u != 50 || ips != 1 {
		t.Fatalf("after one address: %v%% %d ips, want 50%% 1", u, ips)
	}
	// The container counts child space, and its counts follow too.
	if u, ips, kids := cachedUtil(t, f.owner, idOf(parent)); u != 0.01 || ips != 1 || kids != 1 {
		t.Fatalf("container = %v%% ips %d kids %d", u, ips, kids)
	}
	// Moving the address out refreshes the old chain.
	if _, err := f.svc.Update(f.ctx, f.tenant, "ip-addresses", idOf(ip), []byte(`{"address":"10.50.9.9/16"}`)); err != nil {
		t.Fatal(err)
	}
	if u, ips, _ := cachedUtil(t, f.owner, idOf(child)); u != 0 || ips != 0 {
		t.Fatalf("after moving out: %v%% %d", u, ips)
	}
	// mark_utilized → 100.
	if _, err := f.svc.Update(f.ctx, f.tenant, "prefixes", idOf(child), []byte(`{"mark_utilized":true}`)); err != nil {
		t.Fatal(err)
	}
	if u, _, _ := cachedUtil(t, f.owner, idOf(child)); u != 100 {
		t.Fatalf("mark_utilized = %v", u)
	}
	// A utilised range counts on its prefix.
	other := f.create(t, "prefixes", map[string]any{"prefix": "10.50.2.0/29"})
	f.create(t, "ip-ranges", map[string]any{"start_address": "10.50.2.1", "end_address": "10.50.2.3", "mark_utilized": true})
	if u, _, _ := cachedUtil(t, f.owner, idOf(other)); u != 50 {
		t.Fatalf("range utilisation = %v, want 50 (3 of 6)", u)
	}
	// The detail's live computation agrees with the cache.
	d, err := f.svc.PrefixDetail(f.ctx, f.tenant, idOf(other), PrefixDetailParams{IPLimit: 5, AvailableLimit: 5})
	if err != nil || d.Utilization.Percent != 50 || d.AvailableIPs.Available != "3" {
		t.Fatalf("detail = %+v %v", d, err)
	}
	if !slices.Equal(d.AvailableIPs.Addresses, []string{"10.50.2.4", "10.50.2.5", "10.50.2.6"}) {
		t.Fatalf("available = %v", d.AvailableIPs.Addresses)
	}
}

// Mutation: drop vrfClause from findInVRF's prefix query → red.
func TestIntegration_Find_ReturnsLongestMatchInVRF_NotGlobal(t *testing.T) {
	f := newIPAMFixture(t)
	blue := f.create(t, "vrfs", map[string]any{"name": "blue"})
	f.create(t, "prefixes", map[string]any{"prefix": "10.10.0.0/16", "vrf_id": blue["id"]})
	inBlue := f.create(t, "prefixes", map[string]any{"prefix": "10.10.0.0/24", "vrf_id": blue["id"]})
	// A MORE specific global prefix: must not answer for VRF blue.
	f.create(t, "prefixes", map[string]any{"prefix": "10.10.0.0/28"})
	ip := f.create(t, "ip-addresses", map[string]any{"address": "10.10.0.5/24", "vrf_id": blue["id"], "dns_name": "pbx"})
	var asset uuid.UUID
	if err := f.owner.QueryRow(`INSERT INTO assets (tenant_id, class_key, class_path, display_name, primary_ip4_id) VALUES ($1, 'server', 'hardware.computer.server', 'pbx-01', $2) RETURNING id`, f.tenant, idOf(ip)).Scan(&asset); err != nil {
		t.Fatal(err)
	}
	bid := idOf(blue)
	res, err := f.svc.FindAddress(f.ctx, f.tenant, netip.MustParseAddr("10.10.0.5"), &bid, false)
	if err != nil || len(res) != 1 {
		t.Fatalf("find in blue: %v %v", res, err)
	}
	var p map[string]any
	_ = json.Unmarshal(res[0].Prefix, &p)
	if p["id"] != inBlue["id"] {
		t.Fatalf("longest match in blue = %v, want %v (10.10.0.0/24, not the global /28)", p["prefix"], inBlue["prefix"])
	}
	if res[0].Asset == nil || res[0].Asset.ID != asset || res[0].Asset.Via != "primary_ip4" {
		t.Fatalf("asset = %+v", res[0].Asset)
	}
	// Global only sees the global /28, and no address.
	res, err = f.svc.FindAddress(f.ctx, f.tenant, netip.MustParseAddr("10.10.0.5"), nil, false)
	if err != nil || len(res) != 1 || string(res[0].IPAddress) != "null" {
		t.Fatalf("find global: %+v %v", res, err)
	}
	_ = json.Unmarshal(res[0].Prefix, &p)
	if p["prefix"] != "10.10.0.0/28" {
		t.Fatalf("global match = %v", p["prefix"])
	}
	// Unscoped: one answer per VRF.
	res, err = f.svc.FindAddress(f.ctx, f.tenant, netip.MustParseAddr("10.10.0.5"), nil, true)
	if err != nil || len(res) != 2 {
		t.Fatalf("find all VRFs: %d %v", len(res), err)
	}
}

// Mutation: write dns_name = $6 (instead of COALESCE(t.dns_name, $6)) in
// observedIPRefresh → red.
func TestIntegration_UpsertObservedIP_NeverOverwritesDeclaredDNSName(t *testing.T) {
	f := newIPAMFixture(t)
	declared := f.create(t, "ip-addresses", map[string]any{"address": "10.30.0.7/24", "dns_name": "printer.corp", "description": "3rd floor", "operational_status": "reserved", "role": "secondary"})
	id, created, err := f.svc.UpsertObservedIP(context.Background(), f.tenant, "sensor", ObservedIP{
		Address: netip.MustParsePrefix("10.30.0.7/32"), DNSName: "android-1234.lan.", MACAddress: "aa:bb:cc:dd:ee:ff", LastSeenSource: "dhcp",
	})
	if err != nil || created || id != idOf(declared) {
		t.Fatalf("upsert matched %v created=%v err=%v", id, created, err)
	}
	var dns, desc, opStatus, role, mac, src string
	var obs int
	if err := f.owner.QueryRow(`SELECT dns_name, description, operational_status, role, mac_address::text, last_seen_source, observation_count FROM ip_addresses WHERE id = $1`, id).
		Scan(&dns, &desc, &opStatus, &role, &mac, &src, &obs); err != nil {
		t.Fatal(err)
	}
	if dns != "printer.corp" || desc != "3rd floor" || opStatus != "reserved" || role != "secondary" {
		t.Fatalf("declared fields overwritten: dns=%q desc=%q status=%q role=%q", dns, desc, opStatus, role)
	}
	if src != "dhcp" || obs != 1 || mac == "" {
		t.Fatalf("measured fields not refreshed: src=%q obs=%d mac=%q", src, obs, mac)
	}
	// A new observed address is pending and measured, with its DNS name.
	nid, created, err := f.svc.UpsertObservedIP(context.Background(), f.tenant, "sensor", ObservedIP{Address: netip.MustParsePrefix("10.30.0.8/24"), DNSName: "cam-2.lan", LastSeenSource: "arp"})
	if err != nil || !created {
		t.Fatalf("new observed address: %v %v", created, err)
	}
	var st, sk string
	if err := f.owner.QueryRow(`SELECT status, source_kind, dns_name FROM ip_addresses WHERE id = $1`, nid).Scan(&st, &sk, &dns); err != nil {
		t.Fatal(err)
	}
	if st != "pending" || sk != "measured" || dns != "cam-2.lan" {
		t.Fatalf("new observed = %s %s %s", st, sk, dns)
	}
	// The change record names the intake, not a person.
	var source string
	if err := f.owner.QueryRow(`SELECT source FROM object_changes WHERE tenant_id = $1 AND object_id = $2 AND action = 'update'`, f.tenant, id).Scan(&source); err != nil || source != "intake:sensor" {
		t.Fatalf("change source = %q %v", source, err)
	}
}

func TestIntegration_UpsertObservedPrefix_PendingThenRefreshNeverDeclared(t *testing.T) {
	f := newIPAMFixture(t)
	id, created, err := f.svc.UpsertObservedPrefix(context.Background(), f.tenant, "cloud", ObservedPrefix{Prefix: netip.MustParsePrefix("172.31.5.9/20"), CloudNetworkRef: "subnet-1", NetworkType: "cloud"})
	if err != nil || !created {
		t.Fatalf("observed prefix: %v %v", created, err)
	}
	if _, err := f.svc.Update(f.ctx, f.tenant, "prefixes", id, []byte(`{"description":"declared","operational_status":"reserved","status":"active"}`)); err != nil {
		t.Fatal(err)
	}
	again, created, err := f.svc.UpsertObservedPrefix(context.Background(), f.tenant, "cloud", ObservedPrefix{Prefix: netip.MustParsePrefix("172.31.0.0/20")})
	if err != nil || created || again != id {
		t.Fatalf("second observation: %v %v %v", again, created, err)
	}
	var p, desc, op, st string
	var obs int
	var approvedBy sql.NullString
	if err := f.owner.QueryRow(`SELECT prefix::text, description, operational_status, status, observation_count, approved_by::text FROM prefixes WHERE id = $1`, id).
		Scan(&p, &desc, &op, &st, &obs, &approvedBy); err != nil {
		t.Fatal(err)
	}
	if p != "172.31.0.0/20" || desc != "declared" || op != "reserved" || st != "active" || obs != 2 || !approvedBy.Valid {
		t.Fatalf("prefix = %s %q %s %s obs=%d approved=%v", p, desc, op, st, obs, approvedBy)
	}
}

func TestIntegration_VLAN_VidOutsideGroupRangesRefused(t *testing.T) {
	f := newIPAMFixture(t)
	grp := f.create(t, "vlan-groups", map[string]any{"name": "dc", "vid_ranges": [][2]int{{100, 199}, {300, 399}}})
	f.create(t, "vlans", map[string]any{"vid": 350, "name": "ok", "group_id": grp["id"]})
	if err := f.tryCreate("vlans", map[string]any{"vid": 250, "name": "gap", "group_id": grp["id"]}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("vid outside ranges: %v", err)
	}
	if err := f.tryCreate("vlans", map[string]any{"vid": 350, "name": "dup", "group_id": grp["id"]}); !errors.Is(err, ErrIPAMConflict) {
		t.Fatalf("duplicate vid: %v", err)
	}
}

func TestIntegration_IPAM_TenantCannotReferenceAnotherTenantsObjects(t *testing.T) {
	f := newIPAMFixture(t)
	other := &ipamFixture{owner: f.owner, app: f.app, svc: f.svc, tenant: testdb.NewTenant(t, f.owner), ctx: f.ctx}
	theirRole := other.create(t, "prefix-roles", map[string]any{"name": "Theirs"})
	theirVRF := other.create(t, "vrfs", map[string]any{"name": "theirs"})
	if err := f.tryCreate("prefixes", map[string]any{"prefix": "10.0.0.0/24", "role_id": theirRole["id"]}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("another tenant's role accepted: %v", err)
	}
	if err := f.tryCreate("prefixes", map[string]any{"prefix": "10.0.0.0/24", "vrf_id": theirVRF["id"]}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("another tenant's VRF accepted: %v", err)
	}
	var theirUnit string
	if err := f.owner.QueryRow(`INSERT INTO business_units (tenant_id, name, slug) VALUES ($1, 'Theirs', 'theirs') RETURNING id`, other.tenant).Scan(&theirUnit); err != nil {
		t.Fatal(err)
	}
	if err := f.tryCreate("prefixes", map[string]any{"prefix": "10.0.0.0/24", "business_unit_id": theirUnit}); !errors.Is(err, ErrIPAMInvalid) {
		t.Fatalf("another tenant's business unit accepted: %v", err)
	}
	if _, err := f.svc.Get(f.ctx, f.tenant, "vrfs", idOf(theirVRF)); !errors.Is(err, ErrIPAMNotFound) {
		t.Fatalf("another tenant's VRF readable: %v", err)
	}
}
