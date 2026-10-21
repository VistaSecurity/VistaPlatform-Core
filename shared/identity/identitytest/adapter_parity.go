package identitytest

// RunAdapterParity is the parity harness every intake adapter of DCIM row 1.5
// runs (1.5a–1.5f). It drives the REAL shared path — the adapter turns a
// recorded vendor response into the Sighting its collector sends,
// identity.Intake builds the observation, identity.Engine resolves it, the
// Postgres repository writes it — against a real database, and holds the
// result to what the fixture says the response describes:
//
//  1. Parity: exactly the expected interfaces (name, type, MAC, MTU, speed,
//     operational/admin status, mode, parent, LAG, untagged and tagged VLANs),
//     the expected addresses on each (with the configured length, and the VRF
//     when not global), the expected prefixes (with their VLAN, DHCP posture
//     and cloud network) and VLANs, the virtual device contexts (with their
//     identifier and member interfaces, DCIM gap 1), and the asset's
//     primary IPv4/IPv6 address. Nothing more: an interface or a prefix the
//     fixture does not list is a failure, so a projection that starts
//     inventing rows goes red as surely as one that drops a field.
//  2. Idempotence: the same response observed again later resolves to the
//     SAME asset, writes no new interface, MAC, address, prefix, VLAN or
//     tagged-VLAN row, and moves every one's `observation_count` by exactly
//     one.
//  3. Posture, never secrets: every value in Fixture.Secrets — plant one in
//     each recorded response, in a field the projection must not carry —
//     appears in no row of any tenant table after both runs.
//
// The harness needs a database: without TEST_DATABASE_URL it skips, like
// every shared/testdb test (`make test-integration-db` runs it).

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// ParityAdapter is one collector's intake adapter under test: it turns ONE
// recorded vendor response into the Sighting the collector sends, through the
// same projection production uses. It must not write anything itself.
type ParityAdapter interface {
	Name() string
	Sighting(tenantID string, response []byte, observedAt time.Time) (identity.Sighting, error)
}

// ParityAdapterFunc makes a function a [ParityAdapter].
type ParityAdapterFunc struct {
	AdapterName string
	Fn          func(tenantID string, response []byte, observedAt time.Time) (identity.Sighting, error)
}

// Name implements [ParityAdapter].
func (f ParityAdapterFunc) Name() string { return f.AdapterName }

// Sighting implements [ParityAdapter].
func (f ParityAdapterFunc) Sighting(tenantID string, response []byte, observedAt time.Time) (identity.Sighting, error) {
	return f.Fn(tenantID, response, observedAt)
}

// ParityFixture is one recorded vendor response and what it describes.
type ParityFixture struct {
	// Name names the subtest.
	Name string
	// Response is the recorded vendor response, byte for byte as the
	// collector received it (read it from testdata).
	Response []byte
	// Want is what the response describes, completely.
	Want ParityWant
	// Secrets are values planted in Response that must never reach a table:
	// a PSK, a community string, an API token, in a field the projection has
	// no business carrying. At least one per fixture.
	Secrets []string
	// Setup runs before the first observation, for state the fixture assumes
	// (a declared VRF, a prefix). Optional.
	Setup func(t *testing.T, db *sql.DB, tenantID string)
}

// ParityWant is the complete expected result of one observation.
type ParityWant struct {
	Interfaces []WantInterface
	Prefixes   []WantPrefix
	VLANs      []WantVLAN
	// WirelessLANs are the wireless LANs the observation must have recorded
	// (row 4.4), and nothing else: an adapter with none expects none.
	WirelessLANs []WantWirelessLAN
	// VirtualDeviceContexts are the observed asset's virtual device contexts
	// (DCIM gap 1), and nothing else: an adapter with none expects none.
	VirtualDeviceContexts []WantVirtualDeviceContext
	// PrimaryIP4 / PrimaryIP6 are the host part of the asset's primary
	// address of each family, "" for none.
	PrimaryIP4, PrimaryIP6 string
}

// WantInterface is one expected interface. A zero value of an optional field
// means the column must be NULL (or, for Type, the registry's `other`).
type WantInterface struct {
	Name string
	Type string
	// MAC is the interface's primary MAC in identifier spelling, "" for none.
	MAC         string
	MTU         int
	SpeedKbps   int64
	OperStatus  string
	AdminStatus string
	Mode        string
	Parent, LAG string
	// UntaggedVLAN and TaggedVLANs are VIDs.
	UntaggedVLAN int
	TaggedVLANs  []int
	// Addresses are "host/len" for the global VRF and "vrf|host/len" for a
	// named one, in any order.
	Addresses []string
}

// WantPrefix is one expected prefix. VRF is the VRF's name, "" for global.
// CloudNetworkRef is the cloud network the prefix belongs to (a cloud
// collector's VPC / VNet id, row 1.5f), "" for a prefix that names none.
type WantPrefix struct {
	Prefix          string
	VRF             string
	VLAN            int
	DHCPManaged     *bool
	CloudNetworkRef string
}

// WantWirelessLAN is one expected wireless LAN. Algorithm is the catalogue
// code its cipher is scored by, "" for not assessed.
type WantWirelessLAN struct {
	SSID, AuthType, AuthCipher, Algorithm string
	PSKPresent                            bool
	// Serving are the names of the observed asset's interfaces that serve it.
	Serving []string
}

// WantVLAN is one expected VLAN.
type WantVLAN struct {
	VID  int
	Name string
}

// RunAdapterParity runs every fixture through the adapter against a real
// database, one tenant per fixture.
func RunAdapterParity(t *testing.T, adapter ParityAdapter, fixtures []ParityFixture) {
	t.Helper()
	if len(fixtures) == 0 {
		t.Fatalf("%s: no fixtures", adapter.Name())
	}
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	for _, fx := range fixtures {
		t.Run(adapter.Name()+"/"+fx.Name, func(t *testing.T) {
			if len(fx.Secrets) == 0 {
				t.Fatalf("fixture %s plants no secret: every recorded response must carry one the projection has to drop", fx.Name)
			}
			for _, s := range fx.Secrets {
				if !strings.Contains(string(fx.Response), s) {
					t.Fatalf("fixture %s: secret %q is not in the recorded response, so its absence proves nothing", fx.Name, s)
				}
			}
			runParityFixture(t, db, adapter, fx)
		})
	}
}

func runParityFixture(t *testing.T, db *sql.DB, adapter ParityAdapter, fx ParityFixture) {
	tenant := testdb.NewTenant(t, db).String()
	if fx.Setup != nil {
		fx.Setup(t, db, tenant)
	}
	repo := pgrepo.New(db)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	intake, err := identity.NewIntake(repo)
	if err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	observe := func(at time.Time) identity.Resolution {
		t.Helper()
		s, err := adapter.Sighting(tenant, fx.Response, at)
		if err != nil {
			t.Fatalf("adapter: %v", err)
		}
		ctx := context.Background()
		obs, err := intake.Build(ctx, s)
		if err != nil {
			t.Fatalf("intake: %v", err)
		}
		var res identity.Resolution
		if err := repo.RunInTx(ctx, tenant, func(bound *pgrepo.Repository) error {
			var rerr error
			res, rerr = engine.WithRepository(bound).Resolve(ctx, obs)
			return rerr
		}); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if res.Asset.Zero() {
			t.Fatalf("observation resolved to no asset (outcome %s)", res.Outcome)
		}
		return res
	}

	first := observe(at)
	asset := first.Asset.ID
	checkParity(t, db, tenant, asset, fx.Want, "first observation")
	before := parityCounts(t, db, tenant)

	second := observe(at.Add(time.Hour))
	if second.Asset.ID != asset {
		t.Fatalf("re-observing the same response resolved to asset %s (outcome %s), want %s: the adapter is not idempotent",
			second.Asset.ID, second.Outcome, asset)
	}
	checkParity(t, db, tenant, asset, fx.Want, "re-observation")
	after := parityCounts(t, db, tenant)
	for table, rows := range before.rows {
		if after.rows[table] != rows {
			t.Errorf("re-observation changed the number of %s rows: %d → %d (want no duplicates)", table, rows, after.rows[table])
		}
	}
	for key, n := range before.observed {
		if got := after.observed[key]; got != n+1 {
			t.Errorf("observation_count of %s moved %d → %d on re-observation, want +1", key, n, got)
		}
	}

	checkNoSecrets(t, db, tenant, fx.Secrets)
}

// --------------------------------------------------------------- reading ----

func q(t *testing.T, db *sql.DB, query string, args ...any) *sql.Rows {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatalf("parity read: %v\n%s", err, query)
	}
	return rows
}

// macSpelling turns a macaddr8 column's text into identifier spelling, the
// 6-byte MAC Postgres widened to EUI-64 reported as the MAC it was.
func macSpelling(v string) string {
	hw, err := net.ParseMAC(strings.TrimSpace(v))
	if err != nil {
		return v
	}
	if len(hw) == 8 && hw[3] == 0xff && hw[4] == 0xfe {
		hw = net.HardwareAddr{hw[0], hw[1], hw[2], hw[5], hw[6], hw[7]}
	}
	if n, err := identity.Normalize(identity.KindMACAddress, hw.String()); err == nil {
		return n
	}
	return hw.String()
}

func readInterfaces(t *testing.T, db *sql.DB, tenant, asset string) []WantInterface {
	t.Helper()
	rows := q(t, db, `
		SELECT i.id, i.name, i.type, coalesce(i.mac_address::text, ''), coalesce(i.mtu, 0), coalesce(i.speed_kbps, 0),
		       coalesce(i.operational_status, ''), coalesce(i.admin_status, ''), coalesce(i.mode, ''),
		       coalesce(p.name, ''), coalesce(l.name, ''), coalesce(v.vid, 0)
		  FROM public.interfaces i
		  LEFT JOIN public.interfaces p ON p.tenant_id = i.tenant_id AND p.id = i.parent_id
		  LEFT JOIN public.interfaces l ON l.tenant_id = i.tenant_id AND l.id = i.lag_id
		  LEFT JOIN public.vlans v ON v.tenant_id = i.tenant_id AND v.id = i.untagged_vlan_id
		 WHERE i.tenant_id = $1 AND i.asset_id = $2 AND i.status <> 'rejected'
		 ORDER BY i.name`, tenant, asset)
	var (
		out []WantInterface
		ids []uuid.UUID
	)
	for rows.Next() {
		var (
			w  WantInterface
			id uuid.UUID
		)
		if err := rows.Scan(&id, &w.Name, &w.Type, &w.MAC, &w.MTU, &w.SpeedKbps, &w.OperStatus, &w.AdminStatus,
			&w.Mode, &w.Parent, &w.LAG, &w.UntaggedVLAN); err != nil {
			t.Fatal(err)
		}
		if w.MAC != "" {
			w.MAC = macSpelling(w.MAC)
		}
		out = append(out, w)
		ids = append(ids, id)
	}
	_ = rows.Close()
	for i, id := range ids {
		tr := q(t, db, `SELECT v.vid FROM public.interface_tagged_vlans tv JOIN public.vlans v ON v.tenant_id = tv.tenant_id AND v.id = tv.vlan_id
			WHERE tv.tenant_id = $1 AND tv.interface_id = $2 ORDER BY v.vid`, tenant, id)
		for tr.Next() {
			var vid int
			if err := tr.Scan(&vid); err != nil {
				t.Fatal(err)
			}
			out[i].TaggedVLANs = append(out[i].TaggedVLANs, vid)
		}
		_ = tr.Close()
		ar := q(t, db, `SELECT coalesce(v.name, ''), host(ip.address) || '/' || masklen(ip.address)
			FROM public.ip_addresses ip LEFT JOIN public.vrfs v ON v.tenant_id = ip.tenant_id AND v.id = ip.vrf_id
			WHERE ip.tenant_id = $1 AND ip.assigned_kind = 'interface' AND ip.assigned_id = $2 AND ip.status <> 'rejected'`, tenant, id)
		for ar.Next() {
			var vrf, addr string
			if err := ar.Scan(&vrf, &addr); err != nil {
				t.Fatal(err)
			}
			if vrf != "" {
				addr = vrf + "|" + addr
			}
			out[i].Addresses = append(out[i].Addresses, addr)
		}
		_ = ar.Close()
		sort.Strings(out[i].Addresses)
	}
	return out
}

func readPrefixes(t *testing.T, db *sql.DB, tenant string) []WantPrefix {
	t.Helper()
	rows := q(t, db, `
		SELECT p.prefix::text, coalesce(vr.name, ''), coalesce(v.vid, 0), p.dhcp_managed, coalesce(p.cloud_network_ref, '')
		  FROM public.prefixes p
		  LEFT JOIN public.vrfs vr ON vr.tenant_id = p.tenant_id AND vr.id = p.vrf_id
		  LEFT JOIN public.vlans v ON v.tenant_id = p.tenant_id AND v.id = p.vlan_id
		 WHERE p.tenant_id = $1 AND p.status <> 'rejected' ORDER BY p.prefix`, tenant)
	defer func() { _ = rows.Close() }()
	var out []WantPrefix
	for rows.Next() {
		var (
			w    WantPrefix
			dhcp sql.NullBool
		)
		if err := rows.Scan(&w.Prefix, &w.VRF, &w.VLAN, &dhcp, &w.CloudNetworkRef); err != nil {
			t.Fatal(err)
		}
		if dhcp.Valid {
			b := dhcp.Bool
			w.DHCPManaged = &b
		}
		out = append(out, w)
	}
	return out
}

func readVLANs(t *testing.T, db *sql.DB, tenant string) []WantVLAN {
	t.Helper()
	rows := q(t, db, `SELECT vid, name FROM public.vlans WHERE tenant_id = $1 AND status <> 'rejected' ORDER BY vid`, tenant)
	defer func() { _ = rows.Close() }()
	var out []WantVLAN
	for rows.Next() {
		var w WantVLAN
		if err := rows.Scan(&w.VID, &w.Name); err != nil {
			t.Fatal(err)
		}
		out = append(out, w)
	}
	return out
}

func readWirelessLANs(t *testing.T, db *sql.DB, tenant, asset string) []WantWirelessLAN {
	t.Helper()
	rows := q(t, db, `
		SELECT l.ssid, coalesce(l.auth_type, ''), coalesce(l.auth_cipher, ''), coalesce(a.code, ''), l.auth_psk_present,
		       ARRAY(SELECT i.name FROM public.interfaces i WHERE i.tenant_id = l.tenant_id AND i.asset_id = $2::uuid
		              AND l.id = ANY(i.wireless_lan_ids) ORDER BY i.name)
		  FROM public.wireless_lans l LEFT JOIN public.algorithms a ON a.id = l.algorithm_id
		 WHERE l.tenant_id = $1 AND l.status <> 'rejected' ORDER BY l.ssid`, tenant, asset)
	defer func() { _ = rows.Close() }()
	var out []WantWirelessLAN
	for rows.Next() {
		var w WantWirelessLAN
		if err := rows.Scan(&w.SSID, &w.AuthType, &w.AuthCipher, &w.Algorithm, &w.PSKPresent, pq.Array(&w.Serving)); err != nil {
			t.Fatal(err)
		}
		if len(w.Serving) == 0 {
			w.Serving = nil
		}
		out = append(out, w)
	}
	return out
}

// WantVirtualDeviceContext is one expected virtual device context of the
// observed asset. Identifier is "" for none; Interfaces are the names of its
// member interfaces.
type WantVirtualDeviceContext struct {
	Name, Identifier string
	Interfaces       []string
}

func readVirtualDeviceContexts(t *testing.T, db *sql.DB, tenant, asset string) []WantVirtualDeviceContext {
	t.Helper()
	rows := q(t, db, `
		SELECT c.name, coalesce(c.identifier::text, ''),
		       ARRAY(SELECT i.name FROM public.interface_virtual_device_contexts j
		              JOIN public.interfaces i ON i.tenant_id = j.tenant_id AND i.id = j.interface_id
		             WHERE j.tenant_id = c.tenant_id AND j.virtual_device_context_id = c.id ORDER BY i.name)
		  FROM public.virtual_device_contexts c
		 WHERE c.tenant_id = $1 AND c.asset_id = $2::uuid AND c.status <> 'rejected' ORDER BY c.name`, tenant, asset)
	defer func() { _ = rows.Close() }()
	var out []WantVirtualDeviceContext
	for rows.Next() {
		var w WantVirtualDeviceContext
		if err := rows.Scan(&w.Name, &w.Identifier, pq.Array(&w.Interfaces)); err != nil {
			t.Fatal(err)
		}
		if len(w.Interfaces) == 0 {
			w.Interfaces = nil
		}
		out = append(out, w)
	}
	return out
}

// ------------------------------------------------------------- comparing ----

func normWantInterface(w WantInterface) WantInterface {
	if w.Type == "" {
		w.Type = identity.SyntheticInterfaceType
	}
	w.Addresses = append([]string(nil), w.Addresses...)
	sort.Strings(w.Addresses)
	w.TaggedVLANs = append([]int(nil), w.TaggedVLANs...)
	slices.Sort(w.TaggedVLANs)
	if len(w.Addresses) == 0 {
		w.Addresses = nil
	}
	if len(w.TaggedVLANs) == 0 {
		w.TaggedVLANs = nil
	}
	return w
}

func describeDHCP(b *bool) string {
	if b == nil {
		return "unset"
	}
	return fmt.Sprint(*b)
}

func checkParity(t *testing.T, db *sql.DB, tenant, asset string, want ParityWant, when string) {
	t.Helper()
	got := readInterfaces(t, db, tenant, asset)
	// The database orders by its collation, which ignores punctuation
	// (`Gi1/0/2.200` sorts after `Gi1/0/22`); compare in byte order, as the
	// expectation is.
	sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
	wantI := make([]WantInterface, 0, len(want.Interfaces))
	for _, w := range want.Interfaces {
		wantI = append(wantI, normWantInterface(w))
	}
	sort.Slice(wantI, func(i, j int) bool { return wantI[i].Name < wantI[j].Name })
	gotNames, wantNames := make([]string, 0, len(got)), make([]string, 0, len(wantI))
	for _, g := range got {
		gotNames = append(gotNames, g.Name)
	}
	for _, w := range wantI {
		wantNames = append(wantNames, w.Name)
	}
	if !slices.Equal(gotNames, wantNames) {
		t.Fatalf("%s: interfaces %v, want %v", when, gotNames, wantNames)
	}
	for i := range got {
		g, w := normWantInterface(got[i]), wantI[i]
		if fmt.Sprintf("%+v", g) != fmt.Sprintf("%+v", w) {
			t.Errorf("%s: interface %s\n got  %+v\n want %+v", when, w.Name, g, w)
		}
	}

	gotP := readPrefixes(t, db, tenant)
	if len(gotP) != len(want.Prefixes) {
		t.Errorf("%s: %d prefixes %+v, want %d %+v", when, len(gotP), gotP, len(want.Prefixes), want.Prefixes)
	} else {
		wantP := append([]WantPrefix(nil), want.Prefixes...)
		sort.Slice(wantP, func(i, j int) bool { return wantP[i].Prefix < wantP[j].Prefix })
		sort.Slice(gotP, func(i, j int) bool { return gotP[i].Prefix < gotP[j].Prefix })
		for i := range gotP {
			g, w := gotP[i], wantP[i]
			if g.Prefix != w.Prefix || g.VRF != w.VRF || g.VLAN != w.VLAN || describeDHCP(g.DHCPManaged) != describeDHCP(w.DHCPManaged) ||
				g.CloudNetworkRef != w.CloudNetworkRef {
				t.Errorf("%s: prefix %s vrf=%q vlan=%d dhcp=%s cloud_network_ref=%q, want %s vrf=%q vlan=%d dhcp=%s cloud_network_ref=%q", when,
					g.Prefix, g.VRF, g.VLAN, describeDHCP(g.DHCPManaged), g.CloudNetworkRef,
					w.Prefix, w.VRF, w.VLAN, describeDHCP(w.DHCPManaged), w.CloudNetworkRef)
			}
		}
	}

	gotV := readVLANs(t, db, tenant)
	wantV := append([]WantVLAN(nil), want.VLANs...)
	sort.Slice(wantV, func(i, j int) bool { return wantV[i].VID < wantV[j].VID })
	if fmt.Sprint(gotV) != fmt.Sprint(wantV) {
		t.Errorf("%s: vlans %+v, want %+v", when, gotV, wantV)
	}

	gotW := readWirelessLANs(t, db, tenant, asset)
	wantW := append([]WantWirelessLAN(nil), want.WirelessLANs...)
	sort.Slice(wantW, func(i, j int) bool { return wantW[i].SSID < wantW[j].SSID })
	if fmt.Sprintf("%+v", gotW) != fmt.Sprintf("%+v", wantW) {
		t.Errorf("%s: wireless LANs %+v, want %+v", when, gotW, wantW)
	}

	gotC := readVirtualDeviceContexts(t, db, tenant, asset)
	wantC := make([]WantVirtualDeviceContext, 0, len(want.VirtualDeviceContexts))
	for _, w := range want.VirtualDeviceContexts {
		w.Interfaces = append([]string(nil), w.Interfaces...)
		sort.Strings(w.Interfaces)
		if len(w.Interfaces) == 0 {
			w.Interfaces = nil
		}
		wantC = append(wantC, w)
	}
	sort.Slice(wantC, func(i, j int) bool { return wantC[i].Name < wantC[j].Name })
	for i := range gotC {
		sort.Strings(gotC[i].Interfaces)
	}
	sort.Slice(gotC, func(i, j int) bool { return gotC[i].Name < gotC[j].Name })
	if fmt.Sprintf("%+v", gotC) != fmt.Sprintf("%+v", wantC) {
		t.Errorf("%s: virtual device contexts %+v, want %+v", when, gotC, wantC)
	}

	var p4, p6 string
	if err := db.QueryRow(`
		SELECT coalesce(host(ip4.address), ''), coalesce(host(ip6.address), '')
		  FROM public.assets a
		  LEFT JOIN public.ip_addresses ip4 ON ip4.tenant_id = a.tenant_id AND ip4.id = a.primary_ip4_id
		  LEFT JOIN public.ip_addresses ip6 ON ip6.tenant_id = a.tenant_id AND ip6.id = a.primary_ip6_id
		 WHERE a.tenant_id = $1 AND a.id = $2`, tenant, asset).Scan(&p4, &p6); err != nil {
		t.Fatal(err)
	}
	if p4 != want.PrimaryIP4 || p6 != want.PrimaryIP6 {
		t.Errorf("%s: primary addresses %q / %q, want %q / %q", when, p4, p6, want.PrimaryIP4, want.PrimaryIP6)
	}
}

// ------------------------------------------------------------ idempotence ----

type counts struct {
	rows     map[string]int
	observed map[string]int
}

// parityCounts reads the row count of every table an adapter's observation
// writes, and the observation_count of every row that carries one.
func parityCounts(t *testing.T, db *sql.DB, tenant string) counts {
	t.Helper()
	c := counts{rows: map[string]int{}, observed: map[string]int{}}
	for _, table := range []string{"assets", "interfaces", "mac_addresses", "ip_addresses", "prefixes", "vlans", "interface_tagged_vlans", "wireless_lan_groups", "wireless_lans", "wireless_links", "virtual_device_contexts", "interface_virtual_device_contexts"} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM public.`+table+` WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		c.rows[table] = n
	}
	for _, sel := range []struct{ table, key string }{
		{"interfaces", "name"},
		{"ip_addresses", "host(address)"},
		{"prefixes", "prefix::text"},
		{"vlans", "vid::text"},
		{"virtual_device_contexts", "name"},
	} {
		rows := q(t, db, `SELECT `+sel.key+`, observation_count FROM public.`+sel.table+` WHERE tenant_id = $1`, tenant)
		for rows.Next() {
			var (
				k string
				n int
			)
			if err := rows.Scan(&k, &n); err != nil {
				t.Fatal(err)
			}
			c.observed[sel.table+":"+k] = n
		}
		_ = rows.Close()
	}
	return c
}

// ---------------------------------------------------------------- secrets ----

// checkNoSecrets looks for every planted secret in every row of every table
// that carries a tenant_id, as JSON text — columns, JSONB payloads, change
// records, history, retained observations alike.
func checkNoSecrets(t *testing.T, db *sql.DB, tenant string, secrets []string) {
	t.Helper()
	rows := q(t, db, `
		SELECT c.table_name FROM information_schema.columns c
		  JOIN information_schema.tables tb ON tb.table_schema = c.table_schema AND tb.table_name = c.table_name
		 WHERE c.table_schema = 'public' AND c.column_name = 'tenant_id' AND tb.table_type = 'BASE TABLE'
		 ORDER BY c.table_name`)
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	_ = rows.Close()
	if len(tables) == 0 {
		t.Fatal("found no tenant tables to search: the secret check would pass without looking")
	}
	for _, table := range tables {
		for _, s := range secrets {
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM public."`+table+`" t
				WHERE t.tenant_id::text = $1 AND strpos(to_jsonb(t)::text, $2) > 0`, tenant, s).Scan(&n); err != nil {
				t.Fatalf("searching %s: %v", table, err)
			}
			if n > 0 {
				t.Errorf("planted secret %q reached %d row(s) of %s", s, n, table)
			}
		}
	}
}
