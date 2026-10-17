package postgres_test

// DCIM row 1.4: the identity engine reads interfaces and IP addresses (ADR-0010
// D3). Each test drives the REAL path — identity.Intake builds the observation,
// identity.Engine resolves it, this package's repository writes it — against a
// real Postgres, so deleting the line that enforces a rule turns one red.

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type ifaceHarness struct {
	t      *testing.T
	db     *sql.DB
	tenant string
	repo   *pgrepo.Repository
	engine *identity.Engine
	intake *identity.Intake
	at     time.Time
}

func newIfaceHarness(t *testing.T) *ifaceHarness {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	repo := pgrepo.New(db)
	engine, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	intake, err := identity.NewIntake(repo)
	if err != nil {
		t.Fatal(err)
	}
	return &ifaceHarness{t: t, db: db, tenant: testdb.NewTenant(t, db).String(), repo: repo,
		engine: engine, intake: intake, at: time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)}
}

// agent is a host's own report of its interfaces: names known.
func (h *ifaceHarness) agent(ids ...identity.SightedIdentifier) identity.Sighting {
	h.at = h.at.Add(time.Minute)
	return identity.Sighting{
		TenantID: h.tenant, Channel: identity.ChannelAuthenticatedSession, ObservedAt: h.at,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "agent:it-host", Mode: identity.ModeActive},
		Identifiers: ids,
	}
}

// passive is a sensor's sighting: no interface names.
func (h *ifaceHarness) passive(ids ...identity.SightedIdentifier) identity.Sighting {
	h.at = h.at.Add(time.Minute)
	return identity.Sighting{
		TenantID: h.tenant, Channel: identity.ChannelL2Frame, ObservedAt: h.at,
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:it", Mode: identity.ModePassive},
		Identifiers: ids,
	}
}

func (h *ifaceHarness) resolve(s identity.Sighting, eps ...identity.EndpointObservation) identity.Resolution {
	h.t.Helper()
	ctx := context.Background()
	obs, err := h.intake.Build(ctx, s)
	if err != nil {
		h.t.Fatalf("Build: %v", err)
	}
	obs.Endpoints = append(obs.Endpoints, eps...)
	var res identity.Resolution
	if err := h.repo.RunInTx(ctx, h.tenant, func(bound *pgrepo.Repository) error {
		var rerr error
		res, rerr = h.engine.WithRepository(bound).Resolve(ctx, obs)
		return rerr
	}); err != nil {
		h.t.Fatalf("Resolve: %v", err)
	}
	return res
}

func (h *ifaceHarness) interfaces(asset string) []identity.StoredInterface {
	return h.repo.Interfaces(identity.AssetRef{TenantID: h.tenant, ID: asset})
}

func mac(v, iface string) identity.SightedIdentifier {
	return identity.SightedIdentifier{Kind: identity.KindMACAddress, Value: v, Interface: iface}
}

func ipOn(v, iface string) identity.SightedIdentifier {
	return identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: v, Interface: iface}
}

func named(ifs []identity.StoredInterface, name string) (identity.StoredInterface, bool) {
	for _, f := range ifs {
		if f.Name == name {
			return f, true
		}
	}
	return identity.StoredInterface{}, false
}

// TestIntegration_Identity_AddressOnSecondaryInterfaceMatches is "done means"
// of row 1.4: a host observation with two interfaces lands as ONE asset with
// both interfaces and their addresses, and a later observation naming only a
// MAC on the second interface — including a further MAC a person or an
// interrogation put there through the interfaces API — matches that asset.
//
// Mutation: drop the `mac_addresses` arm of findMACOwners' union and the
// further-MAC sighting creates a second asset.
func TestIntegration_Identity_AddressOnSecondaryInterfaceMatches(t *testing.T) {
	h := newIfaceHarness(t)
	first := h.resolve(h.agent(
		identity.SightedIdentifier{Kind: identity.KindHostname, Value: "it-dual"},
		mac("00:00:5e:00:80:01", "eth0"), ipOn("10.80.0.10", "eth0"),
		mac("00:00:5e:00:80:02", "eth1"), ipOn("10.80.1.10", "eth1"),
	))
	if first.Outcome != identity.OutcomeCreated {
		t.Fatalf("first report: outcome %s, want created", first.Outcome)
	}
	asset := first.Asset.ID
	ifs := h.interfaces(asset)
	if len(ifs) != 2 {
		t.Fatalf("interfaces = %+v, want eth0 and eth1", ifs)
	}
	eth1, ok := named(ifs, "eth1")
	if !ok || len(eth1.Addresses) != 1 || eth1.Addresses[0] != "10.80.1.10" {
		t.Fatalf("eth1 = %+v, want 10.80.1.10 on it", eth1)
	}

	// A further MAC on eth1, written as the interfaces API writes one: a
	// mac_addresses row, no identifier.
	if _, err := h.db.Exec(`
		INSERT INTO public.mac_addresses (tenant_id, interface_id, mac, source_kind)
		SELECT tenant_id, id, '00:00:5e:00:80:03'::macaddr8, 'declared' FROM public.interfaces
		 WHERE tenant_id = $1 AND asset_id = $2 AND name = 'eth1'`, h.tenant, asset); err != nil {
		t.Fatalf("declare a further MAC on eth1: %v", err)
	}

	for _, m := range []string{"00:00:5e:00:80:02", "00:00:5e:00:80:03"} {
		res := h.resolve(h.passive(mac(m, "")))
		if res.Asset.ID != asset {
			t.Errorf("a sighting of %s (on eth1) resolved %s to %q, want the host %q", m, res.Outcome, res.Asset.ID, asset)
		}
	}
}

// TestIntegration_Identity_DHCPPrefixAppliesDynamicRule replaces the
// segment-based test of the dynamic-address rule: the DHCP posture now comes
// from the IPAM prefix (`prefixes.dhcp_managed`). Inside a DHCP prefix, two
// devices seen at one address with different MACs are two devices — the
// address is a lease and does not vote. Inside a static prefix, the same
// address is evidence of the same device.
//
// Mutation: drop the prefixes read from SegmentSnapshot (scope.go) and the
// DHCP case resolves the second device onto the first's address.
func TestIntegration_Identity_DHCPPrefixAppliesDynamicRule(t *testing.T) {
	h := newIfaceHarness(t)
	for _, p := range []struct {
		cidr string
		dhcp bool
	}{{"10.81.0.0/24", true}, {"10.82.0.0/24", false}} {
		if _, err := h.db.Exec(`INSERT INTO public.prefixes (tenant_id, prefix, dhcp_managed, source_kind, status)
			VALUES ($1, $2::cidr, $3, 'declared', 'active')`, h.tenant, p.cidr, p.dhcp); err != nil {
			t.Fatalf("seed prefix %s: %v", p.cidr, err)
		}
	}

	a := h.resolve(h.passive(mac("00:00:5e:00:81:0a", ""), ipOn("10.81.0.5", "")))
	b := h.resolve(h.passive(mac("00:00:5e:00:81:0b", ""), ipOn("10.81.0.5", "")))
	if a.Asset.ID == "" || b.Asset.ID == a.Asset.ID || b.Outcome == identity.OutcomeConflict {
		t.Errorf("DHCP prefix: second device %s onto %q (first %q); want a separate device — a lease does not vote",
			b.Outcome, b.Asset.ID, a.Asset.ID)
	}

	c := h.resolve(h.passive(mac("00:00:5e:00:82:0c", ""), ipOn("10.82.0.5", "")))
	d := h.resolve(h.passive(mac("00:00:5e:00:82:0d", ""), ipOn("10.82.0.5", "")))
	if d.Outcome != identity.OutcomeConflict && d.Asset.ID != c.Asset.ID {
		t.Errorf("static prefix: second device %s onto %q (first %q); want the address to vote (matched or contested)",
			d.Outcome, d.Asset.ID, c.Asset.ID)
	}
}

// TestIntegration_Identity_NoIdentifierRowsOfKindIP_AfterIntake: after a full
// intake round — named and unnamed interfaces, both address families, a
// re-sighting — the addresses live in ip_addresses on interfaces and NOT ONE
// asset_identifiers row of kind ip_address exists. (`mac_address` stays an
// identifier row as well as an interface MAC: DATA_MODEL §9, "the kind stays
// for mac".) TestNoGoCodeInsertsAddressIdentifiers is the grep-style half.
//
// Mutation: delete the `isAddressKind` skip in repository.go's attach loop
// and the count below is non-zero.
func TestIntegration_Identity_NoIdentifierRowsOfKindIP_AfterIntake(t *testing.T) {
	h := newIfaceHarness(t)
	host := h.resolve(h.agent(
		identity.SightedIdentifier{Kind: identity.KindHostname, Value: "it-nokind"},
		mac("00:00:5e:00:84:01", "eth0"), ipOn("10.84.0.1", "eth0"), ipOn("2001:db8:84::1", "eth0"),
	))
	h.resolve(h.passive(mac("00:00:5e:00:84:01", ""), ipOn("10.84.0.1", "")))
	h.resolve(h.passive(mac("00:00:5e:00:84:09", ""), ipOn("10.84.0.9", "")))

	var identifierRows, addressRows, macRows int
	if err := h.db.QueryRow(`SELECT count(*) FROM public.asset_identifiers WHERE tenant_id = $1 AND kind = 'ip_address'`, h.tenant).Scan(&identifierRows); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(`SELECT count(*) FROM public.ip_addresses WHERE tenant_id = $1 AND assigned_kind = 'interface'`, h.tenant).Scan(&addressRows); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(`SELECT count(*) FROM public.interfaces WHERE tenant_id = $1 AND mac_address IS NOT NULL`, h.tenant).Scan(&macRows); err != nil {
		t.Fatal(err)
	}
	if identifierRows != 0 {
		t.Errorf("%d asset_identifiers rows of kind ip_address after intake, want 0", identifierRows)
	}
	if addressRows != 3 {
		t.Errorf("%d ip_addresses rows on interfaces, want 3 (two on the host, one on the second device)", addressRows)
	}
	if macRows != 2 {
		t.Errorf("%d interfaces carry a MAC, want 2", macRows)
	}
	owners, err := h.repo.FindByIdentifier(context.Background(), h.tenant, identity.KindIPAddress, "10.84.0.1", identity.ScopeTenantDefault)
	if err != nil || len(owners) != 1 || owners[0].ID != host.Asset.ID {
		t.Errorf("FindByIdentifier(10.84.0.1) = %+v, %v; want the host", owners, err)
	}
}

// TestIntegration_Identity_SyntheticInterfaceRenamesOnRealReport: a sensor
// that knows no interface names files the MAC and address under `observed-1`
// (type other, flagged synthetic). The host's own report naming the interface
// that carries that MAC renames it, rather than making a second interface for
// the same NIC; the address stays on it.
//
// Mutation: drop the synthetic-by-MAC branch of identity.ResolveInterfaces
// and the named report makes a second interface.
func TestIntegration_Identity_SyntheticInterfaceRenamesOnRealReport(t *testing.T) {
	h := newIfaceHarness(t)
	seen := h.resolve(h.passive(mac("00:00:5e:00:85:01", ""), ipOn("10.85.0.4", "")))
	ifs := h.interfaces(seen.Asset.ID)
	if len(ifs) != 1 || ifs[0].Name != identity.SyntheticInterfacePrefix+"1" || !ifs[0].Synthetic {
		t.Fatalf("after the sighting: interfaces %+v, want one synthetic observed-1", ifs)
	}
	var typ, ref string
	if err := h.db.QueryRow(`SELECT type, coalesce(source_ref, '') FROM public.interfaces WHERE tenant_id = $1 AND asset_id = $2`,
		h.tenant, seen.Asset.ID).Scan(&typ, &ref); err != nil {
		t.Fatal(err)
	}
	if typ != identity.SyntheticInterfaceType || ref != identity.SyntheticInterfaceSourceRef {
		t.Errorf("synthetic interface type=%q source_ref=%q, want %q and %q", typ, ref, identity.SyntheticInterfaceType, identity.SyntheticInterfaceSourceRef)
	}

	report := h.resolve(h.agent(mac("00:00:5e:00:85:01", "Gi0/1")))
	if report.Asset.ID != seen.Asset.ID {
		t.Fatalf("the named report resolved to %q, want %q", report.Asset.ID, seen.Asset.ID)
	}
	ifs = h.interfaces(seen.Asset.ID)
	if len(ifs) != 1 || ifs[0].Name != "GigabitEthernet0/1" || ifs[0].Synthetic {
		t.Fatalf("after the named report: interfaces %+v, want the one interface renamed GigabitEthernet0/1", ifs)
	}
	if len(ifs[0].Addresses) != 1 || ifs[0].Addresses[0] != "10.85.0.4" {
		t.Errorf("the renamed interface holds %v, want 10.85.0.4", ifs[0].Addresses)
	}
}

// TestIntegration_Identity_PrimaryIPSet: an asset the engine files addresses
// for gets a primary address of each family by rule — the first non-link-local
// one — and an endpoint at its address links the ip_addresses row.
//
// Mutation: drop the setPrimaryIPs call in fileUnderInterfaces and both
// primaries stay NULL; drop linkEndpointAddresses and the endpoint's
// ip_address_id stays NULL.
func TestIntegration_Identity_PrimaryIPSet(t *testing.T) {
	h := newIfaceHarness(t)
	res := h.resolve(h.agent(
		identity.SightedIdentifier{Kind: identity.KindHostname, Value: "it-primary"},
		mac("00:00:5e:00:86:01", "eth0"),
		ipOn("fe80::86:1", "eth0"), ipOn("10.86.0.7", "eth0"), ipOn("2001:db8:86::7", "eth0"),
	), identity.EndpointObservation{Address: "10.86.0.7", Port: 22, Transport: "tcp"})
	var v4, v6, linked sql.NullString
	if err := h.db.QueryRow(`
		SELECT host(p4.address), host(p6.address)
		  FROM public.assets a
		  LEFT JOIN public.ip_addresses p4 ON p4.id = a.primary_ip4_id
		  LEFT JOIN public.ip_addresses p6 ON p6.id = a.primary_ip6_id
		 WHERE a.tenant_id = $1 AND a.id = $2`, h.tenant, res.Asset.ID).Scan(&v4, &v6); err != nil {
		t.Fatal(err)
	}
	if v4.String != "10.86.0.7" {
		t.Errorf("primary_ip4 = %q, want 10.86.0.7", v4.String)
	}
	if v6.String != "2001:db8:86::7" {
		t.Errorf("primary_ip6 = %q, want 2001:db8:86::7 — a link-local address is never primary", v6.String)
	}
	if err := h.db.QueryRow(`
		SELECT host(ip.address) FROM public.asset_endpoints e
		  JOIN public.ip_addresses ip ON ip.id = e.ip_address_id
		 WHERE e.tenant_id = $1 AND e.asset_id = $2 AND e.port = 22`, h.tenant, res.Asset.ID).Scan(&linked); err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	if linked.String != "10.86.0.7" {
		t.Errorf("endpoint :22 links ip_address %q, want the 10.86.0.7 row", linked.String)
	}
}

// TestIntegration_Identity_EndpointLinksAddressThatArrivesLater: an endpoint
// recorded before its address was filed is linked when the address arrives —
// the order an asset's evidence lands in does not decide whether
// `asset_endpoints.ip_address_id` is set.
//
// Mutation: drop the linkEndpointAddresses call in fileUnderInterfaces and the
// endpoint stays unlinked (the call in upsertEndpoints ran before the address
// existed).
func TestIntegration_Identity_EndpointLinksAddressThatArrivesLater(t *testing.T) {
	h := newIfaceHarness(t)
	first := h.resolve(h.passive(mac("00:00:5e:00:87:01", "")),
		identity.EndpointObservation{Address: "10.87.0.9", Port: 443, Transport: "tcp"})
	var linked sql.NullString
	read := func() {
		t.Helper()
		if err := h.db.QueryRow(`SELECT e.ip_address_id::text FROM public.asset_endpoints e
			WHERE e.tenant_id = $1 AND e.asset_id = $2 AND e.port = 443`, h.tenant, first.Asset.ID).Scan(&linked); err != nil {
			t.Fatal(err)
		}
	}
	read()
	if linked.Valid {
		t.Fatalf("the endpoint links %s before any address row exists", linked.String)
	}
	later := h.resolve(h.agent(mac("00:00:5e:00:87:01", "eth0"), ipOn("10.87.0.9", "eth0")))
	if later.Asset.ID != first.Asset.ID {
		t.Fatalf("the report resolved to %q, want %q", later.Asset.ID, first.Asset.ID)
	}
	read()
	if !linked.Valid {
		t.Error("the endpoint at 10.87.0.9:443 is still unlinked after its address was filed")
	}
}

// TestIntegration_Identity_ProposalNamesTheMatchingInterface: a merge proposal
// for a contested candidate carries, on each matched MAC or address, the
// interface of the candidate that holds it — the evidence the Approvals card
// lists (row 1.4).
//
// Mutation: drop the annotateMatchedInterfaces call in OpenMergeProposal and
// the matched address names no interface.
func TestIntegration_Identity_ProposalNamesTheMatchingInterface(t *testing.T) {
	h := newIfaceHarness(t)
	host := h.resolve(h.agent(
		identity.SightedIdentifier{Kind: identity.KindHostname, Value: "it-contested"},
		mac("00:00:5e:00:88:01", "eth0"), ipOn("10.88.0.1", "eth0"),
		mac("00:00:5e:00:88:02", "eth1"), ipOn("10.88.1.1", "eth1"),
	))
	other := h.resolve(h.passive(mac("00:00:5e:00:88:09", ""), ipOn("10.88.1.1", "")))
	if other.Outcome != identity.OutcomeConflict || other.Proposal.ID == "" {
		t.Fatalf("a different MAC at the host's eth1 address: outcome %s, proposal %q; want a contested proposal", other.Outcome, other.Proposal.ID)
	}
	// Read the row the Approvals surface reads.
	var raw []byte
	if err := h.db.QueryRow(`SELECT changes_json FROM public.asset_history WHERE tenant_id = $1 AND id = $2`,
		h.tenant, other.Proposal.ID).Scan(&raw); err != nil {
		t.Fatalf("read the proposal: %v", err)
	}
	var row struct {
		Candidates []struct {
			AssetID string `json:"asset_id"`
			Matched []struct {
				Kind      string `json:"kind"`
				Value     string `json:"value"`
				Interface string `json:"interface"`
			} `json:"matched_identifiers"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &row); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range row.Candidates {
		if c.AssetID != host.Asset.ID {
			continue
		}
		for _, id := range c.Matched {
			if id.Kind == "ip_address" && id.Value == "10.88.1.1" {
				found = true
				if id.Interface != "eth1" {
					t.Errorf("matched 10.88.1.1 names interface %q, want eth1", id.Interface)
				}
			}
		}
	}
	if !found {
		t.Fatalf("the host candidate does not list 10.88.1.1 among its matched identifiers: %s", raw)
	}
}
