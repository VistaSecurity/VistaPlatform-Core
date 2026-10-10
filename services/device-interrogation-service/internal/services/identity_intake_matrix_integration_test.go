package services

// The identity intake characterization matrix, device-interrogation-service
// half.
//
// Every intake path in this service that turns device evidence into identity
// is driven with the SAME evidence — one gateway's address (on ports
// 443/8443/9443 where the path can carry ports at all), with and without its
// MAC, with and without its SSH host key — at three places: inside a segment a
// controller measured as DHCP, inside a static segment, and inside no segment.
// The fixture's established asset already owns every identifier sent
// (shared/identity/identitytest/intakematrix). A path gets only the shapes its
// input can carry: no collector here reports a peer's SSH host key, and the
// Devices form has no MAC field.
//
// Each row records what the path did: its outcome, the observation its adapter
// handed the engine (scope, dynamic scopes, admission flags, the decision's
// reasons), the identifiers and endpoint rows it wrote, assets it created and
// proposals it opened. The expectation is TODAY's behaviour, read off the code
// by running it — not a statement that it is right. Rows the identity-intake
// issue lists as divergences say which item they belong to, so the PR that
// fixes an item knows which expectations it may flip and that nothing else
// should move. shared/identity/identitytest/intakematrix/README.md says how
// to read and update a row; the inventory-service half is
// services/inventory-service/internal/services/identity_intake_matrix_integration_test.go.
//
// Since (platform ADR-0003 D3) no path here resolves anything: each
// posts its sighting to inventory-service. Until that route ships, every row
// posts to shared/identity/identitytest/sightingserver — the REFERENCE route
// (Intake + the engine as inventory-service configures it, over this
// database) — through the real HTTP client (sighting_poster_setup_test.go).
// When inventory-service's route merges, run this against it and re-pin any
// row that moves; a row that moves then is a difference between the two
// resolutions, not a change in this service.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest/intakematrix"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// matrixSerial is the serial the serial-only paths attach. The fixture asset
// owns none, so these rows show what a direct write does with a NEW identifier.
const matrixSerial = "MATRIX-SERIAL-0001"

// diMatrix is one row's world: a fresh tenant, the gateway fixture, and the
// three intakes built the way cmd/main.go builds them (NewDeviceService(db),
// NewObservationSink(db), NewHostInventoryIngest(db, bypassDB)), all over the
// owner connection.
type diMatrix struct {
	*intakematrix.Fixture
	devices *DeviceService
	sink    *ObservationSink
	hosts   *HostInventoryIngest
}

func newDIMatrix(t *testing.T, raw *sql.DB) *diMatrix {
	t.Helper()
	tenant := testdb.NewTenant(t, raw)
	f := intakematrix.Setup(t, raw, tenant)
	return &diMatrix{Fixture: f, devices: NewDeviceService(raw), sink: NewObservationSink(raw), hosts: NewHostInventoryIngest(raw, raw)}
}

// manage gives an asset the asset_management row that makes it a device on
// the Devices page, which UpdateDevice requires.
func (m *diMatrix) manage(t *testing.T, asset uuid.UUID) {
	t.Helper()
	if _, err := m.DB.Exec(`INSERT INTO asset_management(tenant_id,asset_id,management_url) VALUES($1,$2,$3)`,
		m.Tenant, asset, "https://"+intakematrix.TenantAddr); err != nil {
		t.Fatal(err)
	}
}

// diErrOutcome names an intake error the way a row spells it.
func diErrOutcome(err error) string {
	var retained *identity.RetainedObservation
	switch {
	case err == nil:
		return ""
	case errors.As(err, &retained):
		return "retained:" + retained.Result.Outcome
	case errors.Is(err, ErrDeviceIdentityContested):
		return "contested"
	case errors.Is(err, errDeviceHasNoIdentifier):
		return "error:no_identifier"
	}
	var declared *DeviceIdentifierConflictError
	if errors.As(err, &declared) {
		if declared.ProposalID != "" {
			return "refused_conflict:proposal"
		}
		return "refused_conflict"
	}
	return "error:" + err.Error()
}

// diPath is one intake path. shapes lists the evidence shapes the path's
// input can carry at all; places defaults to every place.
type diPath struct {
	name   string
	shapes []intakematrix.Shape
	places []intakematrix.Place
	drive  func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect
}

var (
	diMACShapes  = []intakematrix.Shape{{}, {MAC: true}}
	diBareShapes = []intakematrix.Shape{{}}
	// Rows whose evidence names no address (a serial) or whose place is fixed
	// by the scenario: the place is the scenario's, not a dimension.
	diNoSegmentOnly = []intakematrix.Place{intakematrix.InNoSegment}
	diStaticOnly    = []intakematrix.Place{intakematrix.InStaticSegment}
)

// peerEvidence is how the collector vouched for a peer: a controller's client
// table (Authoritative) or a neighbour on a connected interface (Direct).
type peerEvidence int

const (
	peerFromController peerEvidence = iota
	peerFromNeighbour
)

// peerRun is one interrogation reporting the gateway as a peer of another
// device.
type peerRun struct {
	evidence peerEvidence
	// addrs are the peer's addresses in the order the collector lists them;
	// nil means the place's address alone.
	addrs []string
	// vlans is a net.vlans fact the run also reports (the DHCP overlay).
	vlans []map[string]any
}

// persistPeer drives ObservationSink.Persist — the sink both interrogation
// paths (in-cluster and agent result) hand their observations to — with one
// connects_to edge from the interrogated device to the gateway. The outcome
// is whether the edge landed, which is whether the peer resolved to an asset.
func (m *diMatrix) persistPeer(t *testing.T, p intakematrix.Place, s intakematrix.Shape, run peerRun) intakematrix.Effect {
	t.Helper()
	controller := subjectAsset(t, m.DB, m.Tenant, "matrix-controller")
	addrs := run.addrs
	if addrs == nil {
		addrs = []string{p.Addr()}
	}
	peer := di.PeerRef{DisplayName: intakematrix.AssetName}
	switch run.evidence {
	case peerFromController:
		peer.IdentityEvidence.ControllerInventory = true
	case peerFromNeighbour:
		peer.IdentityEvidence.ConnectedInterface = true
	}
	for _, a := range addrs {
		peer.Identifiers = append(peer.Identifiers, di.PeerIdentifier{Kind: di.IdentifierIPAddress, Value: a})
	}
	if s.MAC {
		peer.Identifiers = append(peer.Identifiers, di.PeerIdentifier{Kind: di.IdentifierMACAddress, Value: intakematrix.MAC})
	}
	obs := InterrogationObservations{
		ObservedAt:    m.Now.Add(-time.Minute),
		Relationships: []di.RelationshipObservation{{Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Peer: peer}},
	}
	if run.vlans != nil {
		obs.Facts = []di.FactObservation{{Key: facts.KeyNetVlans, Value: run.vlans, Confidence: 1}}
	}
	before := m.Take(t)
	err := m.sink.Persist(context.Background(), m.Tenant, controller, interrogationSource(uuid.New()), obs)
	out := diErrOutcome(err)
	if out == "" {
		var edges int
		if err := m.DB.QueryRow(`SELECT count(*) FROM asset_relationships WHERE tenant_id=$1 AND from_asset_id=$2`, m.Tenant, controller).Scan(&edges); err != nil {
			t.Fatal(err)
		}
		out = fmt.Sprintf("edges=%d", edges)
	}
	return m.Effect(t, before, out)
}

// hostReport is a remote (SSH) host-inventory collection of the gateway as
// shared/hostinventory reports it: hostname, interfaces and listeners. Its
// subject carries no ip_address identifier at all (hostPeerRef emits agent id,
// serial, hostname, fqdn and physical MACs), so the hostname is what the
// address SCOPES; the address itself reaches identity only as the scope and as
// the endpoints' address. Listeners are bound to the wildcard address, so the
// endpoints are recorded at the primary address.
func (m *diMatrix) hostReport(agent uuid.UUID, s intakematrix.Shape, ifaces [][]string) *hostinventory.Report {
	rep := &hostinventory.Report{
		Collected: m.Now.Add(-time.Minute),
		Mode:      hostinventory.ModeRemote,
		Platform:  hostinventory.PlatformLinux,
		AgentID:   agent.String(),
		Host:      hostinventory.Host{OS: "Linux", Hostname: intakematrix.AssetName},
		Sections: map[string]string{
			hostinventory.SectionHost:       hostinventory.SectionOK,
			hostinventory.SectionInterfaces: hostinventory.SectionOK,
			hostinventory.SectionListeners:  hostinventory.SectionOK,
		},
	}
	for i, addrs := range ifaces {
		ifc := hostinventory.Interface{Name: fmt.Sprintf("eth%d", i), Addresses: addrs, State: "up"}
		if s.MAC && i == 0 {
			ifc.MAC = intakematrix.MAC
		}
		rep.Interfaces = append(rep.Interfaces, ifc)
	}
	for _, port := range intakematrix.Ports {
		rep.Listeners = append(rep.Listeners, hostinventory.Listener{Proto: "tcp", Address: "0.0.0.0", Port: port, Process: "nginx"})
	}
	return rep
}

// materialiseHost drives HostInventoryIngest.MaterialiseAndRecord, the call
// the result processor makes for a finished remote host_inventory job.
//
// edit, when given, adjusts the report before it is projected — the
// address-assignment rows use it to say which interface the agent reported
// static and which DHCP.
func (m *diMatrix) materialiseHost(t *testing.T, s intakematrix.Shape, ifaces [][]string, edit ...func(*hostinventory.Report)) intakematrix.Effect {
	t.Helper()
	agent := seedHostInventoryAgent(t, m.DB, m.Tenant)
	job := newHostInventoryJob(t, m.DB, m.DB, m.Tenant, agent)
	rep := m.hostReport(agent, s, ifaces)
	for _, e := range edit {
		e(rep)
	}
	obs, err := hostinventory.ToObservations(rep)
	if err != nil {
		t.Fatal(err)
	}
	before := m.Take(t)
	counts, err := m.hosts.MaterialiseAndRecord(context.Background(), m.Tenant, agent, job, obs)
	out := diErrOutcome(err)
	if out == "" {
		out = string(counts.IdentityOutcome)
		if counts.ObservationID != "" && counts.AssetID == "" {
			out += ":no_asset"
		}
	}
	return m.Effect(t, before, out)
}

// createDevice drives DeviceService.CreateDevice, which is the Add device
// button's create (the probe has already run, or the operator typed it in).
// The outcome is where the device landed: on the fixture asset, on a new one,
// or what the error says.
func (m *diMatrix) createDevice(t *testing.T, req models.CreateDeviceRequest) intakematrix.Effect {
	t.Helper()
	before := m.Take(t)
	dev, err := m.devices.CreateDevice(context.Background(), m.Tenant, req)
	out := diErrOutcome(err)
	if out == "" {
		out = "device:other"
		if dev.ID == m.Asset {
			out = "device:fixture"
		}
	}
	return m.Effect(t, before, out)
}

func diOK(err error) string {
	if out := diErrOutcome(err); out != "" {
		return out
	}
	return "ok"
}

func diPaths() []diPath {
	return []diPath{
		{
			// Interrogation peer from a controller's client table
			// (ControllerInventory → controller_inventory channel).
			name: "peer_controller", shapes: diMACShapes,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				return m.persistPeer(t, p, s, peerRun{evidence: peerFromController})
			},
		},
		{
			// Interrogation peer from an LLDP/CDP neighbour table
			// (ConnectedInterface → l2_frame channel).
			name: "peer_neighbour", shapes: diMACShapes,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				return m.persistPeer(t, p, s, peerRun{evidence: peerFromNeighbour})
			},
		},
		{
			// A controller peer with two addresses, the one in no segment
			// listed first and the dynamic-LAN one second: each is scoped on
			// its own (peerObservation used to scope both by the first).
			name: "peer_controller_two_addresses", shapes: diMACShapes, places: diNoSegmentOnly,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				return m.persistPeer(t, p, s, peerRun{evidence: peerFromController, addrs: []string{intakematrix.TenantAddr, intakematrix.DynamicAddr}})
			},
		},
		{
			// A controller peer on the static segment, in a run whose own
			// net.vlans fact says that VLAN hands out DHCP. The segment has no
			// posture before the run.
			name: "peer_controller_run_reports_dhcp", shapes: diMACShapes, places: diStaticOnly,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				return m.persistPeer(t, p, s, peerRun{evidence: peerFromController,
					vlans: []map[string]any{{"name": "matrix static LAN", "subnet": intakematrix.StaticCIDR, "dhcp_enabled": true}}})
			},
		},
		{
			// The same run, but an operator has marked the static segment
			// static: the stored effective posture stays static, the run's
			// overlay is what decides.
			name: "peer_controller_run_reports_dhcp_operator_static", shapes: diMACShapes, places: diStaticOnly,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				if res, err := pgidentity.RecordSegmentPosture(context.Background(), m.DB, m.Tenant.String(), m.StaticSegment.String(),
					pgidentity.PostureOperator, false, pgidentity.PostureEvidence{ObservedAt: m.Now}); err != nil || !res.Written {
					t.Fatalf("operator posture: written=%v err=%v", res.Written, err)
				}
				return m.persistPeer(t, p, s, peerRun{evidence: peerFromController,
					vlans: []map[string]any{{"name": "matrix static LAN", "subnet": intakematrix.StaticCIDR, "dhcp_enabled": true}}})
			},
		},
		{
			// Host inventory (remote collection) of the gateway with one
			// interface at the place's address: hostSighting.
			name: "host_inventory", shapes: diMACShapes,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				return m.materialiseHost(t, s, [][]string{{p.Addr() + "/24"}})
			},
		},
		{
			// Host inventory of a gateway with two interfaces: the primary in
			// no segment, the second on the dynamic LAN.
			name: "host_inventory_two_interfaces", shapes: diMACShapes, places: diNoSegmentOnly,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				return m.materialiseHost(t, s, [][]string{{intakematrix.TenantAddr + "/24"}, {intakematrix.DynamicAddr + "/24"}})
			},
		},
		{
			// The same two-interface gateway, with the agent saying how each
			// address is assigned: the dynamic-LAN address is its
			// static configuration (a router's own LAN address), the
			// no-segment one a DHCP lease. Each address is offered as its own
			// ip_address under its own scope, carrying that assignment; on a
			// match the gateway's rows must say so.
			name: "host_inventory_two_interfaces_static_and_dhcp", shapes: diMACShapes, places: diNoSegmentOnly,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				tenantAddr, dynAddr := intakematrix.TenantAddr+"/24", intakematrix.DynamicAddr+"/24"
				eff := m.materialiseHost(t, s, [][]string{{tenantAddr}, {dynAddr}}, func(rep *hostinventory.Report) {
					rep.Interfaces[0].DynamicAddresses = []string{tenantAddr}
					rep.Interfaces[1].StaticAddresses = []string{dynAddr}
				})
				if s.MAC {
					for addr, want := range map[string]string{intakematrix.TenantAddr: "dynamic", intakematrix.DynamicAddr: "static"} {
						var got string
						if err := m.DB.QueryRow(`SELECT coalesce(address_assignment,'') FROM asset_identifiers
						   WHERE tenant_id=$1 AND asset_id=$2 AND kind='ip_address' AND value=$3`, m.Tenant, m.Asset, addr).Scan(&got); err != nil {
							t.Fatalf("%s on the gateway: %v", addr, err)
						}
						if got != want {
							t.Errorf("%s on the gateway carries assignment %q, want %q (the agent's report)", addr, got, want)
						}
					}
				}
				return eff
			},
		},
		{
			// Add device, typed in by hand (no probe evidence): CreateDevice
			// → deviceSighting (person). The form has no MAC field;
			// its management URL names a port but makes no endpoint.
			name: "add_device_typed", shapes: diBareShapes,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				addr, url := p.Addr(), "https://"+p.Addr()+":443"
				return m.createDevice(t, models.CreateDeviceRequest{DeviceType: "unifi", IPAddress: &addr, ManagementURL: &url})
			},
		},
		{
			// Add device after the probe identified the gateway and read its
			// serial (DiscoveredDeviceInfo.ApplyTo → ProbeEvidence
			// Direct+Authoritative). The probe's MAC goes to metadata only.
			name: "add_device_probed", shapes: diMACShapes,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				url := "https://" + p.Addr() + ":443"
				req := models.CreateDeviceRequest{DeviceType: "unifi", ManagementURL: &url}
				info := DiscoveredDeviceInfo{SerialNumber: matrixSerial, IPAddress: p.Addr(), TargetHost: p.Addr(), TargetPort: 443}
				if s.MAC {
					info.MacAddress = intakematrix.MAC
				}
				info.ApplyTo(&req, false)
				return m.createDevice(t, req)
			},
		},
		{
			// Device update of the gateway itself with its own address:
			// UpdateDevice → attachAddressIdentifiers, a direct
			// AttachIdentifiers with no engine.
			name: "device_update_self", shapes: diBareShapes,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				m.manage(t, m.Asset)
				addr := p.Addr()
				before := m.Take(t)
				_, err := m.devices.UpdateDevice(context.Background(), m.Tenant, m.Asset, models.UpdateDeviceRequest{IPAddress: &addr})
				eff := m.Effect(t, before, diOK(err))
				// Owner decision 1 / ADR-0003 D1: an address the operator typed
				// on the device is pinned, whatever its segment's DHCP flag.
				var assignment string
				if qerr := m.DB.QueryRow(`SELECT coalesce(address_assignment,'') FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2 AND kind='ip_address' AND value=$3`,
					m.Tenant, m.Asset, addr).Scan(&assignment); qerr != nil || assignment != string(identity.AssignmentStatic) {
					t.Errorf("typed address %s on the device: assignment %q (%v), want static", addr, assignment, qerr)
				}
				return eff
			},
		},
		{
			// Device update of ANOTHER managed device that declares the
			// gateway's address.
			name: "device_update_other", shapes: diBareShapes,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				other := subjectAsset(t, m.DB, m.Tenant, "matrix-other")
				m.manage(t, other)
				addr := p.Addr()
				before := m.Take(t)
				_, err := m.devices.UpdateDevice(context.Background(), m.Tenant, other, models.UpdateDeviceRequest{IPAddress: &addr})
				return m.Effect(t, before, diOK(err))
			},
		},
		{
			// Device update supplying a serial: applyDeviceFields' direct
			// AttachIdentifiers (device_service.go:559). A serial has no
			// scope, so the place is immaterial.
			name: "device_update_serial", shapes: diBareShapes, places: diNoSegmentOnly,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				m.manage(t, m.Asset)
				serial := matrixSerial
				before := m.Take(t)
				_, err := m.devices.UpdateDevice(context.Background(), m.Tenant, m.Asset, models.UpdateDeviceRequest{SerialNumber: &serial})
				return m.Effect(t, before, diOK(err))
			},
		},
		{
			// Interrogation self-identity: Persist with the device's own
			// DeviceIdentity → persistIdentity's direct AttachIdentifiers of
			// the serial. Collectors report no address or MAC here.
			name: "interrogation_self_identity", shapes: diBareShapes, places: diNoSegmentOnly,
			drive: func(t *testing.T, m *diMatrix, p intakematrix.Place, s intakematrix.Shape) intakematrix.Effect {
				before := m.Take(t)
				err := m.sink.Persist(context.Background(), m.Tenant, m.Asset, interrogationSource(uuid.New()), InterrogationObservations{
					ObservedAt: m.Now.Add(-time.Minute), DeviceIdentity: &di.DeviceIdentity{SerialNumber: matrixSerial},
				})
				return m.Effect(t, before, diOK(err))
			},
		},
	}
}

func TestIntegration_IdentityIntakeMatrix_DeviceInterrogationService(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	seen := map[string]bool{}
	for _, path := range diPaths() {
		t.Run(path.name, func(t *testing.T) {
			places := path.places
			if places == nil {
				places = intakematrix.Places
			}
			for _, place := range places {
				t.Run(place.String(), func(t *testing.T) {
					for _, shape := range path.shapes {
						t.Run(shape.String(), func(t *testing.T) {
							key := path.name + "/" + place.String() + "/" + shape.String()
							seen[key] = true
							want, ok := diMatrixWant[key]
							m := newDIMatrix(t, raw)
							got := path.drive(t, m, place, shape)
							if !ok {
								t.Errorf("no expectation for this row; today it is:\n\t%q: %q,", key, got.String())
								return
							}
							intakematrix.Check(t, got, want)
						})
					}
				})
			}
		})
	}
	if !t.Failed() {
		for key := range diMatrixWant {
			if !seen[key] {
				t.Errorf("expectation %q names no row; remove it", key)
			}
		}
	}
}

// diMatrixWant is TODAY's behaviour, one line per row. Comments name the
// identity-intake issue's divergence items (1–10) a row demonstrates; only a
// PR that changes that item's rule should flip those rows.
var diMatrixWant = map[string]string{
	// issue item 2: the measured-DHCP segment keeps the gateway's own LAN address from voting
	"peer_controller/dyn_segment/ip": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=dyn dyn=[dyn] ip=[dyn] kinds=- adm=[auth] reasons=[dynamic_address_without_device_binding] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// issue item 3 (decision 3): a controller peer (Authoritative, not Direct) that the fixture's MAC owns is supporting evidence of its owner, as in inventory-service
	"peer_controller/dyn_segment/ip+mac": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac] adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// issue item 3 (decision 3): one existing owner is supporting evidence whatever
	// ProvisionalInventory says, so this path now answers as inventory-service does
	// (its manual_create/static_segment/ip and source_import rows).
	"peer_controller/static_segment/ip": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=static dyn=- ip=[static] kinds=- adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// issue item 3
	"peer_controller/static_segment/ip+mac": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=static dyn=- ip=[static] kinds=[mac] adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// issue item 3
	"peer_controller/no_segment/ip": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=tenant dyn=- ip=[tenant] kinds=- adm=[auth] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// issue item 3
	"peer_controller/no_segment/ip+mac": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=tenant dyn=- ip=[tenant] kinds=[mac] adm=[auth] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// issue item 2
	"peer_neighbour/dyn_segment/ip":        "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=dyn dyn=[dyn] ip=[dyn] kinds=- adm=[direct] reasons=[dynamic_address_without_device_binding] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"peer_neighbour/dyn_segment/ip+mac":    "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"peer_neighbour/static_segment/ip":     "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=static dyn=- ip=[static] kinds=- adm=[direct] reasons=[direct_scoped_address] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"peer_neighbour/static_segment/ip+mac": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=static dyn=- ip=[static] kinds=[mac] adm=[direct] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// issue item 2 inverted here: in this engine the no-segment address does NOT out-vote the dynamic one; both stay unresolved (item 3)
	"peer_neighbour/no_segment/ip":     "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=tenant dyn=- ip=[tenant] kinds=- adm=[direct] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"peer_neighbour/no_segment/ip+mac": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=tenant dyn=- ip=[tenant] kinds=[mac] adm=[direct] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// item 5 fixed (sightings): each address scoped on its own; the sighting segment is the first REAL one (dyn)
	"peer_controller_two_addresses/no_segment/ip": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=dyn dyn=[dyn] ip=[dyn,tenant] kinds=- adm=[auth] reasons=[dynamic_address_without_device_binding] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// item 5 fixed (sightings): each address scoped on its own; the sighting segment is the first REAL one (dyn)
	"peer_controller_two_addresses/no_segment/ip+mac": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=dyn dyn=[dyn] ip=[dyn,tenant] kinds=[mac] adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// issue item 7: the run's net.vlans DHCP overlay marks the static segment dynamic for this peer (ensureVLANSegments also records the measured posture on it).
	// Owner decision 1: the gateway holds this address DECLARED, so it is pinned and admission no longer reads it as a lease;
	// the peer is still Authoritative-only, not Direct, so it is not established — and is linked as supporting evidence
	"peer_controller_run_reports_dhcp/static_segment/ip": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=static dyn=[static] ip=[static] kinds=- adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// issue item 7
	"peer_controller_run_reports_dhcp/static_segment/ip+mac": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=static dyn=[static] ip=[static] kinds=[mac] adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// item 7 fixed (sightings): no per-run DHCP overlay; the operator's static posture stands
	"peer_controller_run_reports_dhcp_operator_static/static_segment/ip": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=static dyn=- ip=[static] kinds=- adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// item 7 fixed (sightings): no per-run DHCP overlay; the operator's static posture stands
	"peer_controller_run_reports_dhcp_operator_static/static_segment/ip+mac": "outcome=edges=1 obs=[1x{src=measured/interrogation/active scope=static dyn=- ip=[static] kinds=[mac] adm=[auth] reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"host_inventory/dyn_segment/ip":                                          "outcome=unresolved:no_asset obs=[1x{src=measured/agent/active scope=dyn dyn=[dyn] ip=[dyn] kinds=- adm=[direct,auth] reasons=[dynamic_address_without_device_binding] state=unresolved asset=-}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// not issue item 1: endpoints ride on the observation and land only on a match
	"host_inventory/dyn_segment/ip+mac": "outcome=matched obs=[1x{src=measured/agent/active scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac] adm=[direct,auth] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=[hostname@dyn] resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// decision 1: host inventory offers the address as an identifier, so a direct, authoritative collection in a static segment
	// matches the address's owner where it used to have nothing to bind
	"host_inventory/static_segment/ip":     "outcome=matched obs=[1x{src=measured/agent/active scope=static dyn=- ip=[static] kinds=- adm=[direct,auth] reasons=[direct_scoped_address] state=linked asset=fixture}] ids=[hostname@static] resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"host_inventory/static_segment/ip+mac": "outcome=matched obs=[1x{src=measured/agent/active scope=static dyn=- ip=[static] kinds=[mac] adm=[direct,auth] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=[hostname@static] resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// decision 1 +: the address now reaches the engine as an identifier the gateway owns; it cannot establish
	// (no segment), and its single owner makes it supporting evidence rather than unresolved
	// — and since D4 the direct measurement's sockets attach to that single owner (ports), its identifiers stay held
	"host_inventory/no_segment/ip":     "outcome=supporting obs=[1x{src=measured/agent/active scope=tenant dyn=- ip=[tenant] kinds=- adm=[direct,auth] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	"host_inventory/no_segment/ip+mac": "outcome=matched obs=[1x{src=measured/agent/active scope=tenant dyn=- ip=[tenant] kinds=[mac] adm=[direct,auth] reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=[hostname@tenant] resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// Intake's sighting segment is the first address in a real segment (dyn), not the primary's tenant default
	"host_inventory_two_interfaces/no_segment/ip": "outcome=supporting obs=[1x{src=measured/agent/active scope=dyn dyn=[dyn] ip=[dyn,tenant] kinds=- adm=[direct,auth] reasons=[dynamic_address_without_device_binding] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// Intake's sighting segment is the first address in a real segment (dyn), not the primary's tenant default
	"host_inventory_two_interfaces/no_segment/ip+mac": "outcome=matched obs=[1x{src=measured/agent/active scope=dyn dyn=[dyn] ip=[dyn,tenant] kinds=[mac] adm=[direct,auth] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=[hostname@tenant] resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// Intake's sighting segment is the first address in a real segment (dyn), as above
	"host_inventory_two_interfaces_static_and_dhcp/no_segment/ip": "outcome=supporting obs=[1x{src=measured/agent/active scope=dyn dyn=[dyn] ip=[dyn,tenant] kinds=- adm=[direct,auth] reasons=[dynamic_address_without_device_binding] state=linked asset=fixture}] ids=- resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// Intake's sighting segment is the first address in a real segment (dyn), as above
	"host_inventory_two_interfaces_static_and_dhcp/no_segment/ip+mac": "outcome=matched obs=[1x{src=measured/agent/active scope=dyn dyn=[dyn] ip=[dyn,tenant] kinds=[mac] adm=[direct,auth] reasons=[direct_scoped_interface] state=linked asset=fixture}] ids=[hostname@tenant] resourced=- ports=[443,8443,9443] new_assets=0 other_ids=0 other_ports=0 proposals=0",
	//: the form's address is sent once (IP field and management URL host were two identifiers)
	"add_device_typed/dyn_segment/ip": "outcome=retained:unresolved obs=[1x{src=declared/manual/- scope=dyn dyn=[dyn] ip=[dyn] kinds=- adm=- reasons=[dynamic_address_without_device_binding] state=unresolved asset=-}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	//: the form's address is sent once (IP field and management URL host were two identifiers)
	"add_device_typed/static_segment/ip": "outcome=device:fixture obs=[1x{src=declared/manual/- scope=static dyn=- ip=[static] kinds=- adm=- reasons=[insufficient_identity_evidence] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	//: the form's address is sent once (IP field and management URL host were two identifiers)
	"add_device_typed/no_segment/ip": "outcome=device:fixture obs=[1x{src=declared/manual/- scope=tenant dyn=- ip=[tenant] kinds=- adm=- reasons=[network_scope_unresolved] state=linked asset=fixture}] ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	//: the address is sent once
	"add_device_probed/dyn_segment/ip": "outcome=device:other obs=[1x{src=declared/manual/- scope=dyn dyn=[dyn] ip=[dyn] kinds=- adm=[direct,auth] reasons=[authoritative_identifier] state=linked asset=other}] ids=- resourced=- ports=- new_assets=1 other_ids=1 other_ports=0 proposals=0",
	// review: the probe's MAC is stored measured (it read it; the person did not type it), so the gateway's MAC row keeps its provenance
	"add_device_probed/dyn_segment/ip+mac": "outcome=device:fixture obs=[1x{src=declared/manual/- scope=dyn dyn=[dyn] ip=[dyn] kinds=[mac] adm=[direct,auth] reasons=[authoritative_identifier] state=linked asset=fixture}] ids=[serial_number@-] resourced=[ip@dyn:measured>declared] ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	//: the address is sent once
	"add_device_probed/static_segment/ip": "outcome=device:fixture obs=[1x{src=declared/manual/- scope=static dyn=- ip=[static] kinds=- adm=[direct,auth] reasons=[authoritative_identifier] state=linked asset=fixture}] ids=[serial_number@-] resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// review: the probe's MAC is stored measured (it read it; the person did not type it), so the gateway's MAC row keeps its provenance
	"add_device_probed/static_segment/ip+mac": "outcome=device:fixture obs=[1x{src=declared/manual/- scope=static dyn=- ip=[static] kinds=[mac] adm=[direct,auth] reasons=[authoritative_identifier] state=linked asset=fixture}] ids=[serial_number@-] resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	//: the address is sent once
	"add_device_probed/no_segment/ip": "outcome=device:fixture obs=[1x{src=declared/manual/- scope=tenant dyn=- ip=[tenant] kinds=- adm=[direct,auth] reasons=[authoritative_identifier] state=linked asset=fixture}] ids=[serial_number@-] resourced=[ip@tenant:measured>declared] ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// review: the probe's MAC is stored measured (it read it; the person did not type it), so the gateway's MAC row keeps its provenance
	"add_device_probed/no_segment/ip+mac": "outcome=device:fixture obs=[1x{src=declared/manual/- scope=tenant dyn=- ip=[tenant] kinds=[mac] adm=[direct,auth] reasons=[authoritative_identifier] state=linked asset=fixture}] ids=[serial_number@-] resourced=[ip@tenant:measured>declared] ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// Owner decision 1 / ADR-0003 D1: a Devices-form edit is a declaration FOR the device (target_asset_id → ResolveDeclaredFor): attached at once, the typed address upgraded to declared and pinned static (asserted by the drive)
	"device_update_self/dyn_segment/ip": "outcome=ok obs=- ids=- resourced=[ip@dyn:measured>declared] ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// Owner decision 1 / ADR-0003 D1: a Devices-form edit is a declaration FOR the device (target_asset_id → ResolveDeclaredFor): attached at once, the typed address upgraded to declared and pinned static (asserted by the drive)
	"device_update_self/static_segment/ip": "outcome=ok obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// Owner decision 1 / ADR-0003 D1: a Devices-form edit is a declaration FOR the device (target_asset_id → ResolveDeclaredFor): attached at once, the typed address upgraded to declared and pinned static (asserted by the drive)
	"device_update_self/no_segment/ip": "outcome=ok obs=- ids=- resourced=[ip@tenant:measured>declared] ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// item 4: another asset's address typed on this device is refused whole — 409 and the identifier edit's merge proposal, nothing written
	"device_update_other/dyn_segment/ip": "outcome=refused_conflict:proposal obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	// item 4: another asset's address typed on this device is refused whole — 409 and the identifier edit's merge proposal, nothing written
	"device_update_other/static_segment/ip": "outcome=refused_conflict:proposal obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	// item 4: another asset's address typed on this device is refused whole — 409 and the identifier edit's merge proposal, nothing written
	"device_update_other/no_segment/ip": "outcome=refused_conflict:proposal obs=- ids=- resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=1",
	// Owner decision 1: the typed serial is a declaration for the device and attaches at once
	"device_update_serial/no_segment/ip": "outcome=ok obs=- ids=[serial_number@-] resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
	// item 4 fixed: the serial goes through the engine, bound by the device's own identifiers; authoritative session, attached to the device
	"interrogation_self_identity/no_segment/ip": "outcome=ok obs=[1x{src=measured/interrogation/active scope=dyn dyn=[dyn] ip=[dyn,static,tenant] kinds=[mac,ssh] adm=[direct,auth] reasons=[authoritative_identifier] state=linked asset=fixture}] ids=[serial_number@-] resourced=- ports=- new_assets=0 other_ids=0 other_ports=0 proposals=0",
}
