package services

// The observation builders, one per intake path (workstream 1.2).
//
// What these pin is the thing the survey found broken: six intake paths using
// four different dedupe keys. Each builder has to answer the same three
// questions honestly — what identifiers did we observe, what scope do the weak
// ones belong to, what class do we believe this is — and must not invent an
// answer to any of them.

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func ptr[T any](v T) *T { return &v }

// ids indexes an observation's identifiers by kind for assertions.
func ids(obs identity.Observation) map[identity.Kind]identity.Identifier {
	out := map[identity.Kind]identity.Identifier{}
	for _, id := range obs.Identifiers {
		out[id.Kind] = id
	}
	return out
}

// A service with no segment service: scope resolution returns empty, which is
// the honest answer when nothing can say which segment an address is in.
func unscopedService() *AssetService { return &AssetService{} }

// A finding goes through the one identity intake: a locally
// administered MAC seen on the wire is a randomised address and is withheld,
// and a `.local` name is a scoped hostname, not an unscoped fqdn — the same
// rules the host-observation path always applied, now applied to findings too.
func TestDiscoveryObservation_WithholdsRotatingMACs(t *testing.T) {
	f := IngestFinding{
		Hostname: ptr("laptop.local"), IPAddress: ptr("192.0.2.11"), Port: ptr(22), Protocol: "SSH",
		RawData: map[string]interface{}{"source": "sensor_discovery", "mac_address": "aa:bb:cc:00:11:22"},
	}
	obs, err := unscopedService().discoveryObservation(uuid.New(), f, f.IPAddress, identity.OwnershipInternal)
	if err != nil {
		t.Fatalf("discoveryObservation: %v", err)
	}
	got := ids(obs)
	if v, ok := got[identity.KindMACAddress]; ok {
		t.Errorf("a locally administered MAC from a finding became an identifier: %+v", v)
	}
	if _, ok := got[identity.KindFQDN]; ok {
		t.Error("`.local` was filed as an unscoped fqdn")
	}
	if v, ok := got[identity.KindHostname]; !ok || v.Value != "laptop.local" || v.Scope != identity.ScopeTenantDefault {
		t.Errorf("hostname identifier = %+v, want laptop.local scoped to the tenant default", v)
	}
}

func TestDiscoveryObservation_ExtractsEveryIdentifierTheFindingCarries(t *testing.T) {
	f := IngestFinding{
		Hostname:  ptr("db-1.example.test"),
		IPAddress: ptr("192.0.2.10"),
		Port:      ptr(5432),
		Protocol:  "TLS",
		AssetType: "server",
		RawData: map[string]interface{}{
			"source": "sensor_discovery",
			// A universally administered MAC (U/L bit clear). A locally
			// administered one is a randomised address on this channel and the
			// intake withholds it (TestDiscoveryObservation_WithholdsRotatingMACs).
			"mac_address":   "A8-BB-CC-DD-EE-01",
			"serial_number": "J7K2L9",
		},
	}
	obs, err := unscopedService().discoveryObservation(uuid.New(), f, f.IPAddress, identity.OwnershipInternal)
	if err != nil {
		t.Fatalf("discoveryObservation: %v", err)
	}

	got := ids(obs)
	// A DOTTED name is an fqdn, which is globally unique and needs no scope. A
	// single label would be a hostname, which identifies only within one.
	if v, ok := got[identity.KindFQDN]; !ok || v.Value != "db-1.example.test" {
		t.Errorf("fqdn identifier = %+v, want db-1.example.test", v)
	}
	if _, ok := got[identity.KindHostname]; ok {
		t.Error("a dotted name produced a hostname identifier as well; it is one identifier, not two")
	}
	if v, ok := got[identity.KindIPAddress]; !ok || v.Value != "192.0.2.10" {
		t.Errorf("ip_address identifier = %+v", v)
	}
	// Normalised, not passed through: two observers spelling one MAC
	// differently must produce the same row.
	if v, ok := got[identity.KindMACAddress]; !ok || v.Value != "a8:bb:cc:dd:ee:01" {
		t.Errorf("mac_address identifier = %+v, want the canonical a8:bb:cc:dd:ee:01 form", v)
	}
	if v, ok := got[identity.KindSerialNumber]; !ok || v.Value != "J7K2L9" {
		t.Errorf("serial_number identifier = %+v — case must survive, it is an opaque token", v)
	}
	if obs.Source.Kind != identity.SourceMeasured || obs.Source.Producer() != "sensor" {
		t.Errorf("source = %+v, want a measured sensor observation", obs.Source)
	}
}

func TestDiscoveryObservation_MapsTheLegacyAssetTypeToAClass(t *testing.T) {
	for _, tc := range []struct {
		legacy string
		want   string
	}{
		{"server", assetclass.KeyServer},
		{"endpoint", assetclass.KeyComputer},
		{"appliance", assetclass.KeyHardware},
		{"service", assetclass.KeyApplication},
		// An empty or unrecognised type leaves the hint EMPTY so the engine
		// falls back to unknown_host/external from the network ownership
		// (ADR-0002 D1). The old ingest defaulted it to "server", which is how
		// printers and switches came to be inventoried as servers.
		{"", ""},
		{"nonsense", ""},
	} {
		f := IngestFinding{Hostname: ptr("h.example.test"), AssetType: tc.legacy}
		obs, err := unscopedService().discoveryObservation(uuid.New(), f, nil, identity.OwnershipInternal)
		if err != nil {
			t.Fatalf("%q: %v", tc.legacy, err)
		}
		if obs.ClassHint != tc.want {
			t.Errorf("asset_type %q gave class hint %q, want %q", tc.legacy, obs.ClassHint, tc.want)
		}
	}
}

func TestDiscoveryObservation_CloudResourceIDIsTheIdentity(t *testing.T) {
	// A bucket has no routable address — the collector stamps 0.0.0.0, which the
	// caller strips. Before the engine, every such resource collapsed onto ONE
	// asset through that shared placeholder. The ARN is what tells them apart.
	f := IngestFinding{
		Hostname: ptr("audit-logs-bucket"),
		Protocol: atRestProtocolSentinel,
		RawData: map[string]interface{}{
			"source":         "cloud_discovery",
			"cloud_provider": "aws",
			"resource_type":  "s3",
			"arn":            "arn:aws:s3:::audit-logs-bucket",
		},
	}
	obs, err := unscopedService().discoveryObservation(uuid.New(), f, nil, identity.OwnershipInternal)
	if err != nil {
		t.Fatalf("discoveryObservation: %v", err)
	}
	got := ids(obs)
	if v, ok := got[identity.KindCloudResourceID]; !ok || v.Value != "arn:aws:s3:::audit-logs-bucket" {
		t.Fatalf("cloud_resource_id identifier = %+v", v)
	}
	if obs.ClassHint != assetclass.KeyObjectStorage {
		t.Errorf("class hint = %q, want %q", obs.ClassHint, assetclass.KeyObjectStorage)
	}
	if obs.Source.Producer() != "cloud" {
		t.Errorf("source producer = %q, want cloud", obs.Source.Producer())
	}
	// At rest: NO ENDPOINT. This is the retirement of the AT-REST port
	// sentinel — there is nothing to connect to, so there is no endpoint row,
	// rather than an endpoint on a fake port.
	if len(obs.Endpoints) != 0 {
		t.Errorf("an at-rest resource produced %d endpoint(s): %+v", len(obs.Endpoints), obs.Endpoints)
	}
}

func TestDiscoveryObservation_EndpointCarriesThePortAndProtocol(t *testing.T) {
	f := IngestFinding{
		IPAddress: ptr("192.0.2.20"),
		Hostname:  ptr("web.example.test"),
		Port:      ptr(443),
		Protocol:  "https",
	}
	obs, err := unscopedService().discoveryObservation(uuid.New(), f, f.IPAddress, identity.OwnershipInternal)
	if err != nil {
		t.Fatalf("discoveryObservation: %v", err)
	}
	if len(obs.Endpoints) != 1 {
		t.Fatalf("want one endpoint, got %+v", obs.Endpoints)
	}
	ep := obs.Endpoints[0]
	if ep.Address != "192.0.2.20" || ep.Port != 443 || ep.Transport != "tcp" {
		t.Errorf("endpoint = %+v", ep)
	}
	if ep.Protocol != "TLS" {
		t.Errorf("endpoint protocol = %q, want the enum value TLS (https maps onto it)", ep.Protocol)
	}
	if ep.FQDN != "web.example.test" {
		t.Errorf("endpoint fqdn = %q", ep.FQDN)
	}
}

func TestDiscoveryObservation_PortlessFindingIsNotASocket(t *testing.T) {
	f := IngestFinding{IPAddress: ptr("192.0.2.21"), Protocol: "TLS"}
	obs, err := unscopedService().discoveryObservation(uuid.New(), f, f.IPAddress, identity.OwnershipInternal)
	if err != nil {
		t.Fatalf("discoveryObservation: %v", err)
	}
	if len(obs.Endpoints) != 1 {
		t.Fatalf("want one endpoint, got %+v", obs.Endpoints)
	}
	if got := obs.Endpoints[0]; got.Port != 0 || got.Transport != "none" {
		t.Errorf("endpoint = %+v; a finding with no port is not a socket, so transport must be none "+
			"and the port must stay 0 (stored NULL) rather than being invented", got)
	}
}

func TestDiscoveryObservation_RefusesAnIdentifierlessFinding(t *testing.T) {
	// The one thing a builder must never do. An observation with no identifier
	// can never be matched again, so every re-observation of the same thing
	// creates another asset — which is what the old path did for any finding
	// carrying neither a hostname nor an address.
	_, err := unscopedService().discoveryObservation(uuid.New(), IngestFinding{Protocol: "TLS"}, nil, identity.OwnershipInternal)
	if err == nil {
		t.Fatal("a finding with no hostname, address or identifier was accepted")
	}
	if !strings.Contains(err.Error(), "identifier") {
		t.Errorf("error does not name the problem: %v", err)
	}
}

func TestDiscoveryObservation_DropsAMalformedIdentifierWithoutLosingTheFinding(t *testing.T) {
	// Leniency is a decision made at the call site, visibly: one bad MAC must
	// not lose a whole discovery, and it must not be recorded either.
	f := IngestFinding{
		Hostname: ptr("h.example.test"),
		RawData:  map[string]interface{}{"mac_address": "not-a-mac"},
	}
	obs, err := unscopedService().discoveryObservation(uuid.New(), f, nil, identity.OwnershipInternal)
	if err != nil {
		t.Fatalf("one malformed identifier lost the whole finding: %v", err)
	}
	if _, ok := ids(obs)[identity.KindMACAddress]; ok {
		t.Error("a value that does not normalise was recorded as a MAC address")
	}
	if _, ok := ids(obs)[identity.KindFQDN]; !ok {
		t.Error("the good identifier was dropped along with the bad one")
	}
}

func TestManualObservation_CarriesDeclaredIdentifiers(t *testing.T) {
	in := models.AssetInput{
		ClassKey: assetclass.KeyServer,
		Hostname: ptr("declared.example.test"),
		Identifiers: []models.AssetIdentifierInput{
			{Kind: "serial_number", Value: "SN-DECLARED"},
			{Kind: "cmdb_sys_id", Value: "sys-1", Scope: ptr("profile-a")},
			{Kind: "not_a_kind", Value: "ignored"},
		},
	}
	obs, err := unscopedService().manualObservation(uuid.New(), in,
		identity.Source{Kind: identity.SourceDeclared, Ref: "manual"})
	if err != nil {
		t.Fatalf("manualObservation: %v", err)
	}
	got := ids(obs)
	if v, ok := got[identity.KindSerialNumber]; !ok || v.Value != "SN-DECLARED" {
		t.Errorf("declared serial = %+v", v)
	}
	// A sys_id is unique within ONE CMDB instance, so the profile is its scope.
	if v, ok := got[identity.KindCMDBSysID]; !ok || v.Scope != "profile-a" {
		t.Errorf("cmdb_sys_id = %+v, want scope profile-a", v)
	}
	if len(obs.Identifiers) != 3 { // serial, sys_id, fqdn from the hostname
		t.Errorf("identifiers = %+v; an unknown kind must be ignored, not stored", obs.Identifiers)
	}
	if obs.Source.Kind != identity.SourceDeclared {
		t.Errorf("source kind = %q: a person typing an asset in is not a measurement", obs.Source.Kind)
	}
}

func TestManualObservation_PreservesExplicitIdentifierScopes(t *testing.T) {
	in := models.AssetInput{
		ClassKey:  assetclass.KeyServer,
		IPAddress: ptr("192.0.2.44"),
		Identifiers: []models.AssetIdentifierInput{
			{Kind: string(identity.KindIPAddress), Value: "192.0.2.44", Scope: ptr("lan-a")},
			{Kind: string(identity.KindHostname), Value: "edge-1", Scope: ptr("lan-a")},
		},
	}
	obs, err := unscopedService().manualObservation(uuid.New(), in,
		identity.Source{Kind: identity.SourceDeclared, Ref: "manual"})
	if err != nil {
		t.Fatalf("manualObservation: %v", err)
	}

	want := map[string]bool{
		identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.44", Scope: identity.ScopeTenantDefault}.Key(): true,
		identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.44", Scope: "lan-a"}.Key():                     true,
		identity.Identifier{Kind: identity.KindHostname, Value: "edge-1", Scope: "lan-a"}.Key():                          true,
	}
	for _, id := range obs.Identifiers {
		if !want[id.Key()] {
			continue
		}
		delete(want, id.Key())
		if id.Kind == identity.KindIPAddress && id.Scope == "lan-a" && id.StoredAssignment() != identity.AssignmentStatic {
			t.Errorf("explicit declared address = %+v, want static assignment", id)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing explicitly scoped identifiers: %v from %+v", want, obs.Identifiers)
	}
}

func TestManualObservation_DropsMalformedExplicitScopeWithoutLosingValidIdentifiers(t *testing.T) {
	in := models.AssetInput{
		ClassKey: assetclass.KeyServer,
		Identifiers: []models.AssetIdentifierInput{
			{Kind: string(identity.KindIPAddress), Value: "not-an-ip", Scope: ptr("lan-a")},
			{Kind: string(identity.KindHostname), Value: "core-1", Scope: ptr("lan-a")},
		},
	}
	obs, err := unscopedService().manualObservation(uuid.New(), in,
		identity.Source{Kind: identity.SourceDeclared, Ref: "manual"})
	if err != nil {
		t.Fatalf("manualObservation: %v", err)
	}

	for _, id := range obs.Identifiers {
		if id.Value == "not-an-ip" {
			t.Fatalf("malformed explicitly scoped IP was stored: %+v", obs.Identifiers)
		}
	}
	if got, ok := ids(obs)[identity.KindHostname]; !ok || got.Value != "core-1" || got.Scope != "lan-a" {
		t.Fatalf("valid scoped hostname = %+v, want core-1 in lan-a", got)
	}
}

func TestManualObservation_RefusesAnAssetWithNothingToIdentifyItBy(t *testing.T) {
	_, err := unscopedService().manualObservation(uuid.New(),
		models.AssetInput{ClassKey: assetclass.KeyServer, Description: ptr("just a description")},
		identity.Source{Kind: identity.SourceDeclared, Ref: "manual"})
	if err == nil {
		t.Fatal("an asset with no hostname, address or identifier was accepted")
	}
}

func TestFindingSourceNamesTheProducer(t *testing.T) {
	// The producer string is what an approval rule filters on
	// (QUERY_LANGUAGE §8), so a path that reports the wrong one silently
	// changes which rules fire.
	for _, tc := range []struct {
		raw          map[string]interface{}
		wantProducer string
		wantMode     identity.MeasurementMode
	}{
		{map[string]interface{}{"source": "sensor_discovery"}, "sensor", identity.ModePassive},
		{map[string]interface{}{"source": "pcap"}, "sensor", identity.ModePassive},
		{map[string]interface{}{"source": "cloud_discovery"}, "cloud", identity.ModeActive},
		{map[string]interface{}{"source": "device_interrogation"}, "interrogation", identity.ModeActive},
		{map[string]interface{}{"source": "active_scan"}, "scan", identity.ModeActive},
		{map[string]interface{}{"cloud_provider": "AWS"}, "cloud", identity.ModeActive},
	} {
		got := findingSource(IngestFinding{RawData: tc.raw})
		if got.Producer() != tc.wantProducer || got.Mode != tc.wantMode {
			t.Errorf("%v → %+v, want producer %q mode %q", tc.raw, got, tc.wantProducer, tc.wantMode)
		}
	}
}

// A scan finding, as the converter now hands it over, resolves to the scan
// producer measuring ACTIVELY — Source.Mode feeds identity reconcile ranking
// (active identity outranks passive) and isSighting.
func TestFindingSource_ScanFindingIsActiveScan(t *testing.T) {
	for _, src := range []string{"active_scan", "discovery_jobs"} {
		got := findingSource(IngestFinding{RawData: map[string]interface{}{"source": src}})
		want := identity.Source{Kind: identity.SourceMeasured, Ref: "scan", Mode: identity.ModeActive}
		if got != want {
			t.Errorf("source %q → %+v, want %+v", src, got, want)
		}
	}
	sensor := uuid.New().String()
	got := findingSource(IngestFinding{SourceSensorID: &sensor, RawData: map[string]interface{}{"source": "active_scan"}})
	if got.Ref != "scan:"+sensor || got.Mode != identity.ModeActive {
		t.Errorf("scan with sensor id → %+v", got)
	}
	if !findingCollectorSource(IngestFinding{RawData: map[string]interface{}{"source": "device_interrogation"}}) {
		t.Error("an interrogation row's collector must be verified like any other")
	}
}

func TestDiscoverySourceMetadata_ScanRowsStayInTheSensorBucket(t *testing.T) {
	for _, src := range []string{"sensor_discovery", "active_scan", "discovery_jobs", "pcap_upload"} {
		got := discoverySourceMetadata(IngestFinding{RawData: map[string]interface{}{"source": src}})
		if got["discovery_source"] != "sensor_discoveries" {
			t.Errorf("%s → %v", src, got["discovery_source"])
		}
	}
}

func TestManualObservation_ImportReceiptUsesCollectorClock(t *testing.T) {
	at := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	input := models.AssetInput{ClassKey: assetclass.KeyServer, Hostname: ptr("import.example.test"), ObservationReceiptID: "run-1:record-1", ObservationTime: at}
	obs, err := unscopedService().manualObservation(uuid.New(), input, identity.Source{Kind: identity.SourceImported, Ref: "cmdb:test"})
	if err != nil {
		t.Fatal(err)
	}
	if !obs.ObservedAt.Equal(at) || obs.Admission.ReceiptID != input.ObservationReceiptID {
		t.Fatalf("lost collector delivery metadata: %+v", obs)
	}
}
