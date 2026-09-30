package services

// Generic-hostname marking on the OTHER intake paths ( B2, part B).
//
// marked the sensor's host observations and device-interrogation's
// peers. This pins the rest of the intake builders to one rule: a MEASURED
// name is marked, a name a person or a system of record supplied is not.
//
//   - discoveryObservation (sensor/scan/PCAP/cloud findings) is measured → marked;
//   - manualObservation (manual create, elevation, SBOM subjects, spreadsheet,
//     CMDB and NetBox imports) is declared or imported → never marked.
//
// The static dictionary alone applies here (no database), which is enough to
// pin WHETHER a path marks; the tenant-frequency half is pinned on the
// host-observation path's integration test and is the same decider.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// Mutation check: delete the MarkAll call at the end of discoveryObservation →
// `iphone` arrives unmarked at confidence 1 and this fails.
func TestDiscoveryObservation_MarksAGenericHostname(t *testing.T) {
	for _, tc := range []struct {
		host    string
		kind    identity.Kind
		generic bool
	}{
		{"iphone", identity.KindHostname, true},
		{"desk-laptop", identity.KindHostname, false},
		{"printer.corp.example", identity.KindFQDN, false}, // an FQDN is issued by the domain's owner
	} {
		t.Run(tc.host, func(t *testing.T) {
			f := IngestFinding{
				Hostname:  ptr(tc.host),
				IPAddress: ptr("192.0.2.10"),
				Port:      ptr(443),
				Protocol:  "TLS",
				RawData:   map[string]interface{}{"source": "sensor_discovery"},
			}
			obs, err := unscopedService().discoveryObservation(uuid.New(), f, f.IPAddress, identity.OwnershipInternal)
			if err != nil {
				t.Fatalf("discoveryObservation: %v", err)
			}
			id := identifierNamed(t, obs, tc.kind, tc.host)
			if id.Generic != tc.generic {
				t.Errorf("Generic = %v, want %v", id.Generic, tc.generic)
			}
			want := 1.0
			if tc.generic {
				want = identity.GenericConfidence
			}
			if id.Confidence != want {
				t.Errorf("Confidence = %v, want %v", id.Confidence, want)
			}
		})
	}
}

// A name somebody TYPED or a system of record supplied is a statement about
// which device this is. `printer` on a manual record is never marked, whatever
// the source kind the builder is handed by its declared and imported callers.
//
// Mutation check: add a MarkAll to manualObservation → this fails.
func TestManualObservation_NeverMarksADeclaredName(t *testing.T) {
	for _, src := range []identity.Source{
		{Kind: identity.SourceDeclared, Ref: "manual"},
		{Kind: identity.SourceImported, Ref: "import:spreadsheet"},
		{Kind: identity.SourceImported, Ref: "netbox:connection-1"},
	} {
		t.Run(src.Ref, func(t *testing.T) {
			in := models.AssetInput{ClassKey: assetclass.KeyServer, Hostname: ptr("printer"), IPAddress: ptr("192.0.2.11")}
			obs, err := unscopedService().manualObservation(uuid.New(), in, src)
			if err != nil {
				t.Fatalf("manualObservation: %v", err)
			}
			id := identifierNamed(t, obs, identity.KindHostname, "printer")
			if id.Generic || id.Confidence != 1 {
				t.Errorf("a declared name was marked generic: %+v", id)
			}
		})
	}
}
