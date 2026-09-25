package pipelinetest_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/pipelinetest"
)

const dir = "../testdata/pipeline"

// TestChain_EveryHopReadsTheGoldenBeforeIt is the drift check, runnable
// without a database: each downstream golden must record the hash of the
// golden it was generated from, so regenerating hop N without regenerating
// hop N+1 fails here, in the plain unit-test run, as well as in hop N+1's own
// DB-integration test.
func TestChain_EveryHopReadsTheGoldenBeforeIt(t *testing.T) {
	root := pipelinetest.Dir(t, dir)
	for _, vendor := range pipelinetest.Vendors {
		t.Run(vendor, func(t *testing.T) {
			vdir := filepath.Join(root, vendor)
			pipelinetest.LoadScenario(t, root, vendor)

			var hop2 pipelinetest.Hop2Handoff
			pipelinetest.ReadJSON(t, filepath.Join(vdir, pipelinetest.Hop2HandoffFile), &hop2)
			if got := pipelinetest.Hash(t, filepath.Join(vdir, pipelinetest.Hop1HandoffFile)); hop2.InputSHA256 != got {
				t.Errorf("hop 2 was generated from a different hop-1 handoff (recorded %s, now %s): "+
					"regenerate hop 2 (discovery-processor-service) and hop 3 with -update-golden", hop2.InputSHA256, got)
			}
			var hop3 pipelinetest.Hop3Inventory
			pipelinetest.ReadJSON(t, filepath.Join(vdir, pipelinetest.Hop3InventoryFile), &hop3)
			if got := pipelinetest.Hash(t, filepath.Join(vdir, pipelinetest.Hop2HandoffFile)); hop3.InputSHA256 != got {
				t.Errorf("hop 3 was generated from a different hop-2 handoff (recorded %s, now %s): "+
					"regenerate hop 3 (inventory-service) with -update-golden", hop3.InputSHA256, got)
			}
		})
	}
}

// TestChain_NoGoldenCarriesPlantedSecrets: the fixtures plant
// MUST-NOT-BE-COLLECTED wherever a vendor returns material we must never
// store. A golden is a copy of what the pipeline stored or forwarded, so the
// string appearing in one is a leak at that hop.
func TestChain_NoGoldenCarriesPlantedSecrets(t *testing.T) {
	root := pipelinetest.Dir(t, dir)
	planted := 0
	for _, vendor := range pipelinetest.Vendors {
		entries, err := os.ReadDir(filepath.Join(root, vendor))
		if err != nil {
			t.Fatalf("%s: %v", vendor, err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".golden.json") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(root, vendor, e.Name()))
			if err != nil {
				t.Fatalf("%s/%s: %v", vendor, e.Name(), err)
			}
			if strings.Contains(string(raw), "MUST-NOT-BE-COLLECTED") {
				t.Errorf("%s/%s carries a planted secret", vendor, e.Name())
			}
		}
		// And the fixtures really do plant it, or this check proves nothing.
		_ = filepath.WalkDir(filepath.Join(root, vendor, "device"), func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if raw, rErr := os.ReadFile(path); rErr == nil && strings.Contains(string(raw), "MUST-NOT-BE-COLLECTED") {
					planted++
				}
			}
			return nil
		})
	}
	if planted == 0 {
		t.Fatal("no fixture plants MUST-NOT-BE-COLLECTED, so the leak check above cannot fail")
	}
}

// TestFixtures_EveryCollectorAnswersItsFakeAppliance drives each vendor's real
// collector, through the Registry, against its fake appliance — the same
// fixtures hop 1 uses, without the database. A fixture that stopped matching
// what its collector asks for fails here in seconds instead of as a golden
// diff in a DB-integration run.
func TestFixtures_EveryCollectorAnswersItsFakeAppliance(t *testing.T) {
	root := pipelinetest.Dir(t, dir)
	registry := di.NewRegistry()
	for _, vendor := range pipelinetest.Vendors {
		t.Run(vendor, func(t *testing.T) {
			s := pipelinetest.LoadScenario(t, root, vendor)
			app := pipelinetest.StartAppliance(t, root, s)
			device := di.DeviceInfo{DeviceType: s.DeviceType, Hostname: s.Hostname}
			if s.Transport == "rest" {
				device.ManagementURL = app.ManagementURL
			} else {
				device.IPAddress, device.Port = app.Host, app.Port
			}
			interrogator, err := registry.Get(s.DeviceType)
			if err != nil {
				t.Fatalf("registry.Get(%s): %v", s.DeviceType, err)
			}
			result, err := interrogator.Interrogate(context.Background(), device,
				di.Credentials{Username: "readonly", Password: "readonly-password", InsecureSkipVerify: true})
			if err != nil {
				t.Fatalf("Interrogate: %v", err)
			}
			if len(result.Assets) == 0 || len(result.Facts) == 0 {
				t.Errorf("the fixture produced %d assets and %d facts; it no longer answers what the collector asks",
					len(result.Assets), len(result.Facts))
			}
			if result.DeviceIdentity == nil {
				t.Errorf("no device identity")
			} else {
				t.Logf("%s identity: vendor=%q model=%q class_hint=%q", vendor,
					result.DeviceIdentity.Vendor, result.DeviceIdentity.Model, result.DeviceIdentity.ClassHint)
			}
		})
	}
}

// TestFixtures_UniFiManagementProbeIsDeterministic interrogates the UniFi fake
// repeatedly and requires the management-plane TLS row to come out the same
// every time, with every support question ANSWERED.
//
// The golden once lacked the support flags because it predated the change
// that forwards them, and on a machine that recorded them the gate read as
// environment-dependent. The two ways this row genuinely could vary from run
// to run are pinned or refused: the server's groups, versions and certificate
// (ApplianceTLSConfig) and the client's (RequireDeterministicTLS). A support
// flag is absent only when its extra handshake did not finish inside the
// probe's 10-second budget, which on loopback means something is badly wrong
// with the machine; this test is where that would show, alone and with a
// count, instead of as a one-line golden diff.
func TestFixtures_UniFiManagementProbeIsDeterministic(t *testing.T) {
	pipelinetest.RequireDeterministicTLS(t)
	root := pipelinetest.Dir(t, dir)
	s := pipelinetest.LoadScenario(t, root, "unifi")
	interrogator, err := di.NewRegistry().Get(s.DeviceType)
	if err != nil {
		t.Fatalf("registry.Get: %v", err)
	}
	want := map[string]any{
		"protocol_version":            "TLS 1.3",
		"cipher_suite":                "TLS_AES_128_GCM_SHA256",
		"key_exchange":                "X25519MLKEM768",
		"tls_versions":                []any{"TLS 1.3", "TLS 1.2"},
		"tls_supports_classical_kex":  true,
		"tls_supports_pqc_hybrid_kex": true,
		"tls_pqc_hybrid_kex_group":    "X25519MLKEM768",
	}
	const runs = 20
	for i := 0; i < runs; i++ {
		app := pipelinetest.StartAppliance(t, root, s)
		result, err := interrogator.Interrogate(context.Background(),
			di.DeviceInfo{DeviceType: s.DeviceType, Hostname: s.Hostname, ManagementURL: app.ManagementURL},
			di.Credentials{Username: "readonly", Password: "readonly-password", InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("run %d: Interrogate: %v", i, err)
		}
		var got map[string]any
		for _, a := range result.Assets {
			if a.Metadata["interface_type"] != "management" {
				continue
			}
			got = map[string]any{
				"protocol_version":            deref(a.ProtocolVersion),
				"cipher_suite":                deref(a.CipherSuite),
				"key_exchange":                deref(a.KeyExchangeAlg),
				"tls_versions":                a.TLSVersions,
				"tls_supports_classical_kex":  a.Metadata["tls_supports_classical_kex"],
				"tls_supports_pqc_hybrid_kex": a.Metadata["tls_supports_pqc_hybrid_kex"],
				"tls_pqc_hybrid_kex_group":    a.Metadata["tls_pqc_hybrid_kex_group"],
			}
		}
		if got == nil {
			t.Fatalf("run %d: no management-plane TLS asset — the probe of the fake failed", i)
		}
		if !pipelinetest.Equal(t, got, want) {
			t.Fatalf("run %d of %d: management-plane TLS row\n   got  %v\n   want %v", i+1, runs, got, want)
		}
	}
}

func deref(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}
