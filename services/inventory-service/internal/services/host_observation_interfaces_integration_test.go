package services

// DCIM row 1.5e: the passive sensor, pcap and the sensor's own self-report
// write interfaces and addresses through the intake seam.
//
// The parity tests drive the REAL path from RECORDED input through
// identitytest.RunAdapterParity: frames → shared/hostobs decoders → Coalesce
// (the sensor's and pcap-processor's shared producer half) → the JSON the
// discovery row carries → hostObservationPayload → hostObservationSighting →
// identity.Intake → identity.Engine → the Postgres repository.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest"
)

// passiveBatch is the recorded shape of testdata/hostobs/passive_batch.json.
type passiveBatch struct {
	SourceSensorID   string `json:"source_sensor_id"`
	DiscoveryMethod  string `json:"discovery_method"`
	CaptureInterface string `json:"capture_interface"`
	Frames           []struct {
		Kind       string `json:"kind"`
		PayloadHex string `json:"payload_hex"`
		SrcMAC     string `json:"src_mac"`
		SrcAddr    string `json:"src_addr"`
	} `json:"frames"`
}

var hostObsKinds = map[string]hostobs.Kind{
	"arp": hostobs.KindARP, "dhcp": hostobs.KindDHCP, "mdns": hostobs.KindMDNS,
	"nbns": hostobs.KindNBNS, "dns": hostobs.KindDNS,
}

// passiveBatchFinding decodes and coalesces a recorded batch exactly as the
// sensor does, and wraps the one observation in the finding discovery-processor
// forwards.
func passiveBatchFinding(response []byte, at time.Time) (IngestFinding, error) {
	var b passiveBatch
	if err := json.Unmarshal(response, &b); err != nil {
		return IngestFinding{}, err
	}
	c := hostobs.NewCoalescer(time.Hour, hostobs.DefaultCoalesceCapacity)
	for i, fr := range b.Frames {
		payload, err := hex.DecodeString(fr.PayloadHex)
		if err != nil {
			return IngestFinding{}, fmt.Errorf("frame %d: %w", i, err)
		}
		f := hostobs.Frame{Payload: payload, SrcMAC: fr.SrcMAC, Interface: b.CaptureInterface, At: at}
		if fr.SrcAddr != "" {
			f.SrcAddr = netip.MustParseAddr(fr.SrcAddr)
		}
		obs, err := hostobs.Decode(hostObsKinds[fr.Kind], f)
		if err != nil {
			return IngestFinding{}, fmt.Errorf("frame %d (%s): %w", i, fr.Kind, err)
		}
		c.Add(obs)
	}
	drained := c.Drain()
	if len(drained) != 1 {
		return IngestFinding{}, fmt.Errorf("batch coalesced into %d observations, want 1", len(drained))
	}
	return hostObservationFindingFromWire(b.SourceSensorID, b.DiscoveryMethod, drained[0])
}

// hostObservationFindingFromWire round-trips ho through JSON the way
// sensor_discoveries → discovery-processor carries it.
func hostObservationFindingFromWire(sensorID, method string, ho *hostobs.HostObservation) (IngestFinding, error) {
	blob, err := json.Marshal(map[string]any{
		"kind":             KindHostObservation,
		"source_sensor_id": sensorID,
		"raw_data":         map[string]any{"discovery_method": method, "host_observation": ho},
	})
	if err != nil {
		return IngestFinding{}, err
	}
	var f IngestFinding
	return f, json.Unmarshal(blob, &f)
}

func hostObservationParityAdapter(name string, toFinding func([]byte, time.Time) (IngestFinding, error), verified bool) identitytest.ParityAdapter {
	return identitytest.ParityAdapterFunc{
		AdapterName: name,
		Fn: func(tenantID string, response []byte, at time.Time) (identity.Sighting, error) {
			f, err := toFinding(response, at)
			if err != nil {
				return identity.Sighting{}, err
			}
			ho, ok := hostObservationPayload(f)
			if !ok {
				return identity.Sighting{}, fmt.Errorf("finding carries no host observation")
			}
			sg := hostObservationSighting(uuid.MustParse(tenantID), f, ho, verified)
			sg.ObservedAt = at
			return sg, nil
		},
	}
}

func selfReportFinding(response []byte, _ time.Time) (IngestFinding, error) {
	var f IngestFinding
	return f, json.Unmarshal(response, &f)
}

func readHostObsFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "hostobs", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// expectAddressProvenance registers a check, run after the harness's two
// observations, that every address row on the tenant has last_seen_source
// `source` and was observed exactly `count` times — the same lease twice is
// one row counted twice.
func expectAddressProvenance(source string, count int) func(t *testing.T, db *sql.DB, tenant string) {
	return func(t *testing.T, db *sql.DB, tenant string) {
		t.Cleanup(func() {
			rows, err := db.Query(`SELECT host(address), coalesce(last_seen_source, ''), observation_count
				FROM public.ip_addresses WHERE tenant_id = $1 AND status <> 'rejected'`, tenant)
			if err != nil {
				t.Errorf("read addresses: %v", err)
				return
			}
			defer func() { _ = rows.Close() }()
			n := 0
			for rows.Next() {
				var (
					host, src string
					obs       int
				)
				if err := rows.Scan(&host, &src, &obs); err != nil {
					t.Error(err)
					return
				}
				n++
				if src != source {
					t.Errorf("address %s: last_seen_source %q, want %q", host, src, source)
				}
				if obs != count {
					t.Errorf("address %s: observation_count %d, want %d", host, obs, count)
				}
			}
			if n == 0 {
				t.Error("no address rows to check")
			}
		})
	}
}

// TestIntegration_HostObservation_AdapterParity: an ARP reply, a DHCP ACK with
// its lease options and an mDNS announcement of one laptop become ONE asset
// whose MAC and leased address sit on one synthetic interface (a passive frame
// never names the interface), the address with last_seen_source `dhcp`, and
// the ACK's subnet a pending, DHCP-managed prefix. The sensor's self-report
// files its own NICs by name, every address with its configured length and
// last_seen_source `agent`.
//
// Mutations: drop the protocol from the ref (hostObservationSightingSource) →
// last_seen_source `passive`, red; drop dhcpLeasePrefix or hostobs's option-1
// parse → no prefix, red; drop selfReportInterfaces → the self-report's
// values land on observed-<n>, red.
func TestIntegration_HostObservation_AdapterParity(t *testing.T) {
	managed := true
	identitytest.RunAdapterParity(t, hostObservationParityAdapter("sensor-passive", passiveBatchFinding, false), []identitytest.ParityFixture{{
		Name:     "arp+dhcp-ack+mdns",
		Response: readHostObsFixture(t, "passive_batch.json"),
		Secrets:  []string{"PARITY-SECRET-upload-token-5e7f"},
		Setup:    expectAddressProvenance("dhcp", 2),
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{{
				Name: identity.SyntheticInterfacePrefix + "1", Type: identity.SyntheticInterfaceType,
				// /24, not /32: the DHCP ACK's subnet is recorded as a prefix
				// before the sighting is scoped (DCIM row 1.6), so the lease
				// is filed masked to it from the first sighting, as NetBox
				// records an interface address.
				MAC: "28:cf:da:01:02:03", Addresses: []string{"10.20.30.41/24"},
			}},
			Prefixes:   []identitytest.WantPrefix{{Prefix: "10.20.30.0/24", DHCPManaged: &managed}},
			PrimaryIP4: "10.20.30.41",
		},
	}})

	identitytest.RunAdapterParity(t, hostObservationParityAdapter("sensor-self-report", selfReportFinding, true), []identitytest.ParityFixture{{
		Name:     "linux-two-nics",
		Response: readHostObsFixture(t, "sensor_self_report.json"),
		Secrets:  []string{"PARITY-SECRET-wifi-psk-91c2"},
		Setup:    expectAddressProvenance(selfReportAddressSource, 2),
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "enp1s0", Type: identity.SyntheticInterfaceType, MAC: "00:1a:2b:3c:4d:01",
					Addresses: []string{"192.0.2.10/24", "2001:db8:5::10/64"}},
				{Name: "enp2s0", Type: identity.SyntheticInterfaceType, MAC: "00:1a:2b:3c:4d:02",
					Addresses: []string{"198.51.100.7/24"}},
			},
			PrimaryIP4: "192.0.2.10",
			PrimaryIP6: "2001:db8:5::10",
		},
	}})
}
