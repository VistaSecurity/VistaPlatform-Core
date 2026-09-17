package processor

// The active TLS enricher probes a destination because a PASSIVE capture saw a
// connection to it, and it records its result as a SECOND sensor_discoveries
// row: same tenant, same batch, same dest_ip/port/protocol, milliseconds apart.
// The enrichment row carries the certificate and the cipher it measured — and
// no "sni" key at all, because the enricher never writes down the name it
// probed with.
//
// So the row whose upsert lands LAST, and therefore decides the stored
// hostname, is precisely the row that cannot see the SNI. Per-row SNI lookup
// cannot fix that at any level of care; the batch is the smallest scope where
// both halves are in hand.
//
// These are the pure-function halves and they run in the plain unit suite. The
// WIRING — that ProcessBatch actually consults the index, and that the name
// reaching external_connections is slack.com — is pinned separately by
// TestIntegration_ProcessBatch_EnrichmentRowInheritsSiblingSNI, because a fix
// that is only exercised through its helper is exactly how the previous
// attempt at this bug passed its tests and stayed broken in production.

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

func discoveryRow(protocol, destIP string, port int, metadata string) *models.SensorDiscovery {
	return &models.SensorDiscovery{
		ID:       uuid.New(),
		Protocol: protocol,
		DestIP:   destIP,
		Port:     port,
		Metadata: []byte(metadata),
	}
}

// The real observed shape, reduced: two rows 218ms apart for 54.163.235.119:443,
// the passive one carrying sni=slack.com and the active_enrichment one carrying
// no sni key whatsoever.
//
// Mutation that proves this test: in resolveMissingHostname, delete the
// `if siblingSNI != ""` branch — "enrichment row inherits" goes red with the
// PTR name (the bug), while every other subtest stays green, because they are
// the only ones the per-row SNI already answered.
func TestBatchSNIIndex_EnrichmentRowBorrowsItsPassiveSiblingsSNI(t *testing.T) {
	passive := discoveryRow("TLS", "54.163.235.119", 443,
		`{"discovery_method":"passive","raw_metadata":{"sni":"slack.com","discovery_method":"passive"}}`)
	enrichment := discoveryRow("TLS", "54.163.235.119", 443,
		`{"discovery_method":"active_enrichment","cipher_suite":"TLS_AES_128_GCM_SHA256","raw_metadata":{"discovery_method":"active_enrichment","cipher_suite":"TLS_AES_128_GCM_SHA256"}}`)

	index := buildBatchSNIIndex([]*models.SensorDiscovery{passive, enrichment})

	if got := index.lookup(enrichment); got != "slack.com" {
		t.Fatalf("enrichment row's sibling SNI = %q, want %q", got, "slack.com")
	}

	ptr := func(string) string { return "ec2-54-163-235-119.compute-1.amazonaws.com" }
	got := resolveMissingHostname(enrichment.Metadata, enrichment.DestIP, index.lookup(enrichment), ptr)

	if got.Name != "slack.com" {
		t.Errorf("enrichment row resolved to %q, want %q — the reverse-DNS guess must not beat the sibling's captured SNI", got.Name, "slack.com")
	}
	if got.SourceKind != "measured" {
		t.Errorf("borrowed SNI provenance = %q, want %q — it is the same measurement, one row over", got.SourceKind, "measured")
	}
}

// One address serves many vhosts — that is what SNI is FOR — so a destination
// this batch contacted under two different names must yield NOTHING rather than
// one of them picked arbitrarily. A borrowed name is only a fact about the flow
// if it is the only candidate.
//
// Mutation that proves it: in buildBatchSNIIndex, replace the `default:` arm
// (which marks the key ambiguous) with a no-op that keeps the first name — this
// test goes red, asserting the enrichment row silently inherited whichever
// vhost happened to be seen first.
func TestBatchSNIIndex_RefusesToGuessBetweenTwoVhostsOnOneAddress(t *testing.T) {
	first := discoveryRow("TLS", "203.0.113.50", 443, `{"raw_metadata":{"sni":"shop.example.com"}}`)
	second := discoveryRow("TLS", "203.0.113.50", 443, `{"raw_metadata":{"sni":"blog.example.com"}}`)
	enrichment := discoveryRow("TLS", "203.0.113.50", 443, `{"raw_metadata":{"cipher_suite":"TLS_AES_128_GCM_SHA256"}}`)

	index := buildBatchSNIIndex([]*models.SensorDiscovery{first, second, enrichment})

	if got := index.lookup(enrichment); got != "" {
		t.Errorf("sibling SNI for an ambiguous destination = %q, want empty — two vhosts on one address is not one answer", got)
	}
}

// Two rows naming the same destination the same way is not ambiguity. Without
// this, a batch that simply saw the same flow twice would refuse to share a
// perfectly unanimous SNI.
func TestBatchSNIIndex_RepeatedIdenticalSNIIsNotAmbiguous(t *testing.T) {
	a := discoveryRow("TLS", "203.0.113.51", 443, `{"raw_metadata":{"sni":"api2.cursor.sh"}}`)
	b := discoveryRow("tls", "203.0.113.51", 443, `{"raw_metadata":{"sni":"api2.cursor.sh"}}`)
	enrichment := discoveryRow("TLS", "203.0.113.51", 443, `{"raw_metadata":{}}`)

	index := buildBatchSNIIndex([]*models.SensorDiscovery{a, b, enrichment})

	if got := index.lookup(enrichment); got != "api2.cursor.sh" {
		t.Errorf("sibling SNI = %q, want %q — the same name twice is unanimity, not ambiguity (and protocol case must not key them apart)", got, "api2.cursor.sh")
	}
}

// An SNI is borrowed only by rows describing the SAME endpoint. A different
// port or a different protocol is a different conversation, and a different
// address is a different server entirely.
func TestBatchSNIIndex_DoesNotLeakAcrossDestinations(t *testing.T) {
	source := discoveryRow("TLS", "203.0.113.52", 443, `{"raw_metadata":{"sni":"tzm.protechts.net"}}`)

	otherPort := discoveryRow("TLS", "203.0.113.52", 8443, `{"raw_metadata":{}}`)
	otherIP := discoveryRow("TLS", "203.0.113.53", 443, `{"raw_metadata":{}}`)
	otherProtocol := discoveryRow("SSH", "203.0.113.52", 443, `{"raw_metadata":{}}`)

	index := buildBatchSNIIndex([]*models.SensorDiscovery{source, otherPort, otherIP, otherProtocol})

	for _, tc := range []struct {
		name string
		row  *models.SensorDiscovery
	}{
		{"different port", otherPort},
		{"different address", otherIP},
		{"different protocol", otherProtocol},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := index.lookup(tc.row); got != "" {
				t.Errorf("borrowed %q across a %s — an SNI belongs to one endpoint", got, tc.name)
			}
		})
	}
}

// A host observation's names are a different measurement — what the host called
// ITSELF over DHCP/mDNS/NetBIOS, not what a client asked a remote endpoint for
// — and its dest_ip is routinely 0.0.0.0 ("no address observed"). It neither
// contributes to nor consumes the index.
func TestBatchSNIIndex_IgnoresHostObservations(t *testing.T) {
	observation := discoveryRow("TLS", "0.0.0.0", 0,
		`{"discovery_type":"host_observation","raw_metadata":{"discovery_type":"host_observation","sni":"printer.corp.example"}}`)
	otherObservation := discoveryRow("TLS", "0.0.0.0", 0,
		`{"discovery_type":"host_observation","raw_metadata":{"discovery_type":"host_observation"}}`)

	index := buildBatchSNIIndex([]*models.SensorDiscovery{observation, otherObservation})

	if got := index.lookup(otherObservation); got != "" {
		t.Errorf("a host observation borrowed %q from another host observation — self-reported names are not SNI", got)
	}
}
