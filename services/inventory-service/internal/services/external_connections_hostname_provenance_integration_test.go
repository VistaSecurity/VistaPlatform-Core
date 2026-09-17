package services

// The precedence ladder for external_connections.dest_hostname, asserted
// against a real Postgres because the ladder lives in the upsert's ON CONFLICT
// clause, not in Go. What a caller intended is not evidence about what the
// stored row ends up holding.
//
// The neighbouring "empty never wins" test
// (external_connections_dest_hostname_integration_test.go) was written for the
// same bug and did not catch it: it proved that an EMPTY hostname cannot blank
// a populated one, and `ec2-54-163-235-119.compute-1.amazonaws.com` is not
// empty. It is a reverse-DNS guess, and it overwrote a captured `slack.com`
// perfectly happily. This file is about the second rule the first one is not:
// an INFERENCE never overwrites a MEASUREMENT.
//
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The exact reported defect, end to end through the upsert: the sensor's
// passive capture stores slack.com, the enrichment probe's reverse-DNS answer
// arrives 218ms later, and the stored name must still be slack.com.
//
// Mutation that proves it: in the upsert's ON CONFLICT clause, replace the
// dest_hostname CASE with the COALESCE it used to be
// (`COALESCE(EXCLUDED.dest_hostname, external_connections.dest_hostname)`) —
// this goes red with the ec2-… name, which is the screenshot the bug report
// came with.
func TestIntegration_ExternalConnectionUpsert_ReverseDNSNeverOverwritesSNI(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	measured := "measured"
	inferred := "inferred"
	sni := "slack.com"
	ptr := "ec2-54-163-235-119.compute-1.amazonaws.com"

	base := models.ExternalConnectionUpsert{
		SourceIP: "192.0.2.11",
		DestIP:   "54.163.235.119",
		DestPort: 443,
		Protocol: "TLS",
	}

	first := base
	first.DestHostname = &sni
	first.DestHostnameSourceKind = &measured
	if _, err := svc.Upsert(tenant, first); err != nil {
		t.Fatalf("upsert the passive observation: %v", err)
	}

	second := base
	second.DestHostname = &ptr
	second.DestHostnameSourceKind = &inferred
	if _, err := svc.Upsert(tenant, second); err != nil {
		t.Fatalf("upsert the enrichment observation: %v", err)
	}

	name, kind := readStoredHostname(t, raw, tenant, 443)
	if name != sni {
		t.Errorf("dest_hostname = %q, want %q — the reverse-DNS guess overwrote the measured SNI", name, sni)
	}
	if kind != measured {
		t.Errorf("dest_hostname_source_kind = %q, want %q", kind, measured)
	}
}

// The full ladder, both directions, including the third state that legacy rows
// are in.
//
// The Go mirror (hostnameSourceKindWins) is the spec here and the DB is checked
// against it, the same way risk_bands_integration_test.go checks generated SQL
// against the Go ladder. If the two ever disagree, this says which pair.
//
// Mutation that proves it: flip the `>=` in the SQL to `>` — the "like
// replaces like" rows (measured over measured, inferred over inferred, and the
// unstated pair) go red. Flip it to `<=` and the inference rows go red.
func TestIntegration_ExternalConnectionUpsert_HostnameProvenanceLadder(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	// nil is the third state — "this producer did not say" — which is what
	// every row written before the column existed carries. It is deliberately
	// NOT folded into either neighbour.
	kinds := []*string{nil, strptr("measured"), strptr("declared"), strptr("imported"), strptr("inferred")}

	port := 1000
	for _, stored := range kinds {
		for _, incoming := range kinds {
			port++
			name := fmt.Sprintf("stored/%s→incoming/%s", kindLabel(stored), kindLabel(incoming))
			t.Run(name, func(t *testing.T) {
				destPort := port
				storedName := "first." + uuid.New().String()[:8] + ".example"
				incomingName := "second." + uuid.New().String()[:8] + ".example"

				base := models.ExternalConnectionUpsert{
					SourceIP: "192.0.2.12",
					DestIP:   "203.0.113.90",
					DestPort: destPort,
					Protocol: "TLS",
				}

				a := base
				a.DestHostname = &storedName
				a.DestHostnameSourceKind = stored
				if _, err := svc.Upsert(tenant, a); err != nil {
					t.Fatalf("first upsert: %v", err)
				}

				b := base
				b.DestHostname = &incomingName
				b.DestHostnameSourceKind = incoming
				if _, err := svc.Upsert(tenant, b); err != nil {
					t.Fatalf("second upsert: %v", err)
				}

				wantName, wantKind := storedName, kindLabel(stored)
				if hostnameSourceKindWins(incoming, stored) {
					wantName, wantKind = incomingName, kindLabel(incoming)
				}

				gotName, gotKind := readStoredHostname(t, raw, tenant, destPort)
				if gotName != wantName {
					t.Errorf("dest_hostname = %q, want %q (Go ladder: incoming rank %d vs stored rank %d)",
						gotName, wantName, hostnameSourceKindRank(incoming), hostnameSourceKindRank(stored))
				}
				if gotKind != wantKind {
					t.Errorf("dest_hostname_source_kind = %q, want %q — the provenance must follow the name that won", gotKind, wantKind)
				}
			})
		}
	}
}

// The other polarity of "empty never wins": a blank name is no claim at all,
// whether it arrives as nil or as a whitespace string, and a `measured` label
// attached to nothing does not make it one.
//
// TWO LOCKS, and neither alone fails this test — worth writing down, because
// "either removal is a red test" is the natural thing to assume here and it is
// false. Go's trimmedOrNil turns a blank into nil before the SQL sees it, and
// the SQL's own btrim-is-not-the-empty-string guard refuses it again:
//
//   - Remove only the Go trim: still green (the SQL refuses the blank).
//   - Remove only the SQL guard: still green (the blank never reaches it).
//   - Remove BOTH: this goes red, and so does the neighbouring
//     DestHostnameFillsButNeverBlanks — which is also the test that fails on
//     the SQL guard alone, because it sends a nil hostname with no provenance
//     and the two unstated ranks then tie.
//
// So the suite catches either removal; this comment says which test does.
func TestIntegration_ExternalConnectionUpsert_BlankHostnameIsNoClaim(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	base := models.ExternalConnectionUpsert{
		SourceIP: "192.0.2.13",
		DestIP:   "203.0.113.91",
		DestPort: 8443,
		Protocol: "TLS",
	}

	kept := "api2.cursor.sh"
	first := base
	first.DestHostname = &kept
	first.DestHostnameSourceKind = strptr("measured")
	if _, err := svc.Upsert(tenant, first); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	for _, blank := range []*string{nil, strptr(""), strptr("   ")} {
		second := base
		second.DestHostname = blank
		// A `measured` label on nothing at all must not be enough to clear the
		// stored name: the label describes a name, and there is no name.
		second.DestHostnameSourceKind = strptr("measured")
		if _, err := svc.Upsert(tenant, second); err != nil {
			t.Fatalf("blank upsert %v: %v", blank, err)
		}
		name, kind := readStoredHostname(t, raw, tenant, 8443)
		if name != kept {
			t.Errorf("dest_hostname = %q after a blank observation, want %q (blank is no claim)", name, kept)
		}
		if kind != "measured" {
			t.Errorf("dest_hostname_source_kind = %q after a blank observation, want %q", kind, "measured")
		}
	}
}

// A provenance must not outlive the name it describes. On the INSERT half of
// the upsert the column is written straight from the payload, so a first
// observation carrying a `measured` label and no hostname would otherwise
// store a provenance for a NULL name — a claim about nothing, and one that
// then outranks the real name when it finally arrives.
//
// Mutation that proves it: delete the `if input.DestHostname == nil {
// destHostnameSourceKind = nil }` block in Upsert — this goes red with
// "measured". The ON CONFLICT path cannot catch this one; it never writes a
// provenance whose name did not win, so only a first observation reaches it.
func TestIntegration_ExternalConnectionUpsert_ProvenanceWithoutAName(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	if _, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP:               "192.0.2.15",
		DestIP:                 "203.0.113.93",
		DestPort:               7443,
		Protocol:               "TLS",
		DestHostname:           nil,
		DestHostnameSourceKind: strptr("measured"),
	}); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	name, kind := readStoredHostname(t, raw, tenant, 7443)
	if name != "" {
		t.Fatalf("dest_hostname = %q, want NULL — nothing supplied a name", name)
	}
	if kind != "" {
		t.Errorf("dest_hostname_source_kind = %q with no hostname stored, want NULL — a provenance describes a name, and there is none", kind)
	}
}

// An unrecognised provenance word must not fail the upsert — that would lose a
// real observation over a label the CHECK constraint refuses. It degrades to
// "unstated", which is exactly what is true about a producer whose vocabulary
// we do not recognise.
func TestIntegration_ExternalConnectionUpsert_UnknownProvenanceDegradesToUnstated(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := NewExternalConnectionsService(db, NewAlgorithmService(db))

	name := "telepathy.example"
	if _, err := svc.Upsert(tenant, models.ExternalConnectionUpsert{
		SourceIP:               "192.0.2.14",
		DestIP:                 "203.0.113.92",
		DestPort:               9443,
		Protocol:               "TLS",
		DestHostname:           &name,
		DestHostnameSourceKind: strptr("telepathy"),
	}); err != nil {
		t.Fatalf("upsert with an unrecognised provenance failed instead of degrading: %v", err)
	}

	gotName, gotKind := readStoredHostname(t, raw, tenant, 9443)
	if gotName != name {
		t.Errorf("dest_hostname = %q, want %q — the observation itself must survive", gotName, name)
	}
	if gotKind != "" {
		t.Errorf("dest_hostname_source_kind = %q, want NULL — an unrecognised word is not a provenance", gotKind)
	}
}

// The OTHER door into external_connections. inventory-service's own ingest can
// route a finding here (AssetService.routeToExternalConnection) on its own
// classification rather than discovery-processor's, so the producer's
// statement about where the name came from has to survive that crossing too.
//
// BOTH polarities, because dropping the label is not uniformly safe in one
// direction. An unlabelled name ranks in the MIDDLE, so losing the label makes
// an inference stronger than it should be AND a measurement weaker — and a
// one-sided test would stay green on half of that. (It did: the first draft of
// this test put a MEASURED name in the table and an inferred one through
// ingest, and deleting the passthrough entirely left it green, because
// unstated already loses to measured.)
//
// Mutation that proves it: delete the RawData["dest_hostname_source_kind"]
// read in routeToExternalConnection — both subtests go red, one because the
// PTR guess then overwrites a legacy name, the other because a real SNI then
// fails to correct one.
func TestIntegration_RouteToExternalConnection_CarriesHostnameProvenance(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	svc := NewAssetService(db)
	external := NewExternalConnectionsService(db, NewAlgorithmService(db))
	svc.SetExternalConnectionsService(external)

	dest := "203.0.113.94"

	tests := []struct {
		name string
		port int
		// The row already in the table. A nil provenance is what EVERY row
		// written before this column existed carries, which is why it is the
		// interesting starting state rather than a contrived one.
		storedName string
		storedKind *string
		// The ingest finding that follows it.
		incomingName string
		incomingKind string
		wantName     string
		wantKind     string
	}{
		{
			name:         "an inference must not overwrite an unlabelled legacy name",
			port:         6443,
			storedName:   "slack.com",
			storedKind:   nil,
			incomingName: "ec2-203-0-113-94.compute-1.amazonaws.com",
			incomingKind: "inferred",
			wantName:     "slack.com",
			wantKind:     "",
		},
		{
			name:         "a measurement must still be able to correct one",
			port:         6444,
			storedName:   "ec2-203-0-113-94.compute-1.amazonaws.com",
			storedKind:   nil,
			incomingName: "api2.cursor.sh",
			incomingKind: "measured",
			wantName:     "api2.cursor.sh",
			wantKind:     "measured",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port := tc.port
			storedName := tc.storedName
			if _, err := external.Upsert(tenant, models.ExternalConnectionUpsert{
				SourceIP:               "192.0.2.16",
				DestIP:                 dest,
				DestPort:               port,
				Protocol:               "TLS",
				DestHostname:           &storedName,
				DestHostnameSourceKind: tc.storedKind,
			}); err != nil {
				t.Fatalf("seed the stored observation: %v", err)
			}

			incomingName := tc.incomingName
			if err := svc.routeToExternalConnection(tenant, IngestFinding{
				IPAddress: &dest,
				Port:      &port,
				Protocol:  "TLS",
				Hostname:  &incomingName,
				RawData: map[string]interface{}{
					"source_ip":                 "192.0.2.16",
					"dest_hostname_source_kind": tc.incomingKind,
				},
			}); err != nil {
				t.Fatalf("routeToExternalConnection: %v", err)
			}

			name, kind := readStoredHostname(t, raw, tenant, port)
			if name != tc.wantName {
				t.Errorf("dest_hostname = %q, want %q — the %q label did not survive the ingest path", name, tc.wantName, tc.incomingKind)
			}
			if kind != tc.wantKind {
				t.Errorf("dest_hostname_source_kind = %q, want %q", kind, tc.wantKind)
			}
		})
	}
}

// readStoredHostname returns the stored name and its provenance, with SQL NULL
// rendered as "". The caller never has to tell NULL from the empty string,
// because the writer never stores an empty string: trimmedOrNil turns a blank
// into nil before it reaches the column.
func readStoredHostname(t *testing.T, raw *sql.DB, tenant uuid.UUID, destPort int) (string, string) {
	t.Helper()
	var name, kind sql.NullString
	if err := raw.QueryRow(
		`SELECT dest_hostname, dest_hostname_source_kind FROM external_connections WHERE tenant_id = $1 AND dest_port = $2`,
		tenant, destPort).Scan(&name, &kind); err != nil {
		t.Fatalf("read back dest_hostname for port %d: %v", destPort, err)
	}
	return name.String, kind.String
}

func kindLabel(kind *string) string {
	if kind == nil {
		return ""
	}
	return *kind
}
