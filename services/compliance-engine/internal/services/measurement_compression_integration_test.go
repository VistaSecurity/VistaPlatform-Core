package services

// tls_compression_enabled: a check that could not fire.
//
// The measurement this file covers reported `false` for every configuration
// that has ever existed, for two independent reasons in four lines of code. It
// uppercased the probe record and then searched the result for the LOWERCASE
// literal `"compression":true` — which no uppercased string can contain — and
// jsonb renders a space after the colon, so even a same-case search would have
// missed. The measurement was therefore constant: "compression disabled",
// whatever the probe had actually seen.
//
// The registry rewrite reads the key out of the jsonb instead, and is
// three-valued: a probe record that says nothing about compression produces NO
// measurement, so the asset is reported as not assessed rather than as clean.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_MeasurementCompression_ReadsTheProbeRecord(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	// One asset per case, so a case is identified by its subject rather than by
	// the order rows come back in.
	cases := []struct {
		host    string
		rawData string
		want    interface{} // nil means NO measurement
	}{
		{"compression-on.example.test", `{"compression": true, "alpn": ["http/1.1"]}`, true},
		{"compression-off.example.test", `{"compression": false}`, false},
		// The probe recorded other things but never looked at compression.
		{"compression-unknown.example.test", `{"alpn": ["h2"]}`, nil},
		// A producer wrote something that is not a boolean. "yes" is not an
		// answer to "is compression enabled"; guessing at it would be inventing
		// a measurement.
		{"compression-nonsense.example.test", `{"compression": "yes"}`, nil},
		// No probe record at all.
		{"compression-none.example.test", "", nil},
	}

	want := map[uuid.UUID]interface{}{}
	for _, c := range cases {
		var asset uuid.UUID
		if err := db.QueryRow(`
			INSERT INTO assets (tenant_id, class_key, class_path, hostname, asset_status)
			VALUES ($1, 'server', 'hardware.computer.server', $2, 'monitoring')
			RETURNING id`, tenant, c.host).Scan(&asset); err != nil {
			t.Fatalf("seed asset %s: %v", c.host, err)
		}
		if _, err := db.Exec(`
			INSERT INTO crypto_implementations_partitioned
				(tenant_id, asset_id, protocol, protocol_version, raw_data, discovery_method, last_verified_at)
			VALUES ($1, $2, 'TLS', 'TLS1.2', NULLIF($3,'')::jsonb, 'active', NOW())`,
			tenant, asset, c.rawData); err != nil {
			t.Fatalf("seed configuration for %s: %v", c.host, err)
		}
		want[asset] = c.want
	}

	values, err := NewMeasurementExtractor(db).ExtractMeasurements(tenant, "tls_compression_enabled")
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	got := map[uuid.UUID]interface{}{}
	for _, v := range values {
		got[v.SubjectID] = v.Value
	}

	for asset, expected := range want {
		actual, present := got[asset]
		if expected == nil {
			if present {
				t.Errorf("asset %s: got %v, want NO measurement — a probe that did not record "+
					"compression has not told us compression is off", asset, actual)
			}
			continue
		}
		if !present {
			t.Errorf("asset %s: no measurement, want %v", asset, expected)
			continue
		}
		if actual != expected {
			t.Errorf("asset %s: got %v, want %v", asset, actual, expected)
		}
	}

	// The bug this replaces made every value false. If that ever comes back,
	// the loop above still passes for two of the five cases, so say it
	// directly: at least one configuration must read as compressed.
	sawTrue := false
	for _, v := range got {
		if v == true {
			sawTrue = true
		}
	}
	if !sawTrue {
		t.Error("no configuration reported compression enabled; the measurement is constant again")
	}
}
