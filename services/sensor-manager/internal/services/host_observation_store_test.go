package services

import (
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// newStoreMock wires a SensorService over sqlmock with the tenant lookup and
// transaction scaffolding StoreDiscoveries always performs, and returns a
// capture hook for the INSERT's arguments.
func newStoreMock(t *testing.T, tenantID, sensorID uuid.UUID) (*SensorService, sqlmock.Sqlmock, *[]driverArgs) {
	t.Helper()

	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	bypassDB, bypassMock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
	if err != nil {
		t.Fatalf("sqlmock bypass: %v", err)
	}
	t.Cleanup(func() { _ = bypassDB.Close() })

	// The tenant is the OUTPUT of this lookup, so it runs on the bypass handle.
	bypassMock.ExpectQuery(`SELECT tenant_id FROM sensors WHERE id = \$1`).
		WithArgs(sensorID).
		WillReturnRows(sqlmock.NewRows([]string{"tenant_id"}).AddRow(tenantID.String()))

	mock.ExpectBegin()
	mock.ExpectExec(`set_tenant_context`).WillReturnResult(sqlmock.NewResult(0, 1))

	var captured []driverArgs
	// sqlmock wants one matcher per placeholder, and the INSERT has thirteen
	// (StoreDiscoveries' own colCount). Supplying exactly that many is itself a
	// check: a column added to the statement without updating this test makes
	// the expectation fail loudly rather than silently matching a prefix.
	caps := make([]driver.Value, 13)
	for i := range caps {
		caps[i] = argCapture{out: &captured}
	}
	mock.ExpectExec(`INSERT INTO sensor_discoveries`).
		WithArgs(caps...).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	return NewSensorService(db, bypassDB), mock, &captured
}

// driverArgs holds one captured INSERT argument list.
type driverArgs []any

// argCapture is a sqlmock argument matcher that accepts anything and records
// what it saw, in the order sqlmock consults them — which is column order.
type argCapture struct{ out *[]driverArgs }

func (a argCapture) Match(v driver.Value) bool {
	if len(*a.out) == 0 {
		*a.out = append(*a.out, driverArgs{})
	}
	(*a.out)[0] = append((*a.out)[0], v)
	return true
}

// TestStoreDiscoveries_HostObservationRoundTrip is the producer-side contract
// test for workstream 2.5: a host_observation submitted by a sensor has to
// reach sensor_discoveries with its payload intact and its columns satisfied.
//
// The column shapes are the constraint. sensor_discoveries.dest_ip is
// `inet NOT NULL` and .port is `integer NOT NULL`, so a host observation — which
// has no port and may have no address — cannot use NULL for either. The values
// written here are what the wire contract tells the consumer to expect.
func TestStoreDiscoveries_HostObservationRoundTrip(t *testing.T) {
	tenantID := uuid.New()
	sensorID := uuid.New()
	svc, mock, captured := newStoreMock(t, tenantID, sensorID)

	observed := time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
	batch := &models.DiscoveryBatch{
		SensorID:  sensorID,
		BatchID:   uuid.New(),
		Timestamp: observed,
		Discoveries: []models.SensorDiscoveryInput{{
			Protocol:        "HOST",
			DestIP:          "192.168.10.50",
			Port:            0,
			DiscoveryMethod: "passive_host_observation",
			DiscoveryType:   "host_observation",
			Confidence:      0.95,
			Timestamp:       observed,
			RawMetadata: map[string]interface{}{
				"discovery_type": "host_observation",
				"hostname":       "acct-ws-14.corp.example",
				"host_observation": map[string]interface{}{
					"mac":       "28:cf:da:11:22:33",
					"vendor":    "Apple",
					"source":    "arp",
					"addresses": []string{"192.168.10.50"},
					"facts":     map[string]interface{}{"hw.vendor": "Apple"},
				},
			},
		}},
	}

	if err := svc.StoreDiscoveries(batch); err != nil {
		t.Fatalf("StoreDiscoveries: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}

	args := (*captured)[0]
	if len(args) != 13 {
		t.Fatalf("INSERT carried %d columns, want 13", len(args))
	}

	// Column order: id, sensor_id, tenant_id, batch_id, protocol, dest_ip,
	// port, confidence, metadata, timestamp, created_at, source_ip, hostname.
	if got := args[4]; got != "HOST" {
		t.Errorf("protocol = %v, want HOST (cryptoparse.NormalizeProtocol must pass an unmodelled name through untouched)", got)
	}
	if got := args[5]; got != "192.168.10.50" {
		t.Errorf("dest_ip = %v", got)
	}
	if got := args[6]; got != int64(0) && got != 0 {
		t.Errorf("port = %v (%T), want 0 — the column is NOT NULL and a host is not an endpoint", got, got)
	}
	// source_ip stays NULL. A host observation has no flow, and writing the
	// subject's own address into both columns would invent a connection.
	if args[11] != nil {
		t.Errorf("source_ip = %v, want NULL", args[11])
	}
	if got := args[12]; got != "acct-ws-14.corp.example" {
		t.Errorf("hostname = %v, want the name lifted from raw_metadata", got)
	}

	var envelope map[string]any
	raw, ok := args[8].([]byte)
	if !ok {
		t.Fatalf("metadata = %T, want []byte", args[8])
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	if envelope["discovery_type"] != "host_observation" {
		t.Errorf("envelope discovery_type = %v", envelope["discovery_type"])
	}
	nested, ok := envelope["raw_metadata"].(map[string]any)
	if !ok {
		t.Fatalf("raw_metadata did not survive: %s", raw)
	}
	obs, ok := nested["host_observation"].(map[string]any)
	if !ok {
		t.Fatalf("host_observation did not survive: %s", raw)
	}
	if obs["mac"] != "28:cf:da:11:22:33" || obs["vendor"] != "Apple" {
		t.Errorf("observation payload altered in transit: %v", obs)
	}
}

// TestStoreDiscoveries_CryptoRowCarriesNoDiscoveryType pins the conditional
// write. discovery_type is the only envelope key written conditionally, and it
// has to stay that way: discovery-processor promotes outer envelope keys over
// nested ones, so an empty outer discovery_type would erase whatever the
// sensor's own raw_metadata said. That is the same mechanism that left
// TLS-over-TCP rows with a full certificate chain and a NULL protocol version.
func TestStoreDiscoveries_CryptoRowCarriesNoDiscoveryType(t *testing.T) {
	tenantID := uuid.New()
	sensorID := uuid.New()
	svc, mock, captured := newStoreMock(t, tenantID, sensorID)

	batch := &models.DiscoveryBatch{
		SensorID:  sensorID,
		BatchID:   uuid.New(),
		Timestamp: time.Now(),
		Discoveries: []models.SensorDiscoveryInput{{
			Protocol:        "TLS",
			SourceIP:        "10.0.0.9",
			DestIP:          "10.0.0.1",
			Port:            443,
			Version:         "TLS 1.3",
			CipherSuite:     "TLS_AES_128_GCM_SHA256",
			DiscoveryMethod: "passive",
			// DiscoveryType deliberately unset — the legacy shape every
			// existing sensor sends.
			RawMetadata: map[string]interface{}{"sni": "api.example.com"},
		}},
	}

	if err := svc.StoreDiscoveries(batch); err != nil {
		t.Fatalf("StoreDiscoveries: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}

	var envelope map[string]any
	if err := json.Unmarshal((*captured)[0][8].([]byte), &envelope); err != nil {
		t.Fatalf("metadata is not JSON: %v", err)
	}
	if _, present := envelope["discovery_type"]; present {
		t.Errorf("a crypto discovery carried discovery_type=%v; an empty outer value erases the nested one downstream", envelope["discovery_type"])
	}
	// The unconditional envelope keys must still be there, empty or not.
	for _, k := range []string{"source_ip", "version", "cipher_suite", "key_size", "discovery_method", "raw_metadata"} {
		if _, present := envelope[k]; !present {
			t.Errorf("envelope lost the unconditional key %q", k)
		}
	}
}
