package services

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	sqlmock "github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// The cloud collectors' handshake against a customer's load balancer / CDN /
// API gateway is a live-handshake site too. It records the negotiated group
// and the support flags through the same shared code, and a config carrying
// them delivers them to the sensor_discoveries row (top level, where the
// converter reads a cloud row's crypto fields) and to the scheduled path's
// DiscoveredAsset.
func TestCloudHandshake_KeyExchangeReachesDiscoveryRowAndAsset(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			r, err := NewTLSHandshakeService(3*time.Second).PerformHandshake(context.Background(), srv.Host, srv.Port)
			if err != nil || r == nil || !r.Success {
				t.Fatalf("handshake: %+v, %v", r, err)
			}

			// Built the way the API Gateway / CloudFront sites build it.
			cfg := map[string]interface{}{
				"protocol":           "HTTPS",
				"protocol_version":   r.TLSVersion,
				"cipher_suite":       r.CipherSuite,
				"port":               srv.Port,
				"hostname":           "lb.example.com",
				"handshake_verified": true,
			}
			applyHandshakeKeyExchange(cfg, r)
			tlskextest.Check(t, c, cfg)
			tlskextest.CheckConnections(t, c, srv)

			meta := writeOneCloudDiscovery(t, cfg)
			if meta["key_exchange_algorithm"] != c.WantGroup {
				t.Errorf("discovery row key_exchange_algorithm = %v, want %q", meta["key_exchange_algorithm"], c.WantGroup)
			}
			if meta["key_exchange_group_raw"] != float64(c.WantGroupRaw) {
				t.Errorf("discovery row key_exchange_group_raw = %v, want %d", meta["key_exchange_group_raw"], c.WantGroupRaw)
			}
			if meta["tls_supports_classical_kex"] != c.WantSupportsClassical || meta["tls_supports_pqc_hybrid_kex"] != c.WantSupportsPQCHybrid {
				t.Errorf("discovery row support flags = %v / %v, want %v / %v",
					meta["tls_supports_classical_kex"], meta["tls_supports_pqc_hybrid_kex"], c.WantSupportsClassical, c.WantSupportsPQCHybrid)
			}
			checkHybridGroup(t, "discovery row", c, meta)

			configs := extractCryptoConfigs(map[string]interface{}{"crypto_configs": []map[string]interface{}{cfg}})
			hostname := "lb.example.com"
			asset := (&PlatformAgentWorker{}).convertCryptoConfigToAsset(&models.Device{Hostname: &hostname}, configs[0])
			if asset == nil || asset.KeyExchangeAlgorithm != c.WantGroup {
				t.Fatalf("scheduled-path asset key exchange = %+v, want %q", asset, c.WantGroup)
			}

			// The scheduled path's asset becomes a sensor_discoveries row
			// through buildSensorDiscoveryMetadata. The support flags are what
			// the "supports hybrid, negotiated classical" hint reads (
			// W1.9); dropping them here silently removes the hint for every
			// scheduled cloud discovery.
			row := roundTripJSON(t, buildSensorDiscoveryMetadata(nil, nil, *asset))
			if row["tls_supports_classical_kex"] != c.WantSupportsClassical || row["tls_supports_pqc_hybrid_kex"] != c.WantSupportsPQCHybrid {
				t.Errorf("scheduled-path discovery row support flags = %v / %v, want %v / %v",
					row["tls_supports_classical_kex"], row["tls_supports_pqc_hybrid_kex"], c.WantSupportsClassical, c.WantSupportsPQCHybrid)
			}
			checkHybridGroup(t, "scheduled-path discovery row", c, row)
		})
	}
}

// checkHybridGroup asserts tls_pqc_hybrid_kex_group is exactly what c says:
// the accepted hybrid group, or absent when hybrid support is not proven.
func checkHybridGroup(t *testing.T, where string, c tlskextest.Case, meta map[string]interface{}) {
	t.Helper()
	got, present := meta["tls_pqc_hybrid_kex_group"]
	switch {
	case c.WantPQCHybridGroup == "" && present:
		t.Errorf("%s tls_pqc_hybrid_kex_group = %v, want absent", where, got)
	case c.WantPQCHybridGroup != "" && got != c.WantPQCHybridGroup:
		t.Errorf("%s tls_pqc_hybrid_kex_group = %v, want %q", where, got, c.WantPQCHybridGroup)
	}
}

// roundTripJSON is what a metadata map looks like once it has been written to
// a JSONB column and read back.
func roundTripJSON(t *testing.T, m map[string]interface{}) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]interface{}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// The support handshakes go to the ADDRESS the main handshake reached, with the
// same SNI — never a fresh resolution of the name. The name here is under
// .invalid (RFC 6761), which never resolves: a support handshake that redialled
// the name would fail, and the question it was asking would come back absent.
func TestCloudHandshake_SupportHandshakesRedialTheReachedAddress(t *testing.T) {
	c := tlskextest.Cases[1] // X25519 only: one support handshake (hybrid-only)
	srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
	r, err := NewTLSHandshakeService(3*time.Second).handshakeTo(context.Background(), "lb.vista-kex.invalid", srv.Addr)
	if err != nil || r == nil || !r.Success {
		t.Fatalf("handshake: %+v, %v", r, err)
	}
	cfg := map[string]interface{}{}
	applyHandshakeKeyExchange(cfg, r)
	tlskextest.Check(t, c, cfg)
	tlskextest.CheckConnections(t, c, srv)
}

// writeOneCloudDiscovery runs writeSensorDiscoveriesTx for one device carrying
// cfg and returns the metadata JSONB it wrote.
func writeOneCloudDiscovery(t *testing.T, cfg map[string]interface{}) map[string]interface{} {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	var captured []byte
	mock.ExpectBegin()
	mock.ExpectQuery(`(?s)SELECT id FROM sensors`).
		WillReturnRows(sqlmock.NewRows([]string{"id"}).AddRow(uuid.New()))
	mock.ExpectExec(`(?s)INSERT INTO sensor_discoveries`).
		WithArgs(
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
			capturingArg{into: &captured},
			sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
		).
		WillReturnResult(sqlmock.NewResult(1, 1))

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	hostname := "lb.example.com"
	device := models.Device{
		ID:              uuid.New(),
		DeviceType:      "aws_api_gateway",
		Hostname:        &hostname,
		DiscoveryMethod: "cloud_api",
		Metadata:        models.JSONB(map[string]interface{}{"crypto_configs": []map[string]interface{}{cfg}}),
		CreatedAt:       time.Now(),
	}
	if _, err := (&CloudDiscoveryService{}).writeSensorDiscoveriesTx(context.Background(), tx, uuid.New(), "batch-1", uuid.New(), "aws",
		[]models.Device{device}, time.Now(), false); err != nil {
		t.Fatalf("writeSensorDiscoveriesTx: %v", err)
	}
	_ = tx.Rollback()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no discovery row was written: %v", err)
	}
	var meta map[string]interface{}
	if err := json.Unmarshal(captured, &meta); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return meta
}
