package processor

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The key-exchange group a passive capture reports has to reach
// inventory-service as the external connection's exchange algorithm AND its
// measured size: with the size missing the connection stays unrated however
// much else is known about it. This drives stored sensor discoveries — in the
// envelope sensor-manager writes — through the real batch processor and reads
// what crossed the inventory HTTP boundary.
func TestIntegration_PassiveKeyExchangeGroupReachesExternalConnectionUpsert(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)

	recorder := newHostConnectionInventoryRecorder(t, uuid.New())
	inventory, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: recorder.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	processor := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), approval.NewService(raw), inventory, nil)

	// What the sensor's passive TLS assembler emits, per port:
	//   443  TLS 1.3 — group from the ServerHello key_share
	//   8443 TLS 1.2 — group from the ECDHE ServerKeyExchange
	//   9443 TLS 1.2 — DHE, a custom prime: a size and the suite label, no group
	//   10443 TLS 1.3 — the ServerHello showed no group
	envelopes := map[int]map[string]any{
		443: {"version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "raw_metadata": map[string]any{
			"key_exchange_algorithm": "X25519", "key_exchange_group_raw": 29, "key_exchange_key_size": 256}},
		8443: {"version": "TLS 1.2", "cipher_suite": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "raw_metadata": map[string]any{
			"key_exchange_algorithm": "DH-ECP-256", "key_exchange_group_raw": 23, "key_exchange_key_size": 256}},
		9443: {"version": "TLS 1.2", "cipher_suite": "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", "raw_metadata": map[string]any{
			"key_exchange_algorithm": "DHE_RSA", "key_exchange_key_size": 2048}},
		10443: {"version": "TLS 1.3", "cipher_suite": "TLS_AES_128_GCM_SHA256", "raw_metadata": map[string]any{
			"handshake_types": []string{"ClientHello", "ServerHello"}}},
	}
	batchID, sensorID := uuid.New().String(), uuid.New()
	for port, env := range envelopes {
		// The envelope keys sensor-manager writes unconditionally. key_size is
		// the generic one and must never be read as an exchange size.
		env["key_size"] = 0
		env["discovery_method"] = "passive"
		env["source_ip"] = "10.1.2.3"
		metadata, _ := json.Marshal(env)
		if _, err := raw.Exec(`INSERT INTO sensor_discoveries
			(id,sensor_id,tenant_id,batch_id,protocol,dest_ip,port,confidence,metadata,source_ip,timestamp,created_at)
			VALUES($1,$2,$3,$4,'TLS','8.8.8.8'::inet,$5,1,$6::jsonb,'10.1.2.3'::inet,now(),now())`,
			uuid.New(), sensorID, tenant, batchID, port, metadata); err != nil {
			t.Fatal(err)
		}
	}

	if err := processor.ProcessBatch(batchID, tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	recorder.mu.Lock()
	got := make(map[int]client.ExternalConnectionUpsert)
	for _, u := range recorder.external {
		got[u.DestPort] = u
	}
	recorder.mu.Unlock()
	if len(got) != len(envelopes) {
		t.Fatalf("external upserts for ports %v, want one per discovery", got)
	}
	for port, want := range map[int]struct {
		kex  string
		bits int
	}{443: {"X25519", 256}, 8443: {"DH-ECP-256", 256}, 9443: {"DHE_RSA", 2048}} {
		u := got[port]
		if u.KeyExchangeAlgorithm == nil || *u.KeyExchangeAlgorithm != want.kex {
			t.Errorf("port %d key_exchange_algorithm = %v, want %q", port, u.KeyExchangeAlgorithm, want.kex)
		}
		if u.KeySize == nil || *u.KeySize != want.bits {
			t.Errorf("port %d key_size = %v, want %d", port, u.KeySize, want.bits)
		}
	}
	if u := got[10443]; u.KeySize != nil || u.KeyExchangeAlgorithm != nil {
		t.Errorf("no group was observed, yet key_exchange_algorithm=%v key_size=%v crossed the wire", u.KeyExchangeAlgorithm, u.KeySize)
	}
}
