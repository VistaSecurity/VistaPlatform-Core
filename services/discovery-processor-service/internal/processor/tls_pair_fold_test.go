package processor

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

// Unit tests for the fold's pairing and merge rules. They run in the PR gate;
// the WIRING (the fold is actually called by ProcessBatch, and both rows are
// settled) is held by tls_pair_fold_integration_test.go.

func foldRow(t *testing.T, tenant uuid.UUID, source, dest string, port int, metadata map[string]any) *models.SensorDiscovery {
	t.Helper()
	blob, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	src := source
	return &models.SensorDiscovery{ID: uuid.New(), TenantID: tenant, Protocol: "TLS", DestIP: dest, Port: port, SourceIP: &src, Metadata: blob, Confidence: 0.8}
}

func decodeMeta(t *testing.T, d *models.SensorDiscovery) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(d.Metadata, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFoldTLSEnrichmentPairs_FoldsOnePairAndKeepsOthers(t *testing.T) {
	tenant := uuid.New()
	passive := foldRow(t, tenant, "10.0.0.5", "203.0.113.10", 443, passiveTLSEnvelope("10.0.0.5", "portal.example.test", boolPtr(true)))
	active := foldRow(t, tenant, "10.0.0.5", "203.0.113.10", 443, activeTLSEnvelope("10.0.0.5"))
	other := foldRow(t, tenant, "10.0.0.5", "203.0.113.11", 443, passiveTLSEnvelope("10.0.0.5", "other.example.test", nil))

	out, followers := foldTLSEnrichmentPairs([]*models.SensorDiscovery{passive, other, active})
	if len(out) != 2 {
		t.Fatalf("got %d rows, want 2 (pair folded, unrelated row kept)", len(out))
	}
	if out[0].ID != passive.ID || out[1] != other {
		t.Fatalf("order/identity wrong: got %s, %s", out[0].ID, out[1].ID)
	}
	if got := followers[passive.ID]; len(got) != 1 || got[0] != active.ID {
		t.Fatalf("followers = %v, want the active row under the passive row", followers)
	}
	m := decodeMeta(t, out[0])
	if m["version"] != "TLS 1.3" || m["cipher_suite"] != "TLS_AES_256_GCM_SHA384" {
		t.Errorf("version/cipher = %v/%v, want the active measurement", m["version"], m["cipher_suite"])
	}
	if m["cert_has_sct"] != false {
		t.Errorf("cert_has_sct = %v, want false (a measured false beats the passive true)", m["cert_has_sct"])
	}
	if m["cert_known_bad_ca"] != "" {
		t.Errorf("cert_known_bad_ca = %v, want the empty string both rows agree on", m["cert_known_bad_ca"])
	}
	if m["source_ip"] != "10.0.0.5" || m["ja3_hash"] == nil || m["sni"] != "portal.example.test" {
		t.Errorf("passive fields lost: source_ip=%v ja3_hash=%v sni=%v", m["source_ip"], m["ja3_hash"], m["sni"])
	}
	if m["discovery_method"] != "active_enrichment" {
		t.Errorf("discovery_method = %v, want active_enrichment", m["discovery_method"])
	}
	if out[0].Confidence != 0.8 {
		t.Errorf("confidence = %v", out[0].Confidence)
	}
	// The input rows are not mutated.
	if string(passive.Metadata) == string(out[0].Metadata) {
		t.Error("the passive row's own metadata was overwritten in place")
	}
}

func TestMergeEnrichmentMetadata_EmptyNeverWinsFalseIsAValue(t *testing.T) {
	passive := map[string]any{"version": "TLS 1.2", "cert_has_sct": true, "key_size": float64(2048), "source_ip": "10.0.0.5", "certificates": []any{map[string]any{"fingerprint_sha256": "p"}}}
	active := map[string]any{"version": "", "cert_has_sct": false, "key_size": float64(0), "source_ip": "10.9.9.9", "certificates": []any{}, "ocsp_status": "good"}
	m := mergeEnrichmentMetadata(passive, active)
	if m["version"] != "TLS 1.2" {
		t.Errorf("version = %v: an empty active value must not erase the passive one", m["version"])
	}
	if m["cert_has_sct"] != false {
		t.Errorf("cert_has_sct = %v: false is a value, not empty", m["cert_has_sct"])
	}
	if m["key_size"] != float64(2048) {
		t.Errorf("key_size = %v: zero is empty", m["key_size"])
	}
	if certs, _ := m["certificates"].([]any); len(certs) != 1 {
		t.Errorf("certificates = %v: an empty active array must not erase the passive chain", m["certificates"])
	}
	if m["source_ip"] != "10.0.0.5" {
		t.Errorf("source_ip = %v, want the passive observation's", m["source_ip"])
	}
	if m["ocsp_status"] != "good" {
		t.Errorf("ocsp_status = %v, want the active-only value", m["ocsp_status"])
	}
}

func TestFoldTLSEnrichmentPairs_LeavesNonPairsAlone(t *testing.T) {
	tenant := uuid.New()
	active := func() *models.SensorDiscovery {
		return foldRow(t, tenant, "10.0.0.5", "203.0.113.10", 443, activeTLSEnvelope("10.0.0.5"))
	}
	passive := func(sni string) *models.SensorDiscovery {
		return foldRow(t, tenant, "10.0.0.5", "203.0.113.10", 443, passiveTLSEnvelope("10.0.0.5", sni, nil))
	}

	otherTenant := foldRow(t, uuid.New(), "10.0.0.5", "203.0.113.10", 443, passiveTLSEnvelope("10.0.0.5", "portal.example.test", nil))
	otherPort := foldRow(t, tenant, "10.0.0.5", "203.0.113.10", 8443, passiveTLSEnvelope("10.0.0.5", "portal.example.test", nil))
	otherProtocol := passive("portal.example.test")
	otherProtocol.Protocol = "SSH"
	hostObservation := foldRow(t, tenant, "10.0.0.5", "203.0.113.10", 443, map[string]any{"discovery_method": "passive", "discovery_type": "host_observation"})
	interrogation := foldRow(t, tenant, "", "203.0.113.10", 443, map[string]any{"discovery_method": "device_interrogation", "source_asset_id": uuid.New().String()})
	hostInventory := foldRow(t, tenant, "10.0.0.5", "203.0.113.10", 443, map[string]any{"discovery_method": "passive", "discovery_type": "host_connection", "source_asset_id": uuid.New().String()})

	activeWithSNI := func(sni string) *models.SensorDiscovery {
		env := activeTLSEnvelope("10.0.0.5")
		env["raw_metadata"].(map[string]any)["sni"] = sni
		return foldRow(t, tenant, "10.0.0.5", "203.0.113.10", 443, env)
	}

	cases := map[string][]*models.SensorDiscovery{
		"passive only":              {passive("portal.example.test")},
		"active only":               {active()},
		"different tenant":          {otherTenant, active()},
		"different port":            {otherPort, active()},
		"different protocol":        {otherProtocol, active()},
		"host observation":          {hostObservation, active()},
		"interrogation-owned row":   {interrogation, active()},
		"host-inventory source row": {hostInventory, active()},
		"different SNI":             {passive("a.example.test"), activeWithSNI("b.example.test")},
		"passives disagree on SNI":  {passive("a.example.test"), passive("b.example.test"), active()},
	}
	for name, rows := range cases {
		t.Run(name, func(t *testing.T) {
			out, followers := foldTLSEnrichmentPairs(rows)
			if len(followers) != 0 || len(out) != len(rows) {
				t.Fatalf("folded %v (%d -> %d rows); this is not a pair", followers, len(rows), len(out))
			}
			for i := range rows {
				if out[i] != rows[i] {
					t.Errorf("row %d was replaced", i)
				}
			}
		})
	}

	// Polarity: the same SNI on both rows IS a pair.
	out, followers := foldTLSEnrichmentPairs([]*models.SensorDiscovery{passive("a.example.test"), activeWithSNI("a.example.test")})
	if len(out) != 1 || len(followers) != 1 {
		t.Errorf("same-SNI pair not folded: %d rows, followers %v", len(out), followers)
	}
}

func TestFoldTLSEnrichmentPairs_PrefersTheTriggeringFlow(t *testing.T) {
	tenant := uuid.New()
	a := foldRow(t, tenant, "10.0.0.5", "203.0.113.10", 443, passiveTLSEnvelope("10.0.0.5", "portal.example.test", nil))
	b := foldRow(t, tenant, "10.0.0.6", "203.0.113.10", 443, passiveTLSEnvelope("10.0.0.6", "portal.example.test", nil))
	active := foldRow(t, tenant, "10.0.0.6", "203.0.113.10", 443, activeTLSEnvelope("10.0.0.6"))

	out, followers := foldTLSEnrichmentPairs([]*models.SensorDiscovery{a, b, active})
	if len(out) != 2 || out[0] != a || out[1].ID != b.ID {
		t.Fatalf("rows = %d; want a untouched and b merged", len(out))
	}
	if got := followers[b.ID]; len(got) != 1 || got[0] != active.ID {
		t.Errorf("followers = %v, want the active row under the flow whose client triggered it", followers)
	}
}

func TestProcessedMarks_FollowersShareTheSurvivorsOutcome(t *testing.T) {
	survivor, follower, other := uuid.New(), uuid.New(), uuid.New()
	asset := uuid.New()
	m := newProcessedMarks()
	m.follow(tlsFoldFollowers{survivor: {follower}})
	m.addWithAsset(survivor, "auto_approved", nil, &asset)
	m.add(other, "pending", nil)

	got := m.ids[processedMark{approvalStatus: "auto_approved"}]
	if len(got) != 2 || got[0] != survivor.String() || got[1] != follower.String() {
		t.Fatalf("auto_approved ids = %v, want survivor then follower", got)
	}
	ids, assets := m.assetPairs()
	if len(ids) != 2 || assets[0] != asset.String() || assets[1] != asset.String() {
		t.Errorf("asset pairs = %v -> %v, want both rows on %s", ids, assets, asset)
	}
	if p := m.ids[processedMark{approvalStatus: "pending"}]; len(p) != 1 || p[0] != other.String() {
		t.Errorf("pending ids = %v", p)
	}
}
