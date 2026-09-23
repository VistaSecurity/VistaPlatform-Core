package services

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// The merge is where an asset with no aggregates would come out with a null
// list, or an aggregate for an asset outside the capped set would add a row.
func TestAssembleNetworkMapAssets(t *testing.T) {
	a1, a2, outside := uuid.New(), uuid.New(), uuid.New()
	seg := uuid.New()
	addr := "10.0.0.5"
	rows := []networkMapAssetRow{
		{AssetID: a1, DisplayName: "web-01", ClassKey: "server", Address: &addr, SegmentID: &seg,
			Site: "DC-East", AssetStatus: "monitoring", RiskScore: 80, RiskAssessed: true},
		{AssetID: a2, DisplayName: "", ClassKey: "server", Site: TopologyUnassignedSite,
			AssetStatus: "pending_approval"},
	}
	agg := networkMapAggregates{
		Services: []networkMapServiceRow{
			{AssetID: a1, ServiceCount: 3, CryptoServiceCount: 2},
			{AssetID: outside, ServiceCount: 9},
		},
		Components: []networkMapComponentRow{
			{AssetID: a1, NetworkMapComponent: NetworkMapComponent{AlgorithmType: "signature", Name: "RSA", Strength: "acceptable", Observed: true}},
			{AssetID: a1, NetworkMapComponent: NetworkMapComponent{AlgorithmType: "key_exchange", Name: "X25519MLKEM768", Strength: "recommended", IsPQC: true, Observed: true}},
			{AssetID: a1, NetworkMapComponent: NetworkMapComponent{AlgorithmType: "key_exchange", Name: "ECDHE", Strength: "", Observed: false}},
			{AssetID: outside, NetworkMapComponent: NetworkMapComponent{AlgorithmType: "hash", Name: "MD5"}},
		},
		PQC:    []networkMapPQCRow{{AssetID: a1, NetworkMapPQC: NetworkMapPQC{NeedsMigration: 2, PQCReady: 1}}},
		Certs:  []networkMapCertRow{{AssetID: a1, CertsExpiring90d: 4}},
		Scopes: map[uuid.UUID]assetCloudScope{a2: {AccountID: "123456789012", Region: "us-east-1"}},
	}

	got := assembleNetworkMapAssets(rows, agg)
	if len(got) != 2 {
		t.Fatalf("got %d assets, want 2 — an aggregate for an asset outside the capped set added a row", len(got))
	}
	if got[0].AssetID != a1 || got[1].AssetID != a2 {
		t.Fatal("the query's order was not preserved")
	}

	w := got[0]
	if w.Address != addr || w.ServiceCount != 3 || w.CryptoServiceCount != 2 || w.Crypto.CertsExpiring90d != 4 {
		t.Errorf("a1 merged wrong: %+v", w)
	}
	if w.Crypto.PQC != (NetworkMapPQC{NeedsMigration: 2, PQCReady: 1}) {
		t.Errorf("a1 pqc = %+v", w.Crypto.PQC)
	}
	var order []string
	for _, c := range w.Crypto.Components {
		order = append(order, c.AlgorithmType+"/"+c.Name)
	}
	if strings.Join(order, ",") != "key_exchange/ECDHE,key_exchange/X25519MLKEM768,signature/RSA" {
		t.Errorf("components not sorted by type then name: %v", order)
	}
	if w.CloudAccount != "" || w.CloudRegion != "" {
		t.Errorf("a1 has no cloud scope but got %q/%q", w.CloudAccount, w.CloudRegion)
	}

	p := got[1]
	if p.Crypto.Components == nil {
		t.Fatal("an asset with no components must carry [] not null")
	}
	if p.ServiceCount != 0 || p.Crypto.PQC != (NetworkMapPQC{}) || p.Crypto.CertsExpiring90d != 0 {
		t.Errorf("a2 has no aggregates but got %+v", p)
	}
	if p.CloudAccount != "123456789012" || p.CloudRegion != "us-east-1" {
		t.Errorf("a2 cloud scope = %q/%q", p.CloudAccount, p.CloudRegion)
	}

	// The wire shape: empty strength survives as "", absent address and cloud
	// fields are omitted, a null segment is an explicit null, lists are [].
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{`"strength":""`, `"segment_id":null`, `"components":[]`} {
		if !strings.Contains(s, want) {
			t.Errorf("wire form lacks %s: %s", want, s)
		}
	}
	var second map[string]any
	var both []map[string]any
	if err := json.Unmarshal(b, &both); err != nil {
		t.Fatal(err)
	}
	second = both[1]
	if _, ok := second["address"]; ok {
		t.Error("address must be omitted when none is recorded")
	}
	if _, ok := both[0]["cloud_account"]; ok {
		t.Error("cloud_account must be omitted when absent")
	}
}

func TestAssembleNetworkMapAssets_Empty(t *testing.T) {
	got := assembleNetworkMapAssets(nil, networkMapAggregates{})
	if got == nil || len(got) != 0 {
		t.Fatalf("empty input must give an empty, non-nil slice; got %#v", got)
	}
}

// The order is total: two components differing only in strength or is_pqc
// must not flap between requests.
func TestSortNetworkMapComponents_Total(t *testing.T) {
	in := []NetworkMapComponent{
		{AlgorithmType: "hash", Name: "SHA", Strength: "strong", IsPQC: true},
		{AlgorithmType: "hash", Name: "SHA", Strength: "strong", IsPQC: false},
		{AlgorithmType: "hash", Name: "SHA", Strength: "acceptable"},
	}
	got := sortNetworkMapComponents(in)
	if got[0].Strength != "acceptable" || got[1].IsPQC || !got[2].IsPQC {
		t.Errorf("not a total order: %+v", got)
	}
	if &in[0] == &got[0] {
		t.Error("must not sort the caller's slice in place")
	}
}
