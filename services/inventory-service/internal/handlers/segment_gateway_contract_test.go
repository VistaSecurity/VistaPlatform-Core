package handlers

// slice B: the gateway fields on every read slice C renders, populated
// and empty, against the spec. Stub services — no database.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func sampleGateway() *models.SegmentGateway {
	return &models.SegmentGateway{AssetID: uuid.New(), DisplayName: "edge-router", Address: "192.0.2.1",
		ObservedAt: time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)}
}

func TestContract_NetworkSegment_CarriesGatewayAndCoverage(t *testing.T) {
	sv := loadSpec(t)
	linked := sampleSegment()
	gwID, addr, ref, at := uuid.New(), "192.0.2.1", "interrogation:job", time.Now()
	// The stored columns are on the struct for `SELECT ns.*`; they must not
	// reach the wire, only `gateway` does.
	linked.GatewayAssetID, linked.GatewayAddress, linked.GatewaySourceRef, linked.GatewayObservedAt = &gwID, &addr, &ref, &at
	linked.Gateway = sampleGateway()
	linked.Coverage = &models.SegmentCoverage{SensorID: uuid.New(), SensorName: "branch-collector"}
	silent := minimalSegment()

	for label, seg := range map[string]models.NetworkSegment{"linked": linked, "silent": silent} {
		s := seg
		w := do(newSegmentEngine(&stubNetworkSegmentService{byID: &s}), http.MethodGet, nsBase+"/network-segments/"+aUUID, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d; body=%s", label, w.Code, w.Body.String())
		}
		sv.assertConforms(t, "NetworkSegment", w.Body.Bytes())
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"gateway", "coverage"} {
			if _, has := got[k]; !has {
				t.Errorf("%s: %s is absent; none must be an explicit null", label, k)
			}
		}
		for _, k := range []string{"gateway_asset_id", "gateway_address", "gateway_source_ref", "gateway_observed_at"} {
			if _, has := got[k]; has {
				t.Errorf("%s: the stored column %s leaked onto the wire", label, k)
			}
		}
	}
	w := do(newSegmentEngine(&stubNetworkSegmentService{byID: &linked}), http.MethodGet, nsBase+"/network-segments/"+aUUID, nil)
	if !strings.Contains(w.Body.String(), `"display_name":"edge-router"`) || !strings.Contains(w.Body.String(), `"sensor_name":"branch-collector"`) {
		t.Fatalf("gateway/coverage not serialised: %s", w.Body.String())
	}
}

func TestContract_GetAsset_CarriesRoutedSegmentsAndSegmentGateway(t *testing.T) {
	sv := loadSpec(t)
	tag, dyn := 20, true
	gateway := sampleAsset()
	routed := []models.RoutedSegment{
		{SegmentID: uuid.New(), Name: "Guest", Value: "198.51.100.0/24", SegmentType: "cidr", Address: "198.51.100.1",
			ObservedAt: time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC), VLANID: &tag, Dynamic: &dyn, HostCount: 3,
			Coverage: &models.SegmentCoverage{SensorID: uuid.New(), SensorName: "c1"}},
		{SegmentID: uuid.New(), Name: "Default", Value: "192.0.2.0/24", SegmentType: "cidr", Address: "192.0.2.1",
			ObservedAt: time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)},
	}
	gateway.RoutedSegments = &routed
	host := sampleAsset()
	none := []models.RoutedSegment{}
	host.RoutedSegments = &none
	host.SegmentGateway = sampleGateway()

	for label, a := range map[string]models.Asset{"gateway": gateway, "host": host} {
		a := a
		w := do(newEngine(&stubAssetStore{getResult: &a}, &stubApprovalStore{}), http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d; body=%s", label, w.Code, w.Body.String())
		}
		sv.assertConforms(t, "AssetResponse", w.Body.Bytes())
	}
	w := do(newEngine(&stubAssetStore{getResult: &host}, &stubApprovalStore{}), http.MethodGet, "/api/v2/inventory-service/infrastructure-assets/"+aUUID, nil)
	// "Routes nothing" is an explicit empty list, distinct from "not loaded".
	if !strings.Contains(w.Body.String(), `"routed_segments":[]`) || !strings.Contains(w.Body.String(), `"segment_gateway":{`) {
		t.Fatalf("host body = %s", w.Body.String())
	}
}

func TestContract_GetNetworkMap_CarriesSegmentGateway(t *testing.T) {
	sv := loadSpec(t)
	m := sampleNetworkMap()
	m.Segments = append(m.Segments, m.Segments[0])
	m.Segments[1].SegmentID = uuid.New()
	m.Segments[1].Gateway = sampleGateway()
	w := do(newNetworkMapEngine(NewNetworkMapHandler(&stubNetworkMapStore{networkMap: m})), http.MethodGet, networkMapPath, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NetworkMapResponse", w.Body.Bytes())
	if !strings.Contains(w.Body.String(), `"gateway":null`) || !strings.Contains(w.Body.String(), `"gateway":{"asset_id"`) {
		t.Fatalf("map segments must carry gateway, null or set: %s", w.Body.String())
	}
}
