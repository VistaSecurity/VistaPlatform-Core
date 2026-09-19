package services

import (
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"testing"
)

func TestCloudSourcesAgreeWithDownstreamProviderNames(t *testing.T) {
	for vendor, want := range map[string]string{"AWS": "aws", "Amazon Web Services": "aws", "Azure": "azure", "Microsoft Azure": "azure", "GCP": "gcp", "Google Cloud": "gcp"} {
		if source := cloudSource(&vendor); source.Ref != "cloud:"+want {
			t.Fatalf("%s source=%s", vendor, source.Ref)
		}
		if got := cloudProviderForDevice(models.Device{Vendor: &vendor}); got != want {
			t.Fatalf("%s provider=%s", vendor, got)
		}
	}
}
func TestCloudDiscoveryReceiptTracksEvidenceNotOrdering(t *testing.T) {
	tenant := uuid.New()
	a := []byte(`{"cert":"a"}`)
	b := []byte(`{"cert":"b"}`)
	original := []uuid.UUID{cloudDiscoveryReceiptID(tenant, "batch", "TLS", "192.0.2.1", 443, a), cloudDiscoveryReceiptID(tenant, "batch", "TLS", "192.0.2.1", 8443, b)}
	reordered := []uuid.UUID{cloudDiscoveryReceiptID(tenant, "batch", "TLS", "192.0.2.1", 8443, b), cloudDiscoveryReceiptID(tenant, "batch", "TLS", "192.0.2.1", 443, a)}
	if original[0] != reordered[1] || original[1] != reordered[0] || original[0] == original[1] {
		t.Fatal("reordered batch changed evidence identity")
	}
	if cloudDiscoveryReceiptID(tenant, "next-batch", "TLS", "192.0.2.1", 443, a) == original[0] {
		t.Fatal("new collection collapsed into a prior sighting")
	}
}
