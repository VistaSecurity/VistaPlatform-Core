package services

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The ingest side of the cloud-resource-id key list.
//
// device-interrogation-service's guard pins what the COLLECTORS write; this
// pins that ingest reads the same keys. The two had drifted — the collector
// side read `gcp_resource_id` and `azure_resource_id`, ingest did not — which
// meant an Azure Application Gateway was identified by its ARM id when the
// collector created the asset and by hostname alone when the same resource
// arrived as a finding. One resource, two identities, two assets.
//
// Driving discoveryObservation rather than cloudResourceID directly is the
// point: this stays red if the identifier stops being recorded on the
// observation, not merely if the helper stops returning a string.
func TestDiscoveryObservation_ReadsEveryCloudResourceIDKey(t *testing.T) {
	for _, key := range identity.CloudResourceIDKeys {
		want := "id-under-" + key
		f := IngestFinding{
			Hostname: ptr("resource.example.test"),
			Protocol: atRestProtocolSentinel,
			RawData: map[string]interface{}{
				"source":           "cloud_discovery",
				"discovery_method": "cloud_api",
				"cloud_provider":   "aws",
				key:                want,
			},
		}
		obs, err := unscopedService().discoveryObservation(uuid.New(), f, nil, identity.OwnershipInternal)
		if err != nil {
			t.Fatalf("%s: discoveryObservation: %v", key, err)
		}
		got, ok := ids(obs)[identity.KindCloudResourceID]
		if !ok || got.Value != want {
			t.Errorf("metadata key %q produced cloud_resource_id %+v, want %q — a key the collectors "+
				"write and ingest does not read is an identifier that never reaches the engine", key, got, want)
		}
	}
}

// The CloudFront shape, at the observation level: two findings for one
// distribution, different hostnames, and the SAME cloud_resource_id. The
// integration test proves they become one asset; this proves the input that
// makes them one, without needing a database.
func TestDiscoveryObservation_CloudFrontAliasCarriesTheDistributionID(t *testing.T) {
	const distributionID = "EXAMPLEDIST123"
	for _, hostname := range []string{"df0pxeck85ppe.cloudfront.net", "shop.example.com"} {
		f := IngestFinding{
			Hostname:  ptr(hostname),
			IPAddress: ptr("203.0.113.55"),
			Port:      ptr(443),
			AssetType: "cdn",
			Protocol:  "TLS",
			RawData: map[string]interface{}{
				"source":           "cloud_discovery",
				"discovery_method": "cloud_api",
				"cloud_provider":   "aws",
				"device_type":      "aws_cloudfront",
				// The only key naming the distribution. There is no ARN here;
				// the CloudFront collector never had one to write.
				"distribution_id": distributionID,
			},
		}
		obs, err := unscopedService().discoveryObservation(uuid.New(), f, ptr("203.0.113.55"), identity.OwnershipInternal)
		if err != nil {
			t.Fatalf("%s: discoveryObservation: %v", hostname, err)
		}
		got, ok := ids(obs)[identity.KindCloudResourceID]
		if !ok || got.Value != distributionID {
			t.Fatalf("%s: cloud_resource_id = %+v, want %q — without it the distribution and its alias "+
				"are two different hostnames and nothing says they are one distribution", hostname, got, distributionID)
		}
	}
}
