package processor

// cloudResourceHint decides whether a discovery's ownership is resolved from
// its cloud account/region instead of its address. Getting it wrong in either
// direction is a real failure: too eager and a sensor discovery would be
// attributed to a cloud segment; too shy and a cloud resource falls back to the
// placeholder address that no segment rule can match.

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

func TestCloudResourceHint(t *testing.T) {
	cases := []struct {
		name     string
		metadata string
		want     bool
	}{
		{
			name:     "cloud discovery with provider and region",
			metadata: `{"discovery_method":"cloud_api","cloud_provider":"aws","cloud_region":"us-east-1","vpc_id":"vpc-123"}`,
			want:     true,
		},
		{
			name:     "sensor discovery",
			metadata: `{"discovery_method":"passive","cloud_provider":"aws","cloud_region":"us-east-1"}`,
			want:     false,
		},
		{
			name:     "device interrogation",
			metadata: `{"discovery_method":"device_interrogation"}`,
			want:     false,
		},
		{
			// Nothing to key a segment off. inventory-service's import path
			// requires both provider and region too, so falling back here keeps
			// classification and attribution saying the same thing.
			name:     "cloud discovery with no region",
			metadata: `{"discovery_method":"cloud_api","cloud_provider":"aws"}`,
			want:     false,
		},
		{
			name:     "unparseable metadata",
			metadata: `{`,
			want:     false,
		},
		{
			name:     "no metadata",
			metadata: ``,
			want:     false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &models.SensorDiscovery{DestIP: "0.0.0.0", Metadata: []byte(tc.metadata)}
			got := cloudResourceHint(d)
			if (got != nil) != tc.want {
				t.Fatalf("cloudResourceHint(%s) = %v, want hint present = %v", tc.metadata, got, tc.want)
			}
			if got != nil {
				if got.Provider == "" || got.Region == "" {
					t.Fatalf("hint is missing the fields ownership resolves from: %+v", got)
				}
			}
		})
	}

	t.Run("nil discovery", func(t *testing.T) {
		if cloudResourceHint(nil) != nil {
			t.Fatal("a nil discovery produced a cloud hint")
		}
	})
}
