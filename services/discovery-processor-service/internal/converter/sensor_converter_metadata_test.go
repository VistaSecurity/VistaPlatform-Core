package converter

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

func rowWithMetadata(raw string) *models.SensorDiscovery {
	return &models.SensorDiscovery{ID: uuid.New(), Protocol: "TLS", DestIP: "10.1.2.3", Port: 443, Confidence: 0.9, Metadata: []byte(raw)}
}

// Metadata that is not a JSON object used to fall back to an empty map, and the
// row was imported as a bare ip/port finding. It is an error now, so the caller
// settles the row as a permanent failure with the reason.
//
// Mutation: restore the empty-map fallback in ToIngestFinding and the array,
// string, number and broken-JSON cases return a finding instead of an error.
func TestToIngestFinding_NonObjectMetadataIsAnError(t *testing.T) {
	for name, raw := range map[string]string{
		"array":        `[1,2,3]`,
		"string":       `"just text"`,
		"number":       `42`,
		"broken json":  `{"version": `,
		"bool literal": `true`,
	} {
		t.Run(name, func(t *testing.T) {
			f, err := NewSensorDiscoveryConverter().ToIngestFinding(rowWithMetadata(raw))
			if err == nil {
				t.Fatalf("converted to %+v, want an error for metadata %s", f, raw)
			}
			if !strings.Contains(err.Error(), "metadata is not a JSON object") {
				t.Fatalf("err = %v, want the reason to name the metadata", err)
			}
		})
	}
}

// Absent, empty and null metadata are legitimate ("nothing measured").
func TestToIngestFinding_AbsentMetadataStillConverts(t *testing.T) {
	for name, raw := range map[string]string{"empty": ``, "null": `null`, "empty object": `{}`} {
		t.Run(name, func(t *testing.T) {
			f, err := NewSensorDiscoveryConverter().ToIngestFinding(rowWithMetadata(raw))
			if err != nil || f == nil {
				t.Fatalf("finding = %v, err = %v, want a finding", f, err)
			}
		})
	}
}
