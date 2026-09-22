package services

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// slice E, the regression this change could have caused and does not.
//
// Making a cloud job's `success` mean "every requested resource type was
// collected" turns a partial run into Success=false — and the scheduled
// worker used to gate result processing on exactly that flag. Left alone, a
// revoked KMS permission would have silently discarded the S3, RDS and EC2
// assets the same run DID collect: an honesty fix that quietly deleted data.
//
// Mutation: drop `|| len(result.Assets) > 0` from shouldProcessResults and the
// "partial run" case below goes red.
func TestPartialCloudRunStillProcessesResults(t *testing.T) {
	cases := []struct {
		name string
		in   *models.JobResult
		want bool
	}{
		{"nil result", nil, false},
		{"clean run", &models.JobResult{Success: true}, true},
		{
			name: "partial run — some types failed, but assets arrived",
			in:   &models.JobResult{Success: false, Assets: []models.DiscoveredAsset{{Hostname: "bucket.example.com"}}},
			want: true,
		},
		{
			name: "total failure with nothing collected",
			in:   &models.JobResult{Success: false},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldProcessResults(tc.in); got != tc.want {
				t.Errorf("shouldProcessResults = %v, want %v", got, tc.want)
			}
		})
	}
}
