package models

// The agent is a SEPARATELY SHIPPED BINARY, so its wire compatibility is not a
// theoretical concern: a customer runs whatever agent build they installed
// against whatever control plane we deployed, in both directions. Phase 1
// renamed the job's target from `device_id` to `asset_id` (ADR-0002 D5:
// `devices` merged into `assets`), and for one release both are on the wire
// carrying the same value.
//
// Reading only one of the two is how an agent ends up with a job whose target
// it cannot see, which the executor then reports as an unexplained failure
// against the device.

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func TestJobTargetPrefersAssetIDAndFallsBackToDeviceID(t *testing.T) {
	assetID := uuid.New()
	deviceID := uuid.New()

	cases := []struct {
		name string
		json string
		want *uuid.UUID
	}{
		{
			name: "a phase-1 control plane sends both, carrying the same value",
			json: `{"id":"` + uuid.New().String() + `","type":"device_interrogation",` +
				`"asset_id":"` + assetID.String() + `","device_id":"` + assetID.String() + `"}`,
			want: &assetID,
		},
		{
			name: "an older control plane sends only device_id",
			json: `{"id":"` + uuid.New().String() + `","type":"device_interrogation",` +
				`"device_id":"` + deviceID.String() + `"}`,
			want: &deviceID,
		},
		{
			name: "a newer control plane that has dropped the alias sends only asset_id",
			json: `{"id":"` + uuid.New().String() + `","type":"device_interrogation",` +
				`"asset_id":"` + assetID.String() + `"}`,
			want: &assetID,
		},
		{
			name: "a cloud-discovery job names no target at all",
			json: `{"id":"` + uuid.New().String() + `","type":"cloud_discovery"}`,
			want: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var job Job
			if err := json.Unmarshal([]byte(tc.json), &job); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got := job.Target()
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("Target() = %s, want nil", got)
			case tc.want != nil && got == nil:
				t.Fatalf("Target() = nil, want %s", tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("Target() = %s, want %s", got, tc.want)
			}
		})
	}

	// The disagreeing case, which only arises if a control plane bug puts two
	// different values on one job: asset_id is the authority, because it is the
	// field the current platform writes from device_jobs.asset_id.
	var job Job
	if err := json.Unmarshal([]byte(`{"asset_id":"`+assetID.String()+`","device_id":"`+deviceID.String()+`"}`), &job); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if *job.Target() != assetID {
		t.Errorf("Target() = %s, want the asset_id %s to win", job.Target(), assetID)
	}
}
