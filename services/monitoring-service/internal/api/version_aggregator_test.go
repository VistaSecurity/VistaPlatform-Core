package api

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/version"
)

// Regression guard for the digest-pinned false-skew bug: on ECR/EKS installs
// every service is pinned by a unique image digest, but they all share one
// release tag. Alignment must key off the (uniform) tag, never the (per-pod)
// digest, so a digest-pinned-but-otherwise-aligned deployment reads "aligned".
func TestComputeSkew(t *testing.T) {
	self := version.Info{Service: "v2.5.3", Chart: "2.5.3", AppVersion: "v2.5.3"}

	tests := []struct {
		name        string
		rows        []ServiceVersionRow
		wantAligned bool
		wantFields  []string
	}{
		{
			name: "digest-pinned uniform release is aligned",
			rows: []ServiceVersionRow{
				{Service: "auth", Tag: "v2.5.3", Chart: "2.5.3", AppVersion: "v2.5.3", Status: "healthy", ImageDigest: "sha256:aaa"},
				{Service: "inventory", Tag: "v2.5.3", Chart: "2.5.3", AppVersion: "v2.5.3", Status: "healthy", ImageDigest: "sha256:bbb"},
			},
			wantAligned: true,
		},
		{
			name: "genuine tag mismatch is skew",
			rows: []ServiceVersionRow{
				{Service: "auth", Tag: "v2.5.3", Chart: "2.5.3", AppVersion: "v2.5.3", Status: "healthy"},
				{Service: "inventory", Tag: "v2.4.0", Chart: "2.5.3", AppVersion: "v2.5.3", Status: "healthy"},
			},
			wantAligned: false,
			wantFields:  []string{"tag"},
		},
		{
			name: "unreachable and unknown rows are ignored",
			rows: []ServiceVersionRow{
				{Service: "auth", Tag: "v2.5.3", Chart: "2.5.3", AppVersion: "v2.5.3", Status: "healthy"},
				{Service: "down", Tag: "v9.9.9", Chart: "9.9.9", AppVersion: "v9.9.9", Status: "unreachable"},
				{Service: "old", Tag: "unknown", Chart: "unknown", AppVersion: "unknown", Status: "healthy"},
			},
			wantAligned: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			aligned, skew := computeSkew(self, tc.rows)
			if aligned != tc.wantAligned {
				t.Fatalf("aligned = %v, want %v (skew=%+v)", aligned, tc.wantAligned, skew)
			}
			if len(skew) != len(tc.wantFields) {
				t.Fatalf("got %d skew entries %+v, want fields %v", len(skew), skew, tc.wantFields)
			}
			for i, f := range tc.wantFields {
				if skew[i].Field != f {
					t.Errorf("skew[%d].Field = %q, want %q", i, skew[i].Field, f)
				}
			}
		})
	}
}

// TestComputeStatus pins the four-state model the About-page badge renders.
// The regression it guards: a deployment where NO service reports a real
// version (every probe returns "unknown", or every probe is unreachable) used
// to read aligned=true — a green "all aligned" badge over an empty table.
// Status must distinguish "unknown" (no data) and "degraded" (a peer is down)
// from the genuine green "aligned".
func TestComputeStatus(t *testing.T) {
	const real = "v2.6.0"
	healthy := func(name, v string) ServiceVersionRow {
		return ServiceVersionRow{Service: name, Tag: v, Chart: v, AppVersion: v, Status: "healthy"}
	}
	down := func(name string) ServiceVersionRow {
		return ServiceVersionRow{Service: name, Tag: "unknown", Chart: "unknown", AppVersion: "unknown", Status: "unreachable"}
	}
	selfReal := version.Info{Service: real, Chart: real, AppVersion: real}
	selfUnknown := version.Info{Service: "unknown", Chart: "unknown", AppVersion: "unknown"}

	tests := []struct {
		name          string
		self          version.Info
		rows          []ServiceVersionRow
		wantStatus    string
		wantReachable int
		wantReporting int
		wantUnreach   int
	}{
		{
			name:          "all reachable and agree is aligned",
			self:          selfReal,
			rows:          []ServiceVersionRow{healthy("auth", real), healthy("inventory", real)},
			wantStatus:    StatusAligned,
			wantReachable: 2, wantReporting: 2, wantUnreach: 0,
		},
		{
			name:          "no real versions anywhere is unknown, not aligned",
			self:          selfUnknown,
			rows:          []ServiceVersionRow{healthy("auth", "unknown"), healthy("inventory", "unknown")},
			wantStatus:    StatusUnknown,
			wantReachable: 2, wantReporting: 0, wantUnreach: 0,
		},
		{
			name:          "reporters agree but a peer is down is degraded",
			self:          selfReal,
			rows:          []ServiceVersionRow{healthy("auth", real), down("pcap-processor")},
			wantStatus:    StatusDegraded,
			wantReachable: 1, wantReporting: 1, wantUnreach: 1,
		},
		{
			name:          "distinct real versions is skew even with a peer down",
			self:          selfReal,
			rows:          []ServiceVersionRow{healthy("auth", real), healthy("inventory", "v2.5.0"), down("pcap-processor")},
			wantStatus:    StatusSkew,
			wantReachable: 2, wantReporting: 2, wantUnreach: 1,
		},
		{
			name:          "self knows its version but all peers down is degraded, not unknown",
			self:          selfReal,
			rows:          []ServiceVersionRow{down("auth"), down("inventory")},
			wantStatus:    StatusDegraded,
			wantReachable: 0, wantReporting: 0, wantUnreach: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			status, _, summary := computeStatus(tc.self, tc.rows)
			if status != tc.wantStatus {
				t.Errorf("status = %q, want %q", status, tc.wantStatus)
			}
			if summary.Reachable != tc.wantReachable {
				t.Errorf("reachable = %d, want %d", summary.Reachable, tc.wantReachable)
			}
			if summary.Reporting != tc.wantReporting {
				t.Errorf("reporting = %d, want %d", summary.Reporting, tc.wantReporting)
			}
			if summary.Unreachable != tc.wantUnreach {
				t.Errorf("unreachable = %d, want %d", summary.Unreachable, tc.wantUnreach)
			}
		})
	}
}
