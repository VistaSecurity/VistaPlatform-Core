package services

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

func strptr(s string) *string { return &s }

func TestValidateSegmentValue(t *testing.T) {
	cases := []struct {
		name        string
		segmentType string
		value       string
		wantErr     bool
	}{
		{"valid cidr", "cidr", "10.0.0.0/24", false},
		{"bad cidr", "cidr", "10.0.0.0/99", true},
		{"not a cidr", "cidr", "not-a-cidr", true},
		{"valid ip range", "ip_range", "10.0.0.1-10.0.0.254", false},
		{"bad ip range", "ip_range", "10.0.0.1", true},
		{"valid domain", "domain", "*.example.com", false},
		{"empty domain", "domain", "  ", true},
		{"valid cloud vpc", "cloud_vpc", "vpc-123", false},
		{"unknown type", "bogus", "x", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSegmentValue(tc.segmentType, tc.value)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for %q/%q, got nil", tc.segmentType, tc.value)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for %q/%q: %v", tc.segmentType, tc.value, err)
			}
		})
	}
}

func TestBulkAssetKey(t *testing.T) {
	cases := []struct {
		name string
		in   models.AssetInput
		want string
	}{
		{"hostname preferred", models.AssetInput{Hostname: strptr("Host-A"), IPAddress: strptr("10.0.0.1")}, "h:host-a"},
		{"hostname lowercased + trimmed", models.AssetInput{Hostname: strptr("  WEB.EXAMPLE.COM ")}, "h:web.example.com"},
		{"ip when no hostname", models.AssetInput{IPAddress: strptr("10.0.0.5")}, "i:10.0.0.5"},
		{"empty when neither", models.AssetInput{}, ""},
		{"blank hostname falls through to ip", models.AssetInput{Hostname: strptr("   "), IPAddress: strptr("10.0.0.9")}, "i:10.0.0.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bulkAssetKey(tc.in); got != tc.want {
				t.Fatalf("bulkAssetKey = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBulkImportResultAdd(t *testing.T) {
	res := models.NewBulkImportResult(0)
	res.Add(0, models.BulkRowCreated, nil, "")
	res.Add(1, models.BulkRowCreated, nil, "")
	res.Add(2, models.BulkRowSkippedDuplicate, nil, "dupe")
	res.Add(3, models.BulkRowError, nil, "boom")
	if res.Created != 2 || res.Skipped != 1 || res.Failed != 1 {
		t.Fatalf("counters = created %d / skipped %d / failed %d; want 2/1/1", res.Created, res.Skipped, res.Failed)
	}
	if len(res.Results) != 4 {
		t.Fatalf("expected 4 row results, got %d", len(res.Results))
	}
	if res.Results[2].Reason != "dupe" || res.Results[2].Status != models.BulkRowSkippedDuplicate {
		t.Fatalf("row 2 mismatch: %+v", res.Results[2])
	}
}
