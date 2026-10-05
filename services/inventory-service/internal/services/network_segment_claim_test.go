package services

// Database-free halves of the claim action ( D8), so the PR gate — which
// does not run the DB-integration tests — still fails when a refusal or the
// server-owned-key protection is removed. The end-to-end behaviour, ownership
// included, is TestIntegration_SegmentClaimRoutes in cmd/.

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateClaimable(t *testing.T) {
	learned := map[string]interface{}{"source": "interrogation"}
	for _, tc := range []struct {
		name string
		row  segmentClaimRow
		want error
		says string
	}{
		{"learned public", segmentClaimRow{"cidr", "93.184.216.0/28", "public", learned}, nil, ""},
		{"legacy label", segmentClaimRow{"cidr", "93.184.216.0/28", "public", map[string]interface{}{"source": "unifi"}}, nil, ""},
		{"declared", segmentClaimRow{"cidr", "93.184.216.0/28", "public", map[string]interface{}{}}, ErrSegmentNotClaimable, "declared"},
		{"imported", segmentClaimRow{"cidr", "93.184.216.0/28", "public", map[string]interface{}{"source": "netbox"}}, ErrSegmentNotClaimable, "declared"},
		{"private", segmentClaimRow{"cidr", "10.0.0.0/24", "private", learned}, ErrSegmentNotClaimable, "already counts as yours"},
		{"not a cidr", segmentClaimRow{"domain", "partner.example", "public", learned}, ErrSegmentNotClaimable, "CIDR"},
		{"too broad v4", segmentClaimRow{"cidr", "92.0.0.0/7", "public", learned}, ErrSegmentTooBroad, "/8"},
		{"too broad v6", segmentClaimRow{"cidr", "2600::/15", "public", learned}, ErrSegmentTooBroad, "/16"},
		{"widest allowed", segmentClaimRow{"cidr", "93.0.0.0/8", "public", learned}, nil, ""},
	} {
		err := validateClaimable(tc.row)
		if tc.want == nil {
			if err != nil {
				t.Errorf("%s: %v, want claimable", tc.name, err)
			}
			continue
		}
		if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.says) {
			t.Errorf("%s: %v, want %v saying %q", tc.name, err, tc.want, tc.says)
		}
	}
}

// A client's metadata on update can neither set nor erase the claim or the
// learned provenance — in both directions.
func TestWithServerOwnedKeys(t *testing.T) {
	claim := map[string]interface{}{"by": "u", "at": "t"}
	current := map[string]interface{}{"source": "interrogation", "source_device_type": "fortinet", "source_asset_id": "a", "claimed": claim, "note": "old"}

	got := withServerOwnedKeys(map[string]interface{}{"note": "new"}, current)
	if got["claimed"] == nil || got["source"] != "interrogation" || got["source_device_type"] != "fortinet" || got["source_asset_id"] != "a" || got["note"] != "new" {
		t.Fatalf("omitting the server-owned keys erased them, or the client's own key was lost: %v", got)
	}

	forged := withServerOwnedKeys(map[string]interface{}{"claimed": map[string]interface{}{"by": "forger"}, "source": "interrogation"},
		map[string]interface{}{})
	if _, ok := forged["claimed"]; ok {
		t.Fatalf("a client set a claim on a declared segment: %v", forged)
	}
	if _, ok := forged["source"]; ok {
		t.Fatalf("a client relabelled a declared segment as learned: %v", forged)
	}
}

func TestWithoutClaim(t *testing.T) {
	got := withoutClaim(map[string]interface{}{"claimed": map[string]interface{}{"by": "forger"}, "note": "kept"})
	if _, ok := got["claimed"]; ok || got["note"] != "kept" {
		t.Fatalf("withoutClaim = %v, want the claim dropped and everything else kept", got)
	}
}
