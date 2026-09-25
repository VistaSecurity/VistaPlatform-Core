package services

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// Registering a segment is a claim of ownership, and sensors enrich TLS
// services inside a registered range without the third-party opt-in (
// W5.13). A segment too wide to be anybody's — /0, IPv4 shorter than /8, IPv6
// shorter than /16 — is refused at save (owner decision on). Both
// polarities at each boundary.
func TestValidateSegmentBreadth(t *testing.T) {
	for _, tc := range []struct {
		segType, value string
		refused        bool
	}{
		{"cidr", "0.0.0.0/0", true},
		{"cidr", "::/0", true},
		{"cidr", "192.0.0.0/7", true},
		{"cidr", "192.0.0.0/8", false},
		{"cidr", "10.0.0.0/8", false},
		{"cidr", "203.0.113.0/24", false},
		{"cidr", "3ffe::/15", true},
		{"cidr", "3fff::/16", false},
		{"cidr", "fd00::/8", false}, // wholly ULA: claims nothing a private address does not
		{"cidr", " 0.0.0.0/0 ", true},
		{"cidr", "not-a-cidr", false},                  // malformed is validateSegmentValue's to report
		{"ip_range", "0.0.0.0-255.255.255.255", false}, // ranges are not ownership for probe consent
		{"domain", "example.com", false},
	} {
		err := validateSegmentBreadth(tc.segType, tc.value)
		if got := errors.Is(err, ErrSegmentTooBroad); got != tc.refused {
			t.Errorf("validateSegmentBreadth(%s, %q) refused = %v (err %v), want %v", tc.segType, tc.value, got, err, tc.refused)
		}
	}
}

// Every save path refuses one: create, update and bulk import. The refusal
// happens before any database access, which is why a nil DB suffices here.
func TestTooBroadSegmentIsRefusedOnEverySavePath(t *testing.T) {
	s := &NetworkSegmentService{}
	in := models.NetworkSegmentInput{Name: "everything", SegmentType: "cidr", Value: "0.0.0.0/0", NetworkType: "public", Environment: "production"}

	if _, err := s.Create(uuid.New(), in); !errors.Is(err, ErrSegmentTooBroad) {
		t.Errorf("Create err = %v, want ErrSegmentTooBroad", err)
	}
	if _, err := s.Update(uuid.New(), uuid.New(), in); !errors.Is(err, ErrSegmentTooBroad) {
		t.Errorf("Update err = %v, want ErrSegmentTooBroad", err)
	}
	res := s.BulkCreate(uuid.New(), []models.NetworkSegmentInput{in})
	if res.Failed != 1 || res.Created != 0 {
		t.Errorf("bulk import of a /0 = %+v, want the row failed", res)
	}
}
