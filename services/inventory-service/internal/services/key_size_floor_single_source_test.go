package services

// One floor, one name.
//
// The 2048-bit RSA and 256-bit EC floors (NIST SP 800-131A Rev 2) are declared
// exactly once, in shared/cryptoparse, and read from there by every site in
// this package that judges a key by its length:
//
//   - highRiskKeySizeSQL, the SQL predicate the Crypto Risks list filters on;
//   - CryptoRisksService.classifyRisk, the Go classifier that labels one row.
//
// They used to be re-declared here as package-local aliases
// (minRSAKeySizeBits / minECCKeySizeBits) OF those same constants. Nothing was
// wrong with the numbers; the hazard is the second NAME. A floor raised in
// cryptoparse — SP 800-131A's next revision, or a customer policy — would move
// the Go classifier and the shared producer while a reader grepping for the
// local name saw a different, stale story, and the two spellings would have to
// be found by somebody who already knew both existed.
//
// So these tests do two things a "does 1024 fail?" test cannot: they assert the
// rules fire at the floors, AND they assert the rules fire at whatever
// cryptoparse currently SAYS the floors are. Change the constant and these
// tests follow it; reintroduce a second constant with a different value and
// they fail.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// The published floors, spelled out longhand. This is the one place a literal
// belongs: it pins cryptoparse itself to the standard, so the derived
// assertions below cannot all agree on a wrong number.
func TestKeySizeFloors_MatchSP800131A(t *testing.T) {
	if cryptoparse.MinRSAKeySizeBits != 2048 {
		t.Errorf("MinRSAKeySizeBits = %d, want 2048 (SP 800-131A Rev 2, 112-bit security)",
			cryptoparse.MinRSAKeySizeBits)
	}
	if cryptoparse.MinECCKeySizeBits != 256 {
		t.Errorf("MinECCKeySizeBits = %d, want 256 (SP 800-131A Rev 2)",
			cryptoparse.MinECCKeySizeBits)
	}
}

// The SQL predicate is generated from the shared constants, not from a literal.
//
// Spelled as "the rendered SQL must contain the number cryptoparse holds": if
// somebody reintroduces a local constant and points the fmt.Sprintf at it, this
// keeps passing only while the two agree — and fails the moment they do not,
// which is the only moment it matters.
func TestHighRiskKeySizeSQL_UsesTheSharedFloors(t *testing.T) {
	got := highRiskKeySizeSQL("ci.key_size", "ci.key_exchange_algorithm")

	for _, want := range []string{
		fmt.Sprintf("< %d", cryptoparse.MinRSAKeySizeBits),
		fmt.Sprintf("< %d", cryptoparse.MinECCKeySizeBits),
	} {
		if !strings.Contains(got, want) {
			t.Errorf("highRiskKeySizeSQL does not compare against %q — it has stopped reading "+
				"the shared floor:\n%s", want, got)
		}
	}
}

// The Go classifier fires at the floor and stays quiet at it.
//
// Both polarities, and both families, because the whole reason the floors are
// family-aware is that a bare `< 2048` labelled every healthy 256-bit EC key a
// critically weak RSA key.
func TestClassifyRisk_KeySizeFloorsComeFromCryptoparse(t *testing.T) {
	rsaKex := "RSA"
	ecKex := "ECDHE"

	cases := []struct {
		name      string
		kex       *string
		bits      int
		wantIssue string
	}{
		{
			name:      "RSA one bit below the shared floor",
			kex:       &rsaKex,
			bits:      cryptoparse.MinRSAKeySizeBits - 1,
			wantIssue: "weak_key_size",
		},
		{
			name: "RSA exactly at the shared floor",
			kex:  &rsaKex,
			bits: cryptoparse.MinRSAKeySizeBits,
			// No key-size issue at all: the floor is a minimum, not a
			// threshold to exceed.
			wantIssue: "",
		},
		{
			name:      "EC one bit below the shared floor",
			kex:       &ecKex,
			bits:      cryptoparse.MinECCKeySizeBits - 1,
			wantIssue: "weak_key_size",
		},
		{
			name:      "EC exactly at the shared floor",
			kex:       &ecKex,
			bits:      cryptoparse.MinECCKeySizeBits,
			wantIssue: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &CryptoRisksService{}
			r := &CryptoRisk{ID: uuid.New()}
			// A modern protocol and a strong suite/hash, so nothing else in
			// classifyRisk can claim the row before the key-size branch and
			// nothing else can be mistaken for it.
			version := "TLSv1.2"
			cipher := "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
			hash := "SHA384"
			bits := tc.bits

			s.classifyRisk(r, &version, &cipher, &hash, tc.kex, &bits, nil)

			if tc.wantIssue == "" {
				if r.Category == "key_size" {
					t.Errorf("%d-bit key with kex %q was flagged %q/%q — at or above the "+
						"shared floor nothing should fire", tc.bits, *tc.kex, r.Category, r.IssueType)
				}
				return
			}
			if r.IssueType != tc.wantIssue {
				t.Errorf("%d-bit key with kex %q: issue_type = %q, want %q",
					tc.bits, *tc.kex, r.IssueType, tc.wantIssue)
			}
			if r.Category != "key_size" {
				t.Errorf("%d-bit key with kex %q: category = %q, want \"key_size\"",
					tc.bits, *tc.kex, r.Category)
			}
		})
	}
}
