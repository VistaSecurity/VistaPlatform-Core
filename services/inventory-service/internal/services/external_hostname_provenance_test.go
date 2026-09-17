package services

// Unit coverage for the hostname-provenance ladder. This is the Go mirror of
// the SQL in the upsert's ON CONFLICT clause; the DB-integration test
// (external_connections_hostname_provenance_integration_test.go) checks the two
// against each other against a real Postgres. Both exist on purpose: the
// integration test is the one that proves the STORED row is right, and this one
// runs in the plain unit suite where it is seen on every PR.

import "testing"

// Three ranks, not two, and the ordering between them. The middle rank is the
// one worth staring at: a row written before the column existed says nothing
// about its own provenance, and reading that silence as either "measured" or
// "inferred" is a fabrication.
func TestHostnameSourceKindRank_ThreeStatesNotTwo(t *testing.T) {
	tests := []struct {
		name string
		kind *string
		want int
	}{
		{"measured — read off the wire", strptr("measured"), 2},
		{"inferred — a guess about the address", strptr("inferred"), 0},
		{"nil — producer did not say (every legacy row)", nil, 1},
		{"empty string is not a fourth state", strptr(""), 1},
		{"declared — a human asserted it", strptr("declared"), 1},
		{"imported — another system of record supplied it", strptr("imported"), 1},
		{"an unrecognised word is not a provenance", strptr("telepathy"), 1},
		{"case and surrounding space do not change the answer", strptr("  MEASURED "), 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostnameSourceKindRank(tc.kind); got != tc.want {
				t.Errorf("hostnameSourceKindRank(%v) = %d, want %d", kindLabel(tc.kind), got, tc.want)
			}
		})
	}

	// The property the whole fix rests on, stated as itself rather than left
	// implicit in the table above.
	if hostnameSourceKindRank(strptr("inferred")) >= hostnameSourceKindRank(strptr("measured")) {
		t.Error("an inference outranks a measurement — this is the bug")
	}
	if hostnameSourceKindRank(strptr("inferred")) >= hostnameSourceKindRank(nil) {
		t.Error("an inference outranks an unlabelled stored name; legacy rows would be clobbered by PTR answers forever")
	}
	if hostnameSourceKindRank(nil) >= hostnameSourceKindRank(strptr("measured")) {
		t.Error("an unlabelled producer outranks a measurement; any unstamped path could stamp over a captured SNI")
	}
}

// Like replaces like — a fresh PTR may refresh a stale PTR, a new SNI a
// previous SNI — while a lower rank is refused. Without the `>=` half, a name
// could never be corrected by its own kind again.
func TestHostnameSourceKindWins_LikeReplacesLike(t *testing.T) {
	tests := []struct {
		name     string
		incoming *string
		stored   *string
		want     bool
	}{
		{"measured over inferred", strptr("measured"), strptr("inferred"), true},
		{"measured over unstated", strptr("measured"), nil, true},
		{"measured over measured", strptr("measured"), strptr("measured"), true},
		{"inferred over inferred", strptr("inferred"), strptr("inferred"), true},
		{"unstated over unstated", nil, nil, true},
		{"unstated over inferred", nil, strptr("inferred"), true},
		{"inferred over measured", strptr("inferred"), strptr("measured"), false},
		{"inferred over unstated", strptr("inferred"), nil, false},
		{"unstated over measured", nil, strptr("measured"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostnameSourceKindWins(tc.incoming, tc.stored); got != tc.want {
				t.Errorf("hostnameSourceKindWins(%q, %q) = %v, want %v",
					kindLabel(tc.incoming), kindLabel(tc.stored), got, tc.want)
			}
		})
	}
}

// The column carries a CHECK constraint, so an unrecognised word must be
// dropped rather than passed through — passing it through fails the whole
// upsert and loses a real observation over a label.
func TestNormalizeHostnameSourceKind(t *testing.T) {
	tests := []struct {
		in   *string
		want string // "" means nil
	}{
		{nil, ""},
		{strptr(""), ""},
		{strptr("   "), ""},
		{strptr("measured"), "measured"},
		{strptr("Measured"), "measured"},
		{strptr(" inferred "), "inferred"},
		{strptr("declared"), "declared"},
		{strptr("imported"), "imported"},
		{strptr("unknown"), ""},
		{strptr("telepathy"), ""},
	}
	for _, tc := range tests {
		got := normalizeHostnameSourceKind(tc.in)
		if tc.want == "" {
			if got != nil {
				t.Errorf("normalizeHostnameSourceKind(%q) = %q, want nil", kindLabel(tc.in), *got)
			}
			continue
		}
		if got == nil || *got != tc.want {
			t.Errorf("normalizeHostnameSourceKind(%q) = %v, want %q", kindLabel(tc.in), got, tc.want)
		}
	}
}
