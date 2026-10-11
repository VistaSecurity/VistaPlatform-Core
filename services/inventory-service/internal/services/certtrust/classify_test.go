package certtrust

import (
	"testing"

	"github.com/google/uuid"
)

// TestClassify_Precedence pins every status and the order in which the rules
// win: distrust > trust > public bundle > self-signed > untrusted > incomplete.
func TestClassify_Precedence(t *testing.T) {
	leaf := uuid.MustParse("00000000-0000-0000-0000-00000000000a")
	inter := uuid.MustParse("00000000-0000-0000-0000-00000000000b")
	root := uuid.MustParse("00000000-0000-0000-0000-00000000000c")
	const publicFP = "aa"
	isPublic := func(fp string) bool { return fp == publicFP }

	l := func(id uuid.UUID, selfSigned bool, fp, decision string) Link {
		return Link{ID: id, SelfSigned: selfSigned, FingerprintSHA256: fp, Decision: decision}
	}

	cases := []struct {
		name       string
		chain      []Link
		want       string
		wantAnchor uuid.UUID
		needs      bool
	}{
		{"distrusted root beats the public bundle",
			[]Link{l(leaf, false, "1", ""), l(inter, false, "2", ""), l(root, true, publicFP, DecisionDistrusted)},
			StatusDistrusted, root, false},
		{"distrusted intermediate beats a trusted root",
			[]Link{l(leaf, false, "1", ""), l(inter, false, "2", DecisionDistrusted), l(root, true, "3", DecisionTrusted)},
			StatusDistrusted, inter, false},
		{"distrust on the certificate itself",
			[]Link{l(root, true, "3", DecisionDistrusted)},
			StatusDistrusted, root, false},
		{"distrust wins even when the chain is incomplete",
			[]Link{l(leaf, false, "1", ""), l(inter, false, "2", DecisionDistrusted)},
			StatusDistrusted, inter, false},
		{"trusted root -> private_trusted",
			[]Link{l(leaf, false, "1", ""), l(inter, false, "2", ""), l(root, true, "3", DecisionTrusted)},
			StatusPrivateTrusted, root, false},
		{"nearest trusted CA is the anchor",
			[]Link{l(leaf, false, "1", ""), l(inter, false, "2", DecisionTrusted), l(root, true, "3", DecisionTrusted)},
			StatusPrivateTrusted, inter, false},
		{"trust beats the public bundle",
			[]Link{l(leaf, false, "1", ""), l(root, true, publicFP, DecisionTrusted)},
			StatusPrivateTrusted, root, false},
		{"trusted intermediate covers an incomplete chain",
			[]Link{l(leaf, false, "1", ""), l(inter, false, "2", DecisionTrusted)},
			StatusPrivateTrusted, inter, false},
		{"top in the public bundle -> public",
			[]Link{l(leaf, false, "1", ""), l(inter, false, "2", ""), l(root, true, publicFP, "")},
			StatusPublic, root, false},
		{"a public root on its own is public, not self_signed",
			[]Link{l(root, true, publicFP, "")},
			StatusPublic, root, false},
		{"self-signed leaf -> self_signed",
			[]Link{l(leaf, true, "1", "")},
			StatusSelfSigned, leaf, false},
		{"chain to an unanchored self-signed root -> untrusted",
			[]Link{l(leaf, false, "1", ""), l(inter, false, "2", ""), l(root, true, "3", "")},
			StatusUntrusted, root, false},
		{"leaf whose issuer is missing -> incomplete, anchor is the leaf",
			[]Link{l(leaf, false, "1", "")},
			StatusIncomplete, leaf, true},
		{"top is a non-self-signed intermediate -> incomplete, anchor is the last issuer found",
			[]Link{l(leaf, false, "1", ""), l(inter, false, "2", "")},
			StatusIncomplete, inter, true},
		{"a public fingerprint below the top does not make the chain public",
			[]Link{l(leaf, false, publicFP, ""), l(root, true, "3", "")},
			StatusUntrusted, root, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.chain, isPublic)
			if got.Status != tc.want || got.Anchor != tc.wantAnchor || got.NeedsIssuer != tc.needs {
				t.Fatalf("Classify = %+v, want status=%s anchor=%s needsIssuer=%v", got, tc.want, tc.wantAnchor, tc.needs)
			}
		})
	}

	if got := Classify(nil, isPublic); got.Status != StatusIncomplete {
		t.Fatalf("empty chain = %+v, want incomplete", got)
	}
	// A nil bundle check never yields public.
	if got := Classify([]Link{l(root, true, publicFP, "")}, nil); got.Status != StatusSelfSigned {
		t.Fatalf("nil bundle = %+v, want self_signed", got)
	}
}
