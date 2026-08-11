package capture

import "testing"

func TestIsBACnetSCALPN(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want bool
	}{
		{"bacnet.sc", true},
		{"BACnet.SC", false}, // case-sensitive per RFC 7301
		{"h2", false},
		{"http/1.1", false},
		{"", false},
		{"bacnet", false},
	}
	for _, c := range cases {
		if got := isBACnetSCALPN(c.in); got != c.want {
			t.Errorf("isBACnetSCALPN(%q)=%v, want %v", c.in, got, c.want)
		}
	}
}

func TestFirstString(t *testing.T) {
	t.Parallel()
	if got := firstString(nil); got != "" {
		t.Errorf("nil → %q, want empty", got)
	}
	if got := firstString([]string{}); got != "" {
		t.Errorf("empty → %q, want empty", got)
	}
	if got := firstString([]string{"a", "b"}); got != "a" {
		t.Errorf("[a b] → %q, want a", got)
	}
}
