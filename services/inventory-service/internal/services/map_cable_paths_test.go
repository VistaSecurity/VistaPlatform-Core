package services

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/cablepath"
)

func grp(kind dcim.ObjectKind, ids ...uuid.UUID) []cablepath.Node {
	out := make([]cablepath.Node, len(ids))
	for i, id := range ids {
		out[i] = cablepath.N(kind, id)
	}
	return out
}

// The run's shape is read off the stored hops: what sits between two cables
// is a patch panel or a circuit; the far end of the last cable is the
// destination and is not counted.
func TestSummarisePath(t *testing.T) {
	c1, c2, c3 := uuid.New(), uuid.New(), uuid.New()
	cases := []struct {
		name                    string
		groups                  [][]cablepath.Node
		cables, panels, circuit int
	}{
		{"direct", [][]cablepath.Node{
			grp(dcim.ObjectKindInterface, uuid.New()), grp(dcim.ObjectKindCable, c1), grp(dcim.ObjectKindInterface, uuid.New()),
		}, 1, 0, 0},
		{"two patch panels", [][]cablepath.Node{
			grp(dcim.ObjectKindInterface, uuid.New()), grp(dcim.ObjectKindCable, c1), grp(dcim.ObjectKindFrontPort, uuid.New()),
			grp(dcim.ObjectKindRearPort, uuid.New()), grp(dcim.ObjectKindCable, c2), grp(dcim.ObjectKindRearPort, uuid.New()),
			grp(dcim.ObjectKindFrontPort, uuid.New()), grp(dcim.ObjectKindCable, c3), grp(dcim.ObjectKindInterface, uuid.New()),
		}, 3, 2, 0},
		{"through a circuit", [][]cablepath.Node{
			grp(dcim.ObjectKindInterface, uuid.New()), grp(dcim.ObjectKindCable, c1), grp(dcim.ObjectKindCircuitTermination, uuid.New()),
			grp(dcim.ObjectKindCircuitTermination, uuid.New()), grp(dcim.ObjectKindCable, c2), grp(dcim.ObjectKindInterface, uuid.New()),
		}, 2, 0, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := summarisePath(tc.groups)
			if s.CableCount != tc.cables || s.PatchPanelCount != tc.panels || s.CircuitCount != tc.circuit {
				t.Fatalf("got cables=%d panels=%d circuits=%d, want %d/%d/%d", s.CableCount, s.PatchPanelCount, s.CircuitCount, tc.cables, tc.panels, tc.circuit)
			}
			if s.CableIDs[0] != c1 {
				t.Fatalf("first cable %s, want %s", s.CableIDs[0], c1)
			}
		})
	}
}

func TestWorseOperationalStatus(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"", "connected", "connected"},
		{"connected", "planned", "planned"},
		{"planned", "connected", "planned"},
		{"planned", "decommissioning", "decommissioning"},
	} {
		if got := worseOperationalStatus(tc.a, tc.b); got != tc.want {
			t.Errorf("worse(%q,%q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}
