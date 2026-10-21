package identity_test

// DCIM gap 1, part 2: a sighting's virtual device contexts are normalised by
// Intake and carried, with the interfaces that name them, to the observed
// network the engine hands the repository.
//
// Mutations (each red, then restored green): drop the
// NormalizeObservedVirtualDeviceContexts call from Intake.assess; drop
// `VirtualDeviceContexts: s.VirtualDeviceContexts` from the observation; drop
// `VirtualDeviceContexts: obs.VirtualDeviceContexts` from
// recordObservedNetwork; drop the contexts from ObservedNetwork.Empty.

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

func TestNormalizeObservedVirtualDeviceContexts(t *testing.T) {
	long := strings.Repeat("v", 65)
	ctxs, ifs, dropped := identity.NormalizeObservedVirtualDeviceContexts(
		[]identity.ObservedVirtualDeviceContext{
			{Name: " vsys1 ", Identifier: i(1)},
			{Name: "vsys2", Identifier: i(40000)}, // out of range: kept without it
			{Name: "vsys1", Identifier: i(9)},     // duplicate: the first stands
			{Name: ""},
			{Name: long},
		},
		[]identity.ObservedInterface{
			{Name: "ethernet1/1", VirtualDeviceContext: "vsys1"},
			{Name: "ethernet1/2", VirtualDeviceContext: " vsys3 "}, // not listed: added without an identifier
			{Name: "ethernet1/3", VirtualDeviceContext: long},      // the name cannot be held
			{Name: "ethernet1/4"},
		})
	want := []identity.ObservedVirtualDeviceContext{{Name: "vsys1", Identifier: i(1)}, {Name: "vsys2"}, {Name: "vsys3"}}
	if !reflect.DeepEqual(ctxs, want) {
		t.Errorf("contexts %+v, want %+v", ctxs, want)
	}
	gotIfc := []string{ifs[0].VirtualDeviceContext, ifs[1].VirtualDeviceContext, ifs[2].VirtualDeviceContext, ifs[3].VirtualDeviceContext}
	if wantIfc := []string{"vsys1", "vsys3", "", ""}; !reflect.DeepEqual(gotIfc, wantIfc) {
		t.Errorf("interface contexts %v, want %v", gotIfc, wantIfc)
	}
	if len(dropped) != 3 {
		t.Errorf("dropped %v, want the empty name, the long name and the interface naming it", dropped)
	}
}

func TestEngineRecordsTheObservedVirtualDeviceContexts(t *testing.T) {
	repo := &recordingRepo{Repository: memory.New()}
	e, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatal(err)
	}
	in, err := identity.NewIntake(repo)
	if err != nil {
		t.Fatal(err)
	}
	s := agentSighting(time.Date(2026, 1, 15, 9, 0, 0, 0, time.UTC),
		identity.ObservedInterface{Name: "port1", VirtualDeviceContext: "root"},
		identity.ObservedInterface{Name: "port2", VirtualDeviceContext: "branch-a"})
	s.VirtualDeviceContexts = []identity.ObservedVirtualDeviceContext{{Name: "root"}}
	obs, err := in.Build(context.Background(), s)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Resolve(context.Background(), obs); err != nil {
		t.Fatal(err)
	}
	if len(repo.calls) != 1 {
		t.Fatalf("%d posture writes, want 1", len(repo.calls))
	}
	n := repo.calls[0]
	if want := []identity.ObservedVirtualDeviceContext{{Name: "root"}, {Name: "branch-a"}}; !reflect.DeepEqual(n.VirtualDeviceContexts, want) {
		t.Errorf("contexts %+v, want %+v", n.VirtualDeviceContexts, want)
	}
	if n.Interfaces[1].VirtualDeviceContext != "branch-a" {
		t.Errorf("port2's context %q, want branch-a", n.Interfaces[1].VirtualDeviceContext)
	}
	if (identity.ObservedNetwork{VirtualDeviceContexts: n.VirtualDeviceContexts}).Empty() {
		t.Error("an observed network holding only contexts reads as empty")
	}
}

// A context's display name is trimmed, bounded to the description column's 200
// characters, and the first non-empty one stated for a name stands.
//
// Mutation: drop boundContextDescription from the add call → the long name
// passes through whole; drop the `out[i].Description == ""` arm → a later
// duplicate's name is lost.
func TestNormalizeObservedVirtualDeviceContexts_Description(t *testing.T) {
	long := strings.Repeat("é", 300)
	ctxs, _, _ := identity.NormalizeObservedVirtualDeviceContexts(
		[]identity.ObservedVirtualDeviceContext{
			{Name: "vsys1", Description: "  Core  "},
			{Name: "vsys2"},
			{Name: "vsys2", Description: "Tenant B"}, // the first name stated wins, an empty one does not count
			{Name: "vsys3", Description: long},
		}, nil)
	if len(ctxs) != 3 || ctxs[0].Description != "Core" || ctxs[1].Description != "Tenant B" {
		t.Fatalf("contexts %+v", ctxs)
	}
	if got := len([]rune(ctxs[2].Description)); got != 200 {
		t.Errorf("long display name has %d characters, want 200", got)
	}
}
