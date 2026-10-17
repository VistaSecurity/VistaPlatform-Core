package tags

import (
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
)

func TestSlugify(t *testing.T) {
	for in, want := range map[string]string{
		"Core Switch":     "core-switch",
		"  PCI -- Scope ": "pci-scope",
		"Rack/4 (MDF)":    "rack-4-mdf",
	} {
		if got := Slugify(in); got != want {
			t.Errorf("Slugify(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormalize(t *testing.T) {
	c := "#AABBCC"
	in, err := Normalize(Input{Name: " Edge ", Color: &c, ObjectKinds: []dcim.ObjectKind{dcim.ObjectKindAsset, dcim.ObjectKindAsset}})
	if err != nil {
		t.Fatal(err)
	}
	if in.Name != "Edge" || in.Slug != "edge" || *in.Color != "aabbcc" || len(in.ObjectKinds) != 1 {
		t.Errorf("normalized = %+v", in)
	}
	bad := []Input{
		{Name: ""},
		{Name: "x", Slug: "Not A Slug"},
		{Name: "x", Color: func() *string { s := "red"; return &s }()},
		{Name: "x", ObjectKinds: []dcim.ObjectKind{"switch_port"}},
	}
	for i, b := range bad {
		if _, err := Normalize(b); !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d accepted: %v", i, err)
		}
	}
}

func TestAppliesTo(t *testing.T) {
	unrestricted := Tag{}
	if !unrestricted.AppliesTo(dcim.ObjectKindRack) {
		t.Error("an unrestricted tag must apply to every kind")
	}
	only := Tag{ObjectKinds: []dcim.ObjectKind{dcim.ObjectKindAsset}}
	if !only.AppliesTo(dcim.ObjectKindAsset) || only.AppliesTo(dcim.ObjectKindRack) {
		t.Error("a restricted tag applied to the wrong kinds")
	}
}
