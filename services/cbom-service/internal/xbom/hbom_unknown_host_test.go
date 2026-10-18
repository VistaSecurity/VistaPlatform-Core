package xbom

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

// An unknown_host is typed `device` by the registry, but that is CycloneDX
// having no "unknown" type. It is in the HBOM only with measured hardware
// evidence.
func TestHBOM_UnknownHostNeedsHardwareEvidence(t *testing.T) {
	withHW, bare := uuid.New(), uuid.New()
	snap := &Snapshot{
		Assets: []Asset{
			{ID: withHW, ClassKey: classUnknownHost, CycloneDXType: "device", DisplayName: "plug"},
			{ID: bare, ClassKey: classUnknownHost, CycloneDXType: "device", DisplayName: "phone"},
		},
		Facts: []Fact{
			{AssetID: withHW, Key: "hw.vendor", Value: "TP-Link", SourceRef: "a"},
			{AssetID: bare, Key: "os.name", Value: "iOS", SourceRef: "a"},
		},
	}
	doc, err := BuildDocument("hbom", snap, fixtureInput())
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Components) != 1 || doc.Components[0].Name != "plug" {
		t.Fatalf("components = %+v, want only the host with a hw.* fact", doc.Components)
	}
	inv, _ := BuildDocument("inventory", snap, fixtureInput())
	if len(inv.Components) != 2 {
		t.Errorf("inventory must still list both hosts, got %d", len(inv.Components))
	}
}

// Sources that agree produce one property; sources that disagree keep one
// per source.
func TestFactProperties_CollapsesAgreeingSources(t *testing.T) {
	a := uuid.New()
	facts := []Fact{
		{AssetID: a, Key: "hw.vendor", Value: "Apple", SourceRef: "s1"},
		{AssetID: a, Key: "hw.vendor", Value: "Apple", SourceRef: "s2"},
		{AssetID: a, Key: "os.name", Value: "Ubuntu", SourceRef: "s1"},
		{AssetID: a, Key: "os.name", Value: "Ubuntu Linux", SourceRef: "s2"},
	}
	var names []string
	for _, p := range factProperties(facts, "") {
		names = append(names, p.Name)
	}
	got := strings.Join(names, ",")
	want := propFactPrefix + "hw.vendor," + propFactPrefix + "os.name@s1," + propFactPrefix + "os.name@s2"
	if got != want {
		t.Errorf("properties = %s, want %s", got, want)
	}
}
