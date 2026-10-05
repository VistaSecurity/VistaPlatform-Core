package dispatchguard

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// observerOf decides which observations may direct an identity probe at all,
// before any database read. It must accept exactly the refs the guard accepted
// when the observer had to be the executor — a collector's own measurement in
// the planned network scope — and no more.
func TestObserverOf(t *testing.T) {
	segment, collector := uuid.New(), uuid.New()
	measured := func(ref string) identity.Observation {
		return identity.Observation{
			Source:  identity.Source{Kind: identity.SourceMeasured, Ref: ref},
			Network: identity.Network{SegmentID: segment.String()},
		}
	}
	for name, tc := range map[string]struct {
		obs  identity.Observation
		want bool
	}{
		"passive sensor sighting":   {measured("sensor:" + collector.String()), true},
		"active scan sighting":      {measured("scan:" + collector.String()), true},
		"tagged sensor ref":         {measured("sensor:identity-dns:" + collector.String()), true},
		"interrogation":             {measured("interrogation"), false},
		"bare sensor ref, no id":    {measured("sensor"), false},
		"bare scan ref, no id":      {measured("scan"), false},
		"pcap ref with no id":       {measured("sensor:pcap"), false},
		"cloud source":              {measured("cloud:aws"), false},
		"other prefix with an id":   {measured("interrogation:" + collector.String()), false},
		"id not last":               {measured("sensor:" + collector.String() + ":x"), false},
		"nil id":                    {measured("sensor:" + uuid.Nil.String()), false},
		"non-canonical id (upper)":  {measured("sensor:" + strings.ToUpper(collector.String())), false},
		"non-canonical id (braces)": {measured("sensor:{" + collector.String() + "}"), false},
		"imported, sensor ref": {identity.Observation{
			Source:  identity.Source{Kind: identity.SourceImported, Ref: "sensor:" + collector.String()},
			Network: identity.Network{SegmentID: segment.String()},
		}, false},
		"another network scope": {identity.Observation{
			Source:  identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + collector.String()},
			Network: identity.Network{SegmentID: uuid.NewString()},
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := observerOf(tc.obs, segment)
			if ok != tc.want {
				t.Fatalf("observerOf(%q) ok = %v, want %v", tc.obs.Source.Ref, ok, tc.want)
			}
			if ok && got != collector {
				t.Fatalf("observerOf(%q) = %s, want %s", tc.obs.Source.Ref, got, collector)
			}
			if !ok && got != uuid.Nil {
				t.Fatalf("a refused ref returned observer %s", got)
			}
		})
	}
}
