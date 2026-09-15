package services

// The heartbeat's uncolumned counters: what is carried, what is refused, and
// what the absence of them means.
//
// These land in `sensor_health_metrics.extra_counters`, a jsonb column, and the
// values come off a request body the SENSOR writes. That makes this the one
// place in the heartbeat path where an open set of caller-chosen keys reaches
// storage, so the bound on it is a contract and not an implementation detail.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
)

// The eight counters the passive pipeline reports are carried verbatim, and
// nothing else on the heartbeat is.
//
// The prefix test is what keeps this from swallowing the columned metrics
// (packets_captured, uptime_seconds) and storing each of them twice, in a
// column and in the jsonb, where the two would drift the first time one writer
// changed.
func TestExtraHeartbeatCounters_CarriesTheHostObservationSet(t *testing.T) {
	in := map[string]interface{}{
		"uptime_seconds":                     float64(3600),
		"packets_captured":                   float64(120000),
		"host_observations_offered":          float64(900),
		"host_observations_decoded":          float64(880),
		"host_observations_emitted":          float64(310),
		"host_observations_malformed":        float64(2),
		"host_observations_queue_dropped":    float64(0),
		"host_observations_emit_dropped":     float64(0),
		"host_observations_coalesce_dropped": float64(7),
		"host_observations_pending":          float64(12),
	}

	got := extraHeartbeatCounters(in)
	if got == nil {
		t.Fatal("a heartbeat carrying the counters reported none")
	}
	if len(*got) != 8 {
		t.Errorf("carried %d counters, want the 8 host_observations_* keys; got %v", len(*got), *got)
	}
	for k := range *got {
		if !strings.HasPrefix(k, models.HostObservationCounterPrefix) {
			t.Errorf("carried %q, which is not a host-observation counter — the columned metrics must not be stored twice", k)
		}
	}
	if (*got)["host_observations_coalesce_dropped"] != 7 {
		t.Errorf("coalesce_dropped = %d, want 7", (*got)["host_observations_coalesce_dropped"])
	}
	// Zero is a VALUE here, not an absence: "running and shedding nothing" is
	// the answer an operator wants and it must survive the trip.
	if v, ok := (*got)["host_observations_queue_dropped"]; !ok || v != 0 {
		t.Errorf("queue_dropped = %v (present=%v), want a stored 0", v, ok)
	}
}

// Nil, not an empty map, when the sensor reported none.
//
// The contract insists on this distinction for these metrics specifically: they
// are absent entirely when the feature is off, so that "not running" and
// "running and seeing nothing" do not look the same. It has to survive the
// whole way to the column, which is nullable for the same reason — `{}` would
// claim the second about a sensor doing the first.
func TestExtraHeartbeatCounters_NoneIsNilNotEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   map[string]interface{}
	}{
		{"no metrics at all", nil},
		{"metrics, but no host-observation counters", map[string]interface{}{"uptime_seconds": float64(60)}},
		{"the only counter is unreadable", map[string]interface{}{"host_observations_emitted": "many"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := extraHeartbeatCounters(tc.in); got != nil {
				t.Errorf("got %v, want nil — NULL means the sensor reported none, and `{}` would mean it reported all zeroes", *got)
			}
		})
	}
}

// A counter that is not a number is skipped, not coerced.
//
// Storing 0 for a value we could not read reports "nothing happened" about
// something we do not know, which is the same three-valued flattening that put
// NOT_ASSESSED into the PASS bucket.
func TestExtraHeartbeatCounters_UnreadableValueIsSkippedNotZeroed(t *testing.T) {
	got := extraHeartbeatCounters(map[string]interface{}{
		"host_observations_emitted": "three hundred",
		"host_observations_pending": float64(4),
	})
	if got == nil {
		t.Fatal("the readable counter was lost along with the unreadable one")
	}
	if _, ok := (*got)["host_observations_emitted"]; ok {
		t.Error("an unreadable counter was stored; a 0 there would read as `nothing happened`")
	}
	if (*got)["host_observations_pending"] != 4 {
		t.Error("a readable counter next to an unreadable one was lost")
	}
}

// The jsonb cannot be grown without bound by the sensor.
//
// The heartbeat body is written by customer-operated software holding a
// registered credential, the endpoint sets no size limit, and nothing prunes
// `sensor_health_metrics`. A prefix match accepts an OPEN set, so without this
// bound a runaway (or hostile) counter loop writes an arbitrarily large jsonb
// value every thirty seconds. The fixed column set this feature replaced could
// not be grown that way; jsonb can, which is the whole reason the ceiling has to
// be stated.
//
// Mutation check: delete either bound in extraHeartbeatCounters and this fails.
func TestExtraHeartbeatCounters_IsBounded(t *testing.T) {
	t.Run("count", func(t *testing.T) {
		in := map[string]interface{}{}
		for i := 0; i < models.MaxHeartbeatCounters*4; i++ {
			in[fmt.Sprintf("%s%04d", models.HostObservationCounterPrefix, i)] = float64(i)
		}
		got := extraHeartbeatCounters(in)
		if got == nil {
			t.Fatal("a heartbeat full of counters reported none")
		}
		if len(*got) > models.MaxHeartbeatCounters {
			t.Errorf("stored %d counters, want at most %d", len(*got), models.MaxHeartbeatCounters)
		}

		// And the subset is STABLE across heartbeats. Map iteration is
		// randomised, so a cut taken in map order would store a different
		// subset every beat — and differencing the ends of a window, which is
		// the only thing these cumulative counters are for, silently stops
		// meaning anything when the two ends hold different keys.
		again := extraHeartbeatCounters(in)
		if len(*again) != len(*got) {
			t.Fatalf("two reads of one heartbeat stored %d and %d counters", len(*got), len(*again))
		}
		for k, v := range *got {
			if w, ok := (*again)[k]; !ok || w != v {
				t.Fatalf("counter %q is not stable across reads (%v vs %v, present=%v); a window's two ends would hold different keys", k, v, w, ok)
			}
		}
	})

	t.Run("key length", func(t *testing.T) {
		long := models.HostObservationCounterPrefix + strings.Repeat("x", models.MaxHeartbeatCounterKeyLen)
		got := extraHeartbeatCounters(map[string]interface{}{
			long:                        float64(1),
			"host_observations_emitted": float64(5),
		})
		if got == nil {
			t.Fatal("the well-formed counter was lost along with the over-long one")
		}
		if _, ok := (*got)[long]; ok {
			t.Errorf("a %d-byte counter name was stored (limit %d)", len(long), models.MaxHeartbeatCounterKeyLen)
		}
		if (*got)["host_observations_emitted"] != 5 {
			t.Error("a well-formed counter next to an over-long one was lost")
		}
	})

	t.Run("the real counter names all fit", func(t *testing.T) {
		// The bound must not be tight enough to drop a counter that actually
		// exists — a limit that refuses real input is the same bug pointed the
		// other way.
		for _, k := range []string{
			"host_observations_offered", "host_observations_decoded",
			"host_observations_emitted", "host_observations_malformed",
			"host_observations_queue_dropped", "host_observations_emit_dropped",
			"host_observations_coalesce_dropped", "host_observations_pending",
		} {
			if len(k) > models.MaxHeartbeatCounterKeyLen {
				t.Errorf("%q is %d bytes and the limit is %d", k, len(k), models.MaxHeartbeatCounterKeyLen)
			}
		}
	})
}
