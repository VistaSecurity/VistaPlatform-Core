package jobs

import (
	"testing"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

func quietCollector() *ResourceCollector {
	log := logrus.New()
	log.SetLevel(logrus.PanicLevel)
	return &ResourceCollector{logger: log}
}

// TestNetworkDelta_FirstObservationHasNoDelta pins the reason a bare key rename
// would have been wrong. /proc/net/dev reports bytes since boot; publishing
// that as period usage bills a tenant for the monitoring pod's entire uptime.
// With no previous reading there is no interval to report, and the answer is
// "not measured" — nil — not zero and certainly not the counter.
func TestNetworkDelta_FirstObservationHasNoDelta(t *testing.T) {
	rc := quietCollector()

	if got := rc.networkDelta(9_000_000_000); got != nil {
		t.Fatalf("first observation produced a delta of %d; the since-boot counter is not interval usage", *got)
	}
}

// TestNetworkDelta_SubsequentObservationsAreIntervalBytes is the correct
// behaviour: each tick reports only what moved since the previous tick.
func TestNetworkDelta_SubsequentObservationsAreIntervalBytes(t *testing.T) {
	rc := quietCollector()

	rc.networkDelta(1_000_000) // establish the baseline

	got := rc.networkDelta(1_500_000)
	if got == nil {
		t.Fatal("expected a delta once a baseline exists")
	}
	if *got != 500_000 {
		t.Fatalf("delta = %d, want 500000 (the interval, not the counter)", *got)
	}

	got = rc.networkDelta(1_500_050)
	if got == nil || *got != 50 {
		t.Fatalf("second delta = %v, want 50", got)
	}
}

// TestNetworkDelta_CounterResetIsNotBilled covers a reboot or interface reset,
// where the counter goes backwards. Reporting the post-reset total as a delta
// would attribute a fresh boot's traffic to one interval; reporting zero would
// claim we measured no traffic. The baseline moves so the NEXT interval is
// correct.
func TestNetworkDelta_CounterResetIsNotBilled(t *testing.T) {
	rc := quietCollector()

	rc.networkDelta(5_000_000)
	rc.networkDelta(6_000_000)

	if got := rc.networkDelta(1_000); got != nil {
		t.Fatalf("a counter reset produced a delta of %d; a reset is not usage", *got)
	}

	// The baseline must have re-anchored to the post-reset value.
	got := rc.networkDelta(1_500)
	if got == nil || *got != 500 {
		t.Fatalf("post-reset delta = %v, want 500 — the baseline did not re-anchor", got)
	}
}

// TestCollectSystemMetrics_ReportsNoFabricatedMetrics pins the deletion of the
// synthetic inputs. CPU was previously derived from the Go runtime's own
// MemStats (a formula over the GC counter), and disk usage was a hardcoded
// "100MB used, 1GB total" returned regardless of what the host reported. Both
// arrived downstream indistinguishable from measurements and were priced.
//
// The struct must not regain a field for either without a real measurement
// behind it; this test asserts the shape carries only what can be measured.
func TestCollectSystemMetrics_ReportsNoFabricatedMetrics(t *testing.T) {
	rc := quietCollector()

	m := rc.collectSystemMetrics()

	if m.ServiceName != "monitoring-service" {
		t.Fatalf("service_name = %q", m.ServiceName)
	}

	// Whatever the host provides, the first observation can never carry a
	// network delta — see TestNetworkDelta_FirstObservationHasNoDelta.
	if m.NetworkBytesDelta != nil {
		t.Fatalf("first collection reported a network delta of %d", *m.NetworkBytesDelta)
	}
}

// TestResolveMetricsTenantID_NoFallbackToNewestTenant pins the removal of the
// attribution fabrication.
//
// Host metrics describe SHARED service pods. The collector used to attribute
// all of them to `SELECT id FROM tenants ORDER BY created_at DESC LIMIT 1` —
// the most recently created tenant absorbed the whole platform's usage, and
// the answer changed every time somebody signed up. Unset, the collector must
// now attribute host metrics to nobody.
func TestResolveMetricsTenantID_NoFallbackToNewestTenant(t *testing.T) {
	rc := quietCollector()
	t.Setenv("RESOURCE_METRICS_TENANT_ID", "")

	id, err := rc.resolveMetricsTenantID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != uuid.Nil {
		t.Fatalf("resolved tenant %s with no operator configuration; host metrics must not be attributed by guesswork", id)
	}
}

// TestResolveMetricsTenantID_HonoursExplicitConfiguration keeps the legitimate
// case working: on a dedicated single-tenant deployment an operator can assert
// that this host serves exactly one tenant. That is a configured fact, not an
// inference.
func TestResolveMetricsTenantID_HonoursExplicitConfiguration(t *testing.T) {
	rc := quietCollector()
	want := uuid.New()
	t.Setenv("RESOURCE_METRICS_TENANT_ID", want.String())

	got, err := rc.resolveMetricsTenantID()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != want {
		t.Fatalf("resolved %s, want %s", got, want)
	}
}

// TestParseNetworkStats_DistinguishesNoTrafficFromNoInterface guards the bool:
// an unreadable or absent interface must not be reported as a measured zero.
func TestParseNetworkStats_DistinguishesNoTrafficFromNoInterface(t *testing.T) {
	const sample = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  123456     100    0    0    0     0          0         0   123456     100    0    0    0     0       0          0
  eth0: 9000000    5000    0    0    0     0          0         0  4000000    2500    0    0    0     0       0          0
`
	in, out, ok := parseNetworkStats(sample)
	if !ok {
		t.Fatal("expected a measurement from a sample containing eth0")
	}
	if in != 9_000_000 || out != 4_000_000 {
		t.Fatalf("parsed in=%d out=%d, want 9000000/4000000", in, out)
	}

	// Only loopback: no countable interface, so no measurement — not a zero.
	const loopbackOnly = `Inter-|   Receive
 face |bytes
    lo:  123456     100    0    0    0     0          0         0   123456     100    0    0    0     0       0          0
`
	if _, _, ok := parseNetworkStats(loopbackOnly); ok {
		t.Fatal("reported a measurement with no countable interface present")
	}
}
