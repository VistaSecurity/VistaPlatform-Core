package processor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
)

// Each distinct destination is looked up exactly once and never more than the
// bound at a time. Mutation: replace the sem/WaitGroup with a plain serial
// loop and the concurrency assertion fails; call lookup once per target slice
// element of a duplicated list and the once-each assertion fails.
func TestPrefetchPTRs_LooksEachTargetUpOnceAndBoundsConcurrency(t *testing.T) {
	var targets []string
	for i := 0; i < 40; i++ {
		targets = append(targets, fmt.Sprintf("198.51.100.%d", i))
	}
	var mu sync.Mutex
	calls := map[string]int{}
	var inFlight, peak int32
	lookup := func(ip string) string {
		n := atomic.AddInt32(&inFlight, 1)
		for {
			p := atomic.LoadInt32(&peak)
			if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
				break
			}
		}
		time.Sleep(15 * time.Millisecond)
		atomic.AddInt32(&inFlight, -1)
		mu.Lock()
		calls[ip]++
		mu.Unlock()
		return "host-" + ip
	}

	answers := prefetchPTRs(targets, lookup, 8)

	for _, ip := range targets {
		if calls[ip] != 1 {
			t.Errorf("%s looked up %d times, want exactly once", ip, calls[ip])
		}
		if answers.lookup(ip) != "host-"+ip {
			t.Errorf("answer for %s = %q", ip, answers.lookup(ip))
		}
	}
	if peak > 8 {
		t.Errorf("peak concurrency %d exceeds the bound of 8", peak)
	}
	if peak < 2 {
		t.Errorf("peak concurrency %d: lookups ran serially", peak)
	}
	if got := answers.lookup("203.0.113.250"); got != "" {
		t.Errorf("an address never looked up answered %q, want empty", got)
	}
}

// ptrTargets names exactly the destinations the batch loop would reverse-look-
// up, deduplicated: public, no name of its own, no SNI, not a host observation
// or interrogation row.
func TestPTRTargets_DedupesAndSkipsRowsThatNeedNoLookup(t *testing.T) {
	name := "already.example"
	mk := func(ip string, port int, host *string, meta string) *models.SensorDiscovery {
		return &models.SensorDiscovery{DestIP: ip, Port: port, Protocol: "TLS", Hostname: host, Metadata: []byte(meta)}
	}
	rows := []*models.SensorDiscovery{
		mk("8.8.8.8", 443, nil, `{}`),
		mk("8.8.8.8", 8443, nil, `{}`),  // same destination, other port: one lookup
		mk("1.1.1.1", 443, nil, `{}`),   // another public destination
		mk("10.0.0.5", 443, nil, `{}`),  // private: never looked up
		mk("9.9.9.9", 443, &name, `{}`), // has a name already
		mk("9.9.9.10", 443, nil, `{"sni":"vhost.example.com"}`),
		mk("9.9.9.11", 443, nil, `{"discovery_method":"device_interrogation"}`),
	}
	got := ptrTargets(rows, buildBatchSNIIndex(rows))
	sort.Strings(got)
	want := []string{"1.1.1.1", "8.8.8.8"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("ptrTargets = %v, want %v", got, want)
	}
}

func TestTransientClassification(t *testing.T) {
	status := func(code int) error { return &client.HTTPStatusError{StatusCode: code} }
	cases := []struct {
		name      string
		err       error
		transient bool
		chunkRej  bool
	}{
		{"nil", nil, false, false},
		{"401", status(401), true, false},
		{"403", status(403), true, false},
		{"404", status(404), true, false},
		{"409", status(409), true, false},
		{"423", status(423), true, false},
		{"429", status(429), true, false},
		{"503", status(503), true, false},
		{"wrapped 502", fmt.Errorf("chunk: %w", status(502)), true, false},
		{"400", status(400), false, true},
		{"413", status(413), false, true},
		{"422", status(422), false, true},
		{"410 gone", status(410), false, false},
		{"transport failure", fmt.Errorf("failed to send request: %w", &url.Error{Op: "Post", URL: "http://x", Err: errors.New("connection refused")}), true, false},
		{"net timeout", fmt.Errorf("x: %w", &net.OpError{Op: "dial", Err: context.DeadlineExceeded}), true, false},
		{"database error is not a transient class", errors.New("mark processed: boom"), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isTransientError(tc.err); got != tc.transient {
				t.Errorf("isTransientError = %v, want %v", got, tc.transient)
			}
			if got := isChunkRejection(tc.err); got != tc.chunkRej {
				t.Errorf("isChunkRejection = %v, want %v", got, tc.chunkRej)
			}
		})
	}
	_ = http.StatusOK
}

func TestRetryPolicy_TransientBudgetDefaultsAndLadderCoversIt(t *testing.T) {
	def := DefaultRetryPolicy()
	if def.MaxTransientAttempts < 48 {
		t.Fatalf("default MaxTransientAttempts = %d, want at least 48 (hours of outage)", def.MaxTransientAttempts)
	}
	if got := len(def.ladderMillis()); got != def.MaxTransientAttempts {
		t.Errorf("ladder has %d rungs, want one per transient attempt (%d)", got, def.MaxTransientAttempts)
	}
	var bp BatchProcessor
	bp.SetRetryPolicy(RetryPolicy{MaxAttempts: 9})
	if got := bp.retryPolicy().MaxTransientAttempts; got < 9 {
		t.Errorf("transient budget %d is below MaxAttempts 9; a transient failure must never have LESS room", got)
	}
}
