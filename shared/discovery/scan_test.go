package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestClassifyDialError(t *testing.T) {
	sys := func(e error) error {
		return &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connect", e)}
	}
	cases := []struct {
		name string
		err  error
		want outcome
	}{
		{"refused", sys(syscall.ECONNREFUSED), outcomeClosed},
		{"reset", sys(syscall.ECONNRESET), outcomeClosed},
		{"timeout", &net.OpError{Op: "dial", Err: context.DeadlineExceeded}, outcomeFiltered},
		{"host unreachable", sys(syscall.EHOSTUNREACH), outcomeFiltered},
		{"net unreachable", sys(syscall.ENETUNREACH), outcomeFiltered},
		{"prohibited", sys(syscall.EACCES), outcomeFiltered},
		{"out of fds", sys(syscall.EMFILE), outcomeLocalError},
		{"system out of fds", sys(syscall.ENFILE), outcomeLocalError},
		{"no ephemeral port", sys(syscall.EADDRNOTAVAIL), outcomeLocalError},
		{"no buffers", sys(syscall.ENOBUFS), outcomeLocalError},
		{"opaque", errors.New("something"), outcomeFiltered},
	}
	for _, c := range cases {
		if got := classifyDialError(c.err); got != c.want {
			t.Errorf("%s: got %d, want %d", c.name, got, c.want)
		}
	}
}

func TestScanTCP_ClassifiesEveryPortState(t *testing.T) {
	addr := mustAddr(t, "10.0.0.1")
	d := newFakeDialer(func(ap netip.AddrPort) fakeBehavior {
		return map[uint16]fakeBehavior{1: behOpen, 2: behRefused, 3: behReset, 4: behFiltered, 5: behUnreachable, 6: behEMFILE}[ap.Port()]
	})
	s := newTestScanner(t, d)
	h, err := s.ScanTCP(context.Background(), addr, portRange(t, 1, 6))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(h.Open, []int{1}) || h.OpenCount != 1 {
		t.Errorf("open = %v (count %d), want [1]", h.Open, h.OpenCount)
	}
	if h.Closed != 2 {
		t.Errorf("closed = %d, want 2 (refused + reset)", h.Closed)
	}
	if h.Filtered != 2 {
		t.Errorf("filtered = %d, want 2 (timeout + unreachable)", h.Filtered)
	}
	if h.LocalErrors != 1 {
		t.Errorf("local errors = %d, want 1 — EMFILE must not be reported as filtered", h.LocalErrors)
	}
	if h.NotProbed != 0 || h.Cancelled || h.RespondsOnAllPorts {
		t.Errorf("unexpected: notProbed=%d cancelled=%v tarpit=%v", h.NotProbed, h.Cancelled, h.RespondsOnAllPorts)
	}
	if h.Liveness != LivenessAssumedUp {
		t.Errorf("ScanTCP liveness = %v, want assumed_up", h.Liveness)
	}
	checkInvariant(t, h)
	if d.unclosed != 0 || d.writes != 0 {
		t.Errorf("unclosed=%d writes=%d, want 0/0", d.unclosed, d.writes)
	}
}

func TestHostScan_RefusedProvesUp_FilteredDoesNot(t *testing.T) {
	ports := portRange(t, 100, 110)
	refused, _ := newTestScanner(t, newFakeDialer(allBehave(behRefused))).ScanTCP(context.Background(), mustAddr(t, "10.0.0.2"), ports)
	if !refused.Responded() {
		t.Error("a host that refuses every port is up (RST proves it), Responded() = false")
	}
	filtered, _ := newTestScanner(t, newFakeDialer(allBehave(behFiltered))).ScanTCP(context.Background(), mustAddr(t, "10.0.0.3"), ports)
	if filtered.Responded() {
		t.Error("a host where everything times out did not respond, Responded() = true")
	}
	if filtered.Filtered != ports.Len() {
		t.Errorf("filtered = %d, want %d", filtered.Filtered, ports.Len())
	}
}

// ---- OT safety ---------------------------------------------------------------

func TestScan_OTPortsAreSerializedPerHost(t *testing.T) {
	d := newFakeDialer(allBehave(behOpen))
	d.latency = 3 * time.Millisecond
	const spacing = 5 * time.Millisecond
	s := newTestScanner(t, d, WithAssumeUp(), WithOTSpacing(spacing))
	hosts := []netip.Addr{mustAddr(t, "10.0.1.1"), mustAddr(t, "10.0.1.2")}
	ports := OTPorts().Union(portRange(t, 1, 200))
	res, err := s.Scan(context.Background(), hosts, ports)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hosts {
		if got := d.peakOT[h]; got != 1 {
			t.Errorf("%s: peak concurrent OT connections = %d, want exactly 1", h, got)
		}
		// Polarity: the same host DID get parallel connections on its
		// ordinary ports, so the measurement can see concurrency.
		if d.peakHost[h] < 2 {
			t.Errorf("%s: peak per-host concurrency = %d; the test cannot see parallelism", h, d.peakHost[h])
		}
		// Every OT connect started only after the previous one was closed,
		// and at least `spacing` later.
		var ot []netip.AddrPort
		for _, ap := range d.dialled() {
			if ap.Addr() == h && OTPorts().Contains(int(ap.Port())) {
				ot = append(ot, ap)
			}
		}
		if len(ot) != OTPorts().Len() {
			t.Fatalf("%s: %d OT dials, want %d (each once)", h, len(ot), OTPorts().Len())
		}
		sort.Slice(ot, func(i, j int) bool { return d.dialAt[ot[i]].Before(d.dialAt[ot[j]]) })
		for i := 1; i < len(ot); i++ {
			gap := d.dialAt[ot[i]].Sub(d.closedAt[ot[i-1]])
			if gap < spacing {
				t.Errorf("%s: OT connect to %d began %s after closing %d, want >= %s", h, ot[i].Port(), gap, ot[i-1].Port(), spacing)
			}
		}
	}
	if d.unclosed != 0 {
		t.Errorf("%d accepted connections were never closed", d.unclosed)
	}
	if d.writes != 0 {
		t.Errorf("engine wrote %d times; it must never send a payload", d.writes)
	}
	if res.Open != 2*ports.Len() {
		t.Errorf("open = %d, want %d", res.Open, 2*ports.Len())
	}
}

// The pause follows an ACCEPTED OT connect only. On a host where the OT ports
// alternate open and refused/filtered, the connect after an open port waits at
// least the spacing after that session closed, and the connect after a refused
// or filtered port does not wait it; the one-at-a-time rule holds throughout.
func TestScan_OTSpacingFollowsOnlyAHeldSession(t *testing.T) {
	ot := OTPorts().Ports()
	behaviour := map[int]fakeBehavior{}
	for i, p := range ot {
		switch i % 3 {
		case 0:
			behaviour[p] = behOpen
		case 1:
			behaviour[p] = behRefused
		default:
			behaviour[p] = behFiltered
		}
	}
	d := newFakeDialer(func(ap netip.AddrPort) fakeBehavior { return behaviour[int(ap.Port())] })
	const spacing = 60 * time.Millisecond
	prof := testPace
	prof.ConnectTimeout = 5 * time.Millisecond // a filtered port answers nothing for this long
	s, err := NewScanner(WithDialer(d), WithPaceProfile(prof), WithAssumeUp(), WithOTSpacing(spacing))
	if err != nil {
		t.Fatal(err)
	}
	h := mustAddr(t, "10.0.1.9")
	if _, err := s.ScanTCP(context.Background(), h, OTPorts()); err != nil {
		t.Fatal(err)
	}
	if d.peakOT[h] != 1 {
		t.Fatalf("peak concurrent OT connections = %d, want exactly 1", d.peakOT[h])
	}
	var dials []netip.AddrPort
	for _, ap := range d.dialled() {
		if ap.Addr() == h {
			dials = append(dials, ap)
		}
	}
	sort.Slice(dials, func(i, j int) bool { return d.dialAt[dials[i]].Before(d.dialAt[dials[j]]) })
	if len(dials) != len(ot) {
		t.Fatalf("%d OT dials, want %d", len(dials), len(ot))
	}
	afterOpen, afterOther := 0, 0
	for i := 1; i < len(dials); i++ {
		prev := dials[i-1]
		gap := d.dialAt[dials[i]].Sub(d.closedAt[prev])
		if behaviour[int(prev.Port())] == behOpen {
			afterOpen++
			if gap < spacing {
				t.Errorf("connect to %d began %s after the session on %d closed, want >= %s", dials[i].Port(), gap, prev.Port(), spacing)
			}
		} else {
			afterOther++
			if gap >= spacing {
				t.Errorf("connect to %d waited %s after %d, which held no session (%v): want no pause", dials[i].Port(), gap, prev.Port(), behaviour[int(prev.Port())])
			}
		}
	}
	if afterOpen == 0 || afterOther == 0 {
		t.Fatalf("the fixture exercised %d gaps after an open port and %d after none; both are needed", afterOpen, afterOther)
	}
}

func TestScan_OTPolicySkip_NeverTouchesOTPorts(t *testing.T) {
	ports := OTPorts().Union(portRange(t, 1, 50))
	isOT := func(ap netip.AddrPort) bool { return OTPorts().Contains(int(ap.Port())) }

	d := newFakeDialer(allBehave(behRefused))
	h, err := newTestScanner(t, d, WithOTPolicy(OTPolicySkip)).ScanTCP(context.Background(), mustAddr(t, "10.0.2.1"), ports)
	if err != nil {
		t.Fatal(err)
	}
	if n := d.dialCount(isOT); n != 0 {
		t.Errorf("OTPolicySkip dialled %d OT ports, want 0", n)
	}
	if h.SkippedOT != OTPorts().Len() || h.NotProbed != OTPorts().Len() {
		t.Errorf("skippedOT=%d notProbed=%d, want both %d (skips are counted, not dropped)", h.SkippedOT, h.NotProbed, OTPorts().Len())
	}
	checkInvariant(t, h)

	// Polarity: the default policy does connect to them.
	d2 := newFakeDialer(allBehave(behRefused))
	if _, err := newTestScanner(t, d2).ScanTCP(context.Background(), mustAddr(t, "10.0.2.1"), ports); err != nil {
		t.Fatal(err)
	}
	if n := d2.dialCount(isOT); n != OTPorts().Len() {
		t.Errorf("default policy dialled %d OT ports, want %d", n, OTPorts().Len())
	}
}

func TestLiveness_NeverProbesOTPorts(t *testing.T) {
	d := newFakeDialer(allBehave(behFiltered))
	s := newTestScanner(t, d, WithLivenessPorts(mustPorts("22,502,44818")))
	if _, err := s.Liveness(context.Background(), []netip.Addr{mustAddr(t, "10.0.3.1")}); err != nil {
		t.Fatal(err)
	}
	got := d.dialled()
	if len(got) != 1 || got[0].Port() != 22 {
		t.Errorf("liveness dialled %v, want only port 22", got)
	}
	if _, err := NewScanner(WithLivenessPorts(mustPorts("502"))); err == nil {
		t.Error("a liveness set of only OT ports must be refused")
	}
}

// ---- tarpit guard -------------------------------------------------------------

func TestScan_TarpitGuardStopsAHostThatAcceptsEverything(t *testing.T) {
	d := newFakeDialer(allBehave(behOpen))
	s := newTestScanner(t, d, WithOTPolicy(OTPolicySkip))
	addr := mustAddr(t, "10.0.4.1")
	h, err := s.ScanTCP(context.Background(), addr, ThoroughPorts())
	if err != nil {
		t.Fatal(err)
	}
	g := DefaultTarpitGuard()
	if !h.RespondsOnAllPorts {
		t.Fatal("a host that accepts every port must be marked RespondsOnAllPorts")
	}
	if len(h.Open) != g.SampleSize {
		t.Errorf("reported %d open ports, want the %d-port sample", len(h.Open), g.SampleSize)
	}
	if !slices.IsSorted(h.Open) {
		t.Errorf("sample not sorted: %v", h.Open)
	}
	// Stopped near the threshold, not after 65 535 connects.
	limit := g.MaxOpen + testPace.PerHostConcurrency
	if n := len(d.dialled()); n > limit {
		t.Errorf("dialled %d ports before stopping, want <= %d", n, limit)
	}
	if h.OpenCount < g.MaxOpen || h.OpenCount > limit {
		t.Errorf("open count %d, want in [%d, %d]", h.OpenCount, g.MaxOpen, limit)
	}
	if h.Cancelled {
		t.Error("a tarpit stop is not a cancellation")
	}
	checkInvariant(t, h)
}

func TestScan_TarpitGuardLeavesBusyRealServersAlone(t *testing.T) {
	// 200 of Standard's ~1300 ports open: a very busy host, but well under
	// the guard's quarter-of-ports / 512 threshold — every port is reported.
	ports := StandardPorts()
	openSet := map[uint16]bool{}
	for _, p := range ports.Ports()[:200] {
		openSet[uint16(p)] = true
	}
	d := newFakeDialer(func(ap netip.AddrPort) fakeBehavior {
		if openSet[ap.Port()] {
			return behOpen
		}
		return behRefused
	})
	h, err := newTestScanner(t, d).ScanTCP(context.Background(), mustAddr(t, "10.0.4.2"), ports)
	if err != nil {
		t.Fatal(err)
	}
	if h.RespondsOnAllPorts || h.OpenCount != 200 || len(h.Open) != 200 {
		t.Errorf("tarpit=%v open=%d listed=%d, want false/200/200", h.RespondsOnAllPorts, h.OpenCount, len(h.Open))
	}

	// A small port set is never "a tarpit", even with every port open.
	d2 := newFakeDialer(allBehave(behOpen))
	q, _ := newTestScanner(t, d2).ScanTCP(context.Background(), mustAddr(t, "10.0.4.3"), QuickPorts())
	if q.RespondsOnAllPorts || q.OpenCount != QuickPorts().Len() {
		t.Errorf("Quick all-open: tarpit=%v open=%d, want false/%d", q.RespondsOnAllPorts, q.OpenCount, QuickPorts().Len())
	}
}

func TestTarpitGuard_Threshold(t *testing.T) {
	g := DefaultTarpitGuard()
	cases := map[int]int{0: 0, 40: 0, 255: 0, 256: 64, 1300: 325, 2048: 512, 65535: 512}
	for n, want := range cases {
		if got := g.threshold(n); got != want {
			t.Errorf("threshold(%d) = %d, want %d", n, got, want)
		}
	}
	if (TarpitGuard{Disabled: true}).threshold(65535) != 0 {
		t.Error("a disabled guard must never trigger")
	}
	for _, bad := range []TarpitGuard{
		{MinPorts: -1, MaxOpen: 1, MaxOpenFraction: 0.5, SampleSize: 1},
		{MaxOpen: 0, MaxOpenFraction: 0.5, SampleSize: 1},
		{MaxOpen: 1, MaxOpenFraction: 0, SampleSize: 1},
		{MaxOpen: 1, MaxOpenFraction: 1.5, SampleSize: 1},
		{MaxOpen: 1, MaxOpenFraction: 0.5, SampleSize: 0},
	} {
		if _, err := NewScanner(WithTarpitGuard(bad)); err == nil {
			t.Errorf("guard %+v accepted, want an error", bad)
		}
	}
}

// ---- liveness -------------------------------------------------------------------

func TestLiveness_AcceptedOrRefusedIsUp_SilenceIsNoAnswer(t *testing.T) {
	up1, up2, quiet, broken := mustAddr(t, "10.0.5.1"), mustAddr(t, "10.0.5.2"), mustAddr(t, "10.0.5.3"), mustAddr(t, "10.0.5.4")
	d := newFakeDialer(func(ap netip.AddrPort) fakeBehavior {
		switch ap.Addr() {
		case up1:
			if ap.Port() == 443 {
				return behOpen
			}
			return behFiltered
		case up2:
			return behRefused
		case broken:
			return behEMFILE
		}
		return behFiltered
	})
	res, err := newTestScanner(t, d).Liveness(context.Background(), []netip.Addr{up1, up2, quiet, broken})
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		state    LivenessState
		evidence string
	}{
		{LivenessUp, "tcp-open:443"},
		{LivenessUp, "tcp-refused:"},
		{LivenessNoAnswer, ""},
		{LivenessUndetermined, ""},
	}
	for i, w := range want {
		if res[i].State != w.state || !strings.HasPrefix(res[i].Evidence, w.evidence) || (w.evidence == "" && res[i].Evidence != "") {
			t.Errorf("%s: state=%v evidence=%q, want %v %q", res[i].Addr, res[i].State, res[i].Evidence, w.state, w.evidence)
		}
	}
	if res[2].Probes != DefaultLivenessPorts().Len() {
		t.Errorf("no-answer host: %d probes, want all %d liveness ports tried", res[2].Probes, DefaultLivenessPorts().Len())
	}
}

func TestScan_NoAnswerHostsAreNotPortScanned_UnlessAssumeUp(t *testing.T) {
	quiet := mustAddr(t, "10.0.6.1")
	ports := portRange(t, 2000, 2100)
	inPortSet := func(ap netip.AddrPort) bool { return ports.Contains(int(ap.Port())) }

	d := newFakeDialer(allBehave(behFiltered))
	res, err := newTestScanner(t, d).Scan(context.Background(), []netip.Addr{quiet}, ports)
	if err != nil {
		t.Fatal(err)
	}
	if n := d.dialCount(inPortSet); n != 0 {
		t.Errorf("a no-answer host got %d port-scan connects, want 0", n)
	}
	if res.HostsNoAnswer != 1 || res.HostsResponded != 0 || res.HostsPortScanned != 0 {
		t.Errorf("noAnswer=%d responded=%d scanned=%d, want 1/0/0", res.HostsNoAnswer, res.HostsResponded, res.HostsPortScanned)
	}
	if h := res.Hosts[0]; h.Liveness != LivenessNoAnswer || h.NotProbed != ports.Len() {
		t.Errorf("host: liveness=%v notProbed=%d", h.Liveness, h.NotProbed)
	}

	d2 := newFakeDialer(allBehave(behFiltered))
	res2, err := newTestScanner(t, d2, WithAssumeUp()).Scan(context.Background(), []netip.Addr{quiet}, ports)
	if err != nil {
		t.Fatal(err)
	}
	if n := d2.dialCount(inPortSet); n != ports.Len() {
		t.Errorf("AssumeUp: %d port-scan connects, want %d", n, ports.Len())
	}
	if n := len(d2.dialled()); n != ports.Len() {
		t.Errorf("AssumeUp still ran liveness: %d dials, want %d", n, ports.Len())
	}
	if res2.HostsPortScanned != 1 || res2.HostsNoAnswer != 1 || res2.Filtered != ports.Len() {
		t.Errorf("AssumeUp: scanned=%d noAnswer=%d filtered=%d", res2.HostsPortScanned, res2.HostsNoAnswer, res2.Filtered)
	}
}

type setOracle map[netip.Addr]bool

func (o setOracle) KnownUp(_ context.Context, a netip.Addr) bool { return o[a] }

func TestScan_LivenessOracleVouchesWithoutProbing(t *testing.T) {
	known, other := mustAddr(t, "10.0.7.1"), mustAddr(t, "10.0.7.2")
	d := newFakeDialer(allBehave(behFiltered))
	s := newTestScanner(t, d, WithLivenessOracle(setOracle{known: true, mustAddr(t, "10.9.9.9"): true}))
	res, err := s.Liveness(context.Background(), []netip.Addr{known, other})
	if err != nil {
		t.Fatal(err)
	}
	if res[0].State != LivenessUp || res[0].Evidence != "oracle" {
		t.Errorf("known: %v %q, want up/oracle", res[0].State, res[0].Evidence)
	}
	if res[1].State != LivenessNoAnswer {
		t.Errorf("other: %v, want no_answer", res[1].State)
	}
	for _, ap := range d.dialled() {
		if ap.Addr() != other {
			t.Errorf("dialled %s: the oracle may vouch for an input address, never add one", ap)
		}
	}
}

// ---- authorization envelope (H16) ---------------------------------------------

func TestScan_ContactsOnlyTheInputAddresses(t *testing.T) {
	inputs := []netip.Addr{
		mustAddr(t, "10.20.0.1"),
		mustAddr(t, "::ffff:10.20.0.2"), // IPv4-mapped: dialled as 10.20.0.2
		mustAddr(t, "fe80::1%eth0"),     // zone kept
		mustAddr(t, "2001:db8::5"),
		mustAddr(t, "10.20.0.1"), // duplicate
	}
	allowed := map[netip.Addr]bool{
		mustAddr(t, "10.20.0.1"):    true,
		mustAddr(t, "10.20.0.2"):    true,
		mustAddr(t, "fe80::1%eth0"): true,
		mustAddr(t, "2001:db8::5"):  true,
	}
	// Answers on some ports, silence and refusals elsewhere, so liveness and
	// the port scan both run against every host.
	behave := func(ap netip.AddrPort) fakeBehavior {
		switch ap.Port() % 3 {
		case 0:
			return behOpen
		case 1:
			return behRefused
		}
		return behFiltered
	}
	for _, mode := range []struct {
		name string
		opts []Option
	}{{"liveness", nil}, {"assume-up", []Option{WithAssumeUp()}}} {
		t.Run(mode.name, func(t *testing.T) {
			d := newFakeDialer(behave)
			res, err := newTestScanner(t, d, mode.opts...).Scan(context.Background(), inputs, QuickPorts())
			if err != nil {
				t.Fatal(err)
			}
			if len(d.badAddrs) > 0 {
				t.Fatalf("dial addresses that are not ip:port literals: %v", d.badAddrs)
			}
			seen := map[netip.Addr]bool{}
			for _, ap := range d.dialled() {
				if !allowed[ap.Addr()] {
					t.Errorf("dialled %s, which is not one of the input addresses", ap)
				}
				seen[ap.Addr()] = true
			}
			for a := range allowed {
				if !seen[a] {
					t.Errorf("input %s was never contacted", a)
				}
			}
			if res.HostsTotal != 4 {
				t.Errorf("hosts total = %d, want 4 (duplicate and mapped form folded)", res.HostsTotal)
			}
		})
	}
}

func TestScan_RefusesAddressesThatMustNeverBeDialled(t *testing.T) {
	for _, bad := range []netip.Addr{{}, mustAddr(t, "0.0.0.0"), mustAddr(t, "::"), mustAddr(t, "::ffff:0.0.0.0"), mustAddr(t, "224.0.0.1"), mustAddr(t, "ff02::1")} {
		d := newFakeDialer(allBehave(behOpen))
		s := newTestScanner(t, d)
		// The bad address is LAST: validation must happen before any dial.
		if _, err := s.Scan(context.Background(), []netip.Addr{mustAddr(t, "10.0.0.1"), bad}, QuickPorts()); err == nil {
			t.Errorf("Scan accepted %v", bad)
		}
		if _, err := s.ScanTCP(context.Background(), bad, QuickPorts()); err == nil {
			t.Errorf("ScanTCP accepted %v", bad)
		}
		if _, err := s.Liveness(context.Background(), []netip.Addr{bad}); err == nil {
			t.Errorf("Liveness accepted %v", bad)
		}
		if n := len(d.dialled()); n != 0 {
			t.Errorf("%v: %d dials happened before the refusal", bad, n)
		}
	}
}

func TestParseScanAddrs_NeverResolves(t *testing.T) {
	// "localhost" resolves on every machine: a parser that resolved names
	// would turn it into 127.0.0.1 and pass. It must be an error instead.
	for _, in := range []string{"localhost", "example.com", "host-name", "10.0.0.0/24", "10.0.0.1-10.0.0.9", "10.0.0.1:22", "[::1]:22", ""} {
		if got, err := ParseScanAddrs([]string{in}); err == nil {
			t.Errorf("ParseScanAddrs(%q) = %v, want an error", in, got)
		} else if !strings.Contains(err.Error(), fmt.Sprintf("%q", in)) {
			t.Errorf("error %q does not name the entry %q", err, in)
		}
	}
	got, err := ParseScanAddrs([]string{" 10.0.0.1 ", "::ffff:10.0.0.2", "fe80::1%eth0"})
	if err != nil {
		t.Fatal(err)
	}
	if got[2].Zone() != "eth0" {
		t.Errorf("zone dropped: %v", got[2])
	}
}

// ---- cancellation ---------------------------------------------------------------

func TestScan_CancelStopsPromptlyAndLeaksNothing(t *testing.T) {
	for _, phase := range []string{"liveness", "ports"} {
		t.Run(phase, func(t *testing.T) {
			baseline := runtime.NumGoroutine()
			d := newFakeDialer(allBehave(behFiltered))
			// A 30s connect timeout: only cancellation can end this scan quickly.
			opts := []Option{WithPaceProfile(PaceProfile{GlobalConcurrency: 64, PerHostConcurrency: 16, ConnectTimeout: 30 * time.Second})}
			if phase == "ports" {
				opts = append(opts, WithAssumeUp())
			}
			s := newTestScanner(t, d, opts...)
			var hosts []netip.Addr
			for i := 1; i <= 20; i++ {
				hosts = append(hosts, netip.AddrFrom4([4]byte{10, 0, 8, byte(i)}))
			}
			// Cancel once every connection slot the scan can use is held by
			// a blocked connect (64 in the port phase; 6 hosts x 10 liveness
			// ports in the liveness phase). From then on, any new connect
			// would have to take a slot freed BY the cancellation — which
			// the engine must refuse.
			saturated := 64
			if phase == "liveness" {
				saturated = 60
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					d.mu.Lock()
					n := d.global
					d.mu.Unlock()
					if n >= saturated {
						break
					}
					time.Sleep(time.Millisecond)
				}
				d.cancelled.Store(true)
				cancel()
			}()
			start := time.Now()
			res, err := s.Scan(ctx, hosts, ThoroughPorts())
			if err != nil {
				t.Fatal(err)
			}
			if el := time.Since(start); el > 5*time.Second {
				t.Errorf("Scan took %s; want a prompt return after cancel", el)
			}
			if d.peakGlobal != saturated {
				t.Errorf("peak in flight = %d, want %d (the cancel point assumes saturation)", d.peakGlobal, saturated)
			}
			if !res.Cancelled {
				t.Error("result not marked Cancelled")
			}
			if n := d.afterCancel.Load(); n != 0 {
				t.Errorf("%d connects started after cancellation: %v", n, d.debug)
			}
			if d.global != 0 || d.unclosed != 0 {
				t.Errorf("in flight after return: %d connects, %d unclosed", d.global, d.unclosed)
			}
			for _, h := range res.Hosts {
				checkInvariant(t, h)
				if !h.Cancelled {
					t.Errorf("%s not marked Cancelled", h.Addr)
				}
			}
			waitGoroutines(t, baseline)
		})
	}
}

// ---- pace and descriptor budget ------------------------------------------------

func TestConnSlotsForFDLimit(t *testing.T) {
	cases := []struct {
		limit uint64
		ok    bool
		want  int
	}{
		{0, false, nonUnixConnSlots},
		{0, true, minConnSlots},
		{256, true, minConnSlots},
		{1024, true, 384},
		{1280, true, 512},
		{65536, true, 16384},
		{1 << 20, true, maxConnSlots},
		{^uint64(0), true, maxConnSlots}, // RLIM_INFINITY
	}
	for _, c := range cases {
		if got := connSlotsForFDLimit(c.limit, c.ok); got != c.want {
			t.Errorf("connSlotsForFDLimit(%d, %v) = %d, want %d", c.limit, c.ok, got, c.want)
		}
	}
	if processConnGate().capacity() < minConnSlots {
		t.Errorf("process gate has %d slots", processConnGate().capacity())
	}
}

func TestScan_ConcurrencyIsCappedByTheDescriptorBudget(t *testing.T) {
	hosts := []netip.Addr{mustAddr(t, "10.0.9.1"), mustAddr(t, "10.0.9.2"), mustAddr(t, "10.0.9.3"), mustAddr(t, "10.0.9.4")}
	ports := portRange(t, 1, 3000)
	run := func(limit uint64) (int, Limits) {
		d := newFakeDialer(allBehave(behRefused))
		d.latency = 5 * time.Millisecond
		s := newTestScanner(t, d, WithPace(PaceFast), WithAssumeUp(), withConnSlotsForFDLimit(limit))
		if _, err := s.Scan(context.Background(), hosts, ports); err != nil {
			t.Fatal(err)
		}
		return d.peakGlobal, s.Limits()
	}
	peak, lim := run(1280) // budget (1280-256)/2 = 512, below fast's 2048
	if lim.EffectiveConcurrency != 512 {
		t.Errorf("effective concurrency = %d, want 512", lim.EffectiveConcurrency)
	}
	if peak > 512 {
		t.Errorf("peak in-flight connects = %d with a 512-slot descriptor budget", peak)
	}
	// Polarity: with a generous budget the same scan goes well past 512.
	if peak2, _ := run(1 << 20); peak2 <= 512 {
		t.Errorf("peak with a large budget = %d; the test cannot see the cap", peak2)
	}
}

func TestScan_RespectsGlobalAndPerHostConcurrency(t *testing.T) {
	prof := PaceProfile{GlobalConcurrency: 8, PerHostConcurrency: 3, ConnectTimeout: time.Second}
	d := newFakeDialer(allBehave(behRefused))
	d.latency = 3 * time.Millisecond
	var hosts []netip.Addr
	for i := 1; i <= 5; i++ {
		hosts = append(hosts, netip.AddrFrom4([4]byte{10, 0, 10, byte(i)}))
	}
	// Liveness runs (10 probe ports per host) and 502 is an OT port with its
	// own serial goroutine: both must stay inside the same per-host bound as
	// the ordinary port workers.
	ports := portRange(t, 1, 60).Union(mustPorts("502"))
	if _, err := newTestScanner(t, d, WithPaceProfile(prof)).Scan(context.Background(), hosts, ports); err != nil {
		t.Fatal(err)
	}
	if d.peakGlobal != prof.GlobalConcurrency {
		t.Errorf("peak global = %d, want exactly %d (reached, never exceeded)", d.peakGlobal, prof.GlobalConcurrency)
	}
	for _, h := range hosts {
		if d.peakHost[h] > prof.PerHostConcurrency {
			t.Errorf("%s: peak per host = %d > %d", h, d.peakHost[h], prof.PerHostConcurrency)
		}
	}
	if slices.Max(mapValues(d.peakHost)) != prof.PerHostConcurrency {
		t.Errorf("no host reached the per-host bound %d; the test cannot see it", prof.PerHostConcurrency)
	}
}

func mapValues(m map[netip.Addr]int) []int {
	out := make([]int, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestScan_BatchDelayPacesAHost(t *testing.T) {
	scan := func(delay time.Duration) time.Duration {
		prof := PaceProfile{GlobalConcurrency: 4, PerHostConcurrency: 4, ConnectTimeout: time.Second, BatchDelay: delay}
		s := newTestScanner(t, newFakeDialer(allBehave(behRefused)), WithPaceProfile(prof))
		start := time.Now()
		if _, err := s.ScanTCP(context.Background(), mustAddr(t, "10.0.11.1"), portRange(t, 1, 12)); err != nil {
			t.Fatal(err)
		}
		return time.Since(start)
	}
	// 12 ports in batches of 4 = two pauses.
	if el := scan(40 * time.Millisecond); el < 80*time.Millisecond {
		t.Errorf("with a 40ms batch delay a 3-batch scan took %s, want >= 80ms", el)
	}
	if el := scan(0); el >= 40*time.Millisecond {
		t.Errorf("without a batch delay the scan took %s", el)
	}
}

func TestPaceProfiles(t *testing.T) {
	for _, name := range []string{"polite", "NORMAL", " fast ", ""} {
		p, err := ParsePace(name)
		if err != nil {
			t.Fatalf("ParsePace(%q): %v", name, err)
		}
		prof, err := p.Profile()
		if err != nil || prof.validate() != nil {
			t.Errorf("%q: profile %+v invalid: %v", name, prof, err)
		}
	}
	if p, _ := ParsePace(""); p != PaceNormal {
		t.Errorf("default pace = %q, want normal", p)
	}
	if _, err := ParsePace("ludicrous"); err == nil {
		t.Error("unknown pace accepted")
	}
	s, err := NewScanner()
	if err != nil {
		t.Fatal(err)
	}
	if s.Limits().PaceProfile != paceProfiles[PaceNormal] {
		t.Errorf("default scanner pace = %+v, want normal", s.Limits().PaceProfile)
	}
	polite, normal, fast := paceProfiles[PacePolite], paceProfiles[PaceNormal], paceProfiles[PaceFast]
	ordered := polite.GlobalConcurrency < normal.GlobalConcurrency && normal.GlobalConcurrency < fast.GlobalConcurrency &&
		polite.PerHostConcurrency < normal.PerHostConcurrency && normal.PerHostConcurrency < fast.PerHostConcurrency &&
		polite.ConnectTimeout > normal.ConnectTimeout && normal.ConnectTimeout > fast.ConnectTimeout
	if !ordered {
		t.Error("pace profiles are not ordered polite < normal < fast")
	}
	for _, bad := range []PaceProfile{
		{GlobalConcurrency: 0, PerHostConcurrency: 1, ConnectTimeout: time.Second},
		{GlobalConcurrency: 1, PerHostConcurrency: 2, ConnectTimeout: time.Second},
		{GlobalConcurrency: 1, PerHostConcurrency: 1, ConnectTimeout: 0},
		{GlobalConcurrency: 1, PerHostConcurrency: 1, ConnectTimeout: time.Minute},
		{GlobalConcurrency: 1, PerHostConcurrency: 1, ConnectTimeout: time.Second, BatchDelay: -1},
	} {
		if _, err := NewScanner(WithPaceProfile(bad)); err == nil {
			t.Errorf("profile %+v accepted", bad)
		}
	}
}

// ---- progress -------------------------------------------------------------------

func TestScan_ProgressIsRateBoundedSerializedAndFinal(t *testing.T) {
	d := newFakeDialer(func(ap netip.AddrPort) fakeBehavior {
		if ap.Port()%10 == 0 {
			return behOpen
		}
		return behRefused
	})
	d.latency = 2 * time.Millisecond
	var calls []Progress
	var inCall, overlapped, afterReturn atomic.Bool
	var returned atomic.Bool
	fn := func(p Progress) {
		if returned.Load() {
			afterReturn.Store(true)
		}
		if !inCall.CompareAndSwap(false, true) {
			overlapped.Store(true)
		}
		calls = append(calls, p)
		inCall.Store(false)
	}
	prof := PaceProfile{GlobalConcurrency: 16, PerHostConcurrency: 8, ConnectTimeout: time.Second}
	s := newTestScanner(t, d, WithPaceProfile(prof), WithAssumeUp(), WithProgress(fn, 100*time.Millisecond))
	hosts := []netip.Addr{mustAddr(t, "10.0.12.1"), mustAddr(t, "10.0.12.2"), mustAddr(t, "10.0.12.3")}
	start := time.Now()
	res, err := s.Scan(context.Background(), hosts, portRange(t, 1, 1000))
	elapsed := time.Since(start)
	returned.Store(true)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond)
	if overlapped.Load() || afterReturn.Load() {
		t.Errorf("progress calls overlapped=%v after-return=%v", overlapped.Load(), afterReturn.Load())
	}
	// 3000 probes, at most one report per 100ms plus the final one.
	maxCalls := int(elapsed/(100*time.Millisecond)) + 1
	if len(calls) > maxCalls || len(calls) < 2 {
		t.Errorf("%d progress calls in %s, want 2..%d (bounded rate, not per port)", len(calls), elapsed, maxCalls)
	}
	last := calls[len(calls)-1]
	if last.Phase != PhaseDone || last.HostsDone != 3 || last.HostsTotal != 3 ||
		last.PortsProbed != int64(res.PortsProbed) || last.Open != int64(res.Open) || last.Closed != int64(res.Closed) {
		t.Errorf("final progress %+v does not match the result (probed %d open %d closed %d)", last, res.PortsProbed, res.Open, res.Closed)
	}
	for i := 1; i < len(calls); i++ {
		if calls[i].PortsProbed < calls[i-1].PortsProbed {
			t.Errorf("progress went backwards: %d then %d", calls[i-1].PortsProbed, calls[i].PortsProbed)
		}
	}
}

func TestScan_ResultTotalsAddUp(t *testing.T) {
	d := newFakeDialer(func(ap netip.AddrPort) fakeBehavior {
		if ap.Addr().As4()[3] == 3 {
			return behFiltered
		}
		return []fakeBehavior{behOpen, behRefused, behFiltered}[ap.Port()%3]
	})
	hosts := []netip.Addr{mustAddr(t, "10.0.13.1"), mustAddr(t, "10.0.13.2"), mustAddr(t, "10.0.13.3")}
	// 240 ports: below the tarpit guard's 256-port minimum, so a host with a
	// third of its ports open is reported in full.
	res, err := newTestScanner(t, d).Scan(context.Background(), hosts, portRange(t, 1, 240))
	if err != nil {
		t.Fatal(err)
	}
	if res.HostsResponded != 2 || res.HostsNoAnswer != 1 || res.HostsUndetermined != 0 || res.HostsPortScanned != 2 {
		t.Errorf("responded=%d noAnswer=%d undetermined=%d scanned=%d, want 2/1/0/2",
			res.HostsResponded, res.HostsNoAnswer, res.HostsUndetermined, res.HostsPortScanned)
	}
	var open, closed, filtered, notProbed int
	for _, h := range res.Hosts {
		checkInvariant(t, h)
		open += h.OpenCount
		closed += h.Closed
		filtered += h.Filtered
		notProbed += h.NotProbed
	}
	if res.Open != open || res.Closed != closed || res.Filtered != filtered || res.NotProbed != notProbed ||
		res.PortsProbed != open+closed+filtered {
		t.Errorf("totals %+v do not match the per-host sums", res)
	}
	if res.Open != 160 || res.Closed != 160 || res.Filtered != 160 || res.NotProbed != 240 {
		t.Errorf("open=%d closed=%d filtered=%d notProbed=%d, want 160/160/160/240", res.Open, res.Closed, res.Filtered, res.NotProbed)
	}
}

// Cancelling the scan context reaches each per-host context one sibling at a
// time. A host whose context has not heard yet must still not start a
// connect: acquire checks the scan's own context too.
func TestAcquire_RefusesOnceTheScanIsCancelled(t *testing.T) {
	s := newTestScanner(t, newFakeDialer(allBehave(behOpen)))
	root, cancel := context.WithCancel(context.Background())
	r := s.newRun(root, 1)
	hostSlot := make(chan struct{}, 1)
	if !r.acquire(context.Background(), hostSlot) {
		t.Fatal("acquire refused before cancellation")
	}
	r.release(hostSlot)
	cancel()
	if r.acquire(context.Background(), hostSlot) {
		t.Error("acquire granted a connect slot after the scan was cancelled")
		r.release(hostSlot)
	}
	if len(hostSlot) != 0 || len(r.paceSlot) != 0 {
		t.Errorf("slots leaked: host %d pace %d", len(hostSlot), len(r.paceSlot))
	}
}
