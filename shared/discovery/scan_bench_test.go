package discovery

import (
	"context"
	"crypto/tls"
	"math"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// Benchmarks. They touch loopback only — never another host.
//
//	go test -run '^$' -bench 'BenchmarkScan' -benchtime 1x ./discovery/

// BenchmarkScanLoopback measures real-socket throughput against 64 listening
// and ~2000 refusing loopback ports at each pace. Loopback has no latency and
// no loss, so this is the engine's ceiling, not a network measurement.
func BenchmarkScanLoopback(b *testing.B) {
	ls := startLoopbackListeners(b, "127.0.0.1", 64)
	closed := freedPorts(b, "127.0.0.1", 2000)
	ports, err := NewPortSet(append(slices.Clone(ls.ports), closed...)...)
	if err != nil {
		b.Fatal(err)
	}
	addr := netip.MustParseAddr("127.0.0.1")
	for _, pace := range []Pace{PacePolite, PaceNormal, PaceFast} {
		b.Run(string(pace), func(b *testing.B) {
			s, err := NewScanner(WithPace(pace))
			if err != nil {
				b.Fatal(err)
			}
			for b.Loop() {
				h, err := s.ScanTCP(context.Background(), addr, ports)
				if err != nil {
					b.Fatal(err)
				}
				if h.OpenCount != len(ls.ports) {
					b.Fatalf("open = %d, want %d", h.OpenCount, len(ls.ports))
				}
			}
			b.ReportMetric(float64(ports.Len()*b.N)/b.Elapsed().Seconds(), "ports/s")
		})
	}
}

// BenchmarkScanFilteredThorough simulates the worst case: one host on which
// all 65 535 ports are filtered, so every connect waits out its timeout. Real
// timeouts would make this take hours at the polite pace, so the profile's
// timeout and batch delay (and the OT spacing) are divided by
// filteredBenchScale and the measured wall clock is multiplied back:
//
//	projected-s  measured × scale — what a silent host costs at this pace
//	theory-s     ceil(ports / PerHost) × (timeout + batch delay), the formula
//	             in PaceProfile's documentation
func BenchmarkScanFilteredThorough(b *testing.B) {
	const filteredBenchScale = 100
	addr := netip.MustParseAddr("10.255.0.1") // never dialled: the fake network is in memory
	ports := ThoroughPorts()
	for _, pace := range []Pace{PacePolite, PaceNormal, PaceFast} {
		b.Run(string(pace), func(b *testing.B) {
			prof, _ := pace.Profile()
			scaled := prof
			scaled.ConnectTimeout /= filteredBenchScale
			scaled.BatchDelay /= filteredBenchScale
			d := newFakeDialer(allBehave(behFiltered))
			s, err := NewScanner(WithDialer(d), WithPaceProfile(scaled), WithOTSpacing(defaultOTSpacing/filteredBenchScale))
			if err != nil {
				b.Fatal(err)
			}
			for b.Loop() {
				h, err := s.ScanTCP(context.Background(), addr, ports)
				if err != nil {
					b.Fatal(err)
				}
				if h.Filtered != ports.Len() {
					b.Fatalf("filtered = %d, want %d", h.Filtered, ports.Len())
				}
			}
			perOp := b.Elapsed().Seconds() / float64(b.N)
			theory := math.Ceil(float64(ports.Len())/float64(prof.PerHostConcurrency)) * (prof.ConnectTimeout + prof.BatchDelay).Seconds()
			b.ReportMetric(perOp*filteredBenchScale, "projected-s")
			b.ReportMetric(theory, "theory-s")
			b.ReportMetric(float64(ports.Len())/(perOp*filteredBenchScale), "ports/s-projected")
		})
	}
}

// BenchmarkIdentifyLoopback measures service-identification throughput against
// a host of silent TLS listeners on loopback at each pace. The banner window is
// kept short so the measurement reflects the handshake cost, not the wait.
// Loopback only — never another host.
func BenchmarkIdentifyLoopback(b *testing.B) {
	const nPorts = 48
	var ports []int
	for range nPorts {
		srv := tlskextest.Start(b, []tls.CurveID{tls.X25519}, 0)
		ports = append(ports, srv.Port)
	}
	addr := netip.MustParseAddr("127.0.0.1")
	h := HostScan{Addr: addr, Liveness: LivenessAssumedUp, Open: ports, OpenCount: len(ports)}
	for _, pace := range []Pace{PacePolite, PaceNormal, PaceFast} {
		b.Run(string(pace), func(b *testing.B) {
			s, err := NewScanner(WithPace(pace))
			if err != nil {
				b.Fatal(err)
			}
			opts := IdentifyOptions{Hostname: "example.com", BannerWait: 50 * time.Millisecond}
			for b.Loop() {
				obs, err := s.Identify(context.Background(), h, opts)
				if err != nil {
					b.Fatal(err)
				}
				id := 0
				for _, o := range obs {
					if o.Identified {
						id++
					}
				}
				if id != nPorts {
					b.Fatalf("identified %d/%d", id, nPorts)
				}
			}
			b.ReportMetric(float64(nPorts*b.N)/b.Elapsed().Seconds(), "ports/s")
		})
	}
}
