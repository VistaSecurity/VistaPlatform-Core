package services

// A whole unit, measured: the liveness sweep of one address, a Thorough TCP
// scan (all 65,535 ports) at the normal pace, identification of what is open,
// and the curated UDP probes — against 127.0.0.1 with three listeners (TLS, an
// SMTP banner, a silent port). Loopback refuses a closed port at once, so this
// is the engine's best case per host: a filtered network waits out the
// connect timeout instead (see PaceProfile).
//
//	go test ./internal/services/ -run '^$' -bench BenchmarkUnit -benchtime 3x

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"testing"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
)

func BenchmarkUnit_ThoroughLoopback(b *testing.B) {
	addr := netip.MustParseAddr("127.0.0.1")
	listen := func(onConn func(net.Conn)) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Skip(err)
		}
		b.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() { defer func() { _ = c.Close() }(); onConn(c) }()
			}
		}()
	}
	listen(func(c net.Conn) { _, _ = c.Write([]byte("220 mx.example.test ESMTP\r\n")) })
	listen(func(c net.Conn) { buf := make([]byte, 64); _, _ = c.Read(buf) })

	engine, err := newUnitEngine(shareddisc.PaceNormal, nil)
	if err != nil {
		b.Fatal(err)
	}
	live, err := livenessScanner(shareddisc.PaceNormal, 4)
	if err != nil {
		b.Fatal(err)
	}
	ports := shareddisc.ThoroughPorts()
	udp := shareddisc.CuratedUDPPorts()
	b.ResetTimer()
	var open int
	for range b.N {
		lv, err := live.Liveness(context.Background(), []netip.Addr{addr})
		if err != nil || lv[0].State != shareddisc.LivenessUp {
			b.Fatalf("liveness = %+v %v", lv, err)
		}
		out, err := engine.Run(context.Background(), shareddisc.UnitInput{Addr: addr, TCP: ports, UDP: udp, Liveness: &lv[0]})
		if err != nil {
			b.Fatal(err)
		}
		c := jobunits.CountsOf(out)
		if c.PortsRequested != c.Open+c.Closed+c.Filtered+c.LocalErrors+c.NotProbed {
			b.Fatalf("counts not conserved: %+v", c)
		}
		open = c.Open
	}
	b.StopTimer()
	b.ReportMetric(float64(ports.Len()*b.N)/b.Elapsed().Seconds(), "ports/s")
	b.ReportMetric(float64(open), "open")
	b.Log("open ports on loopback (this host's own listeners included): " + strconv.Itoa(open))
}
