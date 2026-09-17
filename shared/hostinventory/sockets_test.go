package hostinventory

import (
	"context"
	"fmt"
	"testing"
)

func TestConnections_ExcludeAcceptedInboundAndIgnoreEphemeralLocalPort(t *testing.T) {
	listeners := []Listener{{Proto: "tcp", Address: "0.0.0.0", Port: 443}}
	in := []Connection{
		// Accepted inbound client: an established socket on a proven listener.
		{Proto: "tcp", LocalAddress: "192.0.2.10", LocalPort: 443, RemoteAddress: "198.51.100.8", RemotePort: 53122, Process: "server"},
		// Same outbound peer observed with two different ephemeral ports. It is
		// one durable connection identity, not two rows per collection.
		{Proto: "tcp", LocalAddress: "192.0.2.10", LocalPort: 49152, RemoteAddress: "203.0.113.20", RemotePort: 443, Process: "browser", PID: 10},
		{Proto: "tcp", LocalAddress: "192.0.2.10", LocalPort: 61234, RemoteAddress: "203.0.113.20", RemotePort: 443, Process: "browser", PID: 11},
	}

	got := coalesceConnections(excludeAcceptedConnections(in, listeners), 256)
	if len(got) != 1 {
		t.Fatalf("connections = %+v, want one outbound peer", got)
	}
	if got[0].RemoteAddress != "203.0.113.20" || got[0].RemotePort != 443 {
		t.Fatalf("wrong peer survived: %+v", got[0])
	}
	projected := projectConnections(got)
	if _, ok := projected[0]["local_port"]; ok {
		t.Error("local ephemeral port reached the durable fact projection")
	}
	if _, ok := projected[0]["pid"]; ok {
		t.Error("process id reached the durable fact projection")
	}
}

func TestConnections_FailClosedWhenListenerSnapshotFailed(t *testing.T) {
	rep := &Report{Sections: map[string]string{SectionListeners: SectionFailed}}
	runner := newFakeLocal()
	collectLinuxConnections(context.Background(), runner, rep, Options{CollectConnections: true})
	if len(rep.Connections) != 0 || rep.SectionState(SectionConnections) != SectionFailed {
		t.Fatalf("connections=%+v section=%q; want no projection from an incomplete listener snapshot", rep.Connections, rep.SectionState(SectionConnections))
	}
	if runner.ran(linuxCmdConnections) {
		t.Error("connection command ran even though direction could not be resolved")
	}
}

func TestDarwinConnections_EmptyCompleteSnapshotAndPartialFailure(t *testing.T) {
	rep := &Report{Sections: map[string]string{SectionListeners: SectionOK}}
	runner := newFakeLocal()
	runner.cmdExit(darwinCmdLsofConnections, 1, "")
	runner.cmdExit(darwinCmdLsofUDP, 1, "")
	collectDarwinConnections(context.Background(), runner, rep, Options{CollectConnections: true})
	if !rep.SectionOK(SectionConnections) || rep.Connections == nil {
		t.Fatalf("valid empty lsof snapshot = state %q, value %#v; want measured empty", rep.SectionState(SectionConnections), rep.Connections)
	}

	rep = &Report{Sections: map[string]string{SectionListeners: SectionOK}}
	runner = newFakeLocal()
	runner.cmdExit(darwinCmdLsofConnections, 1, "")
	runner.cmdExit(darwinCmdLsofUDP, 1, "permission denied")
	collectDarwinConnections(context.Background(), runner, rep, Options{CollectConnections: true})
	if rep.SectionState(SectionConnections) != SectionFailed || len(rep.Connections) != 0 {
		t.Fatalf("partial lsof snapshot = state %q, value %#v; want failed with no projection", rep.SectionState(SectionConnections), rep.Connections)
	}
}

func TestConnections_RejectNonRoutablePeersAndApplyStableCap(t *testing.T) {
	in := []Connection{
		{Proto: "tcp", LocalAddress: "127.0.0.1", RemoteAddress: "203.0.113.2", RemotePort: 443},
		{Proto: "tcp", LocalAddress: "192.0.2.2", RemoteAddress: "127.0.0.1", RemotePort: 443},
		{Proto: "tcp", LocalAddress: "::ffff:192.0.2.2", RemoteAddress: "::ffff:127.0.0.1", RemotePort: 443},
		{Proto: "udp", LocalAddress: "192.0.2.2", RemoteAddress: "169.254.1.2", RemotePort: 53},
		{Proto: "tcp", LocalAddress: "192.0.2.2", RemoteAddress: "203.0.113.3", RemotePort: 443},
		{Proto: "tcp", LocalAddress: "192.0.2.2", RemoteAddress: "203.0.113.1", RemotePort: 443},
	}
	got := coalesceConnections(in, 1)
	if len(got) != 1 || got[0].RemoteAddress != "203.0.113.1" {
		t.Fatalf("bounded connections = %+v, want deterministic first routable peer", got)
	}
}

func TestBoundUDPSockets_ApplyStableCap(t *testing.T) {
	in := make([]BoundUDPSocket, 0, defaultMaxBoundUDP+10)
	for i := 0; i < defaultMaxBoundUDP+10; i++ {
		in = append(in, BoundUDPSocket{Address: "0.0.0.0", Port: 1000 + i, Process: fmt.Sprintf("p%d", i)})
	}
	got := coalesceBoundUDP(in)
	if len(got) != defaultMaxBoundUDP {
		t.Fatalf("bound UDP sockets = %d, want cap %d", len(got), defaultMaxBoundUDP)
	}
}

func TestBoundUDPSockets_PreserveUnknownRoleWithoutListenerClaim(t *testing.T) {
	listeners, bound := ParseSSBindings([]byte("Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port\nudp UNCONN 0 0 0.0.0.0:53 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:49664 0.0.0.0:*\n"))
	if len(listeners) != 1 || listeners[0].Port != 49664 {
		t.Fatalf("TCP listener lost: %+v", listeners)
	}
	if len(bound) != 1 || bound[0].Port != 53 {
		t.Fatalf("UDP binding evidence lost: %+v", bound)
	}
	projected := projectBoundUDPSockets(bound)
	if projected[0]["role"] != "unknown" {
		t.Fatalf("UDP role = %v, want explicit unknown", projected[0]["role"])
	}
}
