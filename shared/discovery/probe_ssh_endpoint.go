package discovery

import (
	"context"
	"net"
	"strconv"
)

// SSHEndpointOptions configures ProbeSSHEndpoint.
type SSHEndpointOptions struct {
	// Dial carries EVERY connection the probe makes: the handshake pass, the
	// KEXINIT pass and the banner-only fallback. Nil means a plain net.Dialer.
	Dial ContextDialFunc
}

// ProbeSSHEndpoint probes host:port through opts.Dial and returns the shared
// SSH ProbeResult — the identification banner, the server's offered
// algorithms, what would be negotiated, and the host key's type and
// fingerprint. Nothing authenticates and no key material is kept.
//
// It is the entry point for a caller that already knows the endpoint and owns
// the dialer — device interrogation, whose appliance dial guard must judge
// every connection — as opposed to the scan engine, which identifies a port
// first. host is what opts.Dial is asked to reach: an address literal, or a
// name the caller's dialer resolves under its own guard. The probe opens up to
// three connections (handshake, KEXINIT, and a banner-only read when the
// handshake fails for a reason that leaves the banner worth reading), so a
// caller that must reach one host should wrap its dialer in
// PinToReachedAddress.
func (p *Prober) ProbeSSHEndpoint(ctx context.Context, host string, port int, opts SSHEndpointOptions) (*ProbeResult, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := sshDial(ctx, p, opts.Dial, address)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	return probeSSHConn(ctx, p, conn, address, port, opts.Dial)
}

// sshDial opens one connection to address through dial (nil means a plain
// net.Dialer), bounded by the prober's timeout and by ctx. It is the only way
// the SSH probe connects, so a caller-supplied dialer sees every connection.
func sshDial(ctx context.Context, p *Prober, dial ContextDialFunc, address string) (net.Conn, error) {
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	dctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	return dial(dctx, "tcp", address)
}
