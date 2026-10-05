package discovery

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// A probe to a NAME pinned with PinToReachedAddress: the first dial asks for
// the name; every later one — the support handshake here — asks for the
// address the first connection reached. The name is under .invalid, which
// never resolves, so a redial of the name would fail and the support flag
// would come back absent.
func TestPinToReachedAddress_SupportHandshakesRedialTheReachedAddress(t *testing.T) {
	c := tlskextest.Cases[2] // X25519 only: one support handshake
	srv := tlskextest.Start(t, c.Groups, c.MaxVersion)

	var mu sync.Mutex
	var asked []string
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		mu.Lock()
		asked = append(asked, address)
		mu.Unlock()
		if address == "lb.pin.invalid:443" {
			address = srv.Addr // the name "resolves" to the fixture
		}
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}

	res, err := NewProber(3*time.Second).ProbeTLSEndpoint(context.Background(), "lb.pin.invalid", 443,
		TLSEndpointOptions{Hostname: "lb.pin.invalid", Dial: PinToReachedAddress(dial)})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	tlskextest.Check(t, c, res.Metadata)
	tlskextest.CheckConnections(t, c, srv)

	mu.Lock()
	defer mu.Unlock()
	if len(asked) != 2 || asked[0] != "lb.pin.invalid:443" || asked[1] != srv.Addr {
		t.Errorf("dials = %v, want [lb.pin.invalid:443 %s]", asked, srv.Addr)
	}
}

// A failed first dial pins nothing: the next dial asks for the name again.
func TestPinToReachedAddress_FailedDialPinsNothing(t *testing.T) {
	var asked []string
	dial := PinToReachedAddress(func(_ context.Context, _, address string) (net.Conn, error) {
		asked = append(asked, address)
		return nil, &net.OpError{Op: "dial", Err: errRefused{}}
	})
	_, _ = dial(context.Background(), "tcp", "a.invalid:1")
	_, _ = dial(context.Background(), "tcp", "a.invalid:1")
	if len(asked) != 2 || asked[1] != "a.invalid:1" {
		t.Errorf("dials = %v, want the name both times", asked)
	}
}

type errRefused struct{}

func (errRefused) Error() string { return "refused" }
