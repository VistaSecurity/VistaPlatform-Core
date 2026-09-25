package deviceinterrogation

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/internal/dialguard"
	"github.com/vistasecurity/vistaplatform/shared/network"
)

// TestMain points every OTHER test in this package at an unguarded dialer.
//
// The package's fake appliances are httptest servers, which bind 127.0.0.1 —
// the one address the dial guard refuses outright. Without this, ~27 collector
// tests would be testing the guard instead of the collector, and the obvious
// "fix" (weakening the guard to let loopback through) is the bug itself.
//
// The guard tests below put the REAL dialer back for their own duration with
// [withRealDialGuard], so the production behaviour is asserted against a live
// loopback listener rather than assumed. They are the reason this swap is safe:
// if a collector stops going through newDeviceHTTPClient, or the guard is
// removed from it, those tests go red while every other test in the package
// carries on passing.
func TestMain(m *testing.M) {
	dialguard.Dial = func(timeout time.Duration) func(ctx context.Context, network string, addr string) (net.Conn, error) {
		return (&net.Dialer{Timeout: timeout}).DialContext
	}
	os.Exit(m.Run())
}

// withRealDialGuard restores the production dialer for the duration of one test.
func withRealDialGuard(t *testing.T) {
	t.Helper()
	saved := dialguard.Dial
	dialguard.Dial = network.OnPremDialContext
	t.Cleanup(func() { dialguard.Dial = saved })
}

// Every appliance collector must dial through the guard. The property asserted
// is the strong one: the target receives ZERO requests, so the refusal happens
// before the connection rather than after a response was already fetched.
//
// The clients are built by each vendor's OWN constructor, so a collector that
// goes back to building a bare &http.Client{} — which is how H6 happened, and
// how all four of these looked before this change — fails here.
func TestEveryVendorClientRefusesLoopback(t *testing.T) {
	withRealDialGuard(t)

	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	clients := map[string]*http.Client{
		"unifi":    newUnifiClient(srv.URL, "u", "p", "default", false).httpClient,
		"f5":       newF5Client(srv.URL, "u", "p", "", false).httpClient,
		"fortinet": newFortinetClient(srv.URL, "u", "p", false).httpClient,
		"paloalto": newPanClient(srv.URL, "u", "p", false).httpClient,
		"httpx":    newHTTPXClient(httpxConfig{baseURL: srv.URL}).client,
	}

	for name, client := range clients {
		t.Run(name, func(t *testing.T) {
			resp, err := client.Get(srv.URL)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("%s client reached a loopback server; the dial guard is not installed on its transport", name)
			}
			if !strings.Contains(err.Error(), "ssrf guard") {
				t.Fatalf("%s client failed with %v, want an 'ssrf guard' refusal — a different error means the "+
					"request was attempted and failed for some other reason, so the guard is not covering this sink", name, err)
			}
		})
	}

	if got := atomic.LoadInt64(&hits); got != 0 {
		t.Fatalf("the loopback target received %d request(s); the guard must refuse before anything is sent", got)
	}
}

// The appliance guard is one shared egress boundary, not an HTTP-only policy.
// Every raw transport and database driver must use it too; otherwise a tenant
// target can reach the interrogator's loopback or cloud metadata service by
// choosing SNMP, a handshake probe, PostgreSQL, or MySQL (E-09).
func TestEveryRawProbeAndDatabaseRefusesLoopback(t *testing.T) {
	withRealDialGuard(t)

	assertGuarded := func(name string, run func() error) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			err := run()
			if err == nil || !strings.Contains(err.Error(), "ssrf guard") {
				t.Fatalf("got %v, want an ssrf guard refusal before dialing", err)
			}
		})
	}

	assertGuarded("snmp", func() error {
		_, err := (&SNMPInterrogator{Timeout: 100 * time.Millisecond}).Interrogate(context.Background(),
			DeviceInfo{DeviceType: "generic_snmp", IPAddress: "127.0.0.1", Port: 161}, Credentials{})
		return err
	})
	assertGuarded("tls", func() error {
		_, err := (&TLSProber{timeout: 100 * time.Millisecond}).ProbeTLS("127.0.0.1", 443)
		return err
	})
	assertGuarded("ssh", func() error {
		_, err := (&TLSProber{timeout: 100 * time.Millisecond}).ProbeSSH("127.0.0.1", 22)
		return err
	})
	assertGuarded("postgres", func() error {
		_, err := InterrogatePostgreSQLConn(context.Background(), "postgres://audit:redacted@127.0.0.1:5432/postgres?sslmode=disable")
		return err
	})
	assertGuarded("mysql", func() error {
		_, err := InterrogateMySQLConn(context.Background(), "audit:redacted@tcp(127.0.0.1:3306)/")
		return err
	})
}

// The OTHER polarity, and the one this product cannot live without: an
// appliance on the customer's own RFC1918 network must still be dialled.
//
// Over-strict is the same bug pointed the other way. The sibling
// discover-and-create path uses the BLANKET private denylist
// (network.SafeDialContext) and consequently cannot reach any real F5, UniFi or
// Palo Alto management interface — a characterization test over there records
// that as a known regression. Interrogation must not inherit it, so this test
// fails if someone "hardens" newDeviceHTTPClient onto the blanket guard.
//
// It asserts on the SHAPE of the failure, not on success: 10.255.255.1 is a
// top-of-block RFC1918 address nothing is conventionally assigned, so the dial
// times out. What matters is that the error is a network failure and not a
// policy refusal — the guard let the attempt happen.
func TestPrivateApplianceAddressIsNotRefusedByPolicy(t *testing.T) {
	withRealDialGuard(t)

	client := newDeviceHTTPClient(false, 1*time.Second)
	resp, err := client.Get("http://10.255.255.1/api/")
	if err == nil {
		// Something answered. That is a fine outcome for this assertion: the
		// guard permitted a private appliance, which is the whole point.
		_ = resp.Body.Close()
		return
	}
	if strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("dialing an RFC1918 appliance was refused by policy (%v). Interrogating a device on the "+
			"customer's own network IS the product — newDeviceHTTPClient must use network.OnPremDialContext, "+
			"not the blanket private denylist", err)
	}
}

// Link-local stays refused whatever the private-address allowance says. This is
// the half of the rule that is not negotiable: 169.254.169.254 is OUR cluster's
// cloud metadata endpoint, never a customer appliance.
func TestCloudMetadataAddressIsAlwaysRefused(t *testing.T) {
	withRealDialGuard(t)

	client := newDeviceHTTPClient(false, 2*time.Second)
	for _, target := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://127.0.0.1/",
		"http://[::1]/",
	} {
		resp, err := client.Get(target)
		if err == nil {
			_ = resp.Body.Close()
			t.Fatalf("GET %s succeeded; it must be refused", target)
		}
		if !strings.Contains(err.Error(), "ssrf guard") {
			t.Errorf("GET %s failed with %v, want an 'ssrf guard' refusal", target, err)
		}
	}
}

// A cross-origin redirect is a second request the DEVICE chose, and following it
// replays whatever credential the first request carried at a host the operator
// never named. It must be refused; a same-host redirect (:80 → :443, /api →
// /api/) is ordinary and must still work.
func TestRedirectPolicy(t *testing.T) {
	var elsewhereHits int64
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&elsewhereHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer elsewhere.Close()

	// Addressed by NAME so it is a different host from the origin's 127.0.0.1
	// literal. Two loopback ports are the same host, and a redirect that only
	// changes the port (:80 → :443) is the legitimate case the policy allows.
	elsewhereByName := strings.Replace(elsewhere.URL, "127.0.0.1", "localhost", 1)

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/offsite":
			http.Redirect(w, r, elsewhereByName+"/latest/meta-data/", http.StatusFound)
		case "/moved":
			http.Redirect(w, r, "/final", http.StatusFound)
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("arrived"))
		}
	}))
	defer origin.Close()

	// The dialer is the test one here (TestMain), because both servers are on
	// loopback; the redirect policy under test is the CheckRedirect hook, which
	// is independent of it.
	client := newDeviceHTTPClient(false, 5*time.Second)

	t.Run("cross-origin is refused", func(t *testing.T) {
		resp, err := client.Get(origin.URL + "/offsite")
		if err == nil {
			_ = resp.Body.Close()
			t.Fatal("followed a redirect to another host; CheckRedirect is not refusing cross-origin hops")
		}
		if !strings.Contains(err.Error(), "refusing to follow a redirect") {
			t.Fatalf("failed with %v, want the cross-origin redirect refusal", err)
		}
		if got := atomic.LoadInt64(&elsewhereHits); got != 0 {
			t.Fatalf("the redirect target received %d request(s), want 0", got)
		}
	})

	t.Run("same-host is followed", func(t *testing.T) {
		resp, err := client.Get(origin.URL + "/moved")
		if err != nil {
			t.Fatalf("a same-host redirect was refused (%v) — an appliance moving /api to /api/ or :80 to :443 "+
				"is ordinary, and refusing it breaks interrogation of real devices", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}
	})
}
