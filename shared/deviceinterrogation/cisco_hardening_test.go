package deviceinterrogation

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- the SSRF dial guard ---------------------------------------------------------

// The Cisco collector dials through the same guard as every HTTP collector.
// The assertion is the strong one, against a REAL loopback SSH server that
// would accept every credential: it never sees an authentication attempt — no
// password, no keyboard-interactive answer, no public-key signature — and the
// failure is the guard's refusal, not some other dial error.
func TestCiscoInterrogator_RefusesLoopbackAndMetadataBeforeConnecting(t *testing.T) {
	signer, keyPEM := newClientKey(t)
	f := startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, authorizedKey: signer.PublicKey()})
	kbd := startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, keyboardOnly: true})

	// A raw listener as well, to count bare TCP connections.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var accepted int64
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&accepted, 1)
			_ = conn.Close()
		}
	}()

	// The guard is swapped in AFTER the fakes are up; ciscoDeviceFor pins
	// nothing, so only the guard can stop the dial.
	withRealDialGuard(t)
	creds := Credentials{Username: "netops", Password: fakeCiscoPW, Custom: map[string]interface{}{ciscoCredPrivateKey: keyPEM}}
	for _, addr := range []string{f.addr, kbd.addr, ln.Addr().String(), "169.254.169.254:22", "[::1]:22"} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := (&CiscoInterrogator{}).Interrogate(ctx, ciscoDeviceFor(t, addr, ""), creds)
		cancel()
		if err == nil {
			t.Fatalf("interrogating %s succeeded; it must be refused", addr)
		}
		if !strings.Contains(err.Error(), "ssrf guard") {
			t.Errorf("interrogating %s failed with %v, want an 'ssrf guard' refusal — any other error means a connection was attempted", addr, err)
		}
	}
	for name, server := range map[string]*fakeCisco{"password/publickey": f, "keyboard-interactive": kbd} {
		if got := server.snapshot(&server.authMethods); len(got) != 0 {
			t.Errorf("the %s server saw authentication attempts %v; the guard must refuse before any credential is offered", name, got)
		}
		if got := server.snapshot(&server.passwordsSeen); len(got) != 0 {
			t.Errorf("the %s server was sent passwords", name)
		}
	}
	if got := atomic.LoadInt64(&accepted); got != 0 {
		t.Fatalf("the loopback target accepted %d connection(s); the guard must refuse before connecting", got)
	}
}

// A peer that accepts TCP and never speaks SSH: the handshake has its own
// deadline, so the dial fails within it even with no context deadline at all.
// ssh.Dial's Timeout covered the TCP connect only, and would have hung here.
func TestCiscoDialSSH_HandshakeIsBoundedWithoutAContextDeadline(t *testing.T) {
	old := ciscoHandshakeTimeout
	ciscoHandshakeTimeout = 500 * time.Millisecond
	t.Cleanup(func() { ciscoHandshakeTimeout = old })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var held []net.Conn
	var mu sync.Mutex
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, conn) // accepted, never answered
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		mu.Lock()
		defer mu.Unlock()
		for _, c := range held {
			_ = c.Close()
		}
	})

	auth, _ := ciscoAuthMethods(Credentials{Username: "netops", Password: fakeCiscoPW})
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		c, err := newCiscoSSHClient(context.Background(), "127.0.0.1", ln.Addr().(*net.TCPAddr).Port, "netops", auth, false, "")
		if c != nil {
			_ = c.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a peer that never spoke SSH produced a client")
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("the handshake gave up after %s; the bound is %s", elapsed, ciscoHandshakeTimeout)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the SSH handshake with a silent peer is unbounded")
	}
}

// The other polarity: a device on the customer's private network is dialled.
// 10.255.255.1 answers nothing, so the attempt times out — which is a network
// failure, not a policy refusal, and that is the point.
func TestCiscoInterrogator_PrivateApplianceIsNotRefusedByPolicy(t *testing.T) {
	withRealDialGuard(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, err := (&CiscoInterrogator{}).Interrogate(ctx, DeviceInfo{DeviceType: "cisco", IPAddress: "10.255.255.1", Port: 22},
		Credentials{Username: "netops", Password: fakeCiscoPW})
	if err == nil {
		t.Fatal("an address nothing answers on produced a result")
	}
	if strings.Contains(err.Error(), "ssrf guard") {
		t.Fatalf("an RFC 1918 appliance was refused by policy: %v", err)
	}
}

// --- keyboard-interactive answers password prompts only ------------------------

func TestCiscoKeyboardInteractive_AnswersOnlyPasswordPrompts(t *testing.T) {
	challenge := ciscoKeyboardInteractive("pw-1")
	for _, tc := range []struct {
		questions []string
		echos     []bool
		want      []string
	}{
		{[]string{"Password: "}, []bool{false}, []string{"pw-1"}},
		{[]string{"Username: ", "Password: "}, []bool{true, false}, []string{"", "pw-1"}},
		{[]string{"Passcode: ", "Password: "}, []bool{false, false}, []string{"", "pw-1"}},
		// A lone question that does not ask for a password is a second
		// factor, not a password prompt.
		{[]string{"Verification code: "}, []bool{false}, []string{""}},
		{[]string{"Enter PASSCODE: "}, []bool{false}, []string{""}},
		// Echoed, even if it says password: not a secret prompt.
		{[]string{"Password hint: "}, []bool{true}, []string{""}},
		{nil, nil, []string{}},
	} {
		got, err := challenge("u", "", tc.questions, tc.echos)
		if err != nil {
			t.Fatalf("%v: %v", tc.questions, err)
		}
		if strings.Join(got, "|") != strings.Join(tc.want, "|") || len(got) != len(tc.want) {
			t.Errorf("questions %q echos %v: answers %q, want %q", tc.questions, tc.echos, got, tc.want)
		}
	}
}

// --- the overall bound ------------------------------------------------------------

// A device that accepts every command and answers none: the interrogation ends
// at its overall bound, whatever the caller's context — the device agent
// passes context.Background().
func TestCiscoInterrogator_OverallDeadline(t *testing.T) {
	old := ciscoInterrogationTimeout
	ciscoInterrogationTimeout = 1500 * time.Millisecond
	t.Cleanup(func() { ciscoInterrogationTimeout = old })

	f := startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, execHangs: true})
	start := time.Now()
	result, err := (&CiscoInterrogator{}).Interrogate(context.Background(), ciscoDeviceFor(t, f.addr, ""),
		Credentials{Username: "netops", Password: fakeCiscoPW})
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("the interrogation ran %s past a %s bound", elapsed, ciscoInterrogationTimeout)
	}
	if err != nil {
		t.Fatalf("a device that timed out is a result with warnings, not a failed job: %v", err)
	}
	var timeouts int
	for _, w := range result.Warnings {
		if w.Reason == WarningTimeout {
			timeouts++
		}
	}
	if timeouts == 0 {
		t.Errorf("no timeout warning: %+v", result.Warnings)
	}
}

// A request the device never answers blocks inside x/crypto, where no context
// reaches: here a PTY request, on the shell the collector falls back to when
// exec is refused. The overall bound tears the connection down, which is the
// one thing that unblocks it.
func TestCiscoInterrogator_OverallDeadlineUnblocksAStuckRequest(t *testing.T) {
	old := ciscoInterrogationTimeout
	ciscoInterrogationTimeout = 1500 * time.Millisecond
	t.Cleanup(func() { ciscoInterrogationTimeout = old })

	f := startFakeCisco(t, fakeCiscoConfig{password: fakeCiscoPW, execRefused: true, ptyHangs: true})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = (&CiscoInterrogator{}).Interrogate(context.Background(), ciscoDeviceFor(t, f.addr, ""),
			Credentials{Username: "netops", Password: fakeCiscoPW})
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("the interrogation is still blocked on an unanswered request 10s after a 1.5s bound")
	}
}

// --- ASA below 8.4 ------------------------------------------------------------------

func TestCiscoGetCryptoConfigs_ASAWithoutIKEv1KeywordSaysSo(t *testing.T) {
	run := func(_ context.Context, command string) (string, bool, error) {
		if command == "show crypto ikev1 sa detail" {
			return "ERROR: % Invalid input detected at '^' marker.\n", false, nil
		}
		return "", false, errors.New("not implemented")
	}
	result := &InterrogateResult{collector: ciscoCollector}
	(&ciscoSSHClient{osName: "ASA"}).getCryptoConfigs(context.Background(), result, run)
	assertWarning(t, findWarning(t, result, "show crypto ikev1 sa detail"), ciscoCollector, WarningNotSupported, "8.4")

	// IOS answering invalid input to its own ISAKMP command stays quiet: on
	// IOS it means "no crypto on this box", which is not a gap.
	quiet := &InterrogateResult{collector: ciscoCollector}
	(&ciscoSSHClient{osName: "IOS"}).getCryptoConfigs(context.Background(), quiet, func(_ context.Context, command string) (string, bool, error) {
		return "% Invalid input detected at '^' marker.\n", false, nil
	})
	for _, w := range quiet.Warnings {
		if w.Reason == WarningNotSupported {
			t.Errorf("IOS invalid input raised %+v", w)
		}
	}
}

// --- crypto map: the whole offer, and the block closes ----------------------------

// Every transform set is kept, so a weaker fallback listed second is reported;
// and the lines after the `Transform sets={ … }` block are still read — a
// block that never closed swallowed the peer and PFS lines after it.
func TestCiscoCryptoMap_EveryTransformSetAndTheBlockCloses(t *testing.T) {
	output := `Crypto Map IPv4 "CMAP" 10 ipsec-isakmp
        Transform sets={
                STRONG:  { esp-gcm 256  } ,
                LEGACY:  { esp-3des esp-md5-hmac  } ,
                MID:  { esp-aes esp-sha-hmac  } ,
        }
        Peer = 198.51.100.2
        PFS (Y/N): Y
        DH group:  group14
Crypto Map IPv4 "CMAP" 20 ipsec-isakmp
        Transform sets={ TS1: { esp-256-aes esp-sha256-hmac } , }
        Peer = 203.0.113.5
`
	c := &ciscoSSHClient{host: "192.0.2.1"}
	configs := c.parseCryptoMap(output)
	if len(configs) != 2 {
		t.Fatalf("configs = %+v", configs)
	}
	if configs[0].PeerAddress != "198.51.100.2" || configs[0].PFSGroup != "group14" {
		t.Errorf("lines after the transform block were not read: peer %q pfs %q", configs[0].PeerAddress, configs[0].PFSGroup)
	}
	if configs[1].PeerAddress != "203.0.113.5" || configs[1].CipherSuite != "AES-256-CBC" {
		t.Errorf("one-line block: %+v", configs[1])
	}
	a := c.convertCryptoConfigToAsset(configs[0])
	if a.CipherSuite == nil || *a.CipherSuite != "AES-256-GCM" {
		t.Errorf("preferred cipher = %v, want AES-256-GCM", a.CipherSuite)
	}
	if strings.Join(a.SupportedCiphers, ",") != "AES-256-GCM,3DES,AES-128-CBC" {
		t.Errorf("offered ciphers = %v, want every set in order", a.SupportedCiphers)
	}
	if hashes, _ := a.Metadata["offered_hash_algorithms"].([]string); strings.Join(hashes, ",") != "MD5,SHA1" {
		t.Errorf("offered hashes = %v", a.Metadata["offered_hash_algorithms"])
	}
}
