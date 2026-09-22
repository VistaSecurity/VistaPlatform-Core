// Package sshtrust is the one host-key trust policy for every SSH client this
// project ships that AUTHENTICATES — that is, every client that hands a
// credential to the far end.
//
// The distinction matters and is the whole reason this package exists as a
// policy rather than a helper. A prober whose job is to inventory a host's SSH
// key material (shared/discovery.ProbeSSH, deviceinterrogation.TLSProber.ProbeSSH,
// cluster-sensor-service's SSHKeyAnalyzer) legitimately accepts whatever key it
// is shown: it never reaches the authentication phase, sends no credential, and
// the key IS the thing it came to measure. Refusing an unrecognised key there
// would mean refusing to inventory anything new. Those callers do not use this
// package.
//
// A client that sends `ssh.Password(...)` is a different animal. Trust-on-first-
// use only works if the "first use" capture is COMPARED on the second use, and
// for a long time it was not: the callback recorded a fingerprint, returned nil
// unconditionally, and nothing ever read the recorded value back. That is a
// check that cannot fail, and it meant an on-path attacker could harvest device
// administrator passwords on every interrogation without anything noticing.
//
// The policy here, in precedence order:
//
//  1. A PINNED fingerprint (from the device record) — compare, and fail closed
//     on any difference. This beats InsecureSkipVerify: that flag is an opt-in
//     for a self-signed TLS management certificate, and letting it also unpin a
//     key we have already seen would reopen the hole it is not about.
//  2. InsecureSkipVerify — accept anything, recorded as "skipped".
//  3. A usable known_hosts file — strict verification against it.
//  4. Otherwise — capture on first contact: accept, record the fingerprint, and
//     leave it to the caller to persist so step 1 has something to compare
//     against next time. This is enrolment, and it must keep working.
//
// Failing closed happens inside the host-key callback, which golang.org/x/crypto/ssh
// invokes during the key exchange — BEFORE any authentication method runs. A
// mismatch therefore aborts the handshake with no credential on the wire, which
// is the property the tests assert directly rather than settling for "an error
// was returned".
package sshtrust

import (
	"crypto/subtle"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Verification modes, recorded alongside the observed fingerprint so a result
// can say how the connection was trusted rather than implying it was verified.
const (
	// VerificationPinned — compared against the fingerprint stored on the
	// device record and matched.
	VerificationPinned = "pinned"
	// VerificationKnownHosts — verified against a known_hosts file.
	VerificationKnownHosts = "known_hosts"
	// VerificationFirstUse — no stored fingerprint existed; this contact
	// captured one. Not a verification: an enrolment.
	VerificationFirstUse = "first_use"
	// VerificationSkipped — operator opted out via InsecureSkipVerify and no
	// pin existed to override it.
	VerificationSkipped = "skipped"
)

// MismatchError is returned by the host-key callback when a pinned fingerprint
// does not match the key the far end presented. It aborts the handshake during
// key exchange, so no credential is transmitted.
//
// Callers detect it with errors.As to tell "the device's identity changed" —
// genuine security signal, worth a finding — apart from "the device is down".
type MismatchError struct {
	Host     string
	Expected string
	Observed string
	KeyType  string
}

func (e *MismatchError) Error() string {
	return fmt.Sprintf(
		"ssh host key for %s does not match the fingerprint pinned on this device "+
			"(pinned %s, presented %s, key type %s); refusing to authenticate. "+
			"If the device was replaced or its key rotated, re-pin it deliberately; "+
			"otherwise this is what an interception looks like",
		e.Host, e.Expected, e.Observed, e.KeyType,
	)
}

// Policy decides how one SSH client trusts the host key it is shown, and
// records what it saw.
//
// Construct one per dial, call Callback to get the ssh.HostKeyCallback, dial,
// then read Fingerprint/KeyType/Verification. The observation fields are
// written from inside the handshake, so read them only after Dial returns.
type Policy struct {
	// Host is the device address, for the error message only.
	Host string
	// Pinned is the fingerprint previously stored for this device, in
	// ssh.FingerprintSHA256 form ("SHA256:..."). Empty means not yet pinned.
	Pinned string
	// InsecureSkipVerify is the operator's opt-out. A non-empty Pinned wins
	// over it — see the package comment.
	InsecureSkipVerify bool
	// KnownHostsPath overrides the default ~/.ssh/known_hosts lookup. Empty
	// means use the default.
	KnownHostsPath string

	// Fingerprint / KeyType are what the far end actually presented. They are
	// populated on every path that reaches the callback, INCLUDING a mismatch,
	// so the finding can name the key that turned up.
	Fingerprint string
	KeyType     string
	// Verification is one of the Verification* constants.
	Verification string
}

// Callback returns the ssh.HostKeyCallback implementing this policy and sets
// Verification to the mode it selected.
//
// Verification is set here, before the dial, so a connection that never reaches
// the callback (host down) still reports the mode that WOULD have applied.
func (p *Policy) Callback() ssh.HostKeyCallback {
	switch {
	case p.Pinned != "":
		p.Verification = VerificationPinned
		return p.pinnedCallback()
	case p.InsecureSkipVerify:
		p.Verification = VerificationSkipped
		return p.observeOnly()
	default:
		if cb, ok := knownHostsCallback(p.KnownHostsPath); ok {
			p.Verification = VerificationKnownHosts
			return p.observing(cb)
		}
		p.Verification = VerificationFirstUse
		return p.observeOnly()
	}
}

// pinnedCallback is the line this whole package exists for: it compares the
// presented key against the stored one and returns an error when they differ.
//
// Delete the comparison and TestPolicy_ChangedKeyOnReconnect_RefusesAndSendsNoCredential
// goes red — that is the mutation this fix is checked with.
func (p *Policy) pinnedCallback() ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		p.observe(key)
		// Constant-time only for tidiness; a fingerprint is public. The
		// length guard is what makes subtle.ConstantTimeCompare usable at all,
		// since it returns 0 for differing lengths.
		if len(p.Fingerprint) != len(p.Pinned) ||
			subtle.ConstantTimeCompare([]byte(p.Fingerprint), []byte(p.Pinned)) != 1 {
			return &MismatchError{
				Host:     p.Host,
				Expected: p.Pinned,
				Observed: p.Fingerprint,
				KeyType:  p.KeyType,
			}
		}
		return nil
	}
}

// observeOnly records the key and accepts it. Used for first contact (enrolment)
// and for the operator's explicit opt-out.
func (p *Policy) observeOnly() ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		p.observe(key)
		return nil
	}
}

// observing wraps a verifying callback (known_hosts) so the observation is
// recorded on the way through without weakening the verification.
func (p *Policy) observing(inner ssh.HostKeyCallback) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		p.observe(key)
		return inner(hostname, remote, key)
	}
}

func (p *Policy) observe(key ssh.PublicKey) {
	p.Fingerprint = ssh.FingerprintSHA256(key)
	p.KeyType = key.Type()
}

// knownHostsCallback returns a strict known_hosts callback when a usable file
// exists, else ok=false so the caller can fall back to first-contact capture.
func knownHostsCallback(override string) (ssh.HostKeyCallback, bool) {
	path := override
	if path == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, false
		}
		path = filepath.Join(homeDir, ".ssh", "known_hosts")
	}
	if _, err := os.Stat(path); err != nil {
		return nil, false
	}
	cb, err := knownhosts.New(path)
	if err != nil {
		return nil, false
	}
	return cb, true
}
