// Package agentsecret is the platform side of the per-collector agent secret
//: issuing one, keeping it at rest, and recovering it to seal a job's
// credentials for that collector.
//
// shared/agentcreds is the wire shape and is linked into the collectors; this
// package is not — it uses the platform master key, which a collector must never
// see.
//
// The platform has to be able to read the secret back (it derives the envelope
// key from it for every job), so it cannot store a hash. It stores the secret
// wrapped by a credentials.Cipher — the house helper every stored credential goes
// through, keyed by ENCRYPTION_MASTER_KEY — and returns the plaintext to the
// collector exactly once.
package agentsecret

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

// ErrNoMasterKey means the Cipher does not encrypt (no ENCRYPTION_MASTER_KEY), so
// a secret cannot be stored. Callers fail the enrolment or rotation instead of
// issuing a secret the platform could not later use — or worse, kept in the clear.
var ErrNoMasterKey = errors.New("agentsecret: ENCRYPTION_MASTER_KEY is not configured")

// ErrNotWrapped means a stored value is not in the wrapped form Issue produces.
var ErrNotWrapped = errors.New("agentsecret: stored secret is not wrapped")

// Issue generates a new agent secret and its at-rest form.
func Issue(cipher *credentials.Cipher) (secret, wrapped string, err error) {
	if !cipher.Enabled() {
		return "", "", ErrNoMasterKey
	}
	secret, err = agentcreds.GenerateSecret()
	if err != nil {
		return "", "", err
	}
	wrapped, err = cipher.EncryptValue(secret)
	if err != nil {
		return "", "", fmt.Errorf("agentsecret: wrap secret: %w", err)
	}
	return secret, wrapped, nil
}

// Unwrap recovers the plaintext secret from its at-rest form.
//
// A value without the credentials prefix is refused rather than returned as
// "legacy plaintext", which is what Cipher.DecryptValue would do: a stored agent
// secret is always written wrapped, so an unwrapped one is corruption, and
// sealing job credentials under it would hand the collector an envelope it cannot
// open.
func Unwrap(cipher *credentials.Cipher, wrapped string) (string, error) {
	if !cipher.Enabled() {
		return "", ErrNoMasterKey
	}
	if !strings.HasPrefix(wrapped, credentials.Prefix) {
		return "", ErrNotWrapped
	}
	secret, err := cipher.DecryptValue(wrapped)
	if err != nil {
		return "", fmt.Errorf("agentsecret: unwrap secret: %w", err)
	}
	if secret == "" {
		return "", errors.New("agentsecret: stored secret is empty")
	}
	return secret, nil
}
