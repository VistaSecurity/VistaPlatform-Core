package agentcreds

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/atomicfile"
)

// SecretBytes is the size of an agent secret before encoding.
const SecretBytes = 32

// PreviousSecretWindow is how long a collector keeps opening envelopes with the
// secret a rotation just replaced.
//
// A job is sealed when the platform hands it to the collector, so an envelope
// that left the platform just before a certificate rotation is sealed under the
// OLD secret while the collector already holds the NEW one. The window covers
// that overlap and nothing more: it is far longer than any job's dispatch-to-open
// gap, and short enough that a replaced secret does not stay usable for long.
// The platform does not need a window of its own — it seals only with the
// current secret, at claim time.
const PreviousSecretWindow = 24 * time.Hour

// GenerateSecret returns a new random agent secret: SecretBytes of crypto/rand,
// standard-base64 encoded.
func GenerateSecret() (string, error) {
	b := make([]byte, SecretBytes)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("agentcreds: generate secret: %w", err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// SecretState is everything a collector holds to open credential envelopes.
//
// It is stored as one small JSON document (0600, written atomically with the
// collector's certificate) rather than in the YAML config, which operators copy
// and diff and which used to carry the registration key.
//
// The zero value is a collector that has no agent secret yet: it opens with its
// registration key, exactly as before this existed.
type SecretState struct {
	// Secret is the current agent secret. Empty on a collector that enrolled
	// before agent secrets existed and has not rotated its certificate since.
	Secret string `json:"secret,omitempty"`
	// Version is the platform's counter for Secret. It only ever increases.
	Version int `json:"version,omitempty"`
	// Previous is the secret (or, at a collector's first rotation, the
	// registration key) that Secret replaced; it is honoured until
	// PreviousUntil and then ignored.
	Previous      string    `json:"previous,omitempty"`
	PreviousUntil time.Time `json:"previous_until,omitempty"`
}

// IsZero reports whether the collector holds no agent secret.
func (s SecretState) IsZero() bool { return s.Secret == "" }

// Rotate returns the state after the platform issued newSecret.
//
// The secret being replaced stays valid for PreviousSecretWindow. For a
// collector with no agent secret yet, the secret being replaced is its
// registration key — registrationKey — so jobs the platform sealed under it
// just before the migration still open.
func (s SecretState) Rotate(newSecret string, newVersion int, registrationKey string, now time.Time) SecretState {
	prev := s.Secret
	if prev == "" {
		prev = registrationKey
	}
	out := SecretState{Secret: newSecret, Version: newVersion}
	if prev != "" && prev != newSecret {
		out.Previous = prev
		out.PreviousUntil = now.Add(PreviousSecretWindow)
	}
	return out
}

// Prune drops an expired Previous. It reports whether anything changed, so a
// caller can rewrite the file and stop keeping a replaced secret on disk.
func (s SecretState) Prune(now time.Time) (SecretState, bool) {
	if s.Previous == "" || now.Before(s.PreviousUntil) {
		return s, false
	}
	s.Previous = ""
	s.PreviousUntil = time.Time{}
	return s, true
}

// Candidates lists the secrets an envelope may be sealed under, in the order
// they should be tried.
//
// A collector that holds an agent secret tries it, then the previous one while
// its window lasts. The registration key is NOT a candidate once an agent secret
// exists: it is spent, and it may still be sitting in an environment variable.
// A collector with no agent secret tries only its registration key — the
// pre-change behaviour.
func (s SecretState) Candidates(registrationKey string, now time.Time) []string {
	if s.Secret == "" {
		if registrationKey == "" {
			return nil
		}
		return []string{registrationKey}
	}
	out := []string{s.Secret}
	if s.Previous != "" && now.Before(s.PreviousUntil) {
		out = append(out, s.Previous)
	}
	return out
}

// Marshal encodes the state for its file.
func (s SecretState) Marshal() ([]byte, error) { return json.Marshal(s) }

// ParseSecretState decodes a state file.
func ParseSecretState(data []byte) (SecretState, error) {
	var s SecretState
	if err := json.Unmarshal(data, &s); err != nil {
		return SecretState{}, fmt.Errorf("agentcreds: parse secret state: %w", err)
	}
	return s, nil
}

// OpenAny opens an envelope with the first candidate secret that decrypts it.
// It returns ErrNotSealed untouched (so callers can still accept an unsealed
// payload) and, when every candidate fails, the error from the last one.
func OpenAny(payload map[string]interface{}, jobKey string, secrets []string) (map[string]interface{}, error) {
	if !IsSealed(payload) {
		return nil, ErrNotSealed
	}
	if len(secrets) == 0 {
		// No secret at all: the original job-id-only derivation.
		return Open(payload, jobKey, "")
	}
	var lastErr error
	for _, secret := range secrets {
		creds, err := Open(payload, jobKey, secret)
		if err == nil {
			return creds, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("agentcreds: no secret opened the envelope")
	}
	return nil, lastErr
}

// SecretFileName is the file a collector keeps its SecretState in, inside its
// certificate directory (0600, written atomically with the certificate).
const SecretFileName = "agent-secret.json"

// LoadSecretStateFile reads a collector's secret file. A file that does not
// exist returns an error satisfying errors.Is(err, os.ErrNotExist) so the caller
// can treat a not-yet-enrolled collector as normal.
func LoadSecretStateFile(path string) (SecretState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return SecretState{}, err
	}
	return ParseSecretState(data)
}

// SecretStateFile is the atomicfile entry that persists s at path with owner-only
// permissions, for writing as one unit with the certificate and key.
func SecretStateFile(path string, s SecretState) (atomicfile.File, error) {
	data, err := s.Marshal()
	if err != nil {
		return atomicfile.File{}, err
	}
	return atomicfile.File{Path: path, Data: data, Perm: 0o600}, nil
}
