// Package credentials is the one blessed way to store connector/integration
// credentials at rest.
//
// It exists because there wasn't one. Before this package, eight services each
// hand-rolled an encryptConfig/decryptConfig pair with a private list of
// "sensitive" field names. The lists disagreed (only one of them treated
// access_key_id as a secret; only one treated username as one), and — worse —
// an author adding a new connector had nothing to reach for, so plain
// json.Marshal(config) was the path of least resistance. That stores plaintext,
// and it is exactly how the CMDB gap and the six gaps in happened.
//
// # What it does
//
// A Cipher wraps shared/security/encryption (AES-256-GCM under an HKDF-derived
// key) and applies it to the *fields of a config map* named by a Policy,
// tagging each ciphertext with a prefix.
//
//	stored value = "enc:v1:" + base64(version || nonce || ciphertext)
//
// # Why the prefix
//
// The prefix is the whole migration story, and it is not decoration.
//
// Every store this package is retrofitted onto already holds plaintext rows.
// The naive read path — "call Decrypt, and if it errors assume the value was
// plaintext" — is what several of the pre-existing hand-rolled sites do, and it
// is wrong in both directions: a genuine wrong-key/corruption error is silently
// reported as a plaintext credential, and a plaintext value that happens to
// base64-decode can be mangled. With an explicit marker the read path is
// total and deterministic:
//
//   - no prefix  → legacy plaintext. Returned as-is; encrypted on the row's
//     next save. Nothing breaks during the migration window.
//   - has prefix → MUST decrypt. A failure is surfaced as an error rather than
//     handing ciphertext to a connector as if it were a credential.
//
// Encryption is idempotent: an already-prefixed value is passed through, so a
// read-modify-write cycle that never decrypted a field cannot double-encrypt it.
//
// # Dev fallback
//
// NewCipher("") returns a working, *disabled* Cipher (Enabled() == false) that
// passes values through untouched, and logs once. That matches house style for
// local development, where no master key is set. It is not a production
// weakening: every service that uses this package passes ENCRYPTION_MASTER_KEY
// through shared/config.RejectInsecureDefaults, which log.Fatals in production
// on a well-known dev default, and the deployment plumbing (registry
// required_secrets → compose ${VAR:?} → chart secrets) makes the variable
// mandatory there.
package credentials

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// Prefix marks a stored value as ciphertext produced by this package. The
// version is the *envelope* version (how the value is framed), independent of
// the ciphertext version byte that shared/security/encryption manages inside.
const Prefix = "enc:v1:"

// Policy declares which parts of a config map hold credentials. It is data, not
// code, so a store's denylist is reviewable in one place and testable without a
// database.
//
// Divergence between stores is expected and fine — a cloud connector's secrets
// genuinely are not a Slack channel's. What is not fine is divergence by
// accident, which is what a Policy literal next to its store prevents.
type Policy struct {
	// Fields are top-level keys whose string value is a credential.
	Fields []string

	// AllValuesIn are top-level keys whose value is a nested object in which
	// EVERY string value is treated as a credential. Header bags
	// (headers, extra_headers) belong here: a connector sends them verbatim as
	// HTTP headers, so they routinely carry Authorization / X-Api-Key, and the
	// key names are caller-chosen so no denylist can enumerate them.
	AllValuesIn []string

	// NestedFields maps a top-level key holding a nested object to the keys
	// *within* that object which are credentials. Used for shapes like
	// {"auth": {"type": "basic", "username": ..., "password": ...}} where the
	// discriminator must stay readable.
	NestedFields map[string][]string
}

// Option configures a Cipher.
type Option func(*Cipher)

// WithLegacyUnprefixedCiphertext makes the read path, on encountering a value
// with no Prefix, first attempt a bare Decrypt and use the result if it
// succeeds; only if that fails is the value treated as legacy plaintext.
//
// Use this ONLY for a store that already contains ciphertext written by a
// pre-existing hand-rolled encryptor (which had no prefix). public.integrations
// is the live example: admin-service's MSP writer has been writing bare
// ciphertext into the same column inventory-service reads.
//
// It is safe despite reintroducing a guess, because the guess is
// authenticated: shared/security/encryption is AES-256-GCM, so a bare Decrypt
// only succeeds if the value base64-decodes, carries the current version byte,
// and passes the GCM tag check. A plaintext credential cannot forge that.
// Values recovered this way are re-written WITH the prefix on the next save, so
// the option becomes dead weight once a store has turned over — which is why it
// is opt-in and not the default.
func WithLegacyUnprefixedCiphertext() Option {
	return func(c *Cipher) { c.legacyUnprefixed = true }
}

// Cipher encrypts and decrypts the credential-bearing fields of a config map.
// The zero value is not usable; construct one with NewCipher.
type Cipher struct {
	enc              *encryption.Service
	policy           Policy
	label            string
	legacyUnprefixed bool
}

// NewCipher builds a Cipher for the given store.
//
// label names the store in log lines and error messages ("notification
// channel", "integrations.auth_config"); it is operator-facing only.
//
// An empty masterKey yields a disabled passthrough Cipher and a warning — see
// the package doc. A non-empty but unusable masterKey is an error, because that
// is a misconfiguration rather than a deliberate local-dev choice.
func NewCipher(label, masterKey string, policy Policy, opts ...Option) (*Cipher, error) {
	c := &Cipher{policy: policy, label: label}
	for _, opt := range opts {
		opt(c)
	}
	if masterKey == "" {
		log.Printf("[credentials] WARNING: ENCRYPTION_MASTER_KEY not set — %s credentials will be stored unencrypted", label)
		return c, nil
	}
	enc, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, fmt.Errorf("credentials: init cipher for %s: %w", label, err)
	}
	c.enc = enc
	return c, nil
}

// Enabled reports whether this Cipher actually encrypts. A disabled Cipher
// (no master key) is still safe to call — every method is a passthrough — so
// callers do not need nil checks.
func (c *Cipher) Enabled() bool { return c != nil && c.enc != nil }

// EncryptValue tags and encrypts a single scalar credential, for stores that
// keep one in its own column (discovery_alert_configs.slack_webhook_url,
// security_incident_webhooks.secret) rather than inside a JSON blob.
// Already-tagged and empty values pass through.
func (c *Cipher) EncryptValue(plain string) (string, error) {
	if !c.Enabled() || plain == "" || strings.HasPrefix(plain, Prefix) {
		return plain, nil
	}
	ct, err := c.enc.Encrypt(plain)
	if err != nil {
		return "", fmt.Errorf("credentials: encrypt %s: %w", c.label, err)
	}
	return Prefix + ct, nil
}

// DecryptValue is the read-side inverse of EncryptValue. A value without the
// Prefix is legacy plaintext and is returned unchanged; a prefixed value must
// decrypt or the call errors.
func (c *Cipher) DecryptValue(stored string) (string, error) {
	if !c.Enabled() || stored == "" {
		return stored, nil
	}
	if !strings.HasPrefix(stored, Prefix) {
		if c.legacyUnprefixed {
			if pt, err := c.enc.Decrypt(stored); err == nil {
				return pt, nil
			}
		}
		return stored, nil // legacy plaintext — re-encrypted on next save
	}
	pt, err := c.enc.Decrypt(strings.TrimPrefix(stored, Prefix))
	if err != nil {
		return "", fmt.Errorf("credentials: decrypt %s: %w", c.label, err)
	}
	return pt, nil
}

// EncryptMap returns a copy of config with every credential field named by the
// Policy replaced by prefix-tagged ciphertext. Non-credential fields, non-string
// values, and already-tagged values are copied through untouched.
//
// A nil config yields nil, so "no config" stays distinguishable from "empty
// config" in the JSONB column.
func (c *Cipher) EncryptMap(config map[string]interface{}) (map[string]interface{}, error) {
	return c.transform(config, c.EncryptValue)
}

// DecryptMap is the read-side inverse of EncryptMap.
func (c *Cipher) DecryptMap(config map[string]interface{}) (map[string]interface{}, error) {
	return c.transform(config, c.DecryptValue)
}

// EncryptJSON applies EncryptMap to a raw JSONB value, for callers that hold
// the column as json.RawMessage rather than a decoded map. JSON null and empty
// input pass through.
func (c *Cipher) EncryptJSON(raw json.RawMessage) (json.RawMessage, error) {
	return c.transformJSON(raw, c.EncryptMap)
}

// DecryptJSON is the read-side inverse of EncryptJSON.
func (c *Cipher) DecryptJSON(raw json.RawMessage) (json.RawMessage, error) {
	return c.transformJSON(raw, c.DecryptMap)
}

func (c *Cipher) transformJSON(raw json.RawMessage, fn func(map[string]interface{}) (map[string]interface{}, error)) (json.RawMessage, error) {
	if !c.Enabled() || len(raw) == 0 || string(raw) == "null" {
		return raw, nil
	}
	var config map[string]interface{}
	if err := json.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("credentials: %s is not a JSON object: %w", c.label, err)
	}
	out, err := fn(config)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("credentials: re-marshal %s: %w", c.label, err)
	}
	return encoded, nil
}

// transform walks the Policy over config, applying fn to each credential
// string. It copies rather than mutating in place: callers routinely hand us a
// map they still hold a reference to (a request body, a cached row), and
// mutating it would leave plaintext and ciphertext views of the same object
// aliased — a bug that is invisible until something re-saves the wrong one.
func (c *Cipher) transform(config map[string]interface{}, fn func(string) (string, error)) (map[string]interface{}, error) {
	if !c.Enabled() || config == nil {
		return config, nil
	}

	out := make(map[string]interface{}, len(config))
	for k, v := range config {
		out[k] = v
	}

	for _, key := range c.policy.Fields {
		val, ok := out[key].(string)
		if !ok {
			continue
		}
		next, err := fn(val)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", key, err)
		}
		out[key] = next
	}

	for _, key := range c.policy.AllValuesIn {
		nested, ok := out[key].(map[string]interface{})
		if !ok {
			continue
		}
		copied := make(map[string]interface{}, len(nested))
		for k, v := range nested {
			val, ok := v.(string)
			if !ok {
				copied[k] = v
				continue
			}
			next, err := fn(val)
			if err != nil {
				return nil, fmt.Errorf("%s[%q]: %w", key, k, err)
			}
			copied[k] = next
		}
		out[key] = copied
	}

	for key, nestedKeys := range c.policy.NestedFields {
		nested, ok := out[key].(map[string]interface{})
		if !ok {
			continue
		}
		copied := make(map[string]interface{}, len(nested))
		for k, v := range nested {
			copied[k] = v
		}
		for _, nk := range nestedKeys {
			val, ok := copied[nk].(string)
			if !ok {
				continue
			}
			next, err := fn(val)
			if err != nil {
				return nil, fmt.Errorf("%s.%s: %w", key, nk, err)
			}
			copied[nk] = next
		}
		out[key] = copied
	}

	return out, nil
}
