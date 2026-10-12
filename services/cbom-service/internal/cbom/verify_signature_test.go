package cbom

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

// edSigner is a minimal Ed25519 Signer for exercising /verify in Core's tests.
// The production signer lives in ee/cbomsign (which has its own tests, and an
// integration test that signs through the real Persister).
type edSigner struct {
	priv ed25519.PrivateKey
	kid  string
	keys map[string]ed25519.PublicKey
}

func newEdSigner(t *testing.T) *edSigner {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(pub)
	kid := hex.EncodeToString(sum[:])[:16]
	return &edSigner{priv: priv, kid: kid, keys: map[string]ed25519.PublicKey{kid: pub}}
}

func (s *edSigner) KID() string       { return s.kid }
func (s *edSigner) Algorithm() string { return "ed25519" }
func (s *edSigner) Sign(env []byte) (string, error) {
	return hex.EncodeToString(ed25519.Sign(s.priv, env)), nil
}
func (s *edSigner) Verify(_ context.Context, kid string, env []byte, sig string) (bool, error) {
	pub, ok := s.keys[kid]
	if !ok {
		return false, fmt.Errorf("%w: %q", ErrUnknownKey, kid)
	}
	b, err := hex.DecodeString(sig)
	if err != nil {
		return false, nil
	}
	return ed25519.Verify(pub, env, b), nil
}
func (s *edSigner) PublicKeys(context.Context) ([]SigningKey, error) { return nil, nil }

// signedFixture is an artifact signed exactly as the Persister signs one, with
// the bytes it covers.
func signedFixture(t *testing.T, s *edSigner) (*Artifact, []byte) {
	t.Helper()
	content := []byte(`{"bomFormat":"CycloneDX","components":[]}`)
	a := sampleArtifact()
	a.ContentHash = sha256Hex(content)
	a.Layers = []Layer{{Type: "compliance_attestation", Version: "v1", Data: map[string]interface{}{"open": 3}}}
	env, err := NewEnvelope(a.ContentHash, a.ScopeID, a.ScopeVersion, a.Layers, a.ArtifactKind, a.GeneratedBy)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := env.Bytes()
	sig, _ := s.Sign(raw)
	a.Signature, a.SignatureAlgorithm, a.SignatureKID, a.SignedEnvelope = sig, "ed25519", s.kid, string(raw)
	return &a, content
}

func verifyBody(t *testing.T, s Signer, a *Artifact, content []byte) VerifyResponse {
	t.Helper()
	eng := newEngine(handlerDeps{artifacts: &stubArtifactStore{getResult: a, inlineContent: content}, signer: s})
	w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/verify", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	var v VerifyResponse
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerify_Ed25519RoundTrip(t *testing.T) {
	s := newEdSigner(t)
	a, content := signedFixture(t, s)
	v := verifyBody(t, s, a, content)
	if !v.HashValid || !v.SignatureChecked || !v.SignatureValid {
		t.Fatalf("an untouched signed artifact must verify: %+v", v)
	}
	if v.SignatureKID != s.kid || v.SignatureAlgorithm != "ed25519" || len(v.EnvelopeMismatch) != 0 || v.SignatureReason != "" {
		t.Fatalf("verify must report kid and algorithm and nothing else: %+v", v)
	}
}

// Altering any field of the signed envelope in the row must fail verification
// and name that field.
func TestVerify_TamperingWithEachEnvelopeFieldIsNamed(t *testing.T) {
	cases := map[string]func(a *Artifact, content *[]byte){
		"hash":          func(_ *Artifact, c *[]byte) { *c = []byte(`{"bomFormat":"CycloneDX","components":[1]}`) },
		"scope_id":      func(a *Artifact, _ *[]byte) { a.ScopeID = uuid.New() },
		"scope_version": func(a *Artifact, _ *[]byte) { a.ScopeVersion++ },
		"layers_hash": func(a *Artifact, _ *[]byte) {
			a.Layers = []Layer{{Type: "compliance_attestation", Version: "v1", Data: map[string]interface{}{"open": 0}}}
		},
		"kind":         func(a *Artifact, _ *[]byte) { a.ArtifactKind = KindHBOM },
		"generated_by": func(a *Artifact, _ *[]byte) { a.GeneratedBy = uuid.New() },
	}
	if len(cases) != len(EnvelopeFieldNames) {
		t.Fatalf("covering %d fields, envelope has %d", len(cases), len(EnvelopeFieldNames))
	}
	for field, tamper := range cases {
		t.Run(field, func(t *testing.T) {
			s := newEdSigner(t)
			a, content := signedFixture(t, s)
			tamper(a, &content)
			v := verifyBody(t, s, a, content)
			if v.SignatureValid {
				t.Fatalf("tampered %s still verifies: %+v", field, v)
			}
			if len(v.EnvelopeMismatch) != 1 || v.EnvelopeMismatch[0] != field {
				t.Fatalf("envelope_mismatch = %v, want [%s]", v.EnvelopeMismatch, field)
			}
			if v.SignatureReason != SignatureReasonEnvelope {
				t.Fatalf("reason = %q, want %q", v.SignatureReason, SignatureReasonEnvelope)
			}
		})
	}
}

// Rewriting the stored envelope to match a tampered row does not help: the
// signature covers the envelope's exact bytes.
func TestVerify_EditedEnvelopeBreaksTheSignature(t *testing.T) {
	s := newEdSigner(t)
	a, content := signedFixture(t, s)
	a.ScopeVersion = 7
	env, _ := NewEnvelope(a.ContentHash, a.ScopeID, a.ScopeVersion, a.Layers, a.ArtifactKind, a.GeneratedBy)
	raw, _ := env.Bytes()
	a.SignedEnvelope = string(raw)
	v := verifyBody(t, s, a, content)
	if v.SignatureValid || v.SignatureReason != SignatureReasonInvalid {
		t.Fatalf("a forged envelope must fail the signature: %+v", v)
	}
}

func TestVerify_UnknownKidAndForeignKey(t *testing.T) {
	s := newEdSigner(t)
	a, content := signedFixture(t, s)
	a.SignatureKID = "0123456789abcdef"
	if v := verifyBody(t, s, a, content); v.SignatureValid || v.SignatureReason != SignatureReasonUnknownKID {
		t.Fatalf("unknown kid: %+v", v)
	}
	// Signed by a key nobody recorded, but under a recorded kid.
	other := newEdSigner(t)
	b, content := signedFixture(t, other)
	b.SignatureKID = s.kid
	if v := verifyBody(t, s, b, content); v.SignatureValid || v.SignatureReason != SignatureReasonInvalid {
		t.Fatalf("foreign signature: %+v", v)
	}
}

// An artifact signed with the old shared-secret HMAC is reported invalid with
// a reason, with and without a verifier wired — there is no HMAC fallback.
func TestVerify_LegacyHMACRowIsInvalidWithReason(t *testing.T) {
	content := []byte(`{}`)
	for name, signer := range map[string]Signer{"with verifier": newEdSigner(t), "core (no verifier)": nil} {
		t.Run(name, func(t *testing.T) {
			a := sampleArtifact()
			a.ContentHash = sha256Hex(content)
			a.SignatureHMAC, a.SignatureKID = "00ff", "hmac-internal-v1"
			v := verifyBody(t, signer, &a, content)
			if !v.SignatureChecked || v.SignatureValid || v.SignatureReason != "legacy-hmac; regenerate" || v.SignatureAlgorithm != "hmac-sha256" {
				t.Fatalf("legacy row: %+v", v)
			}
		})
	}
}

func TestVerify_UnsignedAndCoreAreNotAsserted(t *testing.T) {
	a := sampleArtifact()
	content := []byte(`{}`)
	a.ContentHash = sha256Hex(content)
	if v := verifyBody(t, newEdSigner(t), &a, content); v.SignatureChecked {
		t.Fatalf("unsigned artifact must not assert a signature result: %+v", v)
	}
	s := newEdSigner(t)
	b, content := signedFixture(t, s)
	if v := verifyBody(t, nil, b, content); v.SignatureChecked {
		t.Fatalf("no verifier wired must not assert: %+v", v)
	}
}

func TestSigningKeysEndpoint(t *testing.T) {
	eng := newEngine(handlerDeps{artifacts: &stubArtifactStore{}})
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/signing-keys", nil)
	if w.Code != http.StatusOK || w.Body.String() != `{"keys":[]}` {
		t.Fatalf("Core: %d %s", w.Code, w.Body.String())
	}
}

type keyListingSigner struct{ *edSigner }

func (k keyListingSigner) PublicKeys(context.Context) ([]SigningKey, error) {
	return []SigningKey{{KID: k.kid, Algorithm: "ed25519", PublicKeyPEM: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n", Active: true, CreatedAt: time.Now().UTC()}}, nil
}

// The new response shapes conform to the OpenAPI spec the generated client is
// built from.
func TestContract_SigningKeysAndSignatureVerdicts(t *testing.T) {
	sv := loadSpec(t)
	s := newEdSigner(t)

	eng := newEngine(handlerDeps{artifacts: &stubArtifactStore{}, signer: keyListingSigner{s}})
	w := do(eng, http.MethodGet, "/api/v1/cbom-service/cbom/signing-keys", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SigningKeysResponse", w.Body.Bytes())

	// A tampered artifact (reason + envelope_mismatch present) and a legacy one.
	a, content := signedFixture(t, s)
	a.ScopeVersion++
	legacy := sampleArtifact()
	legacy.SignatureHMAC, legacy.SignatureKID = "00", "hmac-internal-v1"
	for name, art := range map[string]*Artifact{"tampered": a, "legacy": &legacy} {
		eng := newEngine(handlerDeps{artifacts: &stubArtifactStore{getResult: art, inlineContent: content}, signer: s})
		w := do(eng, http.MethodPost, "/api/v1/cbom-service/cbom/artifacts/"+aUUID+"/verify", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d: %s", name, w.Code, w.Body.String())
		}
		sv.assertConforms(t, "VerifyResponse", w.Body.Bytes())
	}
}
