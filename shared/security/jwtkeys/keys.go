// Package jwtkeys provides asymmetric JWT signing and verification with
// key-id-based rotation.
//
// # Why this exists
//
// Every service used to sign AND verify with one shared HS256 secret
// (JWT_SECRET). That is a symmetric key held by ~17 pods, which means any one
// of them — or any log line, env dump, core file or compromised sidecar that
// touched it — could mint a token for any user, any tenant, any role. There was
// no `kid`, so rotation was all-or-nothing: change the secret and every live
// session breaks at once.
//
// Here, only the two token ISSUERS (auth-service for tenant sessions,
// admin-service for platform sessions) hold a private key. Every other service
// verifies with a public key it fetches from the issuer's JWKS endpoint. A leak
// from a verifier grants nothing: public keys are public.
//
// # Curve choice
//
// ES256 (ECDSA P-256). Universally understood by JWKS tooling, already the
// curve this repo uses for entitlement-token and content-bundle signing, and
// the algorithm an auditor expects to see. Ed25519 would be marginally faster
// and smaller, but "OKP" key types still surprise some consumers and we gain
// nothing operationally.
//
// # Algorithm confusion
//
// The classic attack on a system in this position is to re-sign a token with
// HS256, using the PUBLIC key as the HMAC secret, and hand it to a verifier
// that trusts the `alg` header. Verifier() therefore selects the key by
// algorithm CLASS, never by what the token asks for: an ES256 token resolves to
// an ECDSA public key and an HS256 token resolves to the legacy shared secret,
// and neither can be made to reach the other's key material. See
// verifier_test.go, which pins that with a real forged token.
package jwtkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Alg is the only asymmetric algorithm this package signs or verifies with.
const Alg = "ES256"

var (
	ErrNoSigningKey = errors.New("jwtkeys: no active signing key configured")
	ErrUnknownKID   = errors.New("jwtkeys: token kid is not in the trusted key set")
	ErrNoKID        = errors.New("jwtkeys: token has no kid header")
)

// KeyPair is one signing key: a P-256 private key plus the id it is published
// under. The kid is derived from the public key (see DeriveKID), so it is
// stable, collision-resistant, and cannot silently disagree with the key it
// names — a kid typo becomes an unknown-key error rather than a wrong-key
// verification.
type KeyPair struct {
	KID     string
	Private *ecdsa.PrivateKey

	// NotAfter, when non-zero, is when this key stops being used for SIGNING.
	// It keeps being published for VERIFICATION until it is removed from the
	// key set entirely, which is what makes a rotation non-breaking: tokens
	// signed just before the cutover stay valid for their full TTL.
	NotAfter time.Time
}

// Public returns the verification half of the pair.
func (k KeyPair) Public() PublicKey {
	return PublicKey{KID: k.KID, Key: &k.Private.PublicKey}
}

// PublicKey is one entry in a trusted key set.
type PublicKey struct {
	KID string
	Key *ecdsa.PublicKey
}

// DeriveKID computes a key id from a public key: base64url(SHA-256(SPKI DER)),
// truncated to 128 bits. This is RFC 7638-adjacent — a real JWK thumbprint
// hashes the canonical JWK JSON, but hashing the SPKI encoding gives the same
// properties (deterministic, key-bound, no coordination needed between the
// service that generates a key and the service that names it) with far less
// canonicalisation surface to get wrong.
func DeriveKID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("jwtkeys: marshal public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:16]), nil
}

// Generate creates a fresh P-256 signing key with a derived kid. Used by the
// key-provisioning tooling, not at service startup — a service that generated
// its own key on boot would issue tokens nothing else could verify.
func Generate() (*KeyPair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("jwtkeys: generate: %w", err)
	}
	kid, err := DeriveKID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &KeyPair{KID: kid, Private: priv}, nil
}

// ─── PEM encoding ──────────────────────────────────────────────────────────
//
// Private keys travel as PKCS#8 PEM, which is what `openssl`, cert-manager and
// every k8s Secret convention already speak. One key per PEM block; a file may
// hold several blocks (an old key and its replacement during a rotation).

// EncodePrivatePEM serialises a signing key as a PKCS#8 PEM block.
func EncodePrivatePEM(k *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("jwtkeys: marshal private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivatePEM reads every PRIVATE KEY block in the input and returns one
// KeyPair per block, kid derived from each.
//
// Order is significant: the FIRST key is the active signer, later ones are kept
// for verification only. That makes a rotation a prepend, and makes "which key
// am I signing with" answerable by looking at the top of the file.
func ParsePrivatePEM(pemBytes []byte) ([]KeyPair, error) {
	var out []KeyPair
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PRIVATE KEY" && block.Type != "EC PRIVATE KEY" {
			continue
		}
		priv, err := parseECPrivate(block)
		if err != nil {
			return nil, err
		}
		kid, err := DeriveKID(&priv.PublicKey)
		if err != nil {
			return nil, err
		}
		out = append(out, KeyPair{KID: kid, Private: priv})
	}
	if len(out) == 0 {
		return nil, errors.New("jwtkeys: no PRIVATE KEY block found in PEM input")
	}
	return out, nil
}

func parseECPrivate(block *pem.Block) (*ecdsa.PrivateKey, error) {
	if block.Type == "EC PRIVATE KEY" {
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("jwtkeys: parse SEC1 EC key: %w", err)
		}
		return k, nil
	}
	any, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwtkeys: parse PKCS#8 key: %w", err)
	}
	k, ok := any.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("jwtkeys: signing key must be ECDSA P-256, got %T", any)
	}
	if k.Curve != elliptic.P256() {
		return nil, fmt.Errorf("jwtkeys: signing key must be P-256, got %s", k.Curve.Params().Name)
	}
	return k, nil
}

// ─── JWKS ──────────────────────────────────────────────────────────────────

// JWK is one public key in JWKS form (RFC 7517), restricted to what an EC
// P-256 verification key needs.
type JWK struct {
	Kty string `json:"kty"` // "EC"
	Crv string `json:"crv"` // "P-256"
	Kid string `json:"kid"`
	Use string `json:"use"` // "sig"
	Alg string `json:"alg"` // "ES256"
	X   string `json:"x"`
	Y   string `json:"y"`
}

// coordLen is the P-256 field size in bytes, and so the width of each JWK
// coordinate.
const coordLen = 32

// JWKS is the document served at /.well-known/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ToJWK converts a public key to its JWKS entry.
//
// The coordinates are fixed-width big-endian, left-padded to the curve size.
// Trimming leading zeroes here is a classic interop bug: a key whose X happens
// to start with a zero byte would serialise one byte short and fail to
// reconstruct in strict parsers. [ecdsa.PublicKey.Bytes] produces exactly that
// encoding — SEC 1 uncompressed, 0x04 || X || Y with both coordinates padded to
// the field size — so the width is structural rather than something this code
// has to remember to do.
//
// It returns an error because Bytes rejects a point that is not on the curve,
// and a JWKS must never publish one.
func ToJWK(pk PublicKey) (JWK, error) {
	if pk.Key == nil {
		return JWK{}, fmt.Errorf("jwtkeys: public key %q has no key material", pk.KID)
	}
	b, err := pk.Key.Bytes()
	if err != nil {
		return JWK{}, fmt.Errorf("jwtkeys: encode public key %q: %w", pk.KID, err)
	}
	if len(b) != 1+2*coordLen {
		return JWK{}, fmt.Errorf("jwtkeys: public key %q is not a P-256 point (%d bytes)", pk.KID, len(b))
	}
	return JWK{
		Kty: "EC",
		Crv: "P-256",
		Kid: pk.KID,
		Use: "sig",
		Alg: Alg,
		X:   base64.RawURLEncoding.EncodeToString(b[1 : 1+coordLen]),
		Y:   base64.RawURLEncoding.EncodeToString(b[1+coordLen:]),
	}, nil
}

// decodeCoord decodes one base64url JWK coordinate into a fixed-width
// big-endian octet string. RFC 7518 requires the encoded value to already be
// the full field width; a shorter one is left-padded rather than rejected, so a
// producer that trims leading zeroes still interoperates.
func decodeCoord(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) > coordLen {
		return nil, fmt.Errorf("coordinate is %d bytes, want at most %d", len(b), coordLen)
	}
	if len(b) < coordLen {
		padded := make([]byte, coordLen)
		copy(padded[coordLen-len(b):], b)
		b = padded
	}
	return b, nil
}

// FromJWK reconstructs a public key from a JWKS entry, rejecting anything that
// is not an ES256 P-256 signing key. A JWKS is fetched over the network, so
// every field is treated as untrusted input.
func FromJWK(j JWK) (PublicKey, error) {
	if j.Kty != "EC" {
		return PublicKey{}, fmt.Errorf("jwtkeys: unsupported kty %q (want EC)", j.Kty)
	}
	if j.Crv != "P-256" {
		return PublicKey{}, fmt.Errorf("jwtkeys: unsupported crv %q (want P-256)", j.Crv)
	}
	if j.Alg != "" && j.Alg != Alg {
		return PublicKey{}, fmt.Errorf("jwtkeys: unsupported alg %q (want %s)", j.Alg, Alg)
	}
	if j.Use != "" && j.Use != "sig" {
		return PublicKey{}, fmt.Errorf("jwtkeys: key use %q is not a signing key", j.Use)
	}
	if j.Kid == "" {
		return PublicKey{}, errors.New("jwtkeys: JWK has no kid")
	}
	xb, err := decodeCoord(j.X)
	if err != nil {
		return PublicKey{}, fmt.Errorf("jwtkeys: decode x: %w", err)
	}
	yb, err := decodeCoord(j.Y)
	if err != nil {
		return PublicKey{}, fmt.Errorf("jwtkeys: decode y: %w", err)
	}
	// Reassemble the SEC 1 uncompressed point and let crypto/ecdsa parse it.
	// ParseUncompressedPublicKey performs the on-curve check for us, so a
	// crafted JWKS response cannot hand us an invalid point and reach the ECDSA
	// verification path with it.
	point := make([]byte, 0, 1+2*coordLen)
	point = append(point, 4)
	point = append(point, xb...)
	point = append(point, yb...)
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), point)
	if err != nil {
		return PublicKey{}, errors.New("jwtkeys: JWK coordinates are not a point on P-256")
	}
	// A kid that does not match its own key means the document is inconsistent
	// — either corrupted in transit or assembled by hand. Refuse it rather than
	// trusting an attacker-chosen name for a key.
	want, err := DeriveKID(pub)
	if err != nil {
		return PublicKey{}, err
	}
	if want != j.Kid {
		return PublicKey{}, fmt.Errorf("jwtkeys: JWK kid %q does not match its key (want %q)", j.Kid, want)
	}
	return PublicKey{KID: j.Kid, Key: pub}, nil
}

// MarshalJWKS renders a public key set as the JWKS document body. Keys are
// sorted by kid so the response bytes are stable — a JWKS that changes shape on
// every request defeats HTTP caching and makes diffs unreadable.
func MarshalJWKS(keys []PublicKey) ([]byte, error) {
	sorted := append([]PublicKey(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].KID < sorted[j].KID })
	doc := JWKS{Keys: make([]JWK, 0, len(sorted))}
	for _, k := range sorted {
		j, err := ToJWK(k)
		if err != nil {
			return nil, err
		}
		doc.Keys = append(doc.Keys, j)
	}
	return json.Marshal(doc)
}

// ParseJWKS reads a JWKS document into a public key set.
//
// A document containing an unusable key is an error, not a silent skip: quietly
// dropping the one key an issuer just rotated to would look exactly like a
// working refresh while every new token failed to verify.
func ParseJWKS(body []byte) ([]PublicKey, error) {
	var doc JWKS
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("jwtkeys: parse JWKS: %w", err)
	}
	if len(doc.Keys) == 0 {
		return nil, errors.New("jwtkeys: JWKS contains no keys")
	}
	out := make([]PublicKey, 0, len(doc.Keys))
	for i, j := range doc.Keys {
		pk, err := FromJWK(j)
		if err != nil {
			return nil, fmt.Errorf("jwtkeys: JWKS key %d: %w", i, err)
		}
		out = append(out, pk)
	}
	return out, nil
}
