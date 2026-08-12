package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// selfSignedPEM returns a throwaway self-signed CA in PEM form.
func selfSignedPEM(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// poolAccepts reports whether a PEM bundle, loaded the way the agents load it,
// contains a certificate with the given common name.
func poolAccepts(t *testing.T, bundle, cn string) bool {
	t.Helper()
	rest := []byte(bundle)
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			return false
		}
		cert, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			continue
		}
		if cert.Subject.CommonName == cn {
			return true
		}
	}
}

// The regression this package exists for: an agent has pinned the CA the
// operator approved for the edge endpoint, then registration hands back the
// platform's agent CA. Both must survive, because which endpoint the agent
// talks to afterwards depends on whether agentMtls is enabled. Replacing (the
// old behaviour) drops the edge anchor and every post-registration call fails.
func TestMergeCAPEMs_KeepsOperatorAnchorAndAddsPlatformCA(t *testing.T) {
	edge := selfSignedPEM(t, "edge.example.test")
	platform := selfSignedPEM(t, "platform-agent-ca")

	merged := MergeCAPEMs(edge, platform)

	if !poolAccepts(t, merged, "edge.example.test") {
		t.Error("operator-approved edge anchor was dropped — this is the bug that made sensors go silent after registration")
	}
	if !poolAccepts(t, merged, "platform-agent-ca") {
		t.Error("platform CA was not added, so the mTLS passthrough endpoint would not verify")
	}
	// The old behaviour was `existing = incoming`; assert we are not that.
	if strings.TrimSpace(merged) == strings.TrimSpace(platform) {
		t.Error("merge collapsed to the incoming bundle — that is the replace behaviour, not a merge")
	}
}

func TestMergeCAPEMs_IsIdempotent(t *testing.T) {
	edge := selfSignedPEM(t, "edge.example.test")
	platform := selfSignedPEM(t, "platform-agent-ca")

	once := MergeCAPEMs(edge, platform)
	twice := MergeCAPEMs(once, platform)
	if once != twice {
		t.Error("re-merging the same CA changed the bundle; repeated registrations or rotations would grow it without bound")
	}
	if got := strings.Count(twice, "BEGIN CERTIFICATE"); got != 2 {
		t.Errorf("expected 2 certificates after re-merge, got %d", got)
	}
}

// Malformed input must never cost us a working anchor.
func TestMergeCAPEMs_UnparsableIncomingKeepsExisting(t *testing.T) {
	edge := selfSignedPEM(t, "edge.example.test")

	for name, junk := range map[string]string{
		"empty":     "",
		"garbage":   "not a pem at all",
		"truncated": "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----\n",
	} {
		t.Run(name, func(t *testing.T) {
			got := MergeCAPEMs(edge, junk)
			if !poolAccepts(t, got, "edge.example.test") {
				t.Errorf("existing anchor lost when incoming was %s", name)
			}
		})
	}
}

func TestMergeCAPEMs_EmptyExistingTakesIncoming(t *testing.T) {
	platform := selfSignedPEM(t, "platform-agent-ca")
	if got := MergeCAPEMs("", platform); !poolAccepts(t, got, "platform-agent-ca") {
		t.Error("with no prior anchor the incoming CA must be adopted")
	}
}

// A non-certificate block must not be carried into a trust bundle.
func TestMergeCAPEMs_DropsNonCertificateBlocks(t *testing.T) {
	edge := selfSignedPEM(t, "edge.example.test")
	withKey := edge + "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"

	got := MergeCAPEMs("", withKey)
	if strings.Contains(got, "PRIVATE KEY") {
		t.Error("private-key block survived into the CA bundle")
	}
	if !poolAccepts(t, got, "edge.example.test") {
		t.Error("certificate was lost while dropping the key block")
	}
}
