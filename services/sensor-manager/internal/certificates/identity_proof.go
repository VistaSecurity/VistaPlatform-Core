package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrClientCertificateRequired is returned when the request carries no
	// client certificate at all, so it cannot prove it already holds the
	// identity it is asking to re-issue.
	ErrClientCertificateRequired = errors.New("sensor client certificate required")

	// ErrIdentityProofFailed is returned when a client certificate WAS
	// presented but is not this sensor's current, active, CA-issued one.
	ErrIdentityProofFailed = errors.New("presented certificate does not prove the current sensor identity")
)

// VerifyPresentedIdentity proves that the caller already holds sensorID's
// CURRENT client certificate. It is the guard for privileged, identity-changing
// operations — above all certificate rotation.
//
// It deliberately does NOT consult AGENT_MTLS_REQUIRED. A rotation endpoint that
// is weaker than the identity it rotates is the bug: with agent mTLS off, the
// path parameter alone is the authenticator for the outbound sensor surface, and
// a path UUID is a public-ish identifier. Anyone who learns one could submit a
// CSR, receive a legitimately CA-signed certificate for that sensor, and see the
// genuine certificate superseded — so turning agent mTLS ON afterwards would
// evict the real sensor and bless the attacker's now-legitimate certificate.
// Rotation therefore requires cryptographic proof of the current identity in
// every mode; when that proof is impossible (no passthrough listener, hence no
// peer certificate), rotation is refused rather than granted.
//
// The checks, in order:
//  1. a client certificate was presented;
//  2. its Subject CN is the sensor id being rotated;
//  3. it is inside its validity window;
//  4. it chains to the tenant's active sensor CA with the clientAuth EKU;
//  5. its serial is the serial of the sensor's current unrevoked certificate
//     (so a superseded or revoked certificate cannot rotate itself back in).
func (s *CertificateService) VerifyPresentedIdentity(tenantID, sensorID uuid.UUID, state *tls.ConnectionState) error {
	if state == nil || len(state.PeerCertificates) == 0 {
		return ErrClientCertificateRequired
	}
	leaf := state.PeerCertificates[0]

	if leaf.Subject.CommonName != sensorID.String() {
		return fmt.Errorf("%w: certificate CN %q is not sensor %s", ErrIdentityProofFailed, leaf.Subject.CommonName, sensorID)
	}

	now := time.Now()
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("%w: certificate expired at %s", ErrIdentityProofFailed, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("%w: certificate is not valid until %s", ErrIdentityProofFailed, leaf.NotBefore.UTC().Format(time.RFC3339))
	}

	if s.db == nil || s.bypassDB == nil {
		return fmt.Errorf("%w: certificate store unavailable", ErrIdentityProofFailed)
	}

	ca, err := s.caManager.GetActiveCA(tenantID)
	if err != nil {
		return fmt.Errorf("%w: tenant CA unavailable: %v", ErrIdentityProofFailed, err)
	}
	caBlock, _ := pem.Decode([]byte(ca.CACertPEM))
	if caBlock == nil {
		return fmt.Errorf("%w: tenant CA PEM could not be decoded", ErrIdentityProofFailed)
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("%w: tenant CA could not be parsed: %v", ErrIdentityProofFailed, err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("%w: certificate does not chain to the tenant sensor CA: %v", ErrIdentityProofFailed, err)
	}

	cert, err := s.GetCertificate(sensorID)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("%w: sensor has no active certificate on record", ErrIdentityProofFailed)
	}
	if err != nil {
		return fmt.Errorf("%w: active certificate lookup failed: %v", ErrIdentityProofFailed, err)
	}
	if cert == nil {
		return fmt.Errorf("%w: sensor has no active certificate on record", ErrIdentityProofFailed)
	}
	if cert.RevokedAt != nil {
		return fmt.Errorf("%w: certificate was revoked", ErrIdentityProofFailed)
	}
	if cert.SerialNumber != leaf.SerialNumber.String() {
		return fmt.Errorf("%w: certificate is not the active certificate", ErrIdentityProofFailed)
	}
	return nil
}
