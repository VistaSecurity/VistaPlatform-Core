package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	"github.com/google/uuid"
)

// CSRGenerator handles Certificate Signing Request generation
type CSRGenerator struct {
}

// NewCSRGenerator creates a new CSR generator
func NewCSRGenerator() *CSRGenerator {
	return &CSRGenerator{}
}

// GenerateKeyPair generates a new RSA keypair
func (g *CSRGenerator) GenerateKeyPair() (*rsa.PrivateKey, error) {
	// Generate 2048-bit RSA key
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	return key, nil
}

// GenerateCSR generates a Certificate Signing Request
// entityID should be the UUID string of the entity (sensor/agent ID)
func (g *CSRGenerator) GenerateCSR(entityID uuid.UUID, privateKey *rsa.PrivateKey) (string, error) {
	// Validate entity ID
	if entityID == uuid.Nil {
		return "", fmt.Errorf("entity ID cannot be nil")
	}

	// Create CSR template
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			Organization:       []string{"VistaPlatform"},
			OrganizationalUnit: []string{"VistaPlatform"},
			Country:            []string{"US"},
			Province:           []string{"Florida"},
			Locality:           []string{"Orlando"},
			CommonName:         entityID.String(), // Use entity ID as CN
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// Create CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create CSR: %w", err)
	}

	// Encode CSR to PEM
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return string(csrPEM), nil
}

// EncodePrivateKey encodes a private key to PEM format
func (g *CSRGenerator) EncodePrivateKey(key *rsa.PrivateKey) (string, error) {
	keyDER := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyDER,
	})
	return string(keyPEM), nil
}

// ParsePrivateKey parses a PEM-encoded private key
func (g *CSRGenerator) ParsePrivateKey(keyPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return key, nil
}
