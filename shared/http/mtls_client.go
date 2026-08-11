package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"
)

// NewMTLSClient creates a new HTTP client configured for mTLS
// clientCertPath: Path to client certificate PEM file
// clientKeyPath: Path to client private key PEM file
// caCertPath: Path to CA certificate PEM file for server validation
func NewMTLSClient(clientCertPath, clientKeyPath, caCertPath string) (*http.Client, error) {
	// Load client certificate and key
	clientCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client certificate: %w", err)
	}

	// Load CA certificate
	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Parse CA certificate
	caCertPool := x509.NewCertPool()
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caCertPool.AddCert(caCert)

	// Configure TLS
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		RootCAs:            caCertPool,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	// Create HTTP client with TLS transport
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		MaxIdleConns:    100,
		IdleConnTimeout: 90 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	return client, nil
}
