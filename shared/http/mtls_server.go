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

// NewAgentMTLSServer creates an HTTP server for the device-agent / sensor
// outbound passthrough listener.
//
// Unlike NewMTLSServer (which pins a single ClientCAs pool and uses
// RequireAndVerifyClientCert against the platform mesh CA), agent and sensor
// client certs are signed by PER-TENANT registration CAs. There is no single
// CA pool that covers every tenant, and tenant CAs are minted/rotated at
// runtime — so chain verification cannot happen at the TLS handshake. Instead
// this listener REQUIRES a client cert to be presented (tls.RequireAnyClientCert)
// and the AgentAuth / SensorAuth middleware performs the real verification:
// CN→identity, identity→tenant, and chain validation against that tenant's
// active CA. The handshake guarantees a cert is present; the middleware
// guarantees it is the right cert for the right tenant.
//
// The server presents serverCert/serverKey (the service's mesh cert) to the
// connecting agent. NOTE: agents currently validate the platform server cert
// against the per-tenant CA returned at registration (ServerCACert); see the
// deployment notes / PR for the server-trust follow-up needed before agents
// will trust this listener's cert end-to-end.
func NewAgentMTLSServer(serverCertPath, serverKeyPath string, handler http.Handler) (*http.Server, error) {
	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load agent-mTLS server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		// Require a client cert at the handshake, but do NOT verify its chain
		// here — the middleware verifies it against the connecting agent's
		// per-tenant CA (which this listener cannot know ahead of time).
		ClientAuth: tls.RequireAnyClientCert,
		MinVersion: tls.VersionTLS12,
	}

	return &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}, nil
}

// NewMTLSServer creates a new HTTP server configured for mTLS
// It loads the server certificate, server key, and CA certificate for client validation
func NewMTLSServer(serverCertPath, serverKeyPath, caCertPath string, handler http.Handler) (*http.Server, error) {
	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
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

	// Configure TLS with client certificate verification
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // Require client certificates
		MinVersion:   tls.VersionTLS12,
	}

	server := &http.Server{
		Handler:           handler,
		TLSConfig:         tlsConfig,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return server, nil
}
