// Package events: NATS TLS support.
//
// Builds nats.Option entries for client cert + CA trust based on environment
// variables. Auto-applied by NewNATSClient when the relevant env is present,
// so callers don't need to thread TLS state through their constructor calls.
//
// Env vars (all optional; absence = no TLS):
//
//	NATS_TLS_CERT_PATH   path to client cert (PEM)
//	NATS_TLS_KEY_PATH    path to client key (PEM)
//	NATS_TLS_CA_PATH     path to CA cert for server validation (PEM)
//
// All three must be set together to enable mTLS. Missing any one logs a
// warning and falls back to non-TLS connect (matching the v0.1.1 token
// behavior so v0.1.1 → v0.1.2 transition is gradual).
//
// In v0.1.2+ the chart sets these env vars when datastores.nats.tls.enabled.
// In v0.1.1 the chart leaves them unset and the existing NATS_TOKEN-based
// auth path stays in effect.
package events

import (
	"log"
	"os"

	"github.com/nats-io/nats.go"
)

// natsTLSOptionsFromEnv returns nats.Option entries for mTLS if all three
// NATS_TLS_* env vars are set. Returns nil if any is missing (caller proceeds
// without TLS, matching pre-v0.1.2 behavior).
func natsTLSOptionsFromEnv() []nats.Option {
	certPath := os.Getenv("NATS_TLS_CERT_PATH")
	keyPath := os.Getenv("NATS_TLS_KEY_PATH")
	caPath := os.Getenv("NATS_TLS_CA_PATH")

	// All-or-nothing: either all three env vars are set (TLS enabled) or
	// none are (TLS disabled). Partial config is treated as misconfiguration.
	allSet := certPath != "" && keyPath != "" && caPath != ""
	anySet := certPath != "" || keyPath != "" || caPath != ""

	if !anySet {
		return nil // No TLS configured; caller uses pre-v0.1.2 path.
	}

	if !allSet {
		log.Printf("[NATS] WARNING: NATS_TLS_* env vars partially set "+
			"(NATS_TLS_CERT_PATH:%s NATS_TLS_KEY_PATH:%s NATS_TLS_CA_PATH:%s). "+
			"All three must be set together. Falling back to non-TLS connect.",
			boolStr(certPath != ""), boolStr(keyPath != ""), boolStr(caPath != ""))
		return nil
	}

	log.Printf("[NATS] mTLS enabled (cert=%s ca=%s)", certPath, caPath)

	return []nats.Option{
		nats.ClientCert(certPath, keyPath),
		nats.RootCAs(caPath),
	}
}

func boolStr(b bool) string {
	if b {
		return "set"
	}
	return "unset"
}
