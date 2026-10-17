// Package trust adds an operator-supplied CA to what maintenance-service's
// outbound TLS connections trust.
//
// The update check lists the chart registry's tags and the pre-flight runs
// `cosign verify` against it; the update Job runs `helm upgrade` from it. A
// site that mirrors the chart behind a registry signed by its own CA (an
// internal Harbor, an air-gapped mirror) presents a certificate the image's
// public trust store cannot verify, and every one of those calls fails with
// "x509: certificate signed by unknown authority". EXTRA_TRUSTED_CA_PATH
// (the same variable monitoring-service reads for its synthetic checks)
// points at a PEM file, mounted from a Secret through
// backends.maintenance-service.extraEnv / extraVolumes, and this package
// turns it into:
//
//   - a CertPool for in-process clients: the system pool plus the extra CA,
//     never the extra CA alone, so a public registry keeps verifying;
//   - a combined bundle file for subprocesses (cosign), passed as
//     SSL_CERT_FILE, which Go's crypto/x509 honours on Linux. The Job's shell
//     script builds the same bundle for helm.
//
// A missing or unreadable file is a warning, not a startup failure: the
// service runs with the public trust store, as it does without the variable,
// and the registry error names the cause.
package trust

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// EnvExtraTrustedCA names the PEM file of an additional CA to trust.
const EnvExtraTrustedCA = "EXTRA_TRUSTED_CA_PATH"

// systemBundles are where the image keeps its public trust store (alpine's
// ca-certificates first, then the other common locations).
var systemBundles = []string{
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
	"/etc/ssl/ca-bundle.pem",
	"/etc/ssl/cert.pem",
}

// Bundle is the loaded trust configuration. The zero Bundle means "no extra
// CA": every method then yields the default behaviour.
type Bundle struct {
	// Path is the PEM file that was loaded.
	Path string
	// Pool is the system pool with the extra CA appended.
	Pool *x509.CertPool
	// File is a PEM file holding the system bundle followed by the extra CA,
	// for subprocesses that take SSL_CERT_FILE.
	File string
}

// Load reads the extra CA at path and builds the pool and the combined
// bundle file under tempDir ("" = os.TempDir()). An empty path returns the
// zero Bundle and no error.
func Load(path, tempDir string) (Bundle, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Bundle{}, nil
	}
	extra, err := os.ReadFile(path)
	if err != nil {
		return Bundle{}, fmt.Errorf("extra trusted CA %s: %w", path, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		// Never a pool holding only the extra CA: that would stop a public
		// registry verifying.
		return Bundle{}, fmt.Errorf("extra trusted CA %s: system trust store unavailable: %w", path, err)
	}
	if !pool.AppendCertsFromPEM(extra) {
		return Bundle{}, fmt.Errorf("extra trusted CA %s: no usable PEM certificate", path)
	}
	file, err := writeBundle(tempDir, extra)
	if err != nil {
		return Bundle{}, fmt.Errorf("extra trusted CA %s: %w", path, err)
	}
	return Bundle{Path: path, Pool: pool, File: file}, nil
}

// writeBundle writes <system bundle> + <extra> to a new file and returns its
// path. Without a readable system bundle the file holds the extra CA alone,
// which SSL_CERT_FILE consumers on Linux still combine with the default
// certificate directories.
func writeBundle(tempDir string, extra []byte) (string, error) {
	f, err := os.CreateTemp(tempDir, "ca-bundle-*.pem")
	if err != nil {
		return "", err
	}
	var system []byte
	for _, p := range systemBundles {
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			system = b
			break
		}
	}
	if len(system) > 0 {
		if _, err := f.Write(system); err != nil {
			_ = f.Close()
			return "", err
		}
		if system[len(system)-1] != '\n' {
			if _, err := f.Write([]byte{'\n'}); err != nil {
				_ = f.Close()
				return "", err
			}
		}
	}
	if _, err := f.Write(extra); err != nil {
		_ = f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return f.Name(), nil
}

// Configured reports whether an extra CA was loaded.
func (b Bundle) Configured() bool { return b.Pool != nil }

// TLSConfig returns a tls.Config trusting the pool, or nil for the default.
func (b Bundle) TLSConfig() *tls.Config {
	if b.Pool == nil {
		return nil
	}
	return &tls.Config{RootCAs: b.Pool, MinVersion: tls.VersionTLS12}
}

// Transport returns an http.Transport trusting the pool; nil means "use the
// default transport".
func (b Bundle) Transport() http.RoundTripper {
	cfg := b.TLSConfig()
	if cfg == nil {
		return nil
	}
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return &http.Transport{TLSClientConfig: cfg}
	}
	t = t.Clone()
	t.TLSClientConfig = cfg
	return t
}

// Env returns the environment entries a subprocess needs to trust the extra
// CA (SSL_CERT_FILE=<combined bundle>), or nil.
func (b Bundle) Env() []string {
	if b.File == "" {
		return nil
	}
	return []string{"SSL_CERT_FILE=" + b.File}
}

// ErrNotConfigured is returned by LoadEnv when the variable is unset; callers
// that only want to log use errors.Is.
var ErrNotConfigured = errors.New("extra trusted CA not configured")

// LoadEnv is Load for EXTRA_TRUSTED_CA_PATH.
func LoadEnv(getenv func(string) string, tempDir string) (Bundle, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	path := strings.TrimSpace(getenv(EnvExtraTrustedCA))
	if path == "" {
		return Bundle{}, ErrNotConfigured
	}
	return Load(path, tempDir)
}
