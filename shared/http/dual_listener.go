// Package http: dual-listener helper for kubelet-probe + mTLS coexistence.
//
// In Kubernetes, kubelet doesn't have a client cert to present, so it can't
// hit a pure-mTLS endpoint for liveness/readiness probes. The standard
// pattern is to run TWO listeners in the same process:
//
//   - 8080 plain HTTP, /health only — kubelet probes hit this. No sensitive
//     data; just returns 200/503.
//   - 8443 mTLS, real API endpoints — backends present client certs to
//     reach this.
//
// This helper factors out the boilerplate of standing up both listeners.
// Some services (sensor-manager, discovery-processor-service, etc.) already
// implement this pattern inline. Others can adopt this helper to match.
//
// Usage:
//
//	cfg := DualListenerConfig{
//	    APIHandler:    apiRouter,            // your real API handler
//	    ProbeHandler:  healthRouter,         // /health only
//	    UseMTLS:       cfg.UseMTLS,
//	    APIPort:       cfg.TLSPort,          // typically "8443"
//	    ProbePort:     "8080",               // kubelet probes
//	    CertPath:      cfg.ServiceCertPath,  // /app/certs/tls.crt
//	    KeyPath:       cfg.ServiceKeyPath,   // /app/certs/tls.key
//	    CACertPath:    cfg.PlatformCACertPath, // /app/certs/ca.crt
//	    Logger:        log.Default(),
//	}
//
//	servers, err := StartDualListeners(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer servers.Shutdown(context.Background())
//
//	// servers.Wait() blocks until any server exits.
package http

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// DualListenerConfig describes the two HTTP listeners a service runs in
// the v0.1.2+ mTLS shape.
type DualListenerConfig struct {
	// APIHandler serves real API endpoints. Required.
	APIHandler http.Handler

	// ProbeHandler serves probe endpoints (/health, /ready, etc.). Required
	// when UseMTLS is true (kubelet probes can't speak mTLS). When UseMTLS
	// is false, the APIHandler is expected to also serve probe endpoints
	// on the same port and ProbeHandler is ignored.
	ProbeHandler http.Handler

	// UseMTLS decides the listener shape:
	//   - true: APIHandler on APIPort with mTLS, ProbeHandler on ProbePort
	//     plain HTTP.
	//   - false: APIHandler on APIPort plain HTTP, no separate probe
	//     listener.
	UseMTLS bool

	// APIPort is the port the API listener binds. Typically "8443" for
	// mTLS, "8080" otherwise.
	APIPort string

	// ProbePort is the port the probe-only listener binds when UseMTLS.
	// Typically "8080".
	ProbePort string

	// Cert paths used when UseMTLS is true. All three required.
	CertPath   string
	KeyPath    string
	CACertPath string

	// Logger for startup messages. Optional — defaults to log.Default().
	Logger *log.Logger
}

// DualListeners holds the running HTTP servers for shutdown coordination.
type DualListeners struct {
	apiServer   *http.Server
	probeServer *http.Server
	wg          sync.WaitGroup
	errCh       chan error
}

// StartDualListeners constructs and starts the listener(s) per config.
// Returns DualListeners which can be Shutdown / Wait'd on.
func StartDualListeners(cfg DualListenerConfig) (*DualListeners, error) {
	if cfg.APIHandler == nil {
		return nil, fmt.Errorf("DualListenerConfig.APIHandler is required")
	}
	if cfg.APIPort == "" {
		cfg.APIPort = "8080"
	}
	if cfg.Logger == nil {
		cfg.Logger = log.Default()
	}

	dl := &DualListeners{
		errCh: make(chan error, 2),
	}

	// API listener (mTLS or plain).
	if cfg.UseMTLS {
		if cfg.CertPath == "" || cfg.KeyPath == "" || cfg.CACertPath == "" {
			return nil, fmt.Errorf("DualListenerConfig: UseMTLS=true requires CertPath, KeyPath, CACertPath")
		}
		srv, err := NewMTLSServer(cfg.CertPath, cfg.KeyPath, cfg.CACertPath, cfg.APIHandler)
		if err != nil {
			return nil, fmt.Errorf("failed to build mTLS server: %w", err)
		}
		srv.Addr = ":" + cfg.APIPort
		dl.apiServer = srv

		dl.wg.Add(1)
		go func() {
			defer dl.wg.Done()
			cfg.Logger.Printf("[dual-listener] API server (mTLS) listening on :%s", cfg.APIPort)
			if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				dl.errCh <- fmt.Errorf("mTLS API server: %w", err)
			}
		}()

		// Probe listener — only when mTLS is enabled. Without it kubelet
		// probes can't reach the service.
		if cfg.ProbeHandler == nil {
			return nil, fmt.Errorf("DualListenerConfig: UseMTLS=true requires ProbeHandler for kubelet probes on port %s", cfg.ProbePort)
		}
		if cfg.ProbePort == "" {
			cfg.ProbePort = "8080"
		}
		probeSrv := &http.Server{
			Addr:              ":" + cfg.ProbePort,
			Handler:           cfg.ProbeHandler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		dl.probeServer = probeSrv

		dl.wg.Add(1)
		go func() {
			defer dl.wg.Done()
			cfg.Logger.Printf("[dual-listener] Probe server (plain HTTP) listening on :%s", cfg.ProbePort)
			if err := probeSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				dl.errCh <- fmt.Errorf("probe server: %w", err)
			}
		}()
	} else {
		// No mTLS — single plain-HTTP server on APIPort. APIHandler should
		// serve both /health probes AND real API endpoints.
		srv := &http.Server{
			Addr:              ":" + cfg.APIPort,
			Handler:           cfg.APIHandler,
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      15 * time.Second,
			IdleTimeout:       60 * time.Second,
		}
		dl.apiServer = srv

		dl.wg.Add(1)
		go func() {
			defer dl.wg.Done()
			cfg.Logger.Printf("[dual-listener] API server (plain HTTP, no mTLS) listening on :%s", cfg.APIPort)
			if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				dl.errCh <- fmt.Errorf("plain HTTP API server: %w", err)
			}
		}()
	}

	return dl, nil
}

// Shutdown gracefully stops both listeners. Safe to call multiple times.
func (dl *DualListeners) Shutdown(ctx context.Context) error {
	var firstErr error

	if dl.apiServer != nil {
		if err := dl.apiServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if dl.probeServer != nil {
		if err := dl.probeServer.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// Wait blocks until both servers exit (gracefully or otherwise) and
// returns the first non-nil error received from either.
func (dl *DualListeners) Wait() error {
	dl.wg.Wait()
	close(dl.errCh)
	for err := range dl.errCh {
		if err != nil {
			return err
		}
	}
	return nil
}
