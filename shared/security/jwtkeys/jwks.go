package jwtkeys

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
)

// JWKSPath is where issuers serve their public key set. Unauthenticated by
// design — it contains only public keys, and a verifier has to be able to fetch
// it before it can authenticate anything.
const JWKSPath = "/.well-known/jwks.json"

// ServeJWKS writes the signer's public key set as a JWKS document.
//
// Cache-Control is deliberately short. It has to be longer than "every
// request" (verifiers poll, and this endpoint sits in the auth hot path) and
// shorter than the rotation window, or a cached document would keep serving a
// retired key past the point an operator believes it is gone.
func ServeJWKS(w http.ResponseWriter, s *Signer) {
	body, err := MarshalJWKS(s.PublicKeys())
	if err != nil {
		http.Error(w, `{"error":"failed to render JWKS"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// Client keeps a Verifier's key set current by polling an issuer's JWKS.
//
// Why poll rather than fetch on unknown-kid: a fetch triggered by an
// unrecognised kid is an unauthenticated attacker's lever on our outbound
// request rate. Polling on a fixed interval means a forged kid costs nothing.
// The cost is that a rotation is only visible after one interval, which is why
// Signer.Rotate documents that the new key must be published before it signs.
type Client struct {
	URL      string
	Interval time.Duration
	HTTP     *http.Client
	Keys     *KeySet
	Log      logrus.FieldLogger
}

// ClientFromEnv wires a JWKS refresher from configuration, or returns nil when
// none is configured.
//
//	JWT_JWKS_URL       where to fetch the issuer's public keys
//	JWT_JWKS_INTERVAL  refresh period (default 5m)
//
// Returns nil when JWT_JWKS_URL is unset, which is the pre-migration state: the
// verifier then holds whatever static keys it was given (possibly none) and the
// legacy HMAC secret.
func ClientFromEnv(keys *KeySet, log logrus.FieldLogger) *Client {
	url := os.Getenv("JWT_JWKS_URL")
	if url == "" {
		return nil
	}
	interval := 5 * time.Minute
	if raw := os.Getenv("JWT_JWKS_INTERVAL"); raw != "" {
		if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
			interval = time.Duration(secs) * time.Second
		}
	}
	return &Client{
		URL:      url,
		Interval: interval,
		HTTP:     &http.Client{Timeout: 10 * time.Second},
		Keys:     keys,
		Log:      log,
	}
}

// Refresh fetches the JWKS once and installs it on the Verifier.
//
// On ANY failure the existing key set is left untouched. A verifier that
// blanked its keys on a transient fetch error would reject every request in the
// deployment — turning a brief network blip into a total outage — so a failed
// refresh is a logged warning and nothing more.
func (c *Client) Refresh(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.URL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("jwtkeys: fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwtkeys: JWKS endpoint returned %d", resp.StatusCode)
	}
	// Bound the read: this is a document of a handful of small keys, and an
	// issuer that has been replaced by something hostile should not be able to
	// exhaust a verifier's memory.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("jwtkeys: read JWKS: %w", err)
	}

	keys, err := ParseJWKS(body)
	if err != nil {
		return err
	}
	c.Keys.Set(keys)
	return nil
}

// Start does one synchronous refresh, then keeps refreshing in the background
// until ctx is cancelled.
//
// The first refresh is synchronous and its error is RETURNED, so a service can
// decide at startup whether it is willing to serve without keys. It is not
// fatal here: a deployment mid-migration legitimately has no JWKS yet and
// verifies HS256, and a hard failure would make the JWKS endpoint a startup
// dependency for all ~17 services.
func (c *Client) Start(ctx context.Context) error {
	first := c.Refresh(ctx)
	if first != nil && c.Log != nil {
		c.Log.WithError(first).Warn("initial JWKS fetch failed; verifying with the keys already configured")
	} else if c.Log != nil {
		c.Log.WithField("kids", c.Keys.KIDs()).Info("JWKS loaded")
	}

	go func() {
		// Until the FIRST success, retry with exponential backoff instead of
		// waiting a whole Interval.
		//
		// The first fetch routinely races the issuer's own startup — a verifier
		// and its issuer roll together in the same helm upgrade — and there is
		// no bootstrap key set to fall back on, because Helm cannot derive a
		// public key from the private PEM it generates. So a verifier that
		// waits a full Interval has a multi-minute window in which freshly
		// issued tokens do not verify at all.
		//
		// Observed, not theorised: on the first Core v0.1.0 deploy every
		// service logged "JWKS endpoint returned 404" at startup and
		// platform-admin login was broken for exactly 300s. It looked benign
		// only because legacy HS256 still covered pre-existing sessions —
		// with acceptLegacyHmac off it would have been a total auth outage on
		// every restart.
		//
		// Backoff rather than a tight loop so a genuinely absent issuer does
		// not turn every verifier into a hot spinner against it.
		if first != nil {
			delay := time.Second
			for {
				select {
				case <-ctx.Done():
					return
				case <-time.After(delay):
				}
				if err := c.Refresh(ctx); err == nil {
					if c.Log != nil {
						c.Log.WithField("kids", c.Keys.KIDs()).Info("JWKS loaded after retry")
					}
					break
				}
				if delay *= 2; delay > c.Interval {
					delay = c.Interval
				}
			}
		}

		t := time.NewTicker(c.Interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := c.Refresh(ctx); err != nil && c.Log != nil {
					c.Log.WithError(err).Warn("JWKS refresh failed; keeping the previous key set")
				}
			}
		}
	}()

	return first
}
