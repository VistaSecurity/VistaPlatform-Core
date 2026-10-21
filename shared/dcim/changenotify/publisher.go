package changenotify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// AlertIntakePath is compliance-engine's HMAC-only route that takes one
// alerts.raise event over HTTP — the fallback when NATS cannot carry it.
// compliance-engine's internal_alert_intake.go serves it.
const AlertIntakePath = "/api/v1/compliance-engine/internal/alerts/raise"

// HTTPAlertIntake raises an event by POSTing it to compliance-engine's alert
// intake, signed with this service's HMAC service credential.
type HTTPAlertIntake struct {
	BaseURL string
	Client  *http.Client
	// Sign signs the request; serviceauth.SignRequestFromEnv in production.
	// An unsigned POST is refused by the route, so leaving this nil makes the
	// fallback deliver nothing — NewHTTPAlertIntakeFromEnv always sets it.
	Sign func(*http.Request)
}

// NewHTTPAlertIntakeFromEnv is the intake as the process is configured:
// COMPLIANCE_ENGINE_URL, or the peer URL for the process's mTLS mode; under
// mTLS a client that presents this service's certificate, since the 8443
// listener demands one (a plain client would fail the handshake and every
// fallback would be lost). A client that cannot be built returns nil and says
// why; the caller then has no HTTP fallback.
func NewHTTPAlertIntakeFromEnv() *HTTPAlertIntake {
	client := &http.Client{Timeout: 10 * time.Second}
	if sharedconfig.MTLSEnabled() {
		c, err := sharedhttp.NewMTLSClient(
			sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
			sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
			sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),
		)
		if err != nil {
			log.Printf("[changenotify] no HTTP fallback for alerts.raise: mTLS client for compliance-engine could not be built: %v", err)
			return nil
		}
		c.Timeout = 10 * time.Second
		client = c
	}
	return &HTTPAlertIntake{
		BaseURL: sharedconfig.PeerServiceURLAuto("COMPLIANCE_ENGINE_URL", "compliance-engine"),
		Client:  client,
		Sign:    serviceauth.SignRequestFromEnv,
	}
}

// Raise implements [Publisher].
func (h *HTTPAlertIntake) Raise(ev events.AlertRaiseEvent) error {
	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal event: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	url := strings.TrimRight(h.BaseURL, "/") + AlertIntakePath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body)) //nolint:gosec // internal S2S call; URL from trusted config, not user input
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The route takes the tenant from the signed header and refuses an event
	// for any other tenant, so a signed call cannot raise into someone else's.
	req.Header.Set(serviceauth.HeaderTenantID, ev.TenantID.String())
	if h.Sign != nil {
		h.Sign(req)
	}
	client := h.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	resp, err := client.Do(req) //nolint:gosec // internal S2S call; URL from trusted config, not user input
	if err != nil {
		return fmt.Errorf("post %s: %w", AlertIntakePath, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("compliance-engine answered %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

// natsLink is the part of *events.NATSClient the fallback publisher uses.
type natsLink interface {
	IsConnected() bool
}

// FallbackPublisher publishes onto alerts.raise over NATS and, when NATS is
// absent, disconnected or refuses the publish, POSTs the event to
// compliance-engine's alert intake instead — the same two rails, in the same
// order, as compliance-engine's own deliverNotification. An error comes back
// only when BOTH failed, and it says so; [Notifier.Flush] logs that as a lost
// notification. A failed NATS attempt that the HTTP rail covered is logged
// once and is not a loss.
//
// nc may be nil (no NATS at startup); intake may be nil (no HTTP fallback),
// in which case a NATS failure is a loss.
func FallbackPublisher(nc *events.NATSClient, intake Publisher) Publisher {
	var link natsLink
	var publish func(events.AlertRaiseEvent) error
	if nc != nil {
		link = nc
		publish = func(ev events.AlertRaiseEvent) error { return events.PublishJSON(nc, events.SubjectAlertsRaise, ev) }
	}
	return fallback{link: link, publish: publish, intake: intake}
}

type fallback struct {
	link    natsLink
	publish func(events.AlertRaiseEvent) error
	intake  Publisher
}

func (f fallback) Raise(ev events.AlertRaiseEvent) error {
	var natsErr error
	switch {
	case f.publish == nil:
		natsErr = errors.New("no NATS client")
	case f.link != nil && !f.link.IsConnected():
		natsErr = errors.New("NATS disconnected")
	default:
		if natsErr = f.publish(ev); natsErr == nil {
			return nil
		}
	}
	if f.intake == nil {
		return fmt.Errorf("NATS failed (%v) and there is no HTTP fallback", natsErr)
	}
	if f.publish != nil {
		log.Printf("[changenotify] alerts.raise over NATS failed, falling back to HTTP: %v", natsErr)
	}
	if err := f.intake.Raise(ev); err != nil {
		return fmt.Errorf("NATS and HTTP both failed: NATS: %v; HTTP: %w", natsErr, err)
	}
	return nil
}

// FallbackPublisherFromEnv is [FallbackPublisher] over nc (nil without NATS)
// and the HTTP intake as the process is configured
// ([NewHTTPAlertIntakeFromEnv]). It is what a service hands
// [Notifier.SetPublisher].
func FallbackPublisherFromEnv(nc *events.NATSClient) Publisher {
	var intake Publisher
	if h := NewHTTPAlertIntakeFromEnv(); h != nil {
		intake = h // not a typed nil: FallbackPublisher tests intake == nil
	}
	return FallbackPublisher(nc, intake)
}
