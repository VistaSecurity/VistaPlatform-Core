package services

// This service's half of the tenant auto-accept threshold (workstream 4.6a,
// ADR-0002 D3).
//
// # What changed, and why it had to
//
// Workstream 4.6 gave a tenant one number — the matcher score at or above which
// the platform may merge two of their assets without asking — and wired it into
// inventory-service's identification engine. This service runs TWO more
// ([DeviceService.identityEngine] and [ObservationSink.engine]), and they were
// hard-wired to zero. A tenant who set 95% therefore got auto-accepted merges on
// the discovery path and never on the interrogation one, whatever the settings
// page said. That was disclosed rather than honoured: the customer doc and the
// settings card both carried a sentence naming the gap.
//
// It fails closed, which is why it was allowed to ship — but "a setting whose
// stated scope is wider than its real one" is a setting that lies, and the
// asymmetry is worse than it looks in one specific way: the SAME host reaches
// both services (a sensor sees it, an interrogation re-sees it), so which engine
// happened to resolve a given sighting decided whether the tenant's threshold
// applied to it. That is not a scope limit a customer can reason about.
//
// Everything the fences do is [identity.Engine]'s, unchanged — the four
// conditions of ADR-0002 D3 live in shared/identity and this service now hands
// the engine the same threshold inventory-service does, per observation, read on
// the engine's own transaction. The reader is
// shared/identity/identitysettings; the audit event is
// shared/identity/identityaudit. Neither is copied here, deliberately: two
// spellings of "may we merge this?" is the divergence the whole exercise is
// about.

import (
	"log"
	"sync"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/identity/identityaudit"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// autoAcceptAudit is the logger every auto-accepted merge in this service is
// recorded through.
//
// # Why a package-level default rather than a constructor argument
//
// The two engines are built at FOUR construction sites across two entrypoints —
// `cmd/main.go` builds a DeviceService for the platform-agent worker,
// `internal/api/router.go` builds another for the HTTP surface, and
// DeviceInterrogationService, ResultProcessor and HostInventoryIngest each build
// an ObservationSink. Threading a logger through all of them is five chances to
// forget one, and a forgotten one is silent: the merge still happens and nothing
// records it.'s lesson applies directly — a fix that depends on wiring is
// not done until the wiring cannot be skipped.
//
// So the default is built from the same environment the router's audit
// middleware is built from, once, on first use. [SetAutoAcceptAuditLogger] is
// for tests, which need to read the event rather than POST it.
var (
	autoAcceptAuditMu    sync.Mutex
	autoAcceptAuditVal   identityaudit.Logger
	autoAcceptAuditReady bool
)

// SetAutoAcceptAuditLogger overrides the logger auto-accepted merges are
// recorded through. A nil logger disables the audit write without disabling the
// merge, which is the state a deployment with `AUDIT_LOGGING_ENABLED=false` is
// in.
func SetAutoAcceptAuditLogger(l identityaudit.Logger) {
	autoAcceptAuditMu.Lock()
	defer autoAcceptAuditMu.Unlock()
	autoAcceptAuditVal, autoAcceptAuditReady = l, true
}

// autoAcceptAuditLogger returns the logger, building the default on first use.
func autoAcceptAuditLogger() identityaudit.Logger {
	autoAcceptAuditMu.Lock()
	defer autoAcceptAuditMu.Unlock()
	if autoAcceptAuditReady {
		return autoAcceptAuditVal
	}
	// Ready either way after this: a config that will not load is a permanent
	// state, and retrying it on every observation would log the same failure
	// once per merge.
	autoAcceptAuditReady = true
	cfg, err := config.Load()
	if err != nil {
		// A merge that committed and an audit event that could not be
		// configured is bad; refusing to resolve observations because the audit
		// client would not build would be worse. Said once, loudly.
		log.Printf("[device-interrogation] audit logging for auto-accepted merges is unavailable: %v", err)
		return nil
	}
	autoAcceptAuditVal = auditmiddleware.NewMiddleware(auditmiddleware.ServiceConfig(
		"device-interrogation-service",
		cfg.UseMTLS, cfg.ClientCertPath, cfg.ClientKeyPath, cfg.PlatformCACertPath,
	))
	return autoAcceptAuditVal
}
