package handlers

import "context"

// This file is the Core/Enterprise seam for audit-service's HTTP layer.
//
// The open-core split for audit-service is *substrate vs distribution*:
//
//	Core       — audit logging, audit-event ingestion (HTTP + NATS), every
//	             query/read/export endpoint, retention, alerting, analytics,
//	             and on-demand compliance report generation.
//	Enterprise — shipping that audit stream elsewhere on a schedule: SIEM
//	             export and scheduled compliance reports.
//
// Audit logging and audit-event emission are never paywalled — they are the
// substrate the rest of the product stands on. Core writes every event exactly
// as before; the Enterprise build additionally tees each one to the configured
// SIEM destinations through the interface below.
//
// Keep this interface minimal: it is the contract the Enterprise build must
// satisfy, and every method added here is a method the open tree can see.
// Implementations live under services/audit-service/ee/ and are absent from
// the open-source tree. See
// docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5.

// SIEMForwarder receives audit events for outbound delivery to a customer's
// SIEM. Implemented by the Enterprise build (ee/siemexport.SIEMService); nil in
// Core, where the ingestion path simply skips the tee.
//
// SendEvent is fire-and-forget by contract: it must not block ingestion and
// must not report failure back to the caller. An audit write that succeeded
// stays succeeded even if every SIEM destination is unreachable.
type SIEMForwarder interface {
	SendEvent(ctx context.Context, event map[string]interface{})
}
