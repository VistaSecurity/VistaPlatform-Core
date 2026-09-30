package handlers

import "github.com/vistasecurity/vistaplatform/audit-service/internal/services"

// This file is where audit-service's HTTP layer meets the outbound plumbing
// that ships the audit trail elsewhere.
//
// The open-core split for audit-service is *substrate vs distribution*:
//
//	Core       — audit logging, audit-event ingestion (HTTP + NATS), every
//	             query/read/export endpoint, retention, alerting, analytics,
//	             on-demand compliance report generation, and the export feed
//	             (the audit log read forward from a cursor, for internal
//	             service callers).
//	Enterprise — shipping that audit stream elsewhere: SIEM export (a separate
//	             Enterprise service that reads the export feed) and scheduled
//	             compliance reports (ee/scheduledreports).
//
// Audit logging and audit-event emission are never paywalled — they are the
// substrate the rest of the product stands on. Ingestion writes every event and
// rings a doorbell; it knows nothing about who, if anyone, is reading the feed.

// StoredDoorbell is rung after an audit entry is stored (see
// services/doorbell.go for the contract). Nil when NATS is unavailable, in
// which case feed consumers simply find new events at their next poll.
type StoredDoorbell = services.StoredDoorbell
