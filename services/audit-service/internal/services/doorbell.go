package services

import (
	"sync/atomic"

	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// StoredDoorbell is told that audit events were stored, so a consumer of the
// export feed (export_feed.go) can read forward now instead of at its next
// poll.
//
// It is a DOORBELL, not a delivery path: it carries no event, and losing a
// ring only delays a consumer until its next poll — the feed, read from the
// consumer's own durable cursor, is the source of truth. So Ring must be
// fire-and-forget: it must not block ingestion and must not report failure. An
// audit write that succeeded stays succeeded whatever happens to the ring.
type StoredDoorbell interface {
	Ring()
}

// RingStored is THE seam between audit ingestion and the export feed. Every
// ingestion path — the HTTP POST /activity-logs handler and the NATS
// audit.activity-logs subscriber (which is also how batched audit entries
// arrive) — calls it once per entry, after the entry is stored. An entry that
// failed to persist rings nothing: there is nothing new to read.
//
// A nil doorbell is a no-op; consumers then find new events at their next poll.
func RingStored(d StoredDoorbell, entry *models.ActivityLog) {
	if d == nil || entry == nil {
		return
	}
	d.Ring()
}

// natsPublisher is the one call NATSDoorbell makes, so a test can observe it.
type natsPublisher func(subject string, data []byte) error

// NATSDoorbell rings over core NATS on events.SubjectDoorbellAuditStored — a
// subject deliberately outside every JetStream stream, so a ring is never
// persisted, acknowledged or redelivered.
//
// It is built before NATS is known to be reachable (ingestion must not wait
// for it) and attached to a client once one connects; until then it rings
// nothing.
type NATSDoorbell struct {
	client  atomic.Pointer[events.NATSClient]
	publish natsPublisher // nil: publish over the attached client
}

// doorbellPayload is the whole message: a hint that something was stored.
var doorbellPayload = []byte(`{"stored":true}`)

// NewNATSDoorbell returns an unattached doorbell.
func NewNATSDoorbell() *NATSDoorbell { return &NATSDoorbell{} }

// Attach connects the doorbell to a NATS client. Safe to call while Ring runs.
func (d *NATSDoorbell) Attach(client *events.NATSClient) { d.client.Store(client) }

// Ring publishes the hint and ignores the outcome (see StoredDoorbell).
func (d *NATSDoorbell) Ring() {
	if d == nil {
		return
	}
	if d.publish != nil {
		_ = d.publish(events.SubjectDoorbellAuditStored, doorbellPayload)
		return
	}
	client := d.client.Load()
	if client == nil {
		return
	}
	// Conn() on every ring: the client replaces its connection when it
	// reconnects. Core NATS Publish only appends to the connection's outbound
	// buffer; it does not wait for the server.
	if conn := client.Conn(); conn != nil {
		_ = conn.Publish(events.SubjectDoorbellAuditStored, doorbellPayload)
	}
}
