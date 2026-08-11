package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// QueueConsumer is the real per-consumer backlog telemetry JetStream exposes for
// a durable consumer bound to a stream. depth (num_pending) is the count of
// stream messages this consumer has not yet been delivered; in_flight
// (num_ack_pending) are delivered-but-unacked; num_waiting is outstanding pull
// requests parked by workers. There is NO rate or p95 latency here — JetStream
// does not expose those, so they are deliberately omitted rather than fabricated.
type QueueConsumer struct {
	Name           string     `json:"name"`
	Depth          uint64     `json:"depth"`           // num_pending — undelivered backlog
	InFlight       int        `json:"in_flight"`       // num_ack_pending — delivered, awaiting ack
	NumWaiting     int        `json:"num_waiting"`     // parked pull requests (idle workers)
	NumRedelivered int        `json:"num_redelivered"` // currently being redelivered
	LastDelivered  *time.Time `json:"last_delivered,omitempty"`
}

// AdminQueue is one JetStream stream, with its real state and the per-consumer
// backlog breakdown. Stream-level Messages is the total retained in the stream
// (subject to MaxAge), not a live "depth" — the meaningful queue depth is each
// consumer's Depth (num_pending).
type AdminQueue struct {
	Name          string          `json:"name"`
	Subjects      []string        `json:"subjects"`
	Messages      uint64          `json:"messages"`       // stream State.Msgs — total retained
	Bytes         uint64          `json:"bytes"`          // stream State.Bytes
	ConsumerCount int             `json:"consumer_count"` // stream State.Consumers
	LastMessageAt *time.Time      `json:"last_message_at,omitempty"`
	Consumers     []QueueConsumer `json:"consumers"`
}

// AdminQueuesHandler serves GET /admin/queues from live JetStream stream/consumer
// info. It holds the NATS client (may be nil when NATS is unconfigured/unavailable,
// e.g. dev compose without NATS) and returns 503 in that case rather than
// inventing metrics.
type AdminQueuesHandler struct {
	nats *events.NATSClient
}

// NewAdminQueuesHandler wires the (possibly nil) NATS client. nil is tolerated and
// surfaced as 503 at request time so the service still boots without NATS.
func NewAdminQueuesHandler(natsClient *events.NATSClient) *AdminQueuesHandler {
	return &AdminQueuesHandler{nats: natsClient}
}

// ListQueues returns per-queue (JetStream stream) real backlog telemetry across
// the whole platform. Read-only, cross-tenant; gated by RequirePlatformAdmin in
// the router. Only metrics JetStream actually provides are returned (depth,
// in-flight, retained message/byte counts) — no synthetic rate or p95.
func (h *AdminQueuesHandler) ListQueues(c *gin.Context) {
	if h.nats == nil || !h.nats.IsConnected() {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "NATS/JetStream unavailable; queue metrics cannot be read",
		})
		return
	}

	js := h.nats.JetStream()
	if js == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "JetStream context not available",
		})
		return
	}

	queues := make([]AdminQueue, 0, len(events.DefaultStreams))
	for _, sc := range events.DefaultStreams {
		info, err := js.StreamInfo(sc.Name)
		if err != nil {
			// Stream may not exist yet (no producer has run); skip it rather than
			// failing the whole roll-up.
			if err == nats.ErrStreamNotFound {
				continue
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read JetStream stream info"})
			return
		}

		q := AdminQueue{
			Name:          info.Config.Name,
			Subjects:      info.Config.Subjects,
			Messages:      info.State.Msgs,
			Bytes:         info.State.Bytes,
			ConsumerCount: info.State.Consumers,
			Consumers:     make([]QueueConsumer, 0, info.State.Consumers),
		}
		if !info.State.LastTime.IsZero() {
			lt := info.State.LastTime
			q.LastMessageAt = &lt
		}

		for ci := range js.Consumers(sc.Name) {
			cons := QueueConsumer{
				Name:           ci.Name,
				Depth:          ci.NumPending,
				InFlight:       ci.NumAckPending,
				NumWaiting:     ci.NumWaiting,
				NumRedelivered: ci.NumRedelivered,
			}
			if ci.Delivered.Last != nil && !ci.Delivered.Last.IsZero() {
				cons.LastDelivered = ci.Delivered.Last
			}
			q.Consumers = append(q.Consumers, cons)
		}

		queues = append(queues, q)
	}

	c.JSON(http.StatusOK, gin.H{
		"queues": queues,
		"count":  len(queues),
		// Be explicit that rate/p95 are intentionally absent — JetStream does not
		// expose them. Clients should not synthesize them from these fields.
		"metrics_note": "depth/in_flight/messages/bytes are live JetStream values; per-queue rate and p95 latency are not provided because JetStream does not expose them",
	})
}
