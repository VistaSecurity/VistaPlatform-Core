package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"time"

	"github.com/nats-io/nats.go"
)

// MessageHandler processes a single NATS message. Returning nil acknowledges
// the message; returning an error triggers a nack (redelivery), unless the
// error is marked Permanent — see ErrPermanent.
type MessageHandler func(ctx context.Context, msg *nats.Msg) error

// ErrPermanent marks a handler failure that redelivery cannot fix.
//
// The default on error is a nack, which is right for a transient fault: the
// database was down, a peer timed out, try again. It is wrong for a message
// whose CONTENT is the problem, because the second and third attempt do exactly
// what the first did. When the work is expensive that is not merely wasted — it
// is an amplifier. One oversized PCAP upload cost pcap-processor three full
// processing passes and three OOM kills of a single-replica pod shared by every
// tenant (H11); the redelivery turned one tenant's bad file into a cross-tenant
// outage three times over.
//
// This is the same reasoning the panic path already uses (a panic is a code
// defect, so the message is Term'd rather than crash-looped). Permanent extends
// it to failures a handler can recognise for itself.
var ErrPermanent = errors.New("permanent failure")

// Permanent marks err so the subscriber terminates the message instead of
// nacking it. Returns nil for a nil err, so it can wrap a call directly.
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrPermanent, err)
}

// IsPermanent reports whether err was marked by Permanent.
func IsPermanent(err error) bool { return errors.Is(err, ErrPermanent) }

// SubscriptionConfig configures a JetStream pull or push subscription.
type SubscriptionConfig struct {
	// Stream is the JetStream stream name (e.g. "COMPLIANCE").
	Stream string
	// Subject is the NATS subject to subscribe to (e.g. "compliance.asset.changed").
	Subject string
	// Durable is the durable consumer name. Required for persistent subscriptions.
	Durable string
	// QueueGroup enables load-balanced delivery across instances sharing the group.
	QueueGroup string
	// MaxDeliver limits how many times a message is redelivered on nack (0 = unlimited).
	MaxDeliver int
	// AckWait is the time the server waits for an ack before redelivering.
	AckWait time.Duration
	// ProcessingTimeout is the context timeout for each message handler invocation.
	ProcessingTimeout time.Duration
}

// Subscriber manages JetStream subscriptions with proper ack/nack semantics.
type Subscriber struct {
	client *NATSClient
	subs   []*nats.Subscription
}

// NewSubscriber creates a subscriber backed by the given NATSClient.
func NewSubscriber(client *NATSClient) *Subscriber {
	return &Subscriber{
		client: client,
	}
}

// runHandlerSafely invokes handler with panic recovery. nats.go runs
// subscription callbacks in their own goroutine and does not recover, so an
// unrecovered panic crashes the whole process (a silent exit-2 with the stack
// lost in the truncated log tail). On panic it returns panicked=true and logs
// the stack; callers should treat the message as poison and terminate it rather
// than redeliver, since a panic is a code defect that would just recur.
func runHandlerSafely(ctx context.Context, msg *nats.Msg, subject string, handler MessageHandler) (handlerErr error, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			panicked = true
			log.Printf("[NATS] PANIC recovered while processing message on %s: %v\n%s",
				subject, r, debug.Stack())
		}
	}()
	handlerErr = handler(ctx, msg)
	return
}

// messageSettler is the slice of *nats.Msg the ack decision uses. It exists so
// the decision can be driven by a test: the thing worth pinning is which of
// Ack / Nak / Term a given outcome reaches, and a unit test of IsPermanent
// alone would stay green if this wiring were deleted.
type messageSettler interface {
	Ack(opts ...nats.AckOpt) error
	Nak(opts ...nats.AckOpt) error
	Term(opts ...nats.AckOpt) error
}

// settleMessage decides a message's fate after the handler has run.
//
//   - panicked → Term. A panic is a code defect; redelivering it would
//     crash-loop through MaxDeliver re-triggering the same bug.
//   - ErrPermanent → Term. The handler has said the content is the problem, so
//     the second and third attempt do exactly what the first did, at the same
//     cost. This is what stops one bad PCAP upload from OOM-killing the
//     single-replica pcap-processor three times (H11).
//   - any other error → Nak, the transient case: retry is the right answer.
//   - nil → Ack.
func settleMessage(msg messageSettler, subject string, handlerErr error, panicked bool) {
	switch {
	case panicked:
		if termErr := msg.Term(); termErr != nil {
			log.Printf("[NATS] Failed to term panicked message on %s: %v", subject, termErr)
		}
	case IsPermanent(handlerErr):
		log.Printf("[NATS] Permanent failure on %s, terminating message (no redelivery): %v", subject, handlerErr)
		if termErr := msg.Term(); termErr != nil {
			log.Printf("[NATS] Failed to term message on %s: %v", subject, termErr)
		}
	case handlerErr != nil:
		log.Printf("[NATS] Error processing message on %s: %v", subject, handlerErr)
		if nakErr := msg.Nak(); nakErr != nil {
			log.Printf("[NATS] Failed to nack message on %s: %v", subject, nakErr)
		}
	default:
		if err := msg.Ack(); err != nil {
			log.Printf("[NATS] Failed to ack message on %s: %v", subject, err)
		}
	}
}

// Subscribe creates a durable JetStream subscription that processes messages
// with the given handler. Messages are acked on success, nacked on a transient
// error, and terminated on a panic or a Permanent error.
func (s *Subscriber) Subscribe(cfg SubscriptionConfig, handler MessageHandler) error {
	js := s.client.JetStream()
	if js == nil {
		return fmt.Errorf("JetStream context not available")
	}

	if cfg.AckWait == 0 {
		cfg.AckWait = 30 * time.Second
	}
	if cfg.ProcessingTimeout == 0 {
		cfg.ProcessingTimeout = 25 * time.Second
	}
	if cfg.MaxDeliver == 0 {
		cfg.MaxDeliver = 5
	}

	opts := []nats.SubOpt{
		nats.Durable(cfg.Durable),
		nats.AckExplicit(),
		nats.ManualAck(),
		nats.MaxDeliver(cfg.MaxDeliver),
		nats.AckWait(cfg.AckWait),
	}

	if cfg.Stream != "" {
		opts = append(opts, nats.BindStream(cfg.Stream))
	}

	wrappedHandler := func(msg *nats.Msg) {
		ctx, cancel := context.WithTimeout(context.Background(), cfg.ProcessingTimeout)
		defer cancel()

		// Run the handler with panic recovery. nats.go invokes this callback in
		// its own goroutine and does NOT recover for us, so an unrecovered panic
		// in any handler crashes the entire process — one malformed message or a
		// nil-deref in one consumer takes down every subscription in the service.
		handlerErr, panicked := runHandlerSafely(ctx, msg, cfg.Subject, handler)
		settleMessage(msg, cfg.Subject, handlerErr, panicked)
	}

	var sub *nats.Subscription
	var err error

	if cfg.QueueGroup != "" {
		sub, err = js.QueueSubscribe(cfg.Subject, cfg.QueueGroup, wrappedHandler, opts...)
	} else {
		sub, err = js.Subscribe(cfg.Subject, wrappedHandler, opts...)
	}

	if err != nil {
		return fmt.Errorf("failed to subscribe to %s: %w", cfg.Subject, err)
	}

	s.subs = append(s.subs, sub)
	log.Printf("[NATS] Subscribed to %s (durable=%s, stream=%s)", cfg.Subject, cfg.Durable, cfg.Stream)
	return nil
}

// Drain drains all subscriptions, finishing in-flight messages before returning.
func (s *Subscriber) Drain() error {
	for _, sub := range s.subs {
		if err := sub.Drain(); err != nil {
			log.Printf("[NATS] Failed to drain subscription: %v", err)
		}
	}
	return nil
}

// Unsubscribe removes all subscriptions immediately.
func (s *Subscriber) Unsubscribe() error {
	for _, sub := range s.subs {
		if err := sub.Unsubscribe(); err != nil {
			log.Printf("[NATS] Failed to unsubscribe: %v", err)
		}
	}
	s.subs = nil
	return nil
}

// UnmarshalMsg is a convenience helper that unmarshals a NATS message into a struct.
func UnmarshalMsg(msg *nats.Msg, v interface{}) error {
	if err := json.Unmarshal(msg.Data, v); err != nil {
		return fmt.Errorf("failed to unmarshal message: %w", err)
	}
	return nil
}
