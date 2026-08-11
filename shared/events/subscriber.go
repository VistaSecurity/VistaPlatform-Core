package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"runtime/debug"
	"time"

	"github.com/nats-io/nats.go"
)

// MessageHandler processes a single NATS message. Returning nil acknowledges
// the message; returning an error triggers a nack (redelivery).
type MessageHandler func(ctx context.Context, msg *nats.Msg) error

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

// Subscribe creates a durable JetStream subscription that processes messages
// with the given handler. Messages are acked on success and nacked on error.
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

		if panicked {
			// A panic is a code defect, not a transient fault. Terminate the
			// message (no redelivery) so it can't crash-loop through MaxDeliver
			// re-triggering the same bug; the logged stack is the signal to fix it.
			if termErr := msg.Term(); termErr != nil {
				log.Printf("[NATS] Failed to term panicked message on %s: %v", cfg.Subject, termErr)
			}
			return
		}

		if handlerErr != nil {
			log.Printf("[NATS] Error processing message on %s: %v", cfg.Subject, handlerErr)
			if nakErr := msg.Nak(); nakErr != nil {
				log.Printf("[NATS] Failed to nack message on %s: %v", cfg.Subject, nakErr)
			}
			return
		}

		if err := msg.Ack(); err != nil {
			log.Printf("[NATS] Failed to ack message on %s: %v", cfg.Subject, err)
		}
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
