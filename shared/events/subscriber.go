package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"runtime/debug"
	"sync"
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
//
// Every durable consumer it subscribes to is OWNED by the platform, not by
// whichever pod happened to create it: Subscribe creates the consumer from
// the code's configuration if it is missing and then binds to it
// (nats.Bind), so no pod's Drain or Unsubscribe can delete it. With the
// library-created consumer nats.go used before, a rolling update — new pod
// binds, old pod drains — deleted the consumer out from under the new pod,
// which then sat subscribed to nothing, silently, for as long as it lived.
type Subscriber struct {
	client *NATSClient
	mu     sync.Mutex
	subs   []*subscription
	closed bool
}

// subscription remembers what a subscription was made from, so Reconcile can
// make it again.
type subscription struct {
	cfg     SubscriptionConfig
	handler MessageHandler
	sub     *nats.Subscription
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
	cfg = withSubscriptionDefaults(cfg)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("subscriber is closed")
	}
	sub, err := s.subscribe(cfg, handler)
	if err != nil {
		return err
	}
	s.subs = append(s.subs, &subscription{cfg: cfg, handler: handler, sub: sub})
	return nil
}

func withSubscriptionDefaults(cfg SubscriptionConfig) SubscriptionConfig {
	if cfg.AckWait == 0 {
		cfg.AckWait = 30 * time.Second
	}
	if cfg.ProcessingTimeout == 0 {
		cfg.ProcessingTimeout = 25 * time.Second
	}
	if cfg.MaxDeliver == 0 {
		cfg.MaxDeliver = 5
	}
	return cfg
}

// subscribe makes one subscription. Caller holds s.mu.
func (s *Subscriber) subscribe(cfg SubscriptionConfig, handler MessageHandler) (*nats.Subscription, error) {
	js := s.client.JetStream()
	if js == nil {
		return nil, fmt.Errorf("JetStream context not available")
	}

	var opts []nats.SubOpt
	if cfg.Durable != "" {
		if cfg.Stream == "" {
			stream, err := js.StreamNameBySubject(cfg.Subject)
			if err != nil {
				return nil, fmt.Errorf("failed to find the stream for %s: %w", cfg.Subject, err)
			}
			cfg.Stream = stream
		}
		if err := ensureConsumer(js, cfg); err != nil {
			return nil, fmt.Errorf("failed to ensure consumer %s on %s: %w", cfg.Durable, cfg.Stream, err)
		}
		// Bind: the consumer exists and is ours; the library must never
		// delete it. The consumer's own settings (ack wait, max deliver,
		// filter, deliver group) are read from the server — passing them
		// here too would make a legacy consumer with other values a refusal.
		opts = []nats.SubOpt{nats.Bind(cfg.Stream, cfg.Durable), nats.ManualAck()}
	} else {
		// An ephemeral consumer: created and deleted with the subscription.
		opts = []nats.SubOpt{
			nats.AckExplicit(),
			nats.ManualAck(),
			nats.MaxDeliver(cfg.MaxDeliver),
			nats.AckWait(cfg.AckWait),
		}
		if cfg.Stream != "" {
			opts = append(opts, nats.BindStream(cfg.Stream))
		}
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
		return nil, fmt.Errorf("failed to subscribe to %s: %w", cfg.Subject, err)
	}

	log.Printf("[NATS] Subscribed to %s (durable=%s, stream=%s)", cfg.Subject, cfg.Durable, cfg.Stream)
	return sub, nil
}

// deliverSubject is the push deliver subject of a platform-owned durable.
// Fixed, not an inbox of whichever connection created the consumer, so the
// consumer's identity does not depend on any pod.
func deliverSubject(stream, durable string) string {
	return "_VISTA_DELIVER." + stream + "." + durable
}

// consumerConfig is the consumer a SubscriptionConfig describes.
func consumerConfig(cfg SubscriptionConfig) *nats.ConsumerConfig {
	return &nats.ConsumerConfig{
		Durable:        cfg.Durable,
		Description:    "platform-owned durable (shared/events); subscribers bind, never delete",
		FilterSubject:  cfg.Subject,
		DeliverSubject: deliverSubject(cfg.Stream, cfg.Durable),
		DeliverGroup:   cfg.QueueGroup,
		DeliverPolicy:  nats.DeliverAllPolicy,
		AckPolicy:      nats.AckExplicitPolicy,
		AckWait:        cfg.AckWait,
		MaxDeliver:     cfg.MaxDeliver,
	}
}

// ensureConsumer makes sure the durable exists. A consumer already there is
// kept as it is (its ack wait and max deliver are brought up to the code's
// values where the server allows it); a missing one is created from the
// code's configuration. Two replicas creating it at once is fine: the
// configuration is the same, and a loser binds to the winner's.
func ensureConsumer(js nats.JetStreamContext, cfg SubscriptionConfig) error {
	info, err := js.ConsumerInfo(cfg.Stream, cfg.Durable)
	if err == nil {
		reconcileConsumerSettings(js, cfg, info)
		return nil
	}
	if !errors.Is(err, nats.ErrConsumerNotFound) {
		return err
	}
	if _, err := js.AddConsumer(cfg.Stream, consumerConfig(cfg)); err != nil {
		if errors.Is(err, nats.ErrConsumerNameAlreadyInUse) {
			// A sibling replica created it between our lookup and our create,
			// possibly an older release's pod with the library's configuration.
			// Either way it exists; bind to it.
			log.Printf("[NATS] Consumer %s on %s was created by another replica; binding to it", cfg.Durable, cfg.Stream)
			return nil
		}
		return err
	}
	log.Printf("[NATS] Created durable consumer %s on %s (deliver=%s, group=%s)", cfg.Durable, cfg.Stream, deliverSubject(cfg.Stream, cfg.Durable), cfg.QueueGroup)
	return nil
}

// reconcileConsumerSettings carries a changed AckWait or MaxDeliver in the
// code to a consumer that already exists, which is what a release that
// changes either means to happen. Before, the live consumer's values won
// forever and nothing said so. Other differences are only reported: a
// consumer's filter and group are its identity, and changing them under a
// running subscriber is not something to do on the quiet.
func reconcileConsumerSettings(js nats.JetStreamContext, cfg SubscriptionConfig, info *nats.ConsumerInfo) {
	live := info.Config
	if live.FilterSubject != cfg.Subject || live.DeliverGroup != cfg.QueueGroup {
		log.Printf("[NATS] WARNING: consumer %s on %s differs from the code (filter=%q group=%q, code wants filter=%q group=%q); the live consumer wins — delete it to adopt the code's values",
			cfg.Durable, cfg.Stream, live.FilterSubject, live.DeliverGroup, cfg.Subject, cfg.QueueGroup)
	}
	if live.AckWait == cfg.AckWait && live.MaxDeliver == cfg.MaxDeliver {
		return
	}
	updated := live
	updated.AckWait = cfg.AckWait
	updated.MaxDeliver = cfg.MaxDeliver
	if _, err := js.UpdateConsumer(cfg.Stream, &updated); err != nil {
		log.Printf("[NATS] WARNING: consumer %s on %s keeps ack_wait=%s max_deliver=%d (code wants %s/%d); update failed: %v",
			cfg.Durable, cfg.Stream, live.AckWait, live.MaxDeliver, cfg.AckWait, cfg.MaxDeliver, err)
		return
	}
	log.Printf("[NATS] Consumer %s on %s updated: ack_wait %s→%s, max_deliver %d→%d",
		cfg.Durable, cfg.Stream, live.AckWait, cfg.AckWait, live.MaxDeliver, cfg.MaxDeliver)
}

// Reconcile re-creates any durable consumer that has gone missing and
// re-subscribes to it, reporting how many it repaired. A push subscription
// whose consumer is deleted gets no error and no messages, ever, and nothing
// else notices — run this from a periodic sweep. A stream that is missing is
// reported, not invented.
func (s *Subscriber) Reconcile() (repaired int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, nil
	}
	js := s.client.JetStream()
	if js == nil {
		return 0, fmt.Errorf("JetStream context not available")
	}
	var errs []error
	for _, e := range s.subs {
		if e.cfg.Durable == "" || e.cfg.Stream == "" {
			continue
		}
		_, infoErr := js.ConsumerInfo(e.cfg.Stream, e.cfg.Durable)
		if infoErr == nil {
			continue
		}
		if !errors.Is(infoErr, nats.ErrConsumerNotFound) {
			errs = append(errs, fmt.Errorf("consumer %s on %s: %w", e.cfg.Durable, e.cfg.Stream, infoErr))
			continue
		}
		log.Printf("[NATS] Consumer %s on %s is MISSING; this subscription has been delivering nothing. Re-creating it", e.cfg.Durable, e.cfg.Stream)
		if e.sub != nil {
			_ = e.sub.Unsubscribe() // bound, so this deletes nothing
		}
		sub, subErr := s.subscribe(e.cfg, e.handler)
		if subErr != nil {
			errs = append(errs, subErr)
			continue
		}
		e.sub = sub
		repaired++
	}
	return repaired, errors.Join(errs...)
}

// Drain drains all subscriptions, finishing in-flight messages before returning.
// The durable consumers stay: they are bound, not owned by this process.
func (s *Subscriber) Drain() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, e := range s.subs {
		if e.sub == nil {
			continue
		}
		if err := e.sub.Drain(); err != nil {
			log.Printf("[NATS] Failed to drain subscription: %v", err)
		}
	}
	return nil
}

// Unsubscribe removes all subscriptions immediately. The durable consumers stay.
func (s *Subscriber) Unsubscribe() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, e := range s.subs {
		if e.sub == nil {
			continue
		}
		if err := e.sub.Unsubscribe(); err != nil {
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
