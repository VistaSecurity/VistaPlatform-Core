package services

// The stuck-job sweep puts the job consumer back before republishing into
// it. A push subscription whose consumer is gone is silent — no error, no
// messages — and the sweep republished into that for a day. Needs both a
// database (the sweep reads queued jobs) and a JetStream NATS: skips without
// TEST_DATABASE_URL and TEST_NATS_URL.

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/nats-io/nats.go"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

func TestIntegration_StuckJobSweepRecreatesTheJobConsumer(t *testing.T) {
	f := newDispatchFixture(t)
	url := os.Getenv("TEST_NATS_URL")
	if url == "" {
		t.Skip("TEST_NATS_URL not set; the sweep's consumer repair needs a JetStream NATS server")
	}
	client, err := events.NewNATSClientOnce(url)
	if err != nil {
		t.Fatalf("NATS: %v", err)
	}
	defer client.Close()
	js := client.JetStream()
	cfg := discoveryJobSubscription
	t.Cleanup(func() { _ = js.DeleteConsumer(cfg.Stream, cfg.Durable) })

	f.jp.natsClient = client
	f.jp.subscriber = events.NewSubscriber(client)
	f.jp.ctx, f.jp.cancel = context.WithCancelCause(context.Background())
	if err := f.jp.subscriber.Subscribe(cfg, f.jp.handleDiscoveryJobJS); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if err := js.DeleteConsumer(cfg.Stream, cfg.Durable); err != nil {
		t.Fatalf("delete consumer: %v", err)
	}
	if _, err := js.ConsumerInfo(cfg.Stream, cfg.Durable); !errors.Is(err, nats.ErrConsumerNotFound) {
		t.Fatalf("premise: consumer should be gone, got %v", err)
	}

	if !f.jp.stuckJobPass(func(string) error { return nil }) {
		t.Fatal("sweep pass failed")
	}
	if _, err := js.ConsumerInfo(cfg.Stream, cfg.Durable); err != nil {
		t.Fatalf("the sweep did not put the consumer back: %v", err)
	}
}
