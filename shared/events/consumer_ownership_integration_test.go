package events

// A durable consumer must outlive the pod that happened to create it.
//
// nats.go deletes a JetStream consumer on Drain/Unsubscribe when the library
// created it (it did whenever a Subscribe found no consumer by that durable
// name). Under a rolling update the new pod starts first and binds to the
// consumer the old pod created; the old pod then drains — and takes the
// consumer with it. The new pod stays subscribed to a deliver subject nothing
// delivers to, logs nothing, and the stuck-job sweep republishes into the void
// for as long as the pod lives (cluster-sensor-service lost a day of scan
// jobs this way).
//
// Needs a JetStream NATS server: skipped unless TEST_NATS_URL is set, e.g.
//
//	docker run -d --rm -p 14222:4222 nats:2.14-alpine -js
//	TEST_NATS_URL=nats://127.0.0.1:14222 go test ./events/ -run Integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nuid"
)

func natsURL(t *testing.T) string {
	t.Helper()
	u := os.Getenv("TEST_NATS_URL")
	if u == "" {
		t.Skip("TEST_NATS_URL not set; a durable-consumer test needs a JetStream NATS server")
	}
	return u
}

// testStream creates a stream of its own for one test, so parallel packages
// sharing the server never see each other's consumers.
func testStream(t *testing.T, url string) (stream, subject string) {
	t.Helper()
	stream = "CSD_" + nuid.Next()
	subject = "csd." + stream + ".jobs"
	nc, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	js, err := nc.JetStream()
	if err != nil {
		t.Fatalf("jetstream: %v", err)
	}
	if _, err := js.AddStream(&nats.StreamConfig{Name: stream, Subjects: []string{subject}, Storage: nats.MemoryStorage}); err != nil {
		t.Fatalf("add stream: %v", err)
	}
	t.Cleanup(func() {
		_ = js.DeleteStream(stream)
		nc.Close()
	})
	return stream, subject
}

func newTestClient(t *testing.T, url string) *NATSClient {
	t.Helper()
	c, err := NewNATSClientOnce(url)
	if err != nil {
		t.Fatalf("NATS client: %v", err)
	}
	return c
}

// waitFor polls cond until it holds or the deadline passes.
func waitFor(t *testing.T, d time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return cond()
}

func publishTo(t *testing.T, c *NATSClient, subject, body string) {
	t.Helper()
	if _, err := c.JetStream().Publish(subject, []byte(body)); err != nil {
		t.Fatalf("publish %q: %v", body, err)
	}
}

func expectDelivery(t *testing.T, got <-chan string, want string) {
	t.Helper()
	select {
	case g := <-got:
		if g != want {
			t.Fatalf("delivered %q, want %q", g, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%q was never delivered: the subscription is bound to nothing", want)
	}
}

// The rolling-update shape: old pod subscribes (and would create the
// consumer), new pod subscribes alongside it, old pod drains and exits. The
// consumer must still exist and the new pod must still receive.
func TestIntegration_DurableConsumerSurvivesCreatorDrain(t *testing.T) {
	url := natsURL(t)
	stream, subject := testStream(t, url)
	cfg := SubscriptionConfig{Stream: stream, Subject: subject, Durable: "owner-test", QueueGroup: "owner-test", AckWait: 2 * time.Second}
	got := make(chan string, 16)
	handler := func(_ context.Context, m *nats.Msg) error { got <- string(m.Data); return nil }

	oldPod := newTestClient(t, url)
	oldSub := NewSubscriber(oldPod)
	if err := oldSub.Subscribe(cfg, handler); err != nil {
		t.Fatalf("old pod subscribe: %v", err)
	}
	publishTo(t, oldPod, subject, "before")
	expectDelivery(t, got, "before")

	newPod := newTestClient(t, url)
	defer newPod.Close()
	newSub := NewSubscriber(newPod)
	if err := newSub.Subscribe(cfg, handler); err != nil {
		t.Fatalf("new pod subscribe: %v", err)
	}

	// The old pod stops. Drain's consumer deletion runs on a goroutine, so
	// give it every chance to land before the connection closes — in
	// production that is the slow-shutdown case that lost the consumer.
	if err := oldSub.Drain(); err != nil {
		t.Fatalf("drain: %v", err)
	}
	time.Sleep(1500 * time.Millisecond)
	oldPod.Close()

	if _, err := newPod.JetStream().ConsumerInfo(stream, cfg.Durable); err != nil {
		t.Fatalf("the old pod's drain took the consumer with it: %v", err)
	}
	publishTo(t, newPod, subject, "after")
	expectDelivery(t, got, "after")
}

// The consumer's configuration comes from the code, so the same durable
// created by two replicas at once is one consumer, and a subscriber that finds
// it already there binds to it rather than failing.
func TestIntegration_DurableConsumerCreatedOnceBoundByAll(t *testing.T) {
	url := natsURL(t)
	stream, subject := testStream(t, url)
	cfg := SubscriptionConfig{Stream: stream, Subject: subject, Durable: "shared-test", QueueGroup: "shared-test", AckWait: 2 * time.Second, MaxDeliver: 3}
	got := make(chan string, 16)
	handler := func(_ context.Context, m *nats.Msg) error { got <- string(m.Data); return nil }

	var pods []*NATSClient
	for i := 0; i < 3; i++ {
		c := newTestClient(t, url)
		defer c.Close()
		pods = append(pods, c)
		if err := NewSubscriber(c).Subscribe(cfg, handler); err != nil {
			t.Fatalf("pod %d subscribe: %v", i, err)
		}
	}
	info, err := pods[0].JetStream().ConsumerInfo(stream, cfg.Durable)
	if err != nil {
		t.Fatalf("consumer info: %v", err)
	}
	if info.Config.AckWait != cfg.AckWait || info.Config.MaxDeliver != cfg.MaxDeliver || info.Config.DeliverGroup != cfg.QueueGroup || info.Config.FilterSubject != subject {
		t.Fatalf("consumer was not created from the code's configuration: %+v", info.Config)
	}
	publishTo(t, pods[1], subject, "one")
	expectDelivery(t, got, "one")
	// A queue group: one delivery, not three.
	select {
	case extra := <-got:
		t.Fatalf("delivered twice (%q): the three pods are not sharing one queue group", extra)
	case <-time.After(300 * time.Millisecond):
	}
}

// Reconcile notices a consumer that has gone (an operator deleted it, or an
// older release's pod drained it away) and re-creates it, so the subscription
// delivers again instead of silently never.
func TestIntegration_ReconcileRecreatesAMissingConsumer(t *testing.T) {
	url := natsURL(t)
	stream, subject := testStream(t, url)
	cfg := SubscriptionConfig{Stream: stream, Subject: subject, Durable: "heal-test", QueueGroup: "heal-test", AckWait: 2 * time.Second}
	got := make(chan string, 16)
	handler := func(_ context.Context, m *nats.Msg) error { got <- string(m.Data); return nil }

	pod := newTestClient(t, url)
	defer pod.Close()
	sub := NewSubscriber(pod)
	if err := sub.Subscribe(cfg, handler); err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if n, err := sub.Reconcile(); err != nil || n != 0 {
		t.Fatalf("a healthy subscription needs no repair, got repaired=%d err=%v", n, err)
	}

	if err := pod.JetStream().DeleteConsumer(stream, cfg.Durable); err != nil {
		t.Fatalf("delete consumer: %v", err)
	}
	publishTo(t, pod, subject, "republished")
	select {
	case g := <-got:
		t.Fatalf("delivered %q with no consumer; the test premise is wrong", g)
	case <-time.After(300 * time.Millisecond):
	}

	n, err := sub.Reconcile()
	if err != nil || n != 1 {
		t.Fatalf("Reconcile: repaired=%d err=%v, want 1 and nil", n, err)
	}
	if !waitFor(t, 2*time.Second, func() bool {
		_, e := pod.JetStream().ConsumerInfo(stream, cfg.Durable)
		return e == nil
	}) {
		t.Fatal("the consumer was not re-created")
	}
	// The message that was published into the void is in the stream, and the
	// re-created consumer starts from the beginning of it.
	expectDelivery(t, got, "republished")

	// A missing stream is reported, not repaired by inventing one.
	if err := pod.JetStream().DeleteStream(stream); err != nil {
		t.Fatalf("delete stream: %v", err)
	}
	if _, err := sub.Reconcile(); err == nil || !errors.Is(err, nats.ErrStreamNotFound) {
		t.Fatalf("Reconcile with the stream gone: err=%v, want ErrStreamNotFound", err)
	}
	_ = fmt.Sprintf // keep fmt for the helpers above
}

// The upgrade that ships this: the consumer on the cluster was created by an
// older release's pod the library way, with the library's inbox as deliver
// subject. The new pod must bind to that consumer as it is and receive on it;
// and when the old pod drains it away (old code still deletes), Reconcile
// brings it back as a platform-owned one.
func TestIntegration_UpgradeFromLibraryOwnedConsumer(t *testing.T) {
	url := natsURL(t)
	stream, subject := testStream(t, url)
	cfg := SubscriptionConfig{Stream: stream, Subject: subject, Durable: "legacy-test", QueueGroup: "legacy-test", AckWait: 2 * time.Second, MaxDeliver: 5}
	got := make(chan string, 16)
	handler := func(_ context.Context, m *nats.Msg) error { got <- string(m.Data); return nil }

	// The old release's pod: nats.Durable, no Bind — the library creates and owns.
	oldNC, err := nats.Connect(url)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	oldJS, _ := oldNC.JetStream()
	oldSub, err := oldJS.QueueSubscribe(subject, cfg.QueueGroup, func(m *nats.Msg) { got <- string(m.Data); _ = m.Ack() },
		nats.Durable(cfg.Durable), nats.AckExplicit(), nats.ManualAck(), nats.MaxDeliver(cfg.MaxDeliver), nats.AckWait(cfg.AckWait), nats.BindStream(stream))
	if err != nil {
		t.Fatalf("legacy subscribe: %v", err)
	}
	info, err := oldJS.ConsumerInfo(stream, cfg.Durable)
	if err != nil || !strings.HasPrefix(info.Config.DeliverSubject, "_INBOX.") {
		t.Fatalf("premise: a library-created consumer delivers to an inbox, got %+v err=%v", info.Config.DeliverSubject, err)
	}

	newPod := newTestClient(t, url)
	defer newPod.Close()
	sub := NewSubscriber(newPod)
	if err := sub.Subscribe(cfg, handler); err != nil {
		t.Fatalf("new pod must bind to the legacy consumer as it is: %v", err)
	}
	if info, err = oldJS.ConsumerInfo(stream, cfg.Durable); err != nil || !strings.HasPrefix(info.Config.DeliverSubject, "_INBOX.") {
		t.Fatalf("binding must not replace the legacy consumer: %+v err=%v", info.Config.DeliverSubject, err)
	}

	// Old pod drains; old code deletes the consumer it created.
	_ = oldSub.Drain()
	if !waitFor(t, 3*time.Second, func() bool {
		_, e := oldJS.ConsumerInfo(stream, cfg.Durable)
		return errors.Is(e, nats.ErrConsumerNotFound)
	}) {
		t.Fatal("premise: the legacy drain should have deleted the consumer")
	}
	oldNC.Close()

	publishTo(t, newPod, subject, "during-upgrade")
	n, err := sub.Reconcile()
	if err != nil || n != 1 {
		t.Fatalf("Reconcile: repaired=%d err=%v, want 1", n, err)
	}
	expectDelivery(t, got, "during-upgrade")
	info, err = newPod.JetStream().ConsumerInfo(stream, cfg.Durable)
	if err != nil || info.Config.DeliverSubject != deliverSubject(stream, cfg.Durable) {
		t.Fatalf("the re-created consumer should be platform-owned: %+v err=%v", info.Config.DeliverSubject, err)
	}
}
