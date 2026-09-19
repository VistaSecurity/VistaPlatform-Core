package events

import (
	"github.com/google/uuid"
	"testing"
)

func TestPublishDurableUnavailableIsRetryable(t *testing.T) {
	t.Setenv("NATS_URL", "")
	publisher := NewLifecyclePublisher(nil)
	if err := publisher.PublishDurable(t.Context(), Envelope{EventID: uuid.New(), EventType: EventTypeAssetMerged, TenantID: uuid.New()}); err == nil {
		t.Fatal("unavailable bus acknowledged durable event")
	}
}
