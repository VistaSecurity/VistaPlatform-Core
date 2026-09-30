package services

import (
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/notification-service/internal/models"
)

func TestHistoryStatusFor(t *testing.T) {
	cases := []struct {
		delivered, unresolved int
		want                  string
	}{
		{2, 0, "sent"},
		{1, 0, "sent"},
		{1, 1, "partial"}, // e.g. in-app landed, email failed
		{3, 1, "partial"},
		{0, 1, "failed"},
		{0, 2, "failed"},
	}
	for _, c := range cases {
		if got := historyStatusFor(c.delivered, c.unresolved); got != c.want {
			t.Errorf("historyStatusFor(delivered=%d, unresolved=%d) = %q, want %q", c.delivered, c.unresolved, got, c.want)
		}
	}
}

func TestBuildChannelResults(t *testing.T) {
	ok := &models.TenantNotificationChannel{ID: uuid.New(), ChannelType: "in_app", Enabled: true}
	transient := &models.TenantNotificationChannel{ID: uuid.New(), ChannelType: "email", Enabled: true}
	permanent := &models.TenantNotificationChannel{ID: uuid.New(), ChannelType: "webhook", Enabled: true}
	off := &models.TenantNotificationChannel{ID: uuid.New(), ChannelType: "slack", Enabled: false}

	results := buildChannelResults(
		[]interface{}{ok, transient, permanent, off},
		[]ChannelFailure{
			{ChannelID: transient.ID, ChannelType: "email", Err: errors.New("smtp 451")},
			{ChannelID: permanent.ID, ChannelType: "webhook", Err: permanentf("bad url")},
		})
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3 (a disabled channel was never attempted): %v", len(results), results)
	}
	want := map[uuid.UUID]string{ok.ID: "sent", transient.ID: "retrying", permanent.ID: "failed"}
	for _, r := range results {
		id, _ := uuid.Parse(r["channel_id"].(string))
		if r["status"] != want[id] {
			t.Errorf("channel %s: status %v, want %s", id, r["status"], want[id])
		}
		if _, hasErr := r["error"]; hasErr {
			t.Errorf("channel_results must not carry error text (it can embed a credential URL): %v", r)
		}
	}
}

func TestBuildChannelResults_RetryDisabledMeansFailedNotRetrying(t *testing.T) {
	t.Setenv("NOTIFICATION_DELIVERY_RETRY_ENABLED", "false")
	ch := &models.TenantNotificationChannel{ID: uuid.New(), ChannelType: "email", Enabled: true}
	results := buildChannelResults([]interface{}{ch}, []ChannelFailure{{ChannelID: ch.ID, ChannelType: "email", Err: errors.New("x")}})
	if results[0]["status"] != "failed" {
		t.Fatalf("status = %v; with retry off nothing will ever retry it, so 'retrying' would be a lie", results[0]["status"])
	}
}

func TestCloneMetadata_DoesNotAlias(t *testing.T) {
	src := map[string]interface{}{"a": 1}
	dst := cloneMetadata(src)
	dst["channel_results"] = "x"
	if _, leaked := src["channel_results"]; leaked {
		t.Fatal("cloneMetadata aliased its input")
	}
	if got := cloneMetadata(nil); got == nil {
		t.Fatal("cloneMetadata(nil) must return a writable map")
	}
}

func TestUpdateChannelResult(t *testing.T) {
	id := uuid.New()
	d := pendingDelivery{channelID: id, channelType: "webhook"}

	existing := []interface{}{
		map[string]interface{}{"channel_id": id.String(), "channel_type": "webhook", "status": "retrying"},
		map[string]interface{}{"channel_id": uuid.NewString(), "channel_type": "in_app", "status": "sent"},
	}
	got := updateChannelResult(existing, d, false, true, "")
	if len(got) != 2 {
		t.Fatalf("expected the entry to be updated in place, got %d entries", len(got))
	}
	first := got[0].(map[string]interface{})
	if first["status"] != "failed" || first["retries_exhausted"] != true {
		t.Errorf("entry not updated: %v", first)
	}

	// A row with no channel_results (digest flush, or written before this change)
	// gains an entry rather than losing the outcome.
	got = updateChannelResult(nil, d, true, false, "")
	if len(got) != 1 || got[0].(map[string]interface{})["status"] != "sent" {
		t.Errorf("missing entry was not added: %v", got)
	}
}

// A retry's terminal failure records WHY, in the tenant-safe vocabulary; a retry
// that finally delivers clears the stale reason.
func TestUpdateChannelResult_RecordsAndClearsTheReason(t *testing.T) {
	id := uuid.New()
	d := pendingDelivery{channelID: id, channelType: "webhook"}
	existing := func() []interface{} {
		return []interface{}{map[string]interface{}{"channel_id": id.String(), "channel_type": "webhook", "status": "retrying", "reason": reasonTimeout}}
	}

	failed := updateChannelResult(existing(), d, false, true, reasonRefused)[0].(map[string]interface{})
	if failed["reason"] != reasonRefused {
		t.Errorf("reason = %v, want the terminal failure's reason %q", failed["reason"], reasonRefused)
	}

	recovered := updateChannelResult(existing(), d, true, false, "")[0].(map[string]interface{})
	if _, has := recovered["reason"]; has {
		t.Errorf("a delivered channel kept its stale reason: %v", recovered)
	}

	added := updateChannelResult(nil, d, false, true, reasonRefused)[0].(map[string]interface{})
	if added["reason"] != reasonRefused {
		t.Errorf("a new entry lost the reason: %v", added)
	}
}
