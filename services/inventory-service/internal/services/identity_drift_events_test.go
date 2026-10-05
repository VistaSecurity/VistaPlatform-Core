package services

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

type capturedLifecycle struct {
	eventType string
	payload   interface{}
}

type fakeLifecycle struct{ got []capturedLifecycle }

func (f *fakeLifecycle) Publish(_ context.Context, eventType string, _ uuid.UUID, _ string, payload interface{}) error {
	f.got = append(f.got, capturedLifecycle{eventType, payload})
	return nil
}

func (f *fakeLifecycle) PublishDurable(context.Context, invevents.Envelope) error { return nil }

func rotatedDrift(assetID string) *identity.Drift {
	return &identity.Drift{
		Verdict:     matcher.DriftRotated,
		Rule:        "mac_and_address_kept_key_changed",
		Explanation: "the SSH host key changed on a device whose hardware address and IP address are unchanged",
		Asset:       identity.AssetRef{TenantID: uuid.NewString(), ID: assetID},
		AssetName:   "db-primary",
		Static:      true,
		Changes: []identity.MaterialChange{{
			Kind: string(identity.KindSSHHostKeyFingerprint), Previous: []string{"SHA256:old"}, Current: []string{"SHA256:new"}, Retired: true,
		}},
	}
}

func TestPublishAssetIdentityDrift_CarriesOldAndNewFingerprints(t *testing.T) {
	lc := &fakeLifecycle{}
	var notes []sharedevents.NotificationEvent
	pub := &EventPublisherService{lifecycle: lc, notify: func(n sharedevents.NotificationEvent) error { notes = append(notes, n); return nil }}
	tenant, asset := uuid.New(), uuid.New()

	if err := pub.PublishAssetIdentityDrift(context.Background(), tenant, rotatedDrift(asset.String()), "scan"); err != nil {
		t.Fatal(err)
	}

	if len(lc.got) != 1 || lc.got[0].eventType != invevents.EventTypeAssetIdentityDrift {
		t.Fatalf("lifecycle events = %+v, want one asset.identity_drift", lc.got)
	}
	p := lc.got[0].payload.(*invevents.AssetIdentityDriftPayload)
	if p.AssetID != asset || p.Verdict != "rotated" || len(p.Changes) != 1 ||
		p.Changes[0].Previous[0] != "SHA256:old" || p.Changes[0].Current[0] != "SHA256:new" {
		t.Errorf("payload = %+v", p)
	}
	if len(notes) != 1 {
		t.Fatalf("notifications = %d, want 1", len(notes))
	}
	n := notes[0]
	if n.TenantID != tenant || n.AlertSource != "inventory-service" || n.AlertType != AlertTypeAssetIdentityDrift {
		t.Errorf("notification routing = %+v", n)
	}
	for _, want := range []string{"SHA256:old", "SHA256:new", "SSH host key"} {
		if !strings.Contains(n.Message, want) {
			t.Errorf("message lacks %q: %s", want, n.Message)
		}
	}
	if !strings.Contains(n.Title, "db-primary") {
		t.Errorf("title = %q, want the asset named", n.Title)
	}
}

func TestIdentityDriftNotification_PerVerdict(t *testing.T) {
	tenant, asset := uuid.New(), uuid.New()
	at := time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name     string
		mutate   func(d *identity.Drift)
		notify   bool
		severity string
		inTitle  string
	}{
		{"rotated", func(*identity.Drift) {}, true, "medium", "SSH host key changed"},
		{"reimaged", func(d *identity.Drift) { d.Verdict = matcher.DriftReimaged }, true, "high", "reimaged"},
		{"unverified asks for review", func(d *identity.Drift) { d.Verdict, d.NeedsReview = matcher.DriftUnverified, true }, true, "high", "needs review"},
		{"moved off a static segment", func(d *identity.Drift) { d.Verdict = matcher.DriftMoved }, true, "low", "moved"},
		// A DHCP client changing lease is what DHCP is for.
		{"moved within a dynamic segment is not notified", func(d *identity.Drift) { d.Verdict, d.Static = matcher.DriftMoved, false }, false, "", ""},
		{"replaced is a proposal, not a notification", func(d *identity.Drift) { d.Verdict = matcher.DriftReplaced }, false, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := rotatedDrift(asset.String())
			tc.mutate(d)
			n, ok := identityDriftNotification(tenant, asset, d, at)
			if ok != tc.notify {
				t.Fatalf("notify = %v, want %v", ok, tc.notify)
			}
			if !ok {
				return
			}
			if n.Severity != tc.severity || !strings.Contains(n.Title, tc.inTitle) {
				t.Errorf("severity=%q title=%q, want %q containing %q", n.Severity, n.Title, tc.severity, tc.inTitle)
			}
			if n.Metadata["verdict"] != string(d.Verdict) || n.Metadata["asset_id"] != asset.String() {
				t.Errorf("metadata = %+v", n.Metadata)
			}
		})
	}
}

func TestFindingLeafCertFingerprints(t *testing.T) {
	raw := map[string]interface{}{"certificates": []interface{}{
		map[string]interface{}{"chain_order": float64(0), "fingerprint_sha256": "AB:CD:EF"},
		map[string]interface{}{"chain_order": float64(1), "fingerprint_sha256": "1111", "is_ca": true},
		map[string]interface{}{"fingerprint_sha256": "2222"},
		map[string]interface{}{"chain_order": float64(0), "fingerprint_sha256": "abcdef"},
		map[string]interface{}{"fingerprint_sha256": "3333", "is_ca": true},
	}}
	got := findingLeafCertFingerprints(raw)
	if len(got) != 2 || got[0] != "abcdef" || got[1] != "2222" {
		t.Errorf("leaf fingerprints = %v, want [abcdef 2222]: leaves only, normalised, deduplicated", got)
	}
	if findingLeafCertFingerprints(nil) != nil {
		t.Error("no raw data must give no fingerprints")
	}
}
