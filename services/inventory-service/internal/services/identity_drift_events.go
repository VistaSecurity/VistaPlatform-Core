package services

// Publishing the identification engine's drift verdicts (owner Decision 4 of
//).
//
// The engine writes the asset_history entry inside the resolving transaction;
// this file is what happens AFTER the commit: an `asset.identity_drift`
// lifecycle event for anything that keeps a copy of the asset, and a tenant
// notification on `notifications.send` (sharedevents.SubjectNotificationsSend,
// published by EventPublisherService.notify) so a person can be told that a host key
// changed. Key rotation is security-relevant, so the notification carries the
// old and new fingerprints (public identities, never key material).
//
// Deliberately NOT a compliance finding. A rotated key is an event in an
// asset's life, and a finding is a standing condition a control evaluates; a
// finding raised for every routine rotation would be noise nobody can resolve.

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	invevents "github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

// AlertTypeAssetIdentityDrift is the notification `alert_type` a drift verdict
// is published under. A tenant routing rule can match it with source
// `inventory-service`.
const AlertTypeAssetIdentityDrift = "asset_identity_drift"

// identityDriftPayload is the lifecycle payload for one verdict.
func identityDriftPayload(assetID uuid.UUID, d *identity.Drift) *invevents.AssetIdentityDriftPayload {
	p := &invevents.AssetIdentityDriftPayload{
		AssetID:     assetID,
		AssetName:   d.AssetName,
		Verdict:     string(d.Verdict),
		Rule:        d.Rule,
		Explanation: d.Explanation,
		NeedsReview: d.NeedsReview,
	}
	for _, c := range d.Changes {
		p.Changes = append(p.Changes, invevents.IdentityMaterialChange{Kind: c.Kind, Previous: c.Previous, Current: c.Current, Retired: c.Retired})
	}
	return p
}

// identityDriftNotification builds the tenant notification for a verdict, and
// reports false when the verdict is not one a person is told about: an address
// moving within a DHCP segment is what DHCP is for.
func identityDriftNotification(tenantID, assetID uuid.UUID, d *identity.Drift, at time.Time) (sharedevents.NotificationEvent, bool) {
	if d == nil || !d.Verdict.Matches() {
		return sharedevents.NotificationEvent{}, false
	}
	if d.Verdict == matcher.DriftMoved && !d.Static {
		return sharedevents.NotificationEvent{}, false
	}
	name := d.AssetName
	if strings.TrimSpace(name) == "" {
		name = assetID.String()
	}
	var title, severity string
	switch d.Verdict {
	case matcher.DriftRotated:
		title, severity = "SSH host key changed on "+name, "medium"
	case matcher.DriftReimaged:
		title, severity = name+" was reimaged", "high"
	case matcher.DriftUnverified:
		title, severity = "Unconfirmed SSH host key change on "+name+" needs review", "high"
	case matcher.DriftMoved:
		title, severity = name+" moved to a new address", "low"
	}
	var lines []string
	for _, c := range d.Changes {
		if len(c.Previous) == 0 && len(c.Current) == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s: %s → %s", materialLabel(c.Kind), listOrNone(c.Previous), listOrNone(c.Current)))
	}
	msg := d.Explanation
	if len(lines) > 0 {
		msg = strings.Join(lines, "\n") + "\n\n" + msg
	}
	if d.NeedsReview {
		msg += "\n\nNothing else known about this device confirms the change. Review the asset's History tab; if this is a different device, it should be a separate asset."
	}
	changes := make([]map[string]any, 0, len(d.Changes))
	for _, c := range d.Changes {
		changes = append(changes, map[string]any{"kind": c.Kind, "previous": c.Previous, "current": c.Current, "retired": c.Retired})
	}
	return sharedevents.NotificationEvent{
		EventID:     uuid.New(),
		TenantID:    tenantID,
		AlertSource: "inventory-service",
		AlertType:   AlertTypeAssetIdentityDrift,
		Severity:    severity,
		Title:       title,
		Message:     msg,
		Timestamp:   at,
		Metadata: map[string]interface{}{
			"asset_id":     assetID.String(),
			"verdict":      string(d.Verdict),
			"rule":         d.Rule,
			"needs_review": d.NeedsReview,
			"changes":      changes,
		},
	}, true
}

func materialLabel(kind string) string {
	switch kind {
	case string(identity.KindSSHHostKeyFingerprint):
		return "SSH host key"
	case string(identity.KindIPAddress):
		return "Address"
	case string(identity.KindHostname):
		return "Name"
	case string(matcher.SignalTLSCert):
		return "TLS certificate"
	default:
		return kind
	}
}

func listOrNone(vs []string) string {
	if len(vs) == 0 {
		return "(none)"
	}
	return strings.Join(vs, ", ")
}

// PublishAssetIdentityDrift publishes one verdict as a lifecycle event and,
// when it is one a person is told about, a tenant notification. Called after
// the resolving transaction commits.
func (s *EventPublisherService) PublishAssetIdentityDrift(ctx context.Context, tenantID uuid.UUID, d *identity.Drift, source string) error {
	if s == nil || d == nil {
		return nil
	}
	assetID, err := uuid.Parse(d.Asset.ID)
	if err != nil {
		return fmt.Errorf("identity drift on a non-uuid asset %q: %w", d.Asset.ID, err)
	}
	var errs []string
	if s.lifecycle != nil {
		if err := s.lifecycle.Publish(ctx, invevents.EventTypeAssetIdentityDrift, tenantID, source, identityDriftPayload(assetID, d)); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if n, ok := identityDriftNotification(tenantID, assetID, d, time.Now().UTC()); ok && s.notify != nil {
		if err := s.notify(n); err != nil {
			errs = append(errs, "notification: "+err.Error())
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("publishing identity drift for %s: %s", d.Asset.ID, strings.Join(errs, "; "))
	}
	return nil
}

// publishIdentityDrift is the post-commit hook of resolveObservationWithRepo.
// A failure is logged, not returned: the verdict is already on the asset's
// timeline, and failing an observation that committed would report a failure
// that did not happen.
func (s *AssetService) publishIdentityDrift(ctx context.Context, obs identity.Observation, res identity.Resolution) {
	if res.Drift == nil || s.eventPublisher == nil {
		return
	}
	tenantID, err := uuid.Parse(obs.TenantID)
	if err != nil {
		log.Printf("[AssetService] identity drift: tenant %q is not a uuid: %v", obs.TenantID, err)
		return
	}
	if err := s.eventPublisher.PublishAssetIdentityDrift(ctx, tenantID, res.Drift, obs.Source.Ref); err != nil {
		log.Printf("[AssetService] identity drift: %v", err)
	}
}
