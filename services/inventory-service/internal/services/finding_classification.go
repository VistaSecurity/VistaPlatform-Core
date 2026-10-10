package services

// One classifier, one approval decision, on the discovery-import path
// ( WP3, F2).
//
// discovery-processor-service used to classify every sensor discovery itself
// — an HMAC round trip per row to network-segments/classify-asset — evaluate
// the tenant's auto-approval rules against that answer, route third-party rows
// to external_connections through its own writer, and send the rest here with
// the status it had decided. This service then classified the same finding a
// second time, without the cloud hint, and could route it again. Two
// classifiers that could disagree, and two writers of one table.
//
// Now the processor imports every row and this file answers both questions,
// once per finding, from the import request's one segment read (WP2):
// classifyFindingIn is the ownership, and pipelineApproval evaluates the
// tenant's rules against it. The rules need nothing the processor has and this
// service lacks — the finding's address, hostname, confidence, first-seen time,
// envelope (for `source`), kind, and this classification — so evaluating them
// here removes the processor's last reason to ask for a classification at all.

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/approval"
)

// classifyFindingIn is the one ownership classification of an ingested
// finding:
//
//   - a cloud-API resource that names its provider and region is classified by
//     the cloud segment it lives in (FindOrCreateCloudSegment) — `internal` —
//     because its address, when it has one, cannot say whose it is;
//   - everything else by address and hostname over the request's segment set:
//     `internal` in a registered segment, `unknown` for an unmatched internal
//     candidate (private or CGNAT), `third_party` otherwise.
//
// Type is the matched segment's network_type, else the address class, else
// public. With no segment service wired (unit tests, a stripped-down build)
// ownership is "unknown", which keeps every finding on the managed path — the
// answer classifyAsset has always given there.
func (s *AssetService) classifyFindingIn(segs *importSegments, tenantID uuid.UUID, f IngestFinding, effectiveIP *string) approval.Classification {
	if s.networkSegmentService == nil {
		return approval.Classification{Ownership: "unknown", Type: addressNetworkType(effectiveIP)}
	}
	if isCloudAPIFinding(f) {
		provider := rawDataString(f.RawData, "cloud_provider")
		region := rawDataString(f.RawData, "cloud_region")
		if provider != "" && region != "" {
			env := rawDataString(f.RawData, "environment")
			if env == "" {
				env = "production"
			}
			seg, err := segs.cloudSegment(provider, region, rawDataString(f.RawData, "vpc_id"), env)
			if err != nil {
				log.Printf("[AssetService] classify: cloud segment for %s/%s failed (classifying by address): %v", provider, region, err)
			} else if seg != nil {
				id, name := seg.ID, seg.Name
				return approval.Classification{Ownership: "internal", Type: seg.NetworkType, SegmentID: &id, SegmentName: &name}
			}
		}
	}
	set, err := segs.segmentSet()
	if err != nil {
		// The answer classifyAsset gives on a failed read: keep it managed.
		log.Printf("[AssetService] classify: segment read for tenant %s failed: %v", tenantID, err)
		return approval.Classification{Ownership: "unknown", Type: addressNetworkType(effectiveIP)}
	}
	cls := approval.Classification{Ownership: set.Classify(effectiveIP, f.Hostname), Type: addressNetworkType(effectiveIP)}
	if seg := set.Match(effectiveIP, f.Hostname); seg != nil {
		id, name := seg.ID, seg.Name
		cls.SegmentID, cls.SegmentName = &id, &name
		if seg.NetworkType != "" {
			cls.Type = seg.NetworkType
		}
	}
	return cls
}

// addressNetworkType is the network_type of an address with no segment: the
// address class, and public for no address at all.
func addressNetworkType(ip *string) string {
	if ip == nil || *ip == "" {
		return "public"
	}
	return NetworkTypeForAddress(*ip)
}

// findingApproval is the status a NEW asset for one finding lands as, and the
// rule that decided it, when one did.
type findingApproval struct {
	status string
	ruleID *uuid.UUID
}

// approvalDecider decides a finding's findingApproval from its classification.
type approvalDecider func(f IngestFinding, cls approval.Classification) findingApproval

// fixedApproval is the decider of a caller that decided the status itself.
func fixedApproval(status string) approvalDecider {
	return func(IngestFinding, approval.Classification) findingApproval {
		return findingApproval{status: status}
	}
}

// pipelineApproval evaluates the tenant's auto-approval rules for each
// finding of one import request. The rules are read once, on the first
// finding that needs them; a failed read is "nothing auto-approves", the
// fail-closed answer the processor's batch gave too.
func (s *AssetService) pipelineApproval(tenantID uuid.UUID) approvalDecider {
	var (
		svc    *approval.Service
		rules  []*approval.Rule
		loaded bool
	)
	return func(f IngestFinding, cls approval.Classification) findingApproval {
		pending := findingApproval{status: "pending_approval"}
		if s.db == nil {
			return pending
		}
		if !loaded {
			loaded = true
			svc = approval.NewService(s.db.DB.DB)
			var err error
			if rules, err = svc.GetActiveRulesForTenant(tenantID); err != nil {
				log.Printf("[AssetService] auto-approval rules for tenant %s could not be read; nothing in this import auto-approves: %v", tenantID, err)
				rules = nil
			}
		}
		if len(rules) == 0 {
			return pending
		}
		ok, ruleID, err := svc.EvaluateAutoApprovalWithRules(rules, pipelineApprovalInput(tenantID, f), &cls)
		if err != nil {
			log.Printf("[AssetService] auto-approval evaluation for %s failed: %v", findingLabel(f), err)
		}
		if !ok || ruleID == nil {
			return pending
		}
		return findingApproval{status: "monitoring", ruleID: ruleID}
	}
}

// pipelineApprovalInput projects an imported finding onto the `observation`
// target the rules are written over — the same projection
// discovery-processor's SensorDiscovery.ApprovalInput made of the row, read
// from the finding the row became:
//
//   - Address is the destination (the discovered thing), never source_ip;
//   - Hostname is the name the finding carries, after the processor's SNI/PTR
//     fill;
//   - Confidence and FirstSeen are the row's, which the converter stamps into
//     raw_data as `confidence` and `timestamp`;
//   - Metadata is raw_data, whose `source` / `discovery_method` decide the
//     rule vocabulary's `source`;
//   - Kind is stated on both paths (crypto, host_observation), never left
//     empty, so `kind:crypto` means what it says.
func pipelineApprovalInput(tenantID uuid.UUID, f IngestFinding) approval.Discovery {
	d := approval.Discovery{TenantID: tenantID, Kind: approval.KindCrypto}
	if isHostObservation(f) {
		d.Kind = approval.KindHostObservation
	}
	if f.Hostname != nil {
		d.Hostname = *f.Hostname
	}
	if f.IPAddress != nil {
		d.Address = strings.TrimSpace(*f.IPAddress)
	}
	if f.RawData != nil {
		if b, err := json.Marshal(f.RawData); err == nil {
			d.Metadata = b
		}
		switch c := f.RawData["confidence"].(type) {
		case float64:
			d = d.WithConfidence(c)
		case int:
			d = d.WithConfidence(float64(c))
		}
		switch ts := f.RawData["timestamp"].(type) {
		case string:
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				d.FirstSeen = t
			}
		case time.Time:
			d.FirstSeen = ts
		}
	}
	return d
}
