package services

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// importSegments is one import request's reads of the tenant's network
// segments ( F4).
//
// Every finding in an import asks the same tenant the same segment questions:
// which segment its address is in (ownership), that segment's tags, the
// segment to enrich the asset from, the scope each identifier is filed under
// (identity intake), and for a cloud resource its VPC segment. Each question
// used to re-read every segment of the tenant, about five times per finding.
// Now the request reads each source once — the inventory-service segment set
// (NetworkSegmentService.LoadSegmentSet) and the identity intake's snapshot
// (identity.Intake.Snapshot) — and answers every question from those reads.
//
// They are two reads, not one, on purpose: the intake's snapshot carries the
// identity layer's dynamic-posture rule, which is decided in SQL in
// shared/identity/postgres and must not be re-derived here from the other
// read's columns.
//
// A read that fails is not cached: the next question retries it, so one
// transient failure costs what it always cost — that finding's answer — and
// not the rest of the batch. A nil *importSegments reads per question, which
// is what every path outside an import request does.
type importSegments struct {
	assets   *AssetService
	tenantID uuid.UUID

	set  *SegmentSet
	snap *identity.SegmentSnapshot
	// cloud memoises FindOrCreateCloudSegment by provider/region/VPC/
	// environment, so fifty resources in one VPC find (or create) its segment
	// once.
	cloud map[string]*models.NetworkSegment
}

// newImportSegments starts one request's segment reads. Nothing is read until
// a question needs it.
func (s *AssetService) newImportSegments(tenantID uuid.UUID) *importSegments {
	return &importSegments{assets: s, tenantID: tenantID}
}

// invalidate drops what the request has read, so the next question reads the
// segments again — after the request itself changed one (an inferred DHCP
// posture). Safe on nil.
func (r *importSegments) invalidate() {
	if r == nil {
		return
	}
	r.set, r.snap = nil, nil
}

// segmentSet is the request's one inventory segment read; nil (matching
// nothing) when no segment service is wired.
func (r *importSegments) segmentSet() (*SegmentSet, error) {
	if r.set != nil {
		return r.set, nil
	}
	svc := r.assets.networkSegmentService
	if svc == nil {
		return nil, nil
	}
	set, err := svc.LoadSegmentSet(r.tenantID)
	if err != nil {
		return nil, err
	}
	r.set = set
	return set, nil
}

// snapshot is the request's one identity-intake segment snapshot.
func (r *importSegments) snapshot(ctx context.Context, in *identity.Intake) (identity.SegmentSnapshot, error) {
	if r.snap != nil {
		return *r.snap, nil
	}
	snap, err := in.Snapshot(ctx, r.tenantID.String())
	if err != nil {
		return identity.SegmentSnapshot{}, err
	}
	r.snap = &snap
	return snap, nil
}

// cloudSegment is FindOrCreateCloudSegment, once per distinct cloud network
// in the request.
func (r *importSegments) cloudSegment(provider, region, vpcID, env string) (*models.NetworkSegment, error) {
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%s", provider, region, vpcID, env)
	if seg, ok := r.cloud[key]; ok {
		return seg, nil
	}
	seg, err := r.assets.networkSegmentService.FindOrCreateCloudSegment(r.tenantID, provider, region, vpcID, env)
	if err != nil {
		return nil, err
	}
	if r.cloud == nil {
		r.cloud = map[string]*models.NetworkSegment{}
	}
	r.cloud[key] = seg
	return seg, nil
}

// getTagsForAssetIn is getTagsForAsset over the request's segment set.
func (s *AssetService) getTagsForAssetIn(segs *importSegments, tenantID uuid.UUID, ipAddress, hostname *string) (map[string]interface{}, error) {
	if segs == nil || s.networkSegmentService == nil {
		return s.getTagsForAsset(tenantID, ipAddress, hostname)
	}
	set, err := segs.segmentSet()
	if err != nil {
		return make(map[string]interface{}), err
	}
	return set.Tags(ipAddress, hostname), nil
}

// enrichAssetIn is NetworkSegmentService.EnrichAssetByID over the request's
// segment set.
func (s *AssetService) enrichAssetIn(segs *importSegments, tenantID, assetID uuid.UUID, ipAddress, hostname *string) error {
	if s.networkSegmentService == nil {
		return nil
	}
	if segs == nil {
		return s.networkSegmentService.EnrichAssetByID(tenantID, assetID, ipAddress, hostname)
	}
	set, err := segs.segmentSet()
	if err != nil {
		return err
	}
	return s.networkSegmentService.EnrichAssetByIDIn(set, tenantID, assetID, ipAddress, hostname)
}

// evaluateAssetApprovalIn is evaluateAssetApproval over the request's segment
// set.
func (s *AssetService) evaluateAssetApprovalIn(segs *importSegments, tenantID uuid.UUID, ipAddress, hostname *string) string {
	if segs == nil || s.networkSegmentService == nil {
		return s.evaluateAssetApproval(tenantID, ipAddress, hostname)
	}
	set, err := segs.segmentSet()
	if err != nil {
		return identity.StatusPendingApproval
	}
	return s.evaluateAssetApprovalOver(tenantID, set, ipAddress, hostname)
}
