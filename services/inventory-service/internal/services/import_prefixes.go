package services

import (
	"context"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// importPrefixes is one import request's reads of the tenant's prefixes
// ( F4; DCIM row 1.6).
//
// Every finding in an import asks the same tenant the same questions: which
// prefix its address is in (ownership, auto-approval), the prefix to enrich
// the asset from, and the scope each identifier is filed under (identity
// intake). The request reads each source once — the inventory prefix set
// (loadPrefixSet) and the identity intake's snapshot (identity.Intake.Snapshot)
// — and answers every question from those reads.
//
// They are two reads, not one, on purpose: the intake's snapshot carries the
// identity layer's DHCP-posture rule, which is decided in SQL in
// shared/identity/postgres and must not be re-derived here from the other
// read's columns.
//
// A read that fails is not cached: the next question retries it, so one
// transient failure costs what it always cost — that finding's answer — and
// not the rest of the batch. A nil *importPrefixes reads per question, which
// is what every path outside an import request does.
type importPrefixes struct {
	assets   *AssetService
	tenantID uuid.UUID

	set  *PrefixSet
	snap *identity.SegmentSnapshot
}

// newImportPrefixes starts one request's prefix reads. Nothing is read until a
// question needs it.
func (s *AssetService) newImportPrefixes(tenantID uuid.UUID) *importPrefixes {
	return &importPrefixes{assets: s, tenantID: tenantID}
}

// invalidate drops what the request has read, so the next question reads the
// prefixes again — after the request itself changed one (an inferred DHCP
// posture). Safe on nil.
func (r *importPrefixes) invalidate() {
	if r == nil {
		return
	}
	r.set, r.snap = nil, nil
}

// prefixSetFor is the tenant's auto-approval prefix index: the request's one
// read when there is a request, else a read for this question.
func (s *AssetService) prefixSetFor(r *importPrefixes, tenantID uuid.UUID) (*approval.PrefixSet, error) {
	set, err := s.prefixSetIn(r, tenantID)
	if err != nil {
		return nil, err
	}
	return set.Approval(), nil
}

// snapshot is the request's one identity-intake prefix snapshot.
func (r *importPrefixes) snapshot(ctx context.Context, in *identity.Intake) (identity.SegmentSnapshot, error) {
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

// cloudEnvironment is a cloud finding's stated environment when it is one of
// `environment_type`'s values, else production.
func cloudEnvironment(v string) string {
	switch v = strings.ToLower(strings.TrimSpace(v)); v {
	case "production", "staging", "development", "test":
		return v
	}
	return "production"
}

// evaluateAssetApprovalIn is evaluateAssetApproval over the request's prefix
// set.
func (s *AssetService) evaluateAssetApprovalIn(segs *importPrefixes, tenantID uuid.UUID, ipAddress, hostname *string) string {
	set, err := s.prefixSetIn(segs, tenantID)
	if err != nil {
		return identity.StatusPendingApproval
	}
	return s.evaluateAssetApprovalOver(tenantID, set, ipAddress, hostname)
}
