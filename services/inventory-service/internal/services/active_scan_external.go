package services

// Per-asset Active Scan of an asset outside the registered networks
// ( W5.13b, owner decision Q10). Pressing Scan on an inventoried asset is
// a person's explicit choice, so an asset whose address is outside every
// registered network is ASKED about, not refused: the scan answers 422 with
// the assets named, and a resend with external_targets_confirmed runs it.
// cluster-sensor-service remains the authority (reserved ranges, the operator
// switch, the bounds); this file only lets the question be asked before
// anything is stamped or dispatched, and maps its answers back to assets.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
)

// ActiveScanExternalTarget is an asset whose scan target is outside the
// tenant's registered networks.
type ActiveScanExternalTarget struct {
	AssetID   uuid.UUID
	AssetName string
	Target    string
	Addresses []string
}

// ExternalConfirmationError says the scan needs a person's confirmation for
// the named assets. Partial carries any jobs that were dispatched for OTHER
// assets before cluster-sensor-service raised the question (only possible for
// assets the preflight could not judge).
type ExternalConfirmationError struct {
	Targets []ActiveScanExternalTarget
	Partial ActiveScanResult
}

func (e *ExternalConfirmationError) Error() string {
	names := make([]string, 0, len(e.Targets))
	for _, t := range e.Targets {
		names = append(names, t.AssetName)
	}
	return fmt.Sprintf("%d asset(s) are outside your registered networks (%s); confirm to scan them", len(e.Targets), strings.Join(names, ", "))
}

// externalAssets finds, before anything changes, the assets whose address —
// or, for an asset known only by name, whose resolved addresses — the
// tenant's scope calls external. cluster-sensor-service judges again
// authoritatively; if it still answers "confirm first" (a name that resolved
// differently a moment later), recordTargetVerdict maps that answer back to
// the asset.
func (s *RevalidationService) externalAssets(tenantID uuid.UUID, assets []activeScanAsset) ([]ActiveScanExternalTarget, error) {
	if s.db == nil || len(assets) == 0 {
		return nil, nil
	}
	var scope dispatchguard.TargetScope
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		var e error
		scope, e = dispatchguard.LoadTargetScope(tx, tenantID.String())
		return e
	})
	if err != nil {
		return nil, fmt.Errorf("load scan scope: %w", err)
	}
	resolver := s.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	var out []ActiveScanExternalTarget
	seen := map[uuid.UUID]bool{}
	for _, a := range assets {
		if seen[a.id] {
			continue
		}
		addrs := []string{a.host}
		if len(scope.ExternalLiterals(addrs)) == 0 {
			// Not an external literal. A NAME is resolved here too, so the
			// question is asked before anything about the asset changes; a
			// name that is refused or does not resolve is left for
			// cluster-sensor-service to refuse with its reason.
			parsed, err := dispatchguard.ParseManualTarget(a.host)
			if err != nil || parsed.Host == "" {
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			resolved, err := dispatchguard.ResolveManualTargets(ctx, resolver, []dispatchguard.ManualTarget{parsed})
			cancel()
			if err != nil || len(resolved) != 1 {
				continue
			}
			addrs = nil
			for _, ip := range resolved[0].Resolved {
				addrs = append(addrs, ip.String())
			}
			if len(scope.ExternalLiterals(addrs)) == 0 {
				continue
			}
		}
		seen[a.id] = true
		out = append(out, ActiveScanExternalTarget{AssetID: a.id, AssetName: a.name, Target: a.host, Addresses: addrs})
	}
	return out, nil
}

// recordTargetVerdict turns cluster-sensor-service's target verdict for one
// batch into per-asset outcomes on result. It reports false for any other
// error, which the caller handles as before.
func (s *RevalidationService) recordTargetVerdict(result *ActiveScanResult, batch activeScanBatch, err error) bool {
	var downstream *DownstreamError
	if !errors.As(err, &downstream) || downstream.Code == "" {
		return false
	}
	assetsFor := func(target string) []uuid.UUID {
		if ids := batch.assetsByHost[target]; len(ids) > 0 {
			return ids
		}
		return nil
	}
	skipAll := func(reason string) {
		for _, id := range batch.assetIDs {
			result.Skipped = append(result.Skipped, ActiveScanSkip{AssetID: id, Reason: reason})
		}
	}
	switch downstream.Code {
	case "external_targets_unconfirmed":
		var ext []dispatchguard.ExternalTarget
		_ = json.Unmarshal(downstream.ExternalTargets, &ext)
		matched := false
		for _, e := range ext {
			for _, id := range assetsFor(e.Target) {
				matched = true
				result.NeedsConfirmation = append(result.NeedsConfirmation, ActiveScanExternalTarget{AssetID: id, AssetName: e.Target, Target: e.Target, Addresses: e.Addresses})
			}
		}
		if !matched {
			skipAll(downstream.Message)
		}
	case "external_targets_disabled":
		skipAll("outside your registered networks, and your platform operator has turned off scanning targets outside them")
	case "targets_refused":
		var refused []dispatchguard.RefusedTarget
		_ = json.Unmarshal(downstream.RefusedTargets, &refused)
		matched := false
		for _, r := range refused {
			for _, id := range assetsFor(r.Target) {
				matched = true
				result.Skipped = append(result.Skipped, ActiveScanSkip{AssetID: id, Reason: r.Reason})
			}
		}
		if !matched {
			skipAll(downstream.Message)
		}
	default:
		return false
	}
	return true
}
