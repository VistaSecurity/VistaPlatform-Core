package services

// Dispatch-time half of explicit external targets ( W5.13b).
//
// CreateJob authorizes a job's targets and records two things on the job, both
// SERVER-written and kept beside the caller-supplied `options` rather than in
// them:
//
//   - metadata.pinned_addresses — for each hostname target, the addresses it
//     resolved to when it was authorized. The scanner connects to those and
//     nothing else; the hostname survives only as the TLS SNI / display name.
//   - metadata.external_targets.confirmed — that a person confirmed the job's
//     targets outside the tenant's registered networks.
//
// processTarget reads both back here and re-authorizes the expanded addresses
// against the tenant's scope as it stands at scan time.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/netip"

	"github.com/jmoiron/sqlx"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
)

// jobTargetGrant is what a job recorded at creation about one target.
type jobTargetGrant struct {
	pinned []string
	// consent is what a person confirmed outside the registered networks:
	// each confirmed target's range or pinned addresses, and the job's total.
	// Consent covers exactly these ( W5.13b review, items 5 and N2) —
	// the zero value when the job recorded no confirmation.
	consent dispatchguard.DispatchConsent
}

// loadJobTargetGrant reads the pin for input and the job's confirmed external
// ranges. A job with neither (created before this existed, or with no hostname
// and nothing external) yields the zero grant: no pin, no consent — which is
// exactly the pre-existing behaviour.
func loadJobTargetGrant(tx *sqlx.Tx, jobID, input string) (jobTargetGrant, error) {
	var (
		pinnedRaw   []byte
		externalRaw []byte
		total       int64
	)
	err := tx.QueryRow(`
		SELECT COALESCE(metadata->'pinned_addresses'->$2, '[]'::jsonb),
		       CASE WHEN metadata->'external_targets'->>'confirmed' = 'true'
		            THEN COALESCE(metadata->'external_targets'->'targets', '[]'::jsonb)
		            ELSE '[]'::jsonb END,
		       COALESCE((metadata->'external_targets'->>'total_addresses')::bigint, 0)
		FROM discovery_jobs WHERE id = $1`, jobID, input).Scan(&pinnedRaw, &externalRaw, &total)
	if errors.Is(err, sql.ErrNoRows) {
		return jobTargetGrant{}, nil
	}
	if err != nil {
		return jobTargetGrant{}, err
	}
	var grant jobTargetGrant
	if err := json.Unmarshal(pinnedRaw, &grant.pinned); err != nil {
		// A pin that is not a list of strings is not a pin; refusing to scan
		// is the safe reading, and authorization below will refuse the bare
		// hostname.
		grant.pinned = nil
	}
	var external []dispatchguard.ExternalTarget
	if err := json.Unmarshal(externalRaw, &external); err == nil {
		grant.consent.Ranges = dispatchguard.ConfirmedRanges(external)
	}
	if total > 0 {
		grant.consent.TotalAddresses = uint64(total)
	}
	return grant, nil
}

// jobHasConfirmedExternalTargets reports whether a job recorded confirmed
// external targets — which a tenant sensor is never handed (see
// dispatchToSensor).
func jobHasConfirmedExternalTargets(tx *sqlx.Tx, jobID string) (bool, error) {
	var has bool
	err := tx.QueryRow(`SELECT COALESCE(metadata->'external_targets'->>'confirmed', '') = 'true' FROM discovery_jobs WHERE id = $1`, jobID).Scan(&has)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return has, err
}

// expandTarget turns one stored target into the addresses a packet will be
// sent to. See processTarget for why a pinned hostname is never re-resolved.
func (jp *JobProcessor) expandTarget(input string, pinned []string) []string {
	if len(pinned) > 0 {
		return append([]string{}, pinned...)
	}
	if net.ParseIP(input) != nil || shareddisc.IsNetworkRange(input) {
		return shareddisc.ExpandTargets([]string{input})
	}
	var resolver dispatchguard.Resolver = net.DefaultResolver
	if jp.discoveryService != nil && jp.discoveryService.resolver != nil {
		resolver = jp.discoveryService.resolver
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	addrs, err := resolver.LookupNetIP(ctx, "ip", input)
	if err != nil || len(addrs) == 0 {
		// Returned as-is: a bare hostname is not an address, so the
		// authorization that follows refuses it with a reason.
		return []string{input}
	}
	rt := dispatchguard.ResolvedTarget{ManualTarget: dispatchguard.ManualTarget{Input: input, Host: input}}
	for _, a := range addrs {
		rt.Resolved = append(rt.Resolved, netip.Addr.Unmap(a))
	}
	return rt.ScanAddresses()
}
