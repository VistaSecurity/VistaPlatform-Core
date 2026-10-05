package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// Claiming a learned public segment (owner decision D8).
//
// Interrogating a firewall brings its networks in as LEARNED segments. A
// learned public range is not treated as the tenant's, because nothing in the
// device's data tells the customer's DMZ /28 from the ISP transit /30 it is
// plugged into (dispatchguard.SegmentGrantsOwnership). The way such a range
// becomes the tenant's is a person saying so: one click, audited, revocable.
// There is no proof-of-control step, and the claim is never made
// automatically — a wrong guess is the platform scanning a third party.
//
// The claim is recorded in metadata under dispatchguard.SegmentClaimKey, and
// the segment keeps its learned provenance beside it, so the row can still say
// which device reported it and a re-interrogation keeps refreshing it (its
// `metadata || …` merge leaves the claim alone). From then on every ownership
// reader treats the segment as declared, still bound by the breadth cap and
// still beaten by sensitive / active-probes-disabled exclusions.

// ErrSegmentNotClaimable refuses a claim (or revocation) on a segment the
// action does not apply to. The wrapped message says why, for the person.
var ErrSegmentNotClaimable = errors.New("segment cannot be claimed")

// segmentClaimRow is what the claim action needs to know about a segment.
type segmentClaimRow struct {
	SegmentType string
	Value       string
	NetworkType string
	Metadata    map[string]interface{}
}

func (r segmentClaimRow) learned() bool {
	source, _ := r.Metadata["source"].(string)
	return source == "interrogation" || source == "unifi"
}

func (r segmentClaimRow) claim() (map[string]interface{}, bool) {
	claim, ok := r.Metadata[dispatchguard.SegmentClaimKey].(map[string]interface{})
	return claim, ok
}

// lockSegmentForClaim reads the segment inside the caller's tenant
// transaction, locked, so a concurrent edit or re-interrogation cannot slip
// between the checks and the write. sql.ErrNoRows means not found.
func lockSegmentForClaim(tx *sqlx.Tx, tenantID, id uuid.UUID) (segmentClaimRow, error) {
	var row segmentClaimRow
	var raw []byte
	if err := tx.QueryRow(`SELECT segment_type, value, network_type, COALESCE(metadata, '{}'::jsonb)
		FROM network_segments WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenantID, id).
		Scan(&row.SegmentType, &row.Value, &row.NetworkType, &raw); err != nil {
		return row, err
	}
	row.Metadata = map[string]interface{}{}
	if err := json.Unmarshal(raw, &row.Metadata); err != nil {
		return row, err
	}
	return row, nil
}

// validateClaimable decides whether a claim means anything on this segment.
// Each refusal is written for the person who pressed the button.
func validateClaimable(row segmentClaimRow) error {
	if !row.learned() {
		return fmt.Errorf("%w: this segment was declared by a person in your organization, so it already counts as yours — there is nothing to claim", ErrSegmentNotClaimable)
	}
	if row.SegmentType != "cidr" {
		return fmt.Errorf("%w: only a network range (CIDR) learned from a device can be claimed", ErrSegmentNotClaimable)
	}
	if row.NetworkType != "public" {
		return fmt.Errorf("%w: a %s segment already counts as yours — only a learned public range needs claiming", ErrSegmentNotClaimable, row.NetworkType)
	}
	prefix, err := netip.ParsePrefix(strings.TrimSpace(row.Value))
	if err != nil {
		return fmt.Errorf("%w: %q is not a valid network range", ErrSegmentNotClaimable, row.Value)
	}
	if probeconsent.TooBroadToClaim(prefix.Masked()) {
		return fmt.Errorf("%w: %s is too broad to claim as one of your networks — IPv4 ranges must be /%d or narrower and IPv6 ranges /%d or narrower; declare the specific ranges you own instead",
			ErrSegmentTooBroad, strings.TrimSpace(row.Value), probeconsent.MinClaimBitsIPv4, probeconsent.MinClaimBitsIPv6)
	}
	return nil
}

// Claim records that userID states this learned public segment is the
// tenant's. It returns the segment, and whether anything changed: claiming a
// segment that is already claimed is a no-op that keeps the original claim
// (who and when), so the record is never silently re-attributed. A nil segment
// and nil error mean not found.
//
// fallbackName is shown when the user's own name cannot be read (the token's
// email, typically). The name is a snapshot for display; the audit entry,
// keyed by user id, is the record.
func (s *NetworkSegmentService) Claim(tenantID, id, userID uuid.UUID, fallbackName string) (*models.NetworkSegment, bool, error) {
	if userID == uuid.Nil {
		return nil, false, fmt.Errorf("%w: a claim is a person's statement and needs a signed-in user", ErrSegmentNotClaimable)
	}
	changed := false
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		row, err := lockSegmentForClaim(tx, tenantID, id)
		if err != nil {
			return err
		}
		if err := validateClaimable(row); err != nil {
			return err
		}
		if _, claimed := row.claim(); claimed {
			return nil
		}
		var name string
		err = tx.QueryRow(`SELECT COALESCE(NULLIF(btrim(concat_ws(' ', first_name, last_name)), ''), email)
			FROM users WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenantID, userID).Scan(&name)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if strings.TrimSpace(name) == "" {
			name = strings.TrimSpace(fallbackName)
		}
		claim, err := json.Marshal(map[string]interface{}{
			"by":      userID.String(),
			"by_name": name,
			"at":      time.Now().UTC().Format(time.RFC3339),
		})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(`UPDATE network_segments
			SET metadata = COALESCE(metadata, '{}'::jsonb) || jsonb_build_object($3::text, $4::jsonb), updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2`, tenantID, id, dispatchguard.SegmentClaimKey, string(claim)); err != nil {
			return err
		}
		changed = true
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	seg, err := s.GetByID(tenantID, id)
	return seg, changed, err
}

// RevokeClaim withdraws a claim. It returns the segment and the claim that was
// withdrawn (nil when there was none — revoking is idempotent). Only a learned
// segment can carry a claim, so a declared one is refused rather than answered
// with a no-op that would suggest it had one. The breadth cap does not apply:
// withdrawing ownership is always allowed.
func (s *NetworkSegmentService) RevokeClaim(tenantID, id uuid.UUID) (*models.NetworkSegment, map[string]interface{}, error) {
	var revoked map[string]interface{}
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		row, err := lockSegmentForClaim(tx, tenantID, id)
		if err != nil {
			return err
		}
		if !row.learned() {
			return fmt.Errorf("%w: this segment was declared by a person in your organization; it has no claim to revoke — edit or delete it instead", ErrSegmentNotClaimable)
		}
		claim, claimed := row.claim()
		if _, present := row.Metadata[dispatchguard.SegmentClaimKey]; !present {
			return nil
		}
		if _, err := tx.Exec(`UPDATE network_segments SET metadata = metadata - $3::text, updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2`, tenantID, id, dispatchguard.SegmentClaimKey); err != nil {
			return err
		}
		if claimed {
			revoked = claim
		} else {
			revoked = map[string]interface{}{}
		}
		return nil
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	seg, err := s.GetByID(tenantID, id)
	return seg, revoked, err
}

// serverOwnedSegmentKeys are the metadata keys a client's `metadata` on the
// ordinary create/update can neither set nor erase.
//
//   - the claim: only the audited claim action writes it. Accepting it from a
//     PUT would let an edit grant ownership of a learned public range with no
//     claim entry in the audit log, and dropping it on a PUT would let an
//     unrelated edit withdraw one.
//   - the learned provenance (`source`, `source_device_type`,
//     `source_asset_id`): a PUT that omitted `source` used to turn a learned
//     segment into a declared one — granting the same ownership as a claim,
//     without one. Interrogation owns these keys; a person who wants the
//     range declared claims it, or deletes the learned row and declares it.
// - the other devices' gateway claims (`gateway_candidates`): only
//     the gateway-links reconcile writes them, beside the gateway columns.
var serverOwnedSegmentKeys = []string{dispatchguard.SegmentClaimKey, "source", "source_device_type", "source_asset_id", pgidentity.GatewayCandidatesKey}

// withServerOwnedKeys returns base with the server-owned keys taken from
// current instead of whatever base says about them (cf. withPostureKeys).
func withServerOwnedKeys(base, current map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(base)+len(serverOwnedSegmentKeys))
	for k, v := range base {
		out[k] = v
	}
	for _, k := range serverOwnedSegmentKeys {
		delete(out, k)
		if v, ok := current[k]; ok {
			out[k] = v
		}
	}
	return out
}

// withoutClaim drops a client-supplied claim from a new segment's metadata. A
// segment a person creates is declared; it has nothing to claim.
func withoutClaim(meta map[string]interface{}) map[string]interface{} {
	if _, ok := meta[dispatchguard.SegmentClaimKey]; !ok {
		return meta
	}
	out := make(map[string]interface{}, len(meta))
	for k, v := range meta {
		if k != dispatchguard.SegmentClaimKey {
			out[k] = v
		}
	}
	return out
}

// ErrSegmentExists refuses a new segment whose value another segment already
// holds (the per-tenant unique index on value). The wrapped message names the
// segment in the way and what to do instead.
var ErrSegmentExists = errors.New("segment already exists")

// duplicateSegmentError explains a create that hit the unique index. When the
// segment in the way is a LEARNED PUBLIC range, declaring it again is what a
// person does to make it theirs — and the answer is the claim action, so the
// message says so. Anything else is a plain duplicate. The lookup runs after
// the failed insert's transaction has rolled back; if it cannot tell, the
// plain message is still right.
func (s *NetworkSegmentService) duplicateSegmentError(tenantID uuid.UUID, value string, cause error) error {
	value = strings.TrimSpace(value)
	var name, networkType string
	var raw []byte
	var device sql.NullString
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT ns.name, ns.network_type, COALESCE(ns.metadata, '{}'::jsonb),
				(SELECT COALESCE(NULLIF(a.display_name, ''), a.hostname) FROM assets a
				  WHERE a.tenant_id = ns.tenant_id AND a.id::text = ns.metadata->>'source_asset_id')
			FROM network_segments ns
			WHERE ns.tenant_id = $1 AND ns.value = $2 AND COALESCE(ns.cloud_network_ref, '') = ''`,
			tenantID, value).Scan(&name, &networkType, &raw, &device)
	})
	if err != nil {
		// The database's own wording stays in the log, not the response.
		log.Printf("[NetworkSegments] duplicate %s: insert failed with %v; describing the existing segment failed with %v", value, cause, err)
		return fmt.Errorf("%w: a network segment for %s already exists; edit that segment instead", ErrSegmentExists, value)
	}
	row := segmentClaimRow{SegmentType: "cidr", Value: value, NetworkType: networkType, Metadata: map[string]interface{}{}}
	_ = json.Unmarshal(raw, &row.Metadata)
	if row.learned() && networkType == "public" {
		from := strings.TrimSpace(device.String)
		if from == "" {
			if dt, _ := row.Metadata["source_device_type"].(string); dt != "" {
				from = "a " + dt + " device"
			} else {
				from = "an interrogated device"
			}
		}
		return fmt.Errorf("%w: this range was learned from %s (segment %q); use 'Claim as mine' on it instead of declaring it again",
			ErrSegmentExists, from, name)
	}
	return fmt.Errorf("%w: a network segment for %s already exists (%q); edit that segment instead", ErrSegmentExists, value, name)
}
