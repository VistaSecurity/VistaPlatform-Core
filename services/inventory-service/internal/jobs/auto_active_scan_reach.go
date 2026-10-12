package jobs

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/identityenrichment"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
)

// Reachability for unattended scans.
//
// The router (sensorrouting) hands every address no tenant sensor covers to the
// platform sensor. For an interactive scan that is a fair default, because a
// person asked and can read the result. For an UNATTENDED one it is a probe
// that cannot succeed whenever the platform is not on the target's network:
// the private address of a cloud instance is reachable only from inside its
// VPC, and a private segment with no sensor is not the cluster's network
// either. Every port comes back `filtered`, liveness is `assumed_up`, and the
// stamp then keeps the host out of the queue for a full rescan interval.
//
// Identity enrichment already answers this question for the same targets: a
// collector can run work on a network only if it is live and has an interface
// inside it (identityenrichment.EligibleCollectors / Collector.Reaches), and
// with none the work is blocked as no_eligible_collector_in_target_network.
// This applies that one rule to the automatic sweep instead of restating it.

// autoScanReach reads what the rule needs about one tenant.
type autoScanReach interface {
	Reachability(ctx context.Context, tenantID uuid.UUID, now time.Time) (autoScanReachability, error)
}

// autoScanReachability is a tenant's networks and collectors at one instant.
type autoScanReachability struct {
	// Segments are the active registered segments, typed.
	Segments []autoscan.Segment
	// Collectors are the live tenant sensors with a reported interface prefix.
	Collectors []identityenrichment.Collector
	// HasLiveSensors is true when the tenant has any live, dispatchable tenant
	// sensor at all. A tenant whose only collector is the platform sensor
	// reports false and keeps scanning from the platform.
	HasLiveSensors bool
}

// reachedBy is one collector and the addresses it is handed.
type reachedBy struct {
	Collector identityenrichment.Collector
	Addresses []string
}

// platformTargetsDecision splits the addresses the router left for the platform.
type platformTargetsDecision struct {
	// Platform keep today's executor.
	Platform []string
	// ViaCollector are reached by a live tenant sensor the router did not
	// match (its interface is inside the target's registered segment).
	ViaCollector []reachedBy
	// Unreachable are not scanned this pass: no executor can reach them.
	Unreachable []string
}

// decidePlatformTargets applies the reachability rule to addresses that would
// otherwise run from the platform.
//
//   - A live tenant sensor with an interface in the target's segment runs it.
//   - Otherwise a `cloud` segment is skipped: the platform is never inside it.
//   - Otherwise (private, VPN or no registered segment) the platform keeps it
//     only when the tenant has no live sensor at all. A tenant that deployed
//     sensors has told us where its networks are, and the platform is not
//     among them.
//
// `strict` is the tenant's "Prefer the observing sensor" switch. With it off
// the tenant chose the platform as executor, so only the cloud rule applies:
// a cloud address is unreachable from the platform whatever the switch says.
func decidePlatformTargets(targets []string, r autoScanReachability, strict bool) platformTargetsDecision {
	var out platformTargetsDecision
	byCollector := map[uuid.UUID]int{}
	for _, target := range targets {
		addr, err := netip.ParseAddr(strings.TrimSpace(target))
		if err != nil {
			out.Platform = append(out.Platform, target)
			continue
		}
		addr = addr.Unmap()
		seg, segPrefix, hasSeg := segmentFor(addr, r.Segments)

		var chosen *identityenrichment.Collector
		if hasSeg {
			for i := range r.Collectors {
				c := &r.Collectors[i]
				if c.Reaches(segPrefix) && !collectorIsHost(*c, addr) {
					chosen = c
					break
				}
			}
		}
		switch {
		case chosen != nil && strict:
			idx, ok := byCollector[chosen.ID]
			if !ok {
				out.ViaCollector = append(out.ViaCollector, reachedBy{Collector: *chosen})
				idx = len(out.ViaCollector) - 1
				byCollector[chosen.ID] = idx
			}
			out.ViaCollector[idx].Addresses = append(out.ViaCollector[idx].Addresses, target)
		case chosen != nil:
			out.Platform = append(out.Platform, target)
		case hasSeg && strings.EqualFold(strings.TrimSpace(seg.NetworkType), "cloud"):
			out.Unreachable = append(out.Unreachable, target)
		case strict && r.HasLiveSensors:
			out.Unreachable = append(out.Unreachable, target)
		default:
			out.Platform = append(out.Platform, target)
		}
	}
	return out
}

// segmentFor is the most specific registered segment containing addr.
func segmentFor(addr netip.Addr, segments []autoscan.Segment) (autoscan.Segment, netip.Prefix, bool) {
	var best autoscan.Segment
	var bestPrefix netip.Prefix
	found := false
	for _, seg := range segments {
		p, err := netip.ParsePrefix(strings.TrimSpace(seg.Value))
		if err != nil || !p.Contains(addr) {
			continue
		}
		if !found || p.Bits() > bestPrefix.Bits() {
			best, bestPrefix, found = seg, p.Masked(), true
		}
	}
	return best, bestPrefix, found
}

// collectorIsHost: never scan yourself.
func collectorIsHost(c identityenrichment.Collector, addr netip.Addr) bool {
	for _, a := range c.Addresses {
		if a.Addr() == addr {
			return true
		}
	}
	return false
}

// sensorFleet is the part of sensorrouting.Store the reach reader uses.
type sensorFleet interface {
	TenantSensors(ctx context.Context, tenantID uuid.UUID) ([]sensorrouting.Sensor, error)
}

// reachStore is the production autoScanReach.
type reachStore struct {
	db       *database.DB
	segments *autoscan.Store
	fleet    sensorFleet
}

// NewAutoScanReach builds the production reachability reader.
func NewAutoScanReach(db *database.DB, segments *autoscan.Store, fleet *sensorrouting.Store) *reachStore {
	return &reachStore{db: db, segments: segments, fleet: fleet}
}

func (r *reachStore) Reachability(ctx context.Context, tenantID uuid.UUID, now time.Time) (autoScanReachability, error) {
	var out autoScanReachability
	segs, err := r.segments.Segments(ctx, tenantID)
	if err != nil {
		return out, err
	}
	out.Segments = segs
	sensors, err := r.fleet.TenantSensors(ctx, tenantID)
	if err != nil {
		return out, err
	}
	for _, s := range sensors {
		if s.Dispatchable(now) {
			out.HasLiveSensors = true
			break
		}
	}
	err = database.WithTenantTx(ctx, r.db, tenantID, func(tx *sqlx.Tx) error {
		cs, err := identityenrichment.EligibleCollectors(ctx, tx, tenantID, now)
		out.Collectors = cs
		return err
	})
	if err != nil {
		return out, fmt.Errorf("read the tenant's collectors: %w", err)
	}
	return out, nil
}
