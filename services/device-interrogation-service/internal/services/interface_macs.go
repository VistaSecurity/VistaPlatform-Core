package services

// An interrogated device owns every interface MAC it reports.
//
// A router or firewall with one MAC per interface reports them all in its
// `net.interfaces` fact, but only the MAC it was first found by became an
// identifier of the asset. When a passive sensor later heard the device answer
// from another interface's MAC, the engine saw "the address is kept, the
// hardware changed" and opened a "replaced" merge proposal against the
// device's own asset. Binding each interface MAC to the asset, in a first-hand
// sighting over the authenticated session, closes that: the engine matches a
// later sighting from any interface to this asset.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
)

// maxInterfaceMACsPerPost bounds one post, well under inventory-service's
// MaxSightingsPerCall.
const maxInterfaceMACsPerPost = 100

// selfInterfaceMACs returns the usable interface MACs of the device ITSELF
// (facts about a peer carry a Subject and are not the device's own).
func selfInterfaceMACs(fs []di.FactObservation) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range fs {
		if f.Key != facts.KeyNetInterfaces || !f.Subject.IsZero() {
			continue
		}
		for _, m := range di.InterfaceMACs(f.Value) {
			if !seen[m] {
				seen[m] = true
				out = append(out, m)
			}
		}
	}
	return out
}

// interfaceMACSighting is the first-hand sighting of one interface MAC of the
// device, read over the session the platform opened to it and bound to it by
// the identifiers the platform already holds (as selfIdentitySighting binds
// the serial).
func interfaceMACSighting(tenantID uuid.UUID, source identity.Source, at time.Time, mac string, known []identity.SightedIdentifier) identity.Sighting {
	ids := []identity.SightedIdentifier{{
		Kind:       identity.KindMACAddress,
		Value:      mac,
		Provenance: identity.IdentifierProvenance{SelfReported: true},
	}}
	return identity.Sighting{
		TenantID:    tenantID.String(),
		Source:      source,
		Channel:     identity.ChannelAuthenticatedSession,
		ObservedAt:  at,
		Confidence:  1,
		Ownership:   identity.OwnershipInternal,
		Identifiers: append(ids, known...),
	}
}

// persistInterfaceMACs attaches every interface MAC the device reported to it.
// One sighting per MAC, so one contested MAC does not hold up the others,
// and only for a MAC the asset does not already own.
func (s *ObservationSink) persistInterfaceMACs(ctx context.Context, tenantID, assetID uuid.UUID, source identity.Source, at time.Time, fs []di.FactObservation) error {
	macs := selfInterfaceMACs(fs)
	if s.db == nil || len(macs) == 0 {
		return nil
	}
	known, err := knownAssetIdentifiers(ctx, s.db, tenantID, assetID)
	if err != nil {
		return fmt.Errorf("interface MACs: reading the device's identifiers: %w", err)
	}
	if len(known) == 0 {
		log.Printf("[ObservationSink] %d interface MAC(s) of asset %s not sent: the asset holds no identifier to bind them to", len(macs), assetID)
		return nil
	}
	// Only a MAC new to the asset is sighted. One it already owns would add
	// nothing but a retained observation row per run (the source ref is the
	// job), for every interface, forever.
	fresh := macs[:0:0]
	for _, m := range macs {
		if !assetOwns(known, identity.KindMACAddress, m) {
			fresh = append(fresh, m)
		}
	}
	macs = fresh
	if len(macs) == 0 {
		return nil
	}
	poster, err := sightingPoster(s.db)
	if err != nil {
		return err
	}
	items := make([]sightingclient.Item, 0, len(macs))
	for _, m := range macs {
		items = append(items, sightingclient.Item{Sighting: interfaceMACSighting(tenantID, source, at, m, known)})
	}
	var errs []error
	for start := 0; start < len(items); start += maxInterfaceMACsPerPost {
		end := min(start+maxInterfaceMACsPerPost, len(items))
		results, err := poster.PostItems(ctx, tenantID.String(), items[start:end])
		if err != nil {
			errs = append(errs, fmt.Errorf("interface MACs: posting: %w", err))
			continue
		}
		for i, r := range results {
			mac := macs[start+i]
			switch {
			case r.Rejected():
				log.Printf("[ObservationSink] interface MAC %s of asset %s refused: %s", mac, assetID, strings.Join(r.Reasons, ", "))
			case r.AssetID != assetID.String():
				log.Printf("[ObservationSink] interface MAC %s of asset %s resolved %s (asset %q, proposal %q); not attached",
					mac, assetID, r.Outcome, r.AssetID, r.ProposalID)
			}
		}
	}
	return errors.Join(errs...)
}
