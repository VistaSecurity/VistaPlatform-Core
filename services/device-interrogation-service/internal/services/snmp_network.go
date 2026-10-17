package services

// The SNMP collector's slice of the intake seam (DCIM row 1.5d, ADR-0010 D3;
// the contract is docsv4/.../asset-inventory/identity-intake.md's row 1.5a
// addendum).
//
// shared/deviceinterrogation's SNMP interrogator walks ifTable/ifXTable,
// ipAddressTable (ipAddrTable as the fallback), the Q-BRIDGE static VLAN
// tables and the ARP cache, and returns them as InterrogateResult.Network. The
// collector writes nothing: this file turns that into the sighting the
// platform posts, and inventory-service's identity engine files the interfaces,
// addresses and VLANs from it — the one path every source writes interfaces by.
// The `net.interfaces` fact is not written for SNMP any more.
//
// Two halves, deliberately:
//
//   - snmpNetworkSighting is the adapter: identifiers + the device's own
//     interfaces, VLANs and prefixes, pure and database-free so
//     identitytest.RunAdapterParity can drive it from a recorded walk.
//   - recordSNMPARPEvidence is the ARP rule. The ARP cache describes OTHER
//     devices' addresses: it is supporting evidence only. An address the
//     platform already holds on another asset gains the MAC it resolved to
//     (when it has none); an address nobody holds is PARKED as an unresolved
//     termination (producer `snmp`, intent `assignment`, far identity the MAC)
//     for the day an asset with that MAC arrives. It never creates an asset,
//     an interface or an address.
//
// Posture only: the interrogator's Network is a typed projection, and it is
// converted here with unknown fields refused (decodeNetwork), so a field one
// side has and the other does not is a loud error, never a silently carried
// one.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// snmpProducer names this adapter in unresolved_terminations.producer.
const snmpProducer = "snmp"

// maxSNMPARPEvidence bounds the ARP rows one run records: the collector caps a
// walk at 500 rows, and this is the same ceiling stated where the rows are
// written.
const maxSNMPARPEvidence = 500

// decodedNetwork is the typed half of a di.NetworkObservation in identity's
// vocabulary.
type decodedNetwork struct {
	Interfaces []identity.ObservedInterface `json:"interfaces"`
	VLANs      []identity.ObservedVLAN      `json:"vlans"`
	Prefixes   []identity.ObservedPrefix    `json:"prefixes"`
	Tunnels    []identity.ObservedTunnel    `json:"tunnels"`
	Neighbors  []identity.ObservedNeighbor  `json:"neighbors"`
	// The hardware half (DCIM row 2.4).
	InventoryItems []identity.ObservedInventoryItem `json:"inventory_items"`
	Modules        []identity.ObservedModule        `json:"modules"`
	VirtualChassis *identity.ObservedVirtualChassis `json:"virtual_chassis"`
}

// decodeNetwork converts the collector's wire form to identity's observed
// types by their shared JSON names, refusing any field the other side lacks.
func decodeNetwork(n *di.NetworkObservation) (decodedNetwork, error) {
	var out decodedNetwork
	blob, err := json.Marshal(struct {
		Interfaces []di.ObservedInterface     `json:"interfaces"`
		VLANs      []di.ObservedVLAN          `json:"vlans"`
		Prefixes   []di.ObservedPrefix        `json:"prefixes"`
		Tunnels    []di.ObservedTunnel        `json:"tunnels"`
		Neighbors  []di.ObservedNeighbor      `json:"neighbors"`
		Items      []di.ObservedInventoryItem `json:"inventory_items"`
		Modules    []di.ObservedModule        `json:"modules"`
		Chassis    *di.ObservedVirtualChassis `json:"virtual_chassis"`
	}{n.Interfaces, n.VLANs, n.Prefixes, n.Tunnels, n.Neighbors, n.InventoryItems, n.Modules, n.VirtualChassis})
	if err != nil {
		return out, err
	}
	dec := json.NewDecoder(bytes.NewReader(blob))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("snmp network observation does not match the identity vocabulary: %w", err)
	}
	return out, nil
}

// snmpNetworkSighting is the SNMP adapter: the sighting for the interrogated
// device's own network posture. ids are the identifiers that bind it to the
// device (the asset's own, as inferred identifiers, in production; a measured
// serial in the parity test).
//
// The management address — the address the platform reached the device on — is
// listed among the identifiers when nothing else lists it, so the engine can
// make it the asset's primary address.
func snmpNetworkSighting(tenantID uuid.UUID, source identity.Source, at time.Time, ids []identity.SightedIdentifier, n *di.NetworkObservation) (identity.Sighting, error) {
	dn, err := decodeNetwork(n)
	if err != nil {
		return identity.Sighting{}, err
	}
	sg := identity.Sighting{
		TenantID:    tenantID.String(),
		Source:      source,
		Channel:     identity.ChannelAuthenticatedSession,
		ObservedAt:  at,
		Confidence:  1,
		Ownership:   identity.OwnershipInternal,
		Identifiers: append([]identity.SightedIdentifier(nil), ids...),
		Interfaces:  dn.Interfaces,
		VLANs:       dn.VLANs,
		Prefixes:    dn.Prefixes,
		Tunnels:     dn.Tunnels,
		Neighbors:   dn.Neighbors,

		InventoryItems: dn.InventoryItems,
		Modules:        dn.Modules,
		VirtualChassis: dn.VirtualChassis,
	}
	if m, err := netip.ParseAddr(strings.TrimSpace(n.ManagementAddress)); err == nil {
		sg.ManagementAddress = m.Unmap().String()
		listed := false
		for _, id := range sg.Identifiers {
			listed = listed || (id.Kind == identity.KindIPAddress && strings.TrimSpace(id.Value) == sg.ManagementAddress)
		}
		for _, ifc := range sg.Interfaces {
			for _, a := range ifc.Addresses {
				listed = listed || a.Address == sg.ManagementAddress
			}
		}
		if !listed {
			sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: sg.ManagementAddress})
		}
	}
	return sg, nil
}

// persistNetwork files an interrogation's network posture for assetID: the
// interfaces, addresses and VLANs through the identity engine, then the ARP
// cache as supporting evidence.
//
// The sighting is bound to the device by the identifiers the platform already
// holds for it (as selfIdentitySighting binds the serial): an interrogation is
// about the asset the session was opened to, and what it newly reports is only
// meaningful bound to that asset.
func (s *ObservationSink) persistNetwork(ctx context.Context, tenantID, assetID uuid.UUID, source identity.Source, at time.Time, n *di.NetworkObservation) error {
	if n.Empty() || s.db == nil {
		return nil
	}
	known, err := knownAssetIdentifiers(ctx, s.db, tenantID, assetID)
	if err != nil {
		return fmt.Errorf("network: reading the device's identifiers: %w", err)
	}
	if len(known) == 0 {
		log.Printf("[ObservationSink] network posture of asset %s not sent: the asset holds no identifier to bind it to", assetID)
		return nil
	}
	if len(n.Interfaces)+len(n.VLANs)+len(n.Prefixes)+len(n.Tunnels)+len(n.Neighbors) > 0 || n.HasHardware() {
		sg, err := snmpNetworkSighting(tenantID, source, at, known, n)
		if err != nil {
			return err
		}
		_, res, err := postSighting(ctx, s.db, sg)
		if err != nil {
			return fmt.Errorf("network: resolving the device's interfaces: %w", err)
		}
		if res.Asset.ID != assetID.String() {
			// A conflict (an address or MAC is another asset's: a merge
			// proposal is waiting) or evidence held for review. The engine said
			// so; the ARP cache is recorded against the device we were asked
			// about, not the asset the engine picked.
			log.Printf("[ObservationSink] network posture of asset %s resolved %s (asset %q, proposal %q); not recorded",
				assetID, res.Outcome, res.Asset.ID, res.Proposal.ID)
			return nil
		}
	}
	if len(n.ARP) > 0 {
		producer := n.Producer
		if producer == "" {
			producer = snmpProducer
		}
		return recordSNMPARPEvidence(ctx, s.db, tenantID, assetID, at, producer, n.ARP)
	}
	return nil
}

// recordSNMPARPEvidence applies the ARP rule. See the file header: supporting
// evidence about other devices' addresses; never an asset, interface or
// address; unknown addresses are parked.
//
// producer names the collector in the parked row: `snmp`, or the vendor
// collector (cisco, paloalto, fortinet, f5) since DCIM row 1.5c.
func recordSNMPARPEvidence(ctx context.Context, db *sql.DB, tenantID, assetID uuid.UUID, at time.Time, producer string, entries []di.ObservedARPEntry) error {
	if len(entries) > maxSNMPARPEvidence {
		entries = entries[:maxSNMPARPEvidence]
	}
	return shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		for _, e := range entries {
			addr, err := netip.ParseAddr(strings.TrimSpace(e.Address))
			mac, merr := identity.Normalize(identity.KindMACAddress, strings.TrimSpace(e.MAC))
			if err != nil || merr != nil || mac == "" {
				continue
			}
			addr = addr.Unmap()

			// Is the address already held, and by whom?
			var (
				ipID     uuid.UUID
				hasMAC   bool
				owner    sql.NullString
				found    = true
				queryErr error
			)
			queryErr = tx.QueryRowContext(ctx, `
				SELECT ip.id, ip.mac_address IS NOT NULL, i.asset_id::text
				  FROM public.ip_addresses ip
				  LEFT JOIN public.interfaces i ON i.tenant_id = ip.tenant_id AND i.id = ip.assigned_id AND ip.assigned_kind = 'interface'
				 WHERE ip.tenant_id = $1 AND ip.vrf_id IS NULL AND ip.host = $2::inet AND ip.status <> 'rejected'
				 ORDER BY ip.created_at LIMIT 1`, tenantID, addr.String()).Scan(&ipID, &hasMAC, &owner)
			if queryErr == sql.ErrNoRows {
				found = false
			} else if queryErr != nil {
				return fmt.Errorf("arp evidence for %s: %w", addr, queryErr)
			}

			if found {
				if owner.Valid && owner.String == assetID.String() {
					continue // the device's own address: not evidence about anyone else
				}
				if !hasMAC {
					if _, err := tx.ExecContext(ctx, `
						UPDATE public.ip_addresses SET mac_address = $3::macaddr8, updated_at = now()
						 WHERE tenant_id = $1 AND id = $2 AND mac_address IS NULL`, tenantID, ipID, mac); err != nil {
						return fmt.Errorf("arp evidence for %s: %w", addr, err)
					}
				}
				continue
			}

			// Nobody holds it: park it against the interface that learned it.
			if e.Interface == "" {
				continue
			}
			var ifaceID uuid.UUID
			err = tx.QueryRowContext(ctx, `
				SELECT id FROM public.interfaces
				 WHERE tenant_id = $1 AND asset_id = $2 AND name = $3 AND status <> 'rejected' LIMIT 1`,
				tenantID, assetID, e.Interface).Scan(&ifaceID)
			if err == sql.ErrNoRows {
				continue // the interface is not filed (the engine refused the sighting): nothing to anchor to
			}
			if err != nil {
				return fmt.Errorf("arp evidence for %s: %w", addr, err)
			}
			t := unresolved.Termination{
				Producer:    producer,
				OriginKind:  dcim.ObjectKind("interface"),
				OriginID:    ifaceID,
				FarIdentity: map[string]string{unresolved.KeyMACAddress: mac},
				Intent:      unresolved.IntentAssignment,
				Attributes:  map[string]any{"address": addr.String(), "learned_via": "arp"},
			}
			if err := t.Validate(); err != nil {
				return fmt.Errorf("arp evidence for %s: %w", addr, err)
			}
			if err := parkTermination(ctx, tx, tenantID, t, at); err != nil {
				return fmt.Errorf("arp evidence for %s: parking: %w", addr, err)
			}
		}
		return nil
	})
}

// parkTermination upserts an unresolved termination (the same statement as
// inventory-service's UnresolvedRepository.Park: insert, or bump the row with
// the same producer, origin, intent and far identity).
func parkTermination(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, t unresolved.Termination, seenAt time.Time) error {
	far, err := json.Marshal(t.FarIdentity)
	if err != nil {
		return err
	}
	attrs, err := json.Marshal(t.Attributes)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO public.unresolved_terminations AS u
			(tenant_id, producer, origin_kind, origin_id, far_identity, intent, attributes,
			 first_seen_at, last_seen_at, observation_count, expires_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::jsonb, $8, $8, 1, $9)
		ON CONFLICT (tenant_id, producer, origin_kind, origin_id, intent, far_identity) DO UPDATE SET
			observation_count = u.observation_count + 1,
			last_seen_at = GREATEST(u.last_seen_at, EXCLUDED.last_seen_at),
			expires_at = GREATEST(u.last_seen_at, EXCLUDED.last_seen_at) + ($10 * interval '1 second'),
			attributes = EXCLUDED.attributes,
			updated_at = now()`,
		tenantID, t.Producer, string(t.OriginKind), t.OriginID, string(far), t.Intent, string(attrs),
		seenAt, seenAt.Add(unresolved.DefaultTTL), int64(unresolved.DefaultTTL/time.Second))
	return err
}
