package services

// The sightings this service produces (platform ADR-0003 D3 step 2).
//
// Every path here that turns device evidence into identity states what it saw
// as an identity.Sighting — no scope, no dynamic flag, no admission flags —
// and inventory-service's identity.Intake decides the rest, the same way it
// does for every other collector. This file is the one place each path's
// sighting is built, so "what did the peer path claim" has one answer.
//
// Two things are decided HERE and nowhere else, because only the collector
// knows them:
//
//   - the Channel: how the evidence was taken (identity.ChannelAdmission maps
//     it to Direct / Relayed / Authoritative);
//   - each identifier's own provenance where it differs from the sighting's —
//     an address the host reported as its own static configuration, a value
//     the operator declared, the identifiers the platform already holds for an
//     asset it dispatched a session to.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/attrlist"
	"github.com/vistasecurity/vistaplatform/shared/identity/classproposal"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
	"github.com/vistasecurity/vistaplatform/shared/identity/identifiersql"
)

// peerConfidence is a peer sighting's confidence: a real measurement, but the
// device told us about its neighbour rather than us taking it ourselves.
const peerConfidence = 0.8

// peerChannel is how a collector came to know about a peer.
//
//   - A neighbour on one of the device's own interfaces (LLDP, CDP, a switch
//     port's client, a UniFi device seen online on its uplink) is a layer-2
//     binding: l2_frame.
//   - A controller listing a device it manages, not seen on an interface: the
//     controller's inventory, authoritative but not direct.
//   - Anything else a device said about a neighbour it did not verify is an
//     advertisement: it names a device without binding one.
//
// A peer that is BOTH (UniFi's adopted device that is online) is sent as
// l2_frame. The design note's disagreement 6: one sighting has one channel,
// and of the two the interface binding is the evidence that can admit a new
// device on its own — the controller's listing alone is supporting evidence.
// Sending it as controller_inventory would stop the controller path creating
// the devices it adopts.
func peerChannel(peer di.PeerRef) identity.Channel {
	switch {
	case peer.IdentityEvidence.ConnectedInterface:
		return identity.ChannelL2Frame
	case peer.IdentityEvidence.ControllerInventory:
		return identity.ChannelControllerInventory
	default:
		return identity.ChannelAdvertisement
	}
}

// peerSighting is the sighting for a peer a collector described.
//
// No endpoints: a neighbour seen over LLDP or adopted by a controller has not
// been observed listening on anything. No scope: every address is scoped on
// its own by Intake (the old path filed every address under the first one's
// scope, item 5), and DHCP posture is the segment's stored posture only
// (the per-run net.vlans overlay is gone, item 7 — ensureVLANPrefixes still
// records the run's measured posture on the segment BEFORE the peer is sent,
// which is the only way a run's answer reaches identity now).
//
// The rule-based classifier's answer is applied to the sighting's class hint
// exactly as it was to the observation; the proposal is returned for the
// caller to raise once it knows the asset.
func (s *ObservationSink) peerSighting(ctx context.Context, tenantID uuid.UUID, peer di.PeerRef, source identity.Source, at time.Time) (identity.Sighting, classify.ClassProposal, error) {
	out := identity.Sighting{
		TenantID:    tenantID.String(),
		Source:      source,
		Channel:     peerChannel(peer),
		ObservedAt:  at,
		ClassHint:   peer.ClassHint,
		DisplayName: strings.TrimSpace(peer.DisplayName),
		Confidence:  peerConfidence,
		// A peer of the tenant's own device, on the tenant's own network.
		Ownership: identity.OwnershipInternal,
	}
	usable := 0
	for _, id := range peer.Identifiers {
		kind := identity.Kind(id.Kind)
		if !kind.Valid() {
			// Pinned to identity's vocabulary by
			// TestPeerIdentifierKindsMatchIdentityRegistry; the loud failure if
			// that ever drifts.
			return identity.Sighting{}, classify.ClassProposal{}, fmt.Errorf("peer identifier kind %q is not one of the nine", id.Kind)
		}
		if strings.TrimSpace(id.Value) == "" {
			continue
		}
		out.Identifiers = append(out.Identifiers, identity.SightedIdentifier{Kind: kind, Value: id.Value})
		if peerIdentifierCanIdentify(kind, id.Value) {
			usable++
		}
	}
	if usable == 0 {
		// Every name is synthetic and every address rotates or is link-local
		// ( D1, D2). Intake would withhold all of it; sending it would
		// only earn an error. A skipped peer, not a failed job.
		if len(out.Identifiers) > 0 {
			return identity.Sighting{}, classify.ClassProposal{}, fmt.Errorf("%w: peer %q", errPeerSyntheticNamesOnly, out.DisplayName)
		}
		return identity.Sighting{}, classify.ClassProposal{}, fmt.Errorf("peer %q carries no usable identifier", out.DisplayName)
	}

	// What a controller reported of the peer's interfaces and networks
	// (DCIM row 1.5b): the engine records them once the sighting resolves.
	if n, ok := subjectNetworkFor(ctx, peer); ok {
		n.applyTo(&out, peer)
	}

	// The class: a RULE's answer fills a hint the collector did not set, with
	// its provenance; anything else is a proposal raised after resolution.
	prop := s.applyPeerClassRules(ctx, peer)
	applyClassToSighting(&out, prop)
	return out, prop, nil
}

// peerIdentifierCanIdentify is the snapshot-free half of Intake's hygiene: a
// synthetic name and a temporary or link-local IPv6 address never become
// identifiers. (A link-local address does inside a real segment; that needs
// the snapshot, so it is counted as unusable here, which errs towards
// skipping a peer whose ONLY identity is a link-local address.)
func peerIdentifierCanIdentify(kind identity.Kind, value string) bool {
	switch kind {
	case identity.KindHostname, identity.KindFQDN:
		return hostnamequality.IsIdentityName(value)
	case identity.KindIPAddress:
		addr, err := netip.ParseAddr(strings.TrimSpace(value))
		if err != nil {
			return true // Intake rejects it and says why
		}
		return attrlist.AddressAttribute(addr, false) == ""
	}
	return true
}

// hostSighting is the sighting for one host inventory: the host's own account
// of itself, taken by its agent or over an authenticated session to it.
//
// Every address the host reported is sent ( WP7), each scoped by Intake
// on its own ( decision 1). An address the host reported as STATICALLY
// configured is SelfReported, which pins it (decision 1); one it reported as a
// DHCP lease carries that assignment and is never pinned; one it said nothing
// about is neither. An address on a VIRTUAL interface is sent with that
// provenance (IdentifierProvenance.VirtualInterface): Intake keeps it as
// attribute evidence, never as an identifier, instead of this file dropping it.
//
// managed is the address the platform knows the host by (managedAddress: the
// remote job's target, or the agent's own reported address). It is sent too
// when the interface list does not already carry it, it is the primary when
// the interfaces offer none — so a report with no `net.interfaces` section
// still reaches the engine with an address — and it is the host's MANAGEMENT
// address (Sighting.ManagementAddress, DCIM row 1.5), which the engine makes
// the asset's primary IP of its family whatever order the interfaces came in.
//
// The host's interfaces ride on the sighting as identity.ObservedInterfaces
// (hostInventoryInterfaces): one per real interface as the OS reported it,
// with its addresses, MTU, speed and state, a VLAN sub-interface as its parent
// plus its untagged VLAN, a bond member with its LAG. Intake names this
// sighting's MACs and addresses by the interface that carries them, and the
// engine writes the interfaces. The hostname is seen AT
// the primary address, so it takes that address's segment, else a domain
// segment, as it always did.
//
// The run's listening sockets are the endpoints, carrying the RUN's ref under
// the agent's prefix, which is what lets the engine's reconciliation
// (EndpointsComplete, set by the caller when the list is licensed) tell this
// run's sockets from the last one's.
func hostSighting(tenantID uuid.UUID, subject di.PeerRef, meta hostInventoryMetadata, obs *di.InterrogateResult, source identity.Source, runRef, managed string) (identity.Sighting, error) {
	primary := meta.primaryAddress(obs)
	if primary == "" {
		primary = managed
	}
	out := identity.Sighting{
		TenantID:   tenantID.String(),
		Source:     source,
		Channel:    identity.ChannelAuthenticatedSession,
		ObservedAt: meta.collectedAt(),
		ReceiptID:  runRef,
		// Coarse and true: a class is a rule's decision (see the file header
		// of host_inventory_ingest.go).
		ClassHint:   assetclass.KeyUnknownHost,
		DisplayName: strings.TrimSpace(subject.DisplayName),
		Confidence:  1,
		Ownership:   identity.OwnershipInternal,
	}
	if out.DisplayName == "" {
		out.DisplayName = primary
	}

	// Addresses first, the primary leading, so the sighting's own segment is
	// the primary's whenever the primary is inside one.
	addrs := meta.hostAddresses(obs)
	listed := false
	for _, ha := range addrs {
		listed = listed || ha.addr == managed
	}
	if managed != "" && !listed {
		addrs = append(addrs, hostAddress{addr: managed})
	}
	for i, ha := range addrs {
		if ha.addr == primary && i > 0 {
			addrs[0], addrs[i] = addrs[i], addrs[0]
			break
		}
	}
	for _, ha := range addrs {
		out.Identifiers = append(out.Identifiers, identity.SightedIdentifier{
			Kind: identity.KindIPAddress, Value: ha.addr, Assignment: ha.assignment,
			Provenance: identity.IdentifierProvenance{
				SelfReported:     ha.assignment == identity.AssignmentStatic && !ha.virtual,
				VirtualInterface: ha.virtual,
			},
		})
	}
	for _, id := range subject.Identifiers {
		kind := identity.Kind(id.Kind)
		if !kind.Valid() {
			return identity.Sighting{}, fmt.Errorf("host inventory: identifier kind %q is not one of the ten", id.Kind)
		}
		sid := identity.SightedIdentifier{Kind: kind, Value: id.Value}
		if kind == identity.KindHostname || kind == identity.KindFQDN {
			sid.Address = primary
		}
		out.Identifiers = append(out.Identifiers, sid)
	}
	out.ManagementAddress = managed
	out.Interfaces, out.VLANs = hostInventoryInterfaces(obs)
	out.Endpoints = hostInventoryEndpoints(obs, meta, primary, identity.Source{
		Kind: identity.SourceMeasured, Ref: runRef, Mode: identity.ModeActive,
	})
	if len(out.Identifiers) == 0 {
		return identity.Sighting{}, fmt.Errorf(
			"host inventory: %s carries no usable identifier; an asset created from it could never be recognised again, so a new one would appear on every collection",
			meta.label())
	}
	return out, nil
}

// deviceSightingInput is a device sighting's input beyond deviceObservationInput.
type deviceSightingInput struct {
	deviceObservationInput
	// Channel is how the device became known: ChannelPerson for the form,
	// ChannelAuthenticatedSession for Add device after its own probe logged in
	// and read the device's identity, ChannelAPI for a cloud collector.
	Channel identity.Channel
	// ProbeMACAddress is the MAC Add device's probe read from the device over
	// its authenticated session. It used to reach metadata only ( item
	// 10, the duplicate gateway); it is an identifier.
	ProbeMACAddress string
	// ProbeRead names which of the form's address, hostname and serial the
	// probe filled in from the device rather than the operator typing them.
	ProbeRead models.ProbeReadValues
	// ProbeSSHHostKey and ProbeSSHHostKeyType are the host key the probe
	// authenticated through ( D4).
	ProbeSSHHostKey     string
	ProbeSSHHostKeyType string
	// DeclaredMAC and InterfaceName are the interface the form's address is
	// on, as the person typed it (DCIM row 1.5f).
	DeclaredMAC   string
	InterfaceName string
}

// deviceChannel is the channel a create's admission evidence implies, for the
// callers that still speak in AdmissionEvidence: the probe's Direct +
// Authoritative is an authenticated session, a cloud collector's
// Authoritative alone is an API, nothing is a person.
func deviceChannel(e identity.AdmissionEvidence) identity.Channel {
	switch {
	case e.Direct && e.Authoritative:
		return identity.ChannelAuthenticatedSession
	case e.Authoritative:
		return identity.ChannelAPI
	default:
		return identity.ChannelPerson
	}
}

// deviceSighting is the sighting for a device added through the form (typed or
// probed) or read through a cloud API.
//
// Each address the form carries is sent ONCE: the IP field, an address typed
// into the name field and the management URL's host are one identifier when
// they are one address (: the IP and the management URL host used to be
// sent twice). The probe's MAC is an identifier, so a probed device on a DHCP
// LAN meets the asset that already owns that MAC instead of minting a second
// one ( item 10).
func deviceSighting(tenantID uuid.UUID, in deviceSightingInput) (identity.Sighting, error) {
	host := strings.TrimSpace(in.Hostname)
	out := identity.Sighting{
		TenantID:        tenantID.String(),
		Source:          in.Source,
		Channel:         in.Channel,
		ObservedAt:      in.ObservedAt,
		ReceiptID:       in.Admission.ReceiptID,
		ClassHint:       DeviceTypeClassKey(in.DeviceType),
		DisplayName:     host,
		Confidence:      1,
		Ownership:       identity.OwnershipInternal,
		CloudNetworkRef: in.CloudNetworkRef,
	}
	if out.Channel == "" {
		out.Channel = deviceChannel(in.Admission)
	}
	add := func(sid identity.SightedIdentifier) {
		if strings.TrimSpace(sid.Value) != "" {
			out.Identifiers = append(out.Identifiers, sid)
		}
	}
	// Per-identifier provenance: a value Add device's probe READ off the
	// device (its own address, name, serial — never the address the
	// operator dialled) is measured; only what the person typed is declared.
	// A value both typed and read stays declared.
	typed := map[string]bool{strings.ToLower(managementHost(in.ManagementURL)): true}
	for field, value := range map[string]string{"ip": in.IPAddress, "host": host, "serial": in.SerialNumber} {
		if v := strings.ToLower(strings.TrimSpace(value)); v != "" && v != strings.ToLower(in.ProbeRead.Value(field)) {
			typed[v] = true
		}
	}
	provenance := func(v string) identity.IdentifierProvenance {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" && !typed[v] && in.ProbeRead.Has(v) {
			return identity.IdentifierProvenance{Kind: identity.SourceMeasured}
		}
		return identity.IdentifierProvenance{}
	}
	// Addresses before names, so the sighting's segment is an address's.
	values := dedupeStrings(in.IPAddress, host, managementHost(in.ManagementURL))
	for _, v := range values {
		if net.ParseIP(v) != nil {
			add(identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: v, Provenance: provenance(v)})
		}
	}
	for _, v := range values {
		if net.ParseIP(v) == nil {
			// Intake files a dotted name as an fqdn and a bare one as a
			// hostname, whichever is written here.
			add(identity.SightedIdentifier{Kind: identity.KindHostname, Value: v, Provenance: provenance(v)})
		}
	}
	add(identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: strings.TrimSpace(in.SerialNumber), Provenance: provenance(in.SerialNumber)})
	add(identity.SightedIdentifier{Kind: identity.KindCloudResourceID, Value: strings.TrimSpace(in.CloudResourceID)})
	if mac := strings.TrimSpace(in.ProbeMACAddress); mac != "" {
		// Read from the device, not typed: measured, whatever the sighting's
		// declared source says about the rest of the form.
		add(identity.SightedIdentifier{Kind: identity.KindMACAddress, Value: mac,
			Provenance: identity.IdentifierProvenance{Kind: identity.SourceMeasured}})
	}
	if fp := strings.TrimSpace(in.ProbeSSHHostKey); fp != "" {
		add(identity.SightedIdentifier{Kind: identity.KindSSHHostKeyFingerprint, Value: fp,
			KeyAlgorithm: in.ProbeSSHHostKeyType,
			Provenance:   identity.IdentifierProvenance{Kind: identity.SourceMeasured}})
	}
	declaredDeviceInterface(&out, in.InterfaceName, in.DeclaredMAC, in.IPAddress)
	if len(out.Identifiers) == 0 && len(out.Interfaces) == 0 {
		return identity.Sighting{}, errDeviceHasNoIdentifier
	}
	return out, nil
}

// declaredDeviceInterface is the manual Add device adapter of the row 1.5
// intake seam (DCIM row 1.5f): the interface a person typed for the device's
// address. A named one is a declared ObservedInterface carrying the MAC and
// the address — Intake folds both into identifiers named by it; with no name
// the MAC is a declared identifier beside the address, and the engine files
// the two on the one interface it names (row 1.4's rule). Nothing is invented.
func declaredDeviceInterface(s *identity.Sighting, name, mac, address string) {
	name, mac, address = strings.TrimSpace(name), strings.TrimSpace(mac), strings.TrimSpace(address)
	if name == "" {
		if mac != "" {
			s.Identifiers = append(s.Identifiers, identity.SightedIdentifier{Kind: identity.KindMACAddress, Value: mac})
		}
		return
	}
	ifc := identity.ObservedInterface{Name: name, MAC: mac}
	if net.ParseIP(address) != nil {
		ifc.Addresses = []identity.ObservedAddress{{Address: address}}
	}
	s.Interfaces = append(s.Interfaces, ifc)
}

// assetIdentifierRefPrefix is the evidence ref of an identifier a sighting
// carries because the platform already holds it for the asset the evidence is
// about: `asset:<id>`.
const assetIdentifierRefPrefix = "asset:"

// knownAssetIdentifiers reads the identifiers the platform holds for an asset,
// as INFERRED sighted identifiers (ref `asset:<id>`).
//
// A device update and an interrogation's self-identity are about an asset the
// platform already chose: the operator is editing THAT device, the session was
// dispatched to THAT device. What they newly report (a serial, an address) is
// only meaningful bound to it, and the engine can only bind it through
// identifiers. Carrying the asset's own identifiers as inferred gives the
// engine that binding without claiming anything was re-measured: an inferred
// identifier never creates an asset, votes only after every native value has
// had its say, and never downgrades the stored row's provenance. A new value
// nobody owns then attaches to the asset it was reported for; a value another
// asset owns is a conflict for a human (a merge proposal), not a skipped
// write the operator is told succeeded ( item 4).
//
// Each address and MAC carries the name of the (non-synthetic) interface that
// holds it (DCIM row 1.5c). Without it the engine planned every carried
// address as one unnamed group and filed the group under whichever interface
// held ANY of them: on a device with several addressed interfaces (a switch's
// SVIs, a firewall's sub-interfaces) a serial or interface-MAC sighting moved
// an address onto the wrong interface, or, once a learned prefix had rescoped
// the address, wrote it a second time there. A synthetic `observed-<n>`
// interface is not named, so a later named report can still rename it.
//
// Reads asset_identifiers through the tenant's RLS-scoped connection; this
// service no longer writes that table.
func knownAssetIdentifiers(ctx context.Context, db *sql.DB, tenantID, assetID uuid.UUID) ([]identity.SightedIdentifier, error) {
	var out []identity.SightedIdentifier
	ref := identity.IdentifierProvenance{Kind: identity.SourceInferred, Ref: assetIdentifierRefPrefix + assetID.String()}
	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT ai.kind::text, ai.value, coalesce(ai.scope, ''), coalesce(n.name, '')
			FROM (`+identifiersql.All+`) ai
			LEFT JOIN LATERAL (
				SELECT ifc.name FROM public.ip_addresses ip
				  JOIN public.interfaces ifc ON ifc.tenant_id = ip.tenant_id AND ifc.id = ip.assigned_id
				 WHERE ai.kind::text = 'ip_address' AND ip.tenant_id = ai.tenant_id AND ip.id = ai.id
				   AND ip.assigned_kind = 'interface' AND coalesce(ifc.source_ref, '') <> $4
				UNION ALL
				SELECT ifc.name FROM public.interfaces ifc
				 WHERE ai.kind::text = 'mac_address' AND ifc.tenant_id = ai.tenant_id AND ifc.asset_id = ai.asset_id
				   AND ifc.status <> 'rejected' AND coalesce(ifc.source_ref, '') <> $4
				   AND ifc.mac_address = (CASE WHEN ai.kind::text = 'mac_address' THEN ai.value END)::macaddr8
				LIMIT 1) n ON true
			WHERE ai.tenant_id = $1 AND ai.asset_id = $2 AND ai.kind::text <> $3
			ORDER BY ai.kind, ai.value`, tenantID, assetID, string(identity.KindDeclarationID), identity.SyntheticInterfaceSourceRef)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var kind, value, scope, iface string
			if err := rows.Scan(&kind, &value, &scope, &iface); err != nil {
				return err
			}
			sid := identity.SightedIdentifier{Kind: identity.Kind(kind), Value: value, Provenance: ref, Interface: iface}
			if sid.Kind == identity.KindCMDBSysID {
				sid.Profile = scope
			}
			out = append(out, sid)
		}
		return rows.Err()
	})
	return out, err
}

// assetOwns reports whether the identifiers the platform already holds for an
// asset (knownAssetIdentifiers) include this kind and value. The value is
// compared in its normal form, as asset_identifiers stores it.
//
// A first-hand sighting of an identifier the asset already owns changes
// nothing the engine keeps for the asset, but its source ref is the job
// (`interrogation:<jobID>`), so under enforced admission every run mints a new
// retained identity_observations row that never expires. A caller whose
// sighting adds nothing but that row sends it only for a value this reports
// as new to the asset.
func assetOwns(known []identity.SightedIdentifier, kind identity.Kind, value string) bool {
	want, err := identity.Normalize(kind, value)
	if err != nil {
		want = strings.TrimSpace(value)
	}
	for _, k := range known {
		if k.Kind != kind {
			continue
		}
		have, err := identity.Normalize(k.Kind, k.Value)
		if err != nil {
			have = strings.TrimSpace(k.Value)
		}
		if have == want {
			return true
		}
	}
	return false
}

// selfIdentitySighting is what an interrogation's own DeviceIdentity says
// about the device it logged in to: the serial it read, over the session the
// platform opened to the asset it dispatched the job to ( item 4: this
// used to be a direct AttachIdentifiers with no engine and no scope check).
func selfIdentitySighting(tenantID uuid.UUID, source identity.Source, at time.Time, serial string, known []identity.SightedIdentifier) identity.Sighting {
	ids := []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: serial}}
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

// deviceUpdateSighting is an operator's edit of an existing device's
// identity: the hostname, address or serial they typed, DECLARED. It is sent
// as a declaration for the device being edited (postDeclaration with the
// asset id): owner decision 1 and ADR-0003 D1 — a person naming the asset is
// the decision, so the values attach to it at once and a typed address is
// pinned (`address_assignment = static`). It used to be a direct
// AttachIdentifiers that skipped a conflicting value and told the operator
// the edit succeeded ( item 4); a value another asset owns is now a 409
// with the merge proposal, exactly as the asset page's identifier edit.
func deviceUpdateSighting(tenantID uuid.UUID, at time.Time, hostname, ip, serial string) (identity.Sighting, bool) {
	out := identity.Sighting{
		TenantID:   tenantID.String(),
		Source:     declaredSource(),
		Channel:    identity.ChannelPerson,
		ObservedAt: at,
		Confidence: 1,
		Ownership:  identity.OwnershipInternal,
	}
	if a := strings.TrimSpace(ip); a != "" {
		out.Identifiers = append(out.Identifiers, identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: a})
	}
	if h := strings.TrimSpace(hostname); h != "" {
		kind := identity.KindHostname
		if net.ParseIP(h) != nil {
			kind = identity.KindIPAddress
		}
		out.Identifiers = append(out.Identifiers, identity.SightedIdentifier{Kind: kind, Value: h})
	}
	if s := strings.TrimSpace(serial); s != "" {
		out.Identifiers = append(out.Identifiers, identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: s})
	}
	if len(out.Identifiers) == 0 {
		return identity.Sighting{}, false
	}
	return out, true
}

// applyClassToSighting is classproposal.Apply for a sighting: a rule's class
// fills an unassigned class hint, with the rule as its provenance. It reports
// whether it did.
func applyClassToSighting(s *identity.Sighting, prop classify.ClassProposal) bool {
	hinted := identity.Observation{ClassHint: s.ClassHint, ClassProvenance: s.ClassProvenance}
	applied := classproposal.Apply(&hinted, prop)
	s.ClassHint, s.ClassProvenance = hinted.ClassHint, hinted.ClassProvenance
	return applied
}

// sightingReceiptKey names one delivery of a sighting in this service's
// retained-context tables (identity_observation_host_inventories,
// identity_observation_cloud_contexts). It used to be
// identity.ObservationReceiptKey of the observation this service built; the
// observation is inventory-service's now, so the key is the sighting's own: a
// digest of exactly what was sent, which a replay of the same envelope
// reproduces.
func sightingReceiptKey(s identity.Sighting) string {
	b, _ := json.Marshal(s)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// hostInterfaceItem is one entry of the host's interface list as the agent
// sends it (the net.interfaces shape, hostinventory.projectInterfaces). Typed,
// so a field the agent never sent — or a future one nobody reviewed — is
// discarded structurally rather than carried along.
type hostInterfaceItem struct {
	Name             string   `json:"name"`
	MAC              string   `json:"mac"`
	Addresses        []string `json:"addresses"`
	StaticAddresses  []string `json:"static_addresses"`
	DynamicAddresses []string `json:"dynamic_addresses"`
	State            string   `json:"state"`
	Virtual          bool     `json:"virtual"`
	MTU              int      `json:"mtu"`
	SpeedMbps        int64    `json:"speed"`
	Kind             string   `json:"kind"`
	Parent           string   `json:"parent"`
	VLAN             int      `json:"vlan"`
	LAG              string   `json:"lag"`
}

// hostInventoryInterfaces projects the host's interface list onto
// identity.ObservedInterfaces, and the VLANs its sub-interfaces carry onto
// identity.ObservedVLANs.
//
//   - One per REAL interface, as the OS reported it. A virtual one (loopback,
//     a container veth or bridge, a tunnel) is left out: its MAC is generated
//     and its addresses exist only inside the machine — the same rule that
//     keeps them out of identity (hostAddresses, hostPeerRef) — and a
//     container host would otherwise grow an interface per container start.
//   - Its MAC only when the identity rule would use it: a locally
//     administered MAC is software-assigned and never identifies a host.
//   - Its addresses exactly as identity takes them (hostAddresses' filter:
//     no loopback, link-local or temporary IPv6 privacy address), each with
//     the length the host configured and the assignment it reported.
//   - A VLAN sub-interface (`bond0.100`) is its parent plus its untagged VLAN
//     in access mode; a bond or team member names its LAG; a bond is type
//     `lag`. Nothing else is inferred: a speed is not turned into a media
//     type, which would be a guess.
//
// No prefixes: a host's view of its own subnet is not a measurement of the
// network's prefix (see identity.ObservedPrefix).
func hostInventoryInterfaces(obs *di.InterrogateResult) ([]identity.ObservedInterface, []identity.ObservedVLAN) {
	var (
		ifaces []identity.ObservedInterface
		vlans  []identity.ObservedVLAN
		seenV  = map[int]bool{}
	)
	for _, f := range obs.Facts {
		if f.Key != facts.KeyNetInterfaces {
			continue
		}
		blob, err := json.Marshal(f.Value)
		if err != nil {
			continue
		}
		var items []hostInterfaceItem
		if err := json.Unmarshal(blob, &items); err != nil {
			continue
		}
		for _, it := range items {
			if it.Virtual || strings.TrimSpace(it.Name) == "" {
				continue
			}
			o := identity.ObservedInterface{Name: it.Name}
			if m := normaliseHostMAC(it.MAC); m != "" {
				o.MAC = m
			}
			if it.MTU > 0 {
				mtu := it.MTU
				o.MTU = &mtu
			}
			if it.SpeedMbps > 0 {
				kbps := it.SpeedMbps * 1000
				o.SpeedKbps = &kbps
			}
			switch it.State {
			case "up", "down", "unknown":
				o.OperStatus = it.State
			}
			switch it.Kind {
			case "bond", "team":
				o.Type = "lag"
			case "vlan":
				o.Type = "virtual"
			}
			o.LAG = it.LAG
			if it.VLAN >= 1 && it.VLAN <= 4094 {
				if it.Parent != "" {
					o.Parent = it.Parent
				}
				o.Mode, o.UntaggedVLAN = "access", it.VLAN
				if !seenV[it.VLAN] {
					seenV[it.VLAN] = true
					vlans = append(vlans, identity.ObservedVLAN{VID: it.VLAN})
				}
			}
			assigned := map[string]identity.AddressAssignment{}
			for _, raw := range it.StaticAddresses {
				assigned[strings.TrimSpace(raw)] = identity.AssignmentStatic
			}
			for _, raw := range it.DynamicAddresses {
				assigned[strings.TrimSpace(raw)] = identity.AssignmentDynamic
			}
			for _, raw := range it.Addresses {
				a, ok := parseHostAddress(raw)
				if !ok || attrlist.AddressAttribute(netip.MustParseAddr(a), false) != "" {
					continue
				}
				oa := identity.ObservedAddress{Address: a, Source: "agent", Assignment: assigned[strings.TrimSpace(raw)]}
				if p, err := netip.ParsePrefix(strings.TrimSpace(raw)); err == nil {
					oa.PrefixLen = p.Bits()
				}
				o.Addresses = append(o.Addresses, oa)
			}
			ifaces = append(ifaces, o)
		}
	}
	return ifaces, vlans
}

// normaliseHostMAC is a host interface's MAC as identity would take it: a
// well-formed, globally administered MAC, else "".
func normaliseHostMAC(v string) string {
	m, err := identity.Normalize(identity.KindMACAddress, strings.TrimSpace(v))
	if err != nil || m == "" {
		return ""
	}
	hw, err := net.ParseMAC(m)
	if err != nil || len(hw) == 0 || hw[0]&0x02 != 0 {
		return ""
	}
	return m
}
