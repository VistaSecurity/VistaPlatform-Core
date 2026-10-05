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
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/attrlist"
	"github.com/vistasecurity/vistaplatform/shared/identity/classproposal"
	"github.com/vistasecurity/vistaplatform/shared/identity/hostnamequality"
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
// (the per-run net.vlans overlay is gone, item 7 — ensureVLANSegments still
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
// Every interface address is its own identifier, scoped by Intake on its own
// ( decision 1). An address the host reported as STATICALLY configured is
// SelfReported, which pins it (decision 1); one it reported as a DHCP lease
// carries that assignment and is never pinned; one it said nothing about is
// neither. The hostname is seen AT the primary address, so it takes that
// address's segment, else a domain segment, as it always did.
//
// The run's listening sockets are the endpoints, carrying the RUN's ref so the
// absent-endpoint sweep (closeAbsentEndpoints) can tell this run's rows from
// the last one's.
func hostSighting(tenantID uuid.UUID, subject di.PeerRef, meta hostInventoryMetadata, obs *di.InterrogateResult, source identity.Source, runRef string) (identity.Sighting, error) {
	primary := meta.primaryAddress(obs)
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
	for i, ha := range addrs {
		if ha.addr == primary && i > 0 {
			addrs[0], addrs[i] = addrs[i], addrs[0]
			break
		}
	}
	for _, ha := range addrs {
		out.Identifiers = append(out.Identifiers, identity.SightedIdentifier{
			Kind: identity.KindIPAddress, Value: ha.addr, Assignment: ha.assignment,
			Provenance: identity.IdentifierProvenance{SelfReported: ha.assignment == identity.AssignmentStatic},
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
	if len(out.Identifiers) == 0 {
		return identity.Sighting{}, errDeviceHasNoIdentifier
	}
	return out, nil
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
// Reads asset_identifiers through the tenant's RLS-scoped connection; this
// service no longer writes that table.
func knownAssetIdentifiers(ctx context.Context, db *sql.DB, tenantID, assetID uuid.UUID) ([]identity.SightedIdentifier, error) {
	var out []identity.SightedIdentifier
	ref := identity.IdentifierProvenance{Kind: identity.SourceInferred, Ref: assetIdentifierRefPrefix + assetID.String()}
	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT kind::text, value, coalesce(scope, '')
			FROM public.asset_identifiers
			WHERE tenant_id = $1 AND asset_id = $2 AND kind::text <> $3
			ORDER BY kind, value`, tenantID, assetID, string(identity.KindDeclarationID))
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var kind, value, scope string
			if err := rows.Scan(&kind, &value, &scope); err != nil {
				return err
			}
			sid := identity.SightedIdentifier{Kind: identity.Kind(kind), Value: value, Provenance: ref}
			if sid.Kind == identity.KindCMDBSysID {
				sid.Profile = scope
			}
			out = append(out, sid)
		}
		return rows.Err()
	})
	return out, err
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
