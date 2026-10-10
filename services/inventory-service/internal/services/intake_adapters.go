package services

// The intake adapters ( phase 2, platform ADR-0003).
//
// Every path in this service that turns device evidence into identity used to
// build its identity.Observation by hand, and each one decided for itself which
// segment an address belonged to, whether that segment was dynamic, and which
// admission flags the evidence earned. The same device with the same evidence
// then got opposite outcomes depending on the path that carried it.
//
// Each path now states only WHAT it saw, as an identity.Sighting — the
// identifiers in the collector's order, each name with the address it was seen
// at, the channel the evidence arrived through — and identity.Intake decides
// scope, dynamic scopes, admission flags and identifier hygiene once, for all
// of them (shared/identity/intake.go; design note
// docsv4/internal/developer/design/asset-inventory/identity-intake.md).
//
// What stays here is what only this service knows: which channel a finding
// came through (a completed TLS/SSH exchange is an L3 probe; a cloud listing
// the platform's own collector wrote is an API listing), whether a sensor's
// self-report checks out against the sensors table, and how a person's form
// maps onto identifiers.

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// intake returns the service's one identity.Intake, building it on first use
// over the identity repository and the shared generic-name decider.
//
// With no database — the pure-unit-test shape every builder has always
// supported — it runs over an empty in-memory repository: no segments, so
// every address and name lands in the tenant default, which is exactly what
// the builders answered without a database before.
func (s *AssetService) intake() (*identity.Intake, error) {
	s.intakeOnce.Do(func() {
		if s.db == nil || s.db.DB == nil {
			s.intakeVal, s.intakeErr = identity.NewIntake(memory.New(), identity.WithIntakeGenericNames(nil))
			return
		}
		if _, err := s.identityEngine(); err != nil {
			s.intakeErr = err
			return
		}
		s.intakeVal, s.intakeErr = identity.NewIntake(s.identityRepo, identity.WithIntakeGenericNames(s.genericNames()))
	})
	return s.intakeVal, s.intakeErr
}

// assessSighting runs a sighting through the intake and logs what it refused,
// so a malformed MAC or a withheld rotating address is never dropped quietly.
// The result is returned in full even with identity.ErrNoUsableIdentifier, so
// a caller can still record what was withheld.
func (s *AssetService) assessSighting(ctx context.Context, label string, sg identity.Sighting) (identity.IntakeResult, error) {
	return s.assessSightingIn(ctx, nil, label, sg)
}

// assessSightingIn is assessSighting scoped against the request's one segment
// snapshot ( F4); a nil segs reads a snapshot for this sighting alone.
func (s *AssetService) assessSightingIn(ctx context.Context, segs *importSegments, label string, sg identity.Sighting) (identity.IntakeResult, error) {
	in, err := s.intake()
	if err != nil {
		return identity.IntakeResult{}, fmt.Errorf("identity intake unavailable: %w", err)
	}
	var res identity.IntakeResult
	if segs != nil && sg.TenantID == segs.tenantID.String() {
		snap, serr := segs.snapshot(ctx, in)
		if serr != nil {
			return identity.IntakeResult{}, serr
		}
		res, err = in.AssessWithSnapshot(ctx, sg, snap)
	} else {
		res, err = in.Assess(ctx, sg)
	}
	for _, r := range res.Rejected {
		log.Printf("[AssetService] identity: %s dropped a %s identifier: %v", label, r.Identifier.Kind, r.Err)
	}
	for _, w := range res.Withheld {
		log.Printf("[AssetService] identity: %s: %s=%q is not used as an identifier (%s)", label, w.Kind, w.Value, w.Reason)
	}
	return res, err
}

// ---------------------------------------------------------------------------
// Discovery findings (sensor, active scan, PCAP, cloud, interrogation rows)
// ---------------------------------------------------------------------------

// findingChannel is how a finding's evidence was taken, for the intake's
// channel table (identity.ChannelAdmission):
//
//   - a cloud provider's own listing of the resource, written by the
//     platform's cloud collector (cloudCollectorAuthoritative) — `api`;
//   - an exchange that COMPLETED with the address on a port: a negotiated TLS
//     cipher or an SSH host key read — `l3_probe`. Something answered;
//   - anything else seen at L3 — `l3_traffic`.
func findingChannel(f IngestFinding, cloudAuthoritative bool) identity.Channel {
	switch {
	case cloudAuthoritative:
		return identity.ChannelAPI
	case f.Port != nil && *f.Port > 0 &&
		(strings.TrimSpace(derefString(f.CipherSuite)) != "" || rawDataString(f.RawData, "ssh_host_key_fingerprint", "host_key_fingerprint") != ""):
		return identity.ChannelL3Probe
	default:
		return identity.ChannelL3Traffic
	}
}

// discoverySighting is what a finding SAW. The finding's name was seen at its
// address (the scan target answered to both), so the name carries that address
// as its own context.
func discoverySighting(tenantID uuid.UUID, f IngestFinding, effectiveIP *string, ownership string, cloudAuthoritative bool) identity.Sighting {
	sg := identity.Sighting{
		TenantID:         tenantID.String(),
		Source:           findingSource(f),
		Channel:          findingChannel(f, cloudAuthoritative),
		ObservedAt:       findingObservedAt(f),
		ReceiptID:        rawDataString(f.RawData, "discovery_id"),
		CollectorVersion: rawDataString(f.RawData, "collector_version", "sensor_version"),
		ClassHint:        findingClassHint(f),
		Confidence:       findingConfidence(f),
		Ownership:        ownership,
		NetworkType:      findingNetworkType(f),
		// A host's own connection table names peers it talked to before their
		// network was registered as well as after: carry the tenant-default
		// key alongside the segment-scoped one so the upgrade matches the
		// pending asset instead of duplicating it.
		BridgePriorScope: isHostInventoryConnectionRawData(f.RawData),
	}
	host := strings.TrimSpace(derefString(f.Hostname))
	ip := strings.TrimSpace(derefString(effectiveIP))
	if host != "" {
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindHostname, Value: host, Address: ip})
		sg.DisplayName = strings.ToLower(host)
	}
	if ip != "" {
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: ip})
		if sg.DisplayName == "" {
			sg.DisplayName = ip
		}
	}
	// The provider's own resource id: the strongest identifier a cloud finding
	// ever carries, and what makes a bucket with no address deduplicate.
	if rid := cloudResourceID(f); rid != "" {
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindCloudResourceID, Value: rid})
	}
	if mac := rawDataString(f.RawData, "mac_address", "mac"); mac != "" {
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindMACAddress, Value: mac})
	}
	if serial := rawDataString(f.RawData, "serial_number", "serial"); serial != "" {
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: serial})
	}
	if fp := rawDataString(f.RawData, "ssh_host_key_fingerprint", "host_key_fingerprint"); fp != "" {
		// The key's algorithm rides beside the fingerprint: a host offers one
		// key per algorithm, and only a same-algorithm change is a rotation
		// ( Decision 4).
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindSSHHostKeyFingerprint, Value: fp,
			KeyAlgorithm: rawDataString(f.RawData, "ssh_host_key_type", "host_key_type")})
	}
	// The leaf certificate a TLS service presented: drift evidence, never an
	// identifier ( Decision 4).
	sg.TLSCertFingerprints = findingLeafCertFingerprints(f.RawData)
	// An APPLICATION's dependent identity (ADR-0002 D3): a `name` the intake
	// scopes by the class hint, which is the class key it was keyed under.
	if id, ok := applicationDependentIdentifier(sg.ClassHint, host, ip, f); ok {
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindName, Value: id.Value})
	}
	if ep, ok := findingEndpoint(f, effectiveIP); ok {
		sg.Endpoints = append(sg.Endpoints, ep)
	}
	return sg
}

// ---------------------------------------------------------------------------
// Declarations (manual create, spreadsheet import, CMDB / NetBox pull)
// ---------------------------------------------------------------------------

// declarationChannel is `api` for a system of record the platform pulled
// through a configured connection (identity.IsConnectionSource) and `person`
// for everything a human typed or uploaded.
func declarationChannel(source identity.Source) identity.Channel {
	if identity.IsConnectionSource(source) {
		return identity.ChannelAPI
	}
	return identity.ChannelPerson
}

// explicitlyScoped reports whether a declared identifier names its own scope
// in a way the intake cannot express: a hostname, address or name with the
// scope written on it. The intake scopes those kinds from the topology; a
// declaration that names the scope is naming one exact stored identifier —
// the edit form sends every held identifier back with its scope — and
// re-deriving it would re-key what the operator meant to keep.
func explicitlyScoped(kind identity.Kind, scope string) bool {
	return scope != "" && (kind == identity.KindHostname || kind == identity.KindIPAddress || kind == identity.KindName)
}

// declaredSighting turns a person's or a system of record's statement about an
// asset into a sighting, plus the identifiers it named with an explicit scope
// (see explicitlyScoped), which bypass the intake's scoping and are appended
// to its observation verbatim by withExplicitScopes.
func declaredSighting(tenantID uuid.UUID, in models.AssetInput, source identity.Source, receiptID string) (identity.Sighting, []identity.Identifier, error) {
	sg := identity.Sighting{
		TenantID:   tenantID.String(),
		Source:     source,
		Channel:    declarationChannel(source),
		ObservedAt: in.ObservationTime,
		ReceiptID:  receiptID,
		ClassHint:  in.ClassKey,
		Confidence: 1, // a person or a system of record asserted it
		// The class attributes, so the matcher seam has a vendor and a model
		// to compare when this turns out to be contested (workstream 4.6).
		Attributes: in.Attributes,
	}
	if in.AssetOwnership != nil {
		sg.Ownership = *in.AssetOwnership
	}
	var scoped []identity.Identifier
	for _, id := range in.Identifiers {
		kind := identity.Kind(strings.TrimSpace(strings.ToLower(id.Kind)))
		if kind == identity.KindDeclarationID {
			return identity.Sighting{}, nil, fmt.Errorf("declaration identifiers are issued only by identity confirmation")
		}
		if !kind.Valid() {
			log.Printf("[AssetService] identity: ignoring identifier of unknown kind %q", id.Kind)
			continue
		}
		value, scope := strings.TrimSpace(id.Value), strings.TrimSpace(derefString(id.Scope))
		switch {
		case explicitlyScoped(kind, scope):
			scoped = append(scoped, identity.Identifier{Kind: kind, Value: value, Scope: scope, Confidence: 1})
		case kind == identity.KindCMDBSysID:
			sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: kind, Value: value, Profile: scope})
		default:
			sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: kind, Value: value})
		}
	}
	host := strings.TrimSpace(derefString(in.Hostname))
	ip := strings.TrimSpace(derefString(in.IPAddress))
	if host != "" {
		// The name a person typed beside an address names the host AT that
		// address, so it is scoped with that address's segment.
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindHostname, Value: host, Address: ip})
		sg.DisplayName = strings.ToLower(host)
	}
	if ip != "" {
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: ip})
		if sg.DisplayName == "" {
			sg.DisplayName = ip
		}
	}
	// A DECLARED service is identified by its name (ADR-0002 D3 erratum); the
	// intake scopes a `name` by the class hint.
	if name := strings.TrimSpace(derefString(in.DisplayName)); name != "" {
		sg.DisplayName = name
		if assetclass.IsAncestor(assetclass.KeyService, in.ClassKey) {
			sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindName, Value: name})
		}
	}
	for _, ep := range in.Endpoints {
		transport := strings.TrimSpace(ep.Transport)
		if transport == "" {
			transport = "tcp"
		}
		port := 0
		if ep.Port != nil {
			port = *ep.Port
		}
		sg.Endpoints = append(sg.Endpoints, identity.EndpointObservation{
			Address: derefString(ep.Address), FQDN: derefString(ep.FQDN), Port: port,
			Transport: transport, Protocol: derefString(ep.Protocol),
		})
	}
	return sg, scoped, nil
}

// withExplicitScopes appends the identifiers a declaration named with their
// own scope to the intake's observation, normalised and deduplicated against
// what the intake produced. Their scopes are flagged dynamic by the SAME
// snapshot the intake used, and a declared address is pinned exactly as the
// intake pins one (owner decision 1), so the only thing these skip is the
// re-derivation of a scope somebody wrote down.
func withExplicitScopes(res identity.IntakeResult, scoped []identity.Identifier) (identity.Observation, []identity.RejectedIdentifier) {
	obs := res.Observation
	if len(scoped) == 0 {
		return obs, nil
	}
	have := make(map[string]bool, len(obs.Identifiers))
	for _, id := range obs.Identifiers {
		have[id.Key()] = true
	}
	var rejected []identity.RejectedIdentifier
	for _, raw := range scoped {
		id, err := raw.Normalized()
		if err != nil {
			rejected = append(rejected, identity.RejectedIdentifier{Identifier: raw, Err: err})
			continue
		}
		if have[id.Key()] {
			continue
		}
		have[id.Key()] = true
		if id.Kind == identity.KindIPAddress && obs.Source.Kind == identity.SourceDeclared {
			id.Pinned = true
		}
		obs.Identifiers = append(obs.Identifiers, id)
		if (id.Kind == identity.KindIPAddress || id.Kind == identity.KindHostname) && res.Snapshot.IsDynamic(id.Scope) {
			if obs.DynamicScopes == nil {
				obs.DynamicScopes = map[string]bool{}
			}
			obs.DynamicScopes[id.Scope] = true
		}
	}
	return obs, rejected
}

// ---------------------------------------------------------------------------
// Host observations (ARP, DHCP, mDNS, NBNS, DNS, LLDP, CDP, sensor self-report)
// ---------------------------------------------------------------------------

// hostObservationChannel maps the frame a host observation came from onto the
// intake's channel table:
//
//   - relayed (an mDNS reflector repeating someone else's announcement) —
//     `relayed`, whatever else is true;
//   - a sensor's verified report about the host it runs on — the platform was
//     ON the host: `authenticated_session`;
//   - ARP, DHCP, LLDP and CDP bind an interface — `l2_frame`;
//   - mDNS, NBNS and DNS name a device without binding one — `advertisement`.
func hostObservationChannel(ho *hostobs.HostObservation, verifiedSelfReport bool) identity.Channel {
	switch {
	case ho.Relayed():
		return identity.ChannelRelayed
	case verifiedSelfReport:
		return identity.ChannelAuthenticatedSession
	}
	switch ho.Source {
	case hostobs.SourceARP, hostobs.SourceDHCP, hostobs.SourceLLDP, hostobs.SourceCDP:
		return identity.ChannelL2Frame
	}
	return identity.ChannelAdvertisement
}

// hostObservationSighting is what a passive frame (or a sensor's self-report)
// saw. verifiedSelfReport is the caller's check that ho.AgentID names a sensor
// registered to this tenant and is the sensor that delivered the row.
//
// Names carry no address of their own: a frame says "this host answers to
// these names and holds these addresses", not which name went with which
// address, so the intake scopes them with the sighting's first resolved
// address — the rule this path already followed ( B5).
//
// The self-report's addresses are deliberately NOT marked SelfReported, which
// would pin them (owner decision 1). A sensor's interface table does not say
// whether an address is static or leased, and pinning a DHCP lease would let
// it vote in its dynamic segment for whichever host holds it next. Host
// inventory, which does report the assignment, is device-interrogation's path.
func hostObservationSighting(tenantID uuid.UUID, f IngestFinding, ho *hostobs.HostObservation, verifiedSelfReport bool) identity.Sighting {
	sg := identity.Sighting{
		TenantID:         tenantID.String(),
		Source:           hostObservationSource(f),
		Channel:          hostObservationChannel(ho, verifiedSelfReport),
		ObservedAt:       hostObservationTime(f, ho),
		ReceiptID:        rawDataString(f.RawData, "discovery_id"),
		CollectorVersion: rawDataString(f.RawData, "collector_version", "sensor_version"),
		// Coarse and true, and the floor rather than the answer: the rule
		// table may replace it before resolution (ingestHostObservation).
		ClassHint:   string(assetclass.KeyUnknownHost),
		Confidence:  hostObservationConfidence(f, ho),
		Ownership:   hostObservationOwnership,
		NetworkType: findingNetworkType(f),
	}
	if verifiedSelfReport {
		// A self-report starts from the sensor's own registered
		// platform/profile — real evidence about the host it runs on, still a
		// hint the rule table can override.
		sg.ClassHint = string(classHintForSelfReport(ho))
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindSensorID, Value: strings.TrimSpace(ho.AgentID)})
	}
	if mac := strings.TrimSpace(ho.MAC); mac != "" {
		sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindMACAddress, Value: mac})
	}
	if verifiedSelfReport {
		// The host's other NICs. Only a verified self-report may say "these
		// hardware addresses are all mine": a passive frame shows one
		// interface, and an unverified row naming a list of MACs is a claim
		// about somebody else's chassis. When another asset already holds one,
		// the engine keeps this match and opens a merge proposal
		// (shared/identity, installation_claims.go).
		for _, mac := range ho.OtherMACs {
			if v := strings.TrimSpace(mac); v != "" {
				sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindMACAddress, Value: v})
			}
		}
	}
	for _, name := range ho.FQDNs {
		if v := strings.TrimSpace(name); v != "" {
			sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindFQDN, Value: v})
		}
	}
	for _, name := range ho.Hostnames {
		if v := strings.TrimSpace(name); v != "" {
			sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindHostname, Value: v})
		}
	}
	for _, addr := range ho.Addresses {
		// 0.0.0.0 is the dest_ip NOT NULL column compromise, not an address.
		if addr.IsValid() && !addr.IsUnspecified() {
			sg.Identifiers = append(sg.Identifiers, identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: addr.String()})
		}
	}
	// The ARP decoder's evidence for the engine's floating-address rule. Only
	// these two keys travel; the rest stay in the asset's metadata.
	for _, key := range []string{"arp_gratuitous", "arp_operation"} {
		if v, ok := ho.Attributes[key]; ok {
			if sg.Attributes == nil {
				sg.Attributes = map[string]any{}
			}
			sg.Attributes[key] = v
		}
	}
	return sg
}

// DeclareFor resolves a declaration about ONE named asset — a connector's link
// to its own record, for instance — through the intake and the engine: the
// sighting is scoped and graded like every other (a cmdb_sys_id by its sync
// profile), then attached to assetID by Engine.ResolveDeclaredFor on one
// transaction. An identifier another asset owns refuses the whole declaration
// with an *identity.DeclaredTargetConflict and writes nothing.
func (s *AssetService) DeclareFor(ctx context.Context, tenantID, assetID uuid.UUID, sg identity.Sighting) (identity.Resolution, error) {
	sg.TenantID = tenantID.String()
	obs, err := s.buildSighting(ctx, "declaration for asset "+assetID.String(), sg)
	if err != nil {
		return identity.Resolution{}, err
	}
	engine, err := s.identityEngine()
	if err != nil {
		return identity.Resolution{}, fmt.Errorf("identification engine unavailable: %w", err)
	}
	target := identity.AssetRef{TenantID: tenantID.String(), ID: assetID.String()}
	var res identity.Resolution
	err = s.identityRepo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		var rerr error
		res, rerr = engine.WithRepository(r).ResolveDeclaredFor(ctx, obs, target)
		return rerr
	})
	return res, err
}

// buildSighting is assessSighting for a caller that needs only the
// observation, and reports a sighting nothing survived in as such.
func (s *AssetService) buildSighting(ctx context.Context, label string, sg identity.Sighting) (identity.Observation, error) {
	res, err := s.assessSighting(ctx, label, sg)
	if err != nil {
		return identity.Observation{}, err
	}
	if len(res.Rejected) > 0 {
		r := res.Rejected[0]
		return identity.Observation{}, fmt.Errorf("%w: %s=%q: %w", identity.ErrInvalidObservation, r.Identifier.Kind, r.Identifier.Value, r.Err)
	}
	return res.Observation, nil
}
