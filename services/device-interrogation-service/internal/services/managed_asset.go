package services

// A "device" is an ASSET WITH MANAGEMENT CONFIGURED (ADR-0002 D5).
//
// `devices` was a second asset table. It held the same hosts inventory already
// knew about, under a different id, with no link between the two: a FortiGate
// the sensor saw on the wire and the same FortiGate an operator added here were
// two rows, and nothing in the product could say they were one thing. Phase 1
// removes the table. What is left of it is two side tables hanging off `assets`:
//
//	asset_management   management_url, management_protocol,
//	                   tls_insecure_skip_verify, connection_status,
//	                   last_interrogated_at, interrogation_error
//	asset_credentials  credential_id, username, password_enc
//
// and the Discovery → Devices page becomes a filter: the assets that have an
// `asset_management` row. That is why every read here INNER JOINs it.
//
// The column map, for anyone following the old code:
//
//	devices.id, tenant_id, hostname   -> assets
//	devices.ip_address                -> assets.primary_address
//	devices.device_type               -> assets.class_key (what it IS) plus
//	                                     assets.metadata->>'device_type' (which
//	                                     interrogator drives it)
//	devices.vendor/model/firmware     -> asset_facts hw.vendor / hw.model /
//	                                     hw.firmware_version, with provenance
//	devices.serial_number             -> asset_identifiers (kind serial_number)
//	devices.metadata                  -> assets.metadata->'device_metadata'
//	devices.tags                      -> assets.tags
//	device_jobs.device_id             -> device_jobs.asset_id
//
// Two of those deserve their reasons written down.
//
// **device_type is not the class.** It meant two things at once: for network
// gear it named the vendor client to dispatch on ("f5"), for cloud resources it
// named the resource kind ("aws_s3_bucket"). Only the second was ever a
// statement about what the thing is. The class taxonomy answers that for both
// (device_class.go); the driver name is pipeline state and lives in
// assets.metadata, beside the other pipeline keys, not in `attributes` — which
// is class-schema-validated and describes the thing, not how we reach it.
//
// **vendor/model/firmware are facts, not attributes.** DATA_MODEL §2's column
// map says `attributes`, and for a firewall that would work — `vendor`, `model`
// and `firmware_version` are in the hardware classes' attribute schemas. It
// does NOT work for the cloud half of this table: `object_storage`,
// `key_store`, `managed_database` and `cloud_load_balancer` declare
// provider/region/account_id and nothing else, and the schemas are
// additionalProperties:false, so half the device population could not store a
// vendor there at all. asset_facts holds all of them, carries the provenance
// that ADR-0002 D4 needs to reconcile a declared value against a measured one,
// and uses the SAME registered keys the collectors in
// shared/deviceinterrogation already emit — so a value typed into the form and
// the same value measured by an interrogation land on one key with two sources
// rather than in two places.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// deviceFactKeys are the registered fact keys that carry what `devices` held in
// its vendor/model/firmware columns. Read back and reconciled into the Device
// shape the API still returns.
var deviceFactKeys = []string{
	facts.KeyHWVendor,
	facts.KeyHWModel,
	facts.KeyHWFirmwareVersion,
}

// deviceMetadataKey is where the free-form map `devices.metadata` held now
// lives, nested under assets.metadata so it cannot collide with the pipeline
// keys the ingest path writes there (discovery_source, sensor_id, batch_id and
// the deferred-findings holding pen).
const deviceMetadataKey = "device_metadata"

// deviceTypeKey is where the interrogation driver name lives.
const deviceTypeKey = "device_type"

// deviceDiscoveryMethodKey records how the DEVICE came to be managed
// ("device_interrogation" for one an operator added, "cloud_api" for one a
// cloud collector found).
//
// It is not `assets.discovery_method`, which the identification engine sets to
// the producer that first observed the ASSET. Those are different facts and the
// UI reads this one: it is what decides whether Interrogate and Test connection
// are offered, and a host first seen by the sensor would otherwise report
// "sensor" and lose its buttons.
const deviceDiscoveryMethodKey = "device_discovery_method"

// cloudIntegrationIDKey records WHICH cloud integration read a resource, inside
// the device metadata map.
//
// It is provenance, not a credential reference. Cloud discovery used to leave
// this fact in `asset_credentials.credential_id`, which was the only thing that
// row ever held for a cloud resource — no username, no password. Cloud
// discovery no longer writes a credentials row at all (nothing discovered
// through a cloud API is a managed device), so the fact lives here instead of
// being lost.
const cloudIntegrationIDKey = "cloud_integration_id"

// sourceManual is the producer reference for a value a person typed into the
// Devices form. `user:<id>` would be better and is what ADR-0003 D3 names, but
// the service layer is not handed the acting user; the handler is. Widening
// that is a follow-up, and "manual" is at least honest about the class of
// producer rather than claiming a measurement.
const sourceManual = "manual"

// declaredSource is the provenance of anything the Devices form writes: a
// person asserted that a device exists at this address, which is `declared`,
// not `measured`. Nothing was probed. An interrogation later writes the same
// keys as measured/active, and ADR-0002 D4's identity table then decides which
// one shows — which is the whole reason these are facts with provenance rather
// than columns.
func declaredSource() identity.Source {
	return identity.Source{Kind: identity.SourceDeclared, Ref: sourceManual}
}

// interrogationSource is the provenance of a value an interrogation measured.
// `interrogation:<job>` is ADR-0003 D3's spelling.
func interrogationSource(jobID uuid.UUID) identity.Source {
	return identity.Source{
		Kind: identity.SourceMeasured,
		Ref:  "interrogation:" + jobID.String(),
		Mode: identity.ModeActive,
	}
}

// managedAssetRow is one row of the assets ⋈ asset_management ⋈
// asset_credentials join, before the facts and identifiers are folded in.
type managedAssetRow struct {
	device models.Device
}

const managedAssetSelect = `
	SELECT a.id, a.tenant_id, a.class_key,
	       a.hostname, host(a.primary_address), a.discovery_method,
	       a.tags, a.metadata, a.created_at,
	       GREATEST(a.updated_at, m.updated_at) AS updated_at, a.deleted_at,
	       m.management_url, m.tls_insecure_skip_verify, m.connection_status,
	       m.last_interrogated_at, m.interrogation_error,
	       m.ssh_host_key_fingerprint, m.ssh_host_key_type, m.ssh_host_key_pinned_at,
	       c.credential_id, c.username, c.password_enc
	FROM public.assets a
	JOIN public.asset_management m ON m.tenant_id = a.tenant_id AND m.asset_id = a.id
	LEFT JOIN public.asset_credentials c ON c.tenant_id = a.tenant_id AND c.asset_id = a.id
	WHERE a.tenant_id = $1 AND a.deleted_at IS NULL`

// scanManagedAsset reads one joined row. The Device it returns has no vendor,
// model, firmware or serial yet — those come from asset_facts and
// asset_identifiers, batched by the caller so a list of N devices is three
// queries rather than 3N.
func scanManagedAsset(scan func(dest ...any) error) (managedAssetRow, error) {
	var (
		row                managedAssetRow
		classKey           string
		hostname, ip       sql.NullString
		discoveryMethod    sql.NullString
		tagsJSON, metaJSON []byte
		managementURL      sql.NullString
		interrogationError sql.NullString
		lastInterrogated   sql.NullTime
		hostKeyFingerprint sql.NullString
		hostKeyType        sql.NullString
		hostKeyPinnedAt    sql.NullTime
		credentialID       sql.NullString
		username           sql.NullString
		passwordEnc        sql.NullString
		deletedAt          sql.NullTime
	)
	err := scan(
		&row.device.ID, &row.device.TenantID, &classKey,
		&hostname, &ip, &discoveryMethod,
		&tagsJSON, &metaJSON, &row.device.CreatedAt,
		&row.device.UpdatedAt, &deletedAt,
		&managementURL, &row.device.TLSInsecureSkipVerify, &row.device.ConnectionStatus,
		&lastInterrogated, &interrogationError,
		&hostKeyFingerprint, &hostKeyType, &hostKeyPinnedAt,
		&credentialID, &username, &passwordEnc,
	)
	if err != nil {
		return managedAssetRow{}, err
	}

	d := &row.device
	d.AssetID = d.ID
	d.ClassKey = classKey
	d.Hostname = nullStringPtr(hostname)
	d.IPAddress = nullStringPtr(ip)
	d.ManagementURL = nullStringPtr(managementURL)
	d.InterrogationError = nullStringPtr(interrogationError)
	if discoveryMethod.Valid {
		d.DiscoveryMethod = discoveryMethod.String
	}
	if lastInterrogated.Valid {
		t := lastInterrogated.Time
		d.LastInterrogatedAt = &t
	}
	d.SSHHostKeyFingerprint = nullStringPtr(hostKeyFingerprint)
	d.SSHHostKeyType = nullStringPtr(hostKeyType)
	if hostKeyPinnedAt.Valid {
		t := hostKeyPinnedAt.Time
		d.SSHHostKeyPinnedAt = &t
	}
	if deletedAt.Valid {
		t := deletedAt.Time
		d.DeletedAt = &t
	}
	if credentialID.Valid {
		if id, err := uuid.Parse(credentialID.String); err == nil {
			d.CredentialID = &id
		}
	}
	d.Username = nullStringPtr(username)
	if passwordEnc.Valid && passwordEnc.String != "" {
		// Masked, always: *models.Device is serialised straight into API
		// responses. Anything that needs the real stored value comes through
		// GetStoredDeviceCredentials instead.
		masked := maskPassword(passwordEnc.String)
		d.Password = &masked
	}

	var tags map[string]interface{}
	if len(tagsJSON) > 0 {
		_ = json.Unmarshal(tagsJSON, &tags)
	}
	d.Tags = tags

	var meta map[string]interface{}
	if len(metaJSON) > 0 {
		_ = json.Unmarshal(metaJSON, &meta)
	}
	if dt, ok := meta[deviceTypeKey].(string); ok {
		d.DeviceType = dt
	}
	if dm, ok := meta[deviceDiscoveryMethodKey].(string); ok && dm != "" {
		d.DiscoveryMethod = dm
	}
	if nested, ok := meta[deviceMetadataKey].(map[string]interface{}); ok {
		d.Metadata = nested
	}
	return row, nil
}

// hydrateDeviceIdentity fills vendor/model/firmware (from asset_facts) and
// serial (from asset_identifiers) across a whole page of devices in two
// queries.
//
// Each fact key may have a row per source; the winner is chosen by
// identity.Reconcile on ADR-0002 D4's IDENTITY table — declared beats an active
// measurement beats a passive one beats an import beats a model. That is the
// same ladder the rest of the platform reconciles on, rather than a second
// "most recent wins" rule invented here.
func (s *DeviceService) hydrateDeviceIdentity(ctx context.Context, tenantID uuid.UUID, devices []*models.Device) error {
	if len(devices) == 0 {
		return nil
	}
	byID := make(map[uuid.UUID]*models.Device, len(devices))
	ids := make([]string, 0, len(devices))
	for _, d := range devices {
		byID[d.ID] = d
		ids = append(ids, d.ID.String())
	}

	// Winning value per (asset, key), reconciled in Go.
	winners := make(map[uuid.UUID]map[string]identity.ValueWithSource, len(devices))

	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT asset_id, key, value, source_kind, source_ref, observed_at
			FROM public.asset_facts
			WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND key = ANY($3::text[])`,
			tenantID, pgUUIDArrayLiteral(ids), pgTextArrayLiteral(deviceFactKeys))
		if err != nil {
			return fmt.Errorf("read device facts: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				assetID          uuid.UUID
				key, kind, ref   string
				raw              []byte
				observedAt       time.Time
				decoded          any
				candidateSources identity.ValueWithSource
			)
			if err := rows.Scan(&assetID, &key, &raw, &kind, &ref, &observedAt); err != nil {
				return fmt.Errorf("scan device fact: %w", err)
			}
			if err := json.Unmarshal(raw, &decoded); err != nil {
				continue
			}
			candidateSources = identity.ValueWithSource{
				Value:  decoded,
				Source: identity.Source{Kind: identity.SourceKind(kind), Ref: ref, Mode: factMeasurementMode(ref)},
				At:     observedAt,
			}
			if winners[assetID] == nil {
				winners[assetID] = map[string]identity.ValueWithSource{}
			}
			cur, seen := winners[assetID][key]
			if !seen {
				winners[assetID][key] = candidateSources
				continue
			}
			winners[assetID][key] = identity.Reconcile(identity.GroupIdentity, cur, candidateSources)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}

	for assetID, keys := range winners {
		d := byID[assetID]
		if d == nil {
			continue
		}
		for key, r := range keys {
			s, ok := r.Value.(string)
			if !ok || s == "" {
				continue
			}
			switch key {
			case facts.KeyHWVendor:
				d.Vendor = &s
			case facts.KeyHWModel:
				d.Model = &s
			case facts.KeyHWFirmwareVersion:
				v := s
				d.FirmwareVersion = &v
			}
		}
	}

	// Serial: an identifier, not a fact. Most recently seen wins — identifiers
	// are not reconciled, they accumulate, and an asset with two serials is a
	// merge waiting to be reviewed rather than a value to pick between.
	return shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT DISTINCT ON (asset_id) asset_id, value
			FROM public.asset_identifiers
			WHERE tenant_id = $1 AND asset_id = ANY($2::uuid[]) AND kind = $3
			ORDER BY asset_id, last_seen_at DESC`,
			tenantID, pgUUIDArrayLiteral(ids), string(identity.KindSerialNumber))
		if err != nil {
			return fmt.Errorf("read device serials: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var assetID uuid.UUID
			var serial string
			if err := rows.Scan(&assetID, &serial); err != nil {
				return fmt.Errorf("scan device serial: %w", err)
			}
			if d := byID[assetID]; d != nil {
				v := serial
				d.SerialNumber = &v
			}
		}
		return rows.Err()
	})
}

// factMeasurementMode infers ADR-0002 D4's active/passive split from the
// producer reference, because `asset_facts` has no mode column.
//
// It is deliberately a small allowlist. Anything unrecognised is
// ModeUnspecified, which ranks BELOW passive — "did not say" is not evidence of
// an active measurement, and ranking silence as the strongest tier is the
// failure shape the 2026-08 audit found sixty times.
func factMeasurementMode(sourceRef string) identity.MeasurementMode {
	producer := sourceRef
	if i := strings.IndexByte(sourceRef, ':'); i >= 0 {
		producer = sourceRef[:i]
	}
	switch producer {
	case "interrogation", "cloud", "agent", "connector":
		return identity.ModeActive
	case "sensor", "pcap":
		return identity.ModePassive
	default:
		return identity.ModeUnspecified
	}
}

// ---------------------------------------------------------------------------
// Observation building
// ---------------------------------------------------------------------------

// deviceObservationInput is what a caller knows about a device before the
// engine has decided which asset it is.
type deviceObservationInput struct {
	DeviceType      string
	Hostname        string
	IPAddress       string
	ManagementURL   string
	SerialNumber    string
	CloudResourceID string
	// CloudNetworkRef is the cloud network (VPC / VNet / GCP network) this
	// observation was made INSIDE, as the provider's own resource id. Empty for
	// every LAN observation, which is all of them except cloud enumeration.
	//
	// It is what stops two VPCs that use the same CIDR sharing one network
	// segment — and therefore one scope, and therefore one ASSET for two
	// instances at the same private address (ADR-0002 D3 erratum).
	CloudNetworkRef string
	DiscoveryMethod string
	Source          identity.Source
	ObservedAt      time.Time
	Admission       identity.AdmissionEvidence
}

// deviceObservation builds the identity.Observation for a managed device.
//
// The identifiers are the honest answer to "what did we actually observe",
// which for a device added through the form is what the operator typed:
//
//   - serial_number, when supplied. Globally unique, top of the precedence list
//     for every hardware class.
//   - cloud_resource_id, for a cloud resource. The provider's own id, and the
//     strongest identifier a cloud resource ever has.
//   - the hostname: an FQDN if it is dotted (globally unique, unscoped), a bare
//     hostname otherwise (scoped to the segment, or recorded and mute).
//   - the management address: the host part of the management URL, which is
//     frequently the only address an operator supplies.
//   - the IP address, scoped to the segment.
//
// SCOPE is what makes the weak two able to decide a match at all, and getting
// it from the same resolver inventory-service uses is what makes a device and
// the same host seen by the sensor resolve to ONE asset. There is always a
// scope: when no segment contains the address it is the tenant-wide default
// (ADR-0002 D3 erratum), because "this tenant has no segments" is a fact about
// their topology and not the absence of one.
func (s *DeviceService) deviceObservation(ctx context.Context, tenantID uuid.UUID, in deviceObservationInput) (identity.Observation, error) {
	host := strings.TrimSpace(in.Hostname)
	ip := strings.TrimSpace(in.IPAddress)
	managementAddress := managementHost(in.ManagementURL)
	scopeIP, scopeHost := deviceScopeInputs(ip, host, managementAddress)
	segmentID, dynamicScope := s.segmentScope(ctx, tenantID, scopeIP, scopeHost, in.CloudNetworkRef)

	obs := identity.Observation{
		TenantID:    tenantID.String(),
		ClassHint:   DeviceTypeClassKey(in.DeviceType),
		Source:      in.Source,
		ObservedAt:  in.ObservedAt,
		Admission:   in.Admission,
		Confidence:  1, // a person asserted it, or a provider API answered
		DisplayName: host,
		// A device the tenant holds credentials for is the tenant's own gear by
		// definition, so the asset must not be created as `external`.
		Network: identity.Network{Ownership: identity.OwnershipInternal, SegmentID: segmentID},
	}
	// assets.hostname is a NAME. The Devices form's one field takes either, and
	// an operator who typed an address there has given us an address — putting
	// it in the hostname column would make every reader that renders "hostname"
	// show an IP and every hostname search miss it. It still becomes an
	// ip_address identifier below, which is where an address belongs.
	if net.ParseIP(host) == nil {
		obs.Hostname = strings.ToLower(host)
	}
	if dynamicScope {
		// The segment hands addresses out; an ip_address inside it must not
		// decide a match, because today's DHCP lease is tomorrow's other host.
		obs.DynamicScopes = map[string]bool{segmentID: true}
	}

	add := func(kind identity.Kind, value, scope string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		obs.Identifiers = append(obs.Identifiers, identity.Identifier{
			Kind: kind, Value: value, Scope: scope, Confidence: 1,
		})
	}

	if serial := strings.TrimSpace(in.SerialNumber); serial != "" {
		add(identity.KindSerialNumber, serial, "")
	}
	if rid := strings.TrimSpace(in.CloudResourceID); rid != "" {
		add(identity.KindCloudResourceID, rid, "")
	}
	for _, name := range dedupeStrings(host, managementAddress) {
		if parsed := net.ParseIP(name); parsed != nil {
			add(identity.KindIPAddress, name, segmentID)
			if obs.DisplayName == "" {
				obs.DisplayName = name
			}
			continue
		}
		if strings.Contains(strings.TrimSuffix(name, "."), ".") {
			add(identity.KindFQDN, name, "")
		} else {
			add(identity.KindHostname, name, segmentID)
		}
		if obs.DisplayName == "" {
			obs.DisplayName = name
		}
	}
	if ip != "" {
		add(identity.KindIPAddress, ip, segmentID)
		if obs.DisplayName == "" {
			obs.DisplayName = ip
		}
	}

	// Leniency is a decision made HERE and visible: a malformed serial typed
	// into the form must not lose the device, but the reject is reported rather
	// than dropped.
	clean, rejected := obs.Sanitize()
	for _, r := range rejected {
		logDroppedIdentifier(in, r)
	}
	if len(clean.Identifiers) == 0 {
		return identity.Observation{}, errDeviceHasNoIdentifier
	}
	return clean, nil
}

// deviceScopeInputs makes the management target participate in the same
// segment lookup as an explicitly entered IP/hostname. Operators commonly
// provide only a URL; treating its address as tenant-default made it unable to
// match the same appliance observed by a sensor in a configured segment.
func deviceScopeInputs(ip, hostname, managementAddress string) (string, string) {
	if strings.TrimSpace(ip) == "" && net.ParseIP(strings.TrimSpace(managementAddress)) != nil {
		ip = managementAddress
	}
	if strings.TrimSpace(hostname) == "" && net.ParseIP(strings.TrimSpace(managementAddress)) == nil {
		hostname = managementAddress
	}
	return strings.TrimSpace(ip), strings.TrimSpace(hostname)
}

// managementHost returns the host part of a management URL, or "".
//
// A URL with no scheme ("fw1.corp.example.com") does not parse into a Host, so
// it is tried as a bare host:port and then as a bare host. An operator typing
// the address without "https://" is the common case, not an error.
func managementHost(managementURL string) string {
	raw := strings.TrimSpace(managementURL)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		if h, _, splitErr := net.SplitHostPort(u.Host); splitErr == nil {
			return strings.Trim(h, "[]")
		}
		return strings.Trim(u.Host, "[]")
	}
	if h, _, err := net.SplitHostPort(raw); err == nil {
		return strings.Trim(h, "[]")
	}
	if strings.ContainsAny(raw, "/?#") {
		return ""
	}
	return raw
}

func dedupeStrings(values ...string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(strings.ToLower(v))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// ---------------------------------------------------------------------------
// Segment scope
// ---------------------------------------------------------------------------

// scopeResolver answers "where was I standing?" — the scope a hostname or an IP
// identifies within (ADR-0002 D3).
//
// It exists as a type rather than a method so the two intakes in this package
// that need it — the Devices form and the interrogation observation sink —
// share ONE implementation.
type scopeResolver struct {
	db   *sql.DB
	repo *pgidentity.Repository
}

func newDeviceScopeResolver(db *sql.DB, repo *pgidentity.Repository) scopeResolver {
	return scopeResolver{db: db, repo: repo}
}

// segmentScope resolves the scope, and whether it hands addresses out
// dynamically.
//
// It NEVER returns an empty scope. "This tenant has no segments" — which is
// every fresh tenant — is a fact about their topology, not the absence of one,
// and `identity.ScopeTenantDefault` is what it means. An empty scope is what
// made one host, observed three times, into three assets: neither its hostname
// nor its IP could vote, so nothing matched.
//
// The ADDRESS half is `shared/identity/postgres.ScopeForAddress`, byte for byte
// the call inventory-service makes, so the two services cannot disagree about
// which segment an address is in — one more spelling of this lookup is one more
// dedupe key. The NAME half is local for the same reason it is local there: a
// `domain` segment is matched by hostname, which an address-keyed lookup cannot
// answer.
func (r scopeResolver) segmentScope(ctx context.Context, tenantID uuid.UUID, ip, hostname, cloudNetworkRef string) (string, bool) {
	if addr, ok := parseScopeAddr(ip); ok && r.repo != nil {
		scope, dynamic, err := r.repo.ScopeForAddress(ctx, tenantID.String(), addr, cloudNetworkRef)
		if err == nil && scope != "" {
			return scope, dynamic
		}
		if err != nil {
			// A failed lookup must not lose the device, and must not be silent:
			// it degrades every identifier in this observation to the tenant
			// default.
			logSegmentLookupFailed(tenantID, err)
		}
	}
	if hostname != "" {
		if scope, ok := r.domainScope(ctx, tenantID, hostname); ok {
			return scope, false
		}
	}
	return identity.ScopeTenantDefault, false
}

// domainScope matches a hostname against the tenant's `domain` segments, using
// the same rule inventory-service's segment service applies
// (shared/network.MatchSegment).
func (r scopeResolver) domainScope(ctx context.Context, tenantID uuid.UUID, hostname string) (string, bool) {
	var candidates []sharednetwork.Segment
	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, segment_type, value
			FROM public.network_segments
			WHERE tenant_id = $1 AND is_active = true AND segment_type = 'domain'
			ORDER BY created_at`, tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var seg sharednetwork.Segment
			if err := rows.Scan(&seg.ID, &seg.Type, &seg.Value); err != nil {
				return err
			}
			candidates = append(candidates, seg)
		}
		return rows.Err()
	})
	if err != nil {
		logSegmentLookupFailed(tenantID, err)
		return "", false
	}
	match, ok := sharednetwork.MatchSegment(candidates, "", hostname)
	if !ok {
		return "", false
	}
	return match.ID, true
}

// parseScopeAddr turns an observed address into a netip.Addr. False for absent,
// empty or unparseable values, and for the unspecified address, which cloud
// collectors use as a placeholder and which is inside nothing.
func parseScopeAddr(ip string) (netip.Addr, bool) {
	v := strings.TrimSpace(ip)
	if v == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(v)
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() || addr.IsUnspecified() {
		return netip.Addr{}, false
	}
	return addr, true
}

// segmentScope is the Devices form's seat at the same resolver.
func (s *DeviceService) segmentScope(ctx context.Context, tenantID uuid.UUID, ip, hostname, cloudNetworkRef string) (string, bool) {
	repo, err := s.Repo()
	if err != nil {
		logSegmentLookupFailed(tenantID, err)
		repo = nil
	}
	return newDeviceScopeResolver(s.db, repo).segmentScope(ctx, tenantID, ip, hostname, cloudNetworkRef)
}

// ---------------------------------------------------------------------------
// asset_management
// ---------------------------------------------------------------------------

// managementUpsert is the set of asset_management columns a caller is writing.
// A nil pointer means "leave whatever is there" — the difference between "the
// operator cleared the management URL" and "this call is not about the
// management URL" is a difference the update path has to keep.
type managementUpsert struct {
	ManagementURL         *string
	ManagementProtocol    *string
	TLSInsecureSkipVerify *bool
	ConnectionStatus      *string
	LastInterrogatedAt    *time.Time
	InterrogationError    *string
	// ClearInterrogationError sets the column to NULL. Needed because
	// InterrogationError is a pointer whose nil already means "leave it".
	ClearInterrogationError bool
	// SSHHostKeyFingerprint / SSHHostKeyType pin the key a device presented on
	// first contact. Writing them also stamps ssh_host_key_pinned_at.
	SSHHostKeyFingerprint *string
	SSHHostKeyType        *string
	// ClearSSHHostKey unpins the device — the deliberate re-pin path for a
	// replaced device or a rotated key. Same reason ClearInterrogationError
	// exists: a nil pointer already means "leave it alone", so "set it to NULL"
	// needs a flag of its own.
	ClearSSHHostKey bool
}

// upsertManagement writes the asset_management row for an asset, creating it if
// the asset is not yet managed.
//
// COALESCE on every column is what makes a partial update partial: the INSERT
// supplies defaults, and the DO UPDATE keeps the stored value wherever the
// caller passed NULL.
func upsertManagement(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID, in managementUpsert) error {
	if in.ConnectionStatus != nil {
		normalized := normalizeConnectionStatus(*in.ConnectionStatus)
		in.ConnectionStatus = &normalized
	}
	_, err := tx.ExecContext(ctx, `
			INSERT INTO public.asset_management (
				tenant_id, asset_id, management_url, management_protocol,
				tls_insecure_skip_verify, connection_status,
				last_interrogated_at, interrogation_error,
				ssh_host_key_fingerprint, ssh_host_key_type, ssh_host_key_pinned_at
			) VALUES (
				$1, $2, $3, $4,
				coalesce($5, false), coalesce($6, 'unknown'),
				$7, $8,
				CASE WHEN $10 THEN NULL ELSE $11 END,
				CASE WHEN $10 THEN NULL ELSE $12 END,
				CASE WHEN $10 OR $11 IS NULL THEN NULL ELSE now() END
			)
			ON CONFLICT (tenant_id, asset_id) DO UPDATE
			SET management_url           = coalesce($3, public.asset_management.management_url),
			    management_protocol      = coalesce($4, public.asset_management.management_protocol),
			    tls_insecure_skip_verify = coalesce($5, public.asset_management.tls_insecure_skip_verify),
			    connection_status        = coalesce($6, public.asset_management.connection_status),
			    last_interrogated_at     = coalesce($7, public.asset_management.last_interrogated_at),
			    interrogation_error      = CASE WHEN $9 THEN NULL
			                                    ELSE coalesce($8, public.asset_management.interrogation_error) END,
			    ssh_host_key_fingerprint = CASE WHEN $10 THEN NULL
			                                    ELSE coalesce($11, public.asset_management.ssh_host_key_fingerprint) END,
			    ssh_host_key_type        = CASE WHEN $10 THEN NULL
			                                    ELSE coalesce($12, public.asset_management.ssh_host_key_type) END,
			    ssh_host_key_pinned_at   = CASE WHEN $10 THEN NULL
			                                    WHEN $11 IS NOT NULL
			                                     AND public.asset_management.ssh_host_key_fingerprint IS DISTINCT FROM $11 THEN now()
			                                    ELSE public.asset_management.ssh_host_key_pinned_at END,
			    updated_at               = now()`,
		tenantID, assetID, in.ManagementURL, in.ManagementProtocol,
		in.TLSInsecureSkipVerify, in.ConnectionStatus,
		in.LastInterrogatedAt, in.InterrogationError, in.ClearInterrogationError,
		in.ClearSSHHostKey, in.SSHHostKeyFingerprint, in.SSHHostKeyType)
	if err != nil {
		return fmt.Errorf("upsert asset_management: %w", err)
	}
	return nil
}

// normalizeConnectionStatus maps a caller's status onto the four
// `asset_management_connection_status_check` allows.
//
// `devices.connection_status` was free text and the cloud collectors used a
// fifth value, "discovered", which the CHECK rejects — an unmapped value would
// abort the whole discovery run at the first bucket. It means "we enumerated
// this resource through the provider API and have never tested a connection TO
// it", and `unknown` is what that is: we have not measured the device's own
// reachability. Mapping it to `connected` would claim a measurement nothing
// took.
//
// Anything else unrecognised also becomes `unknown`, for the same reason: a
// status we cannot place is not evidence of health.
func normalizeConnectionStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "connected":
		return "connected"
	case "disconnected":
		return "disconnected"
	case "error", "failed":
		return "error"
	default:
		return "unknown"
	}
}

// upsertManagementOwnTx is upsertManagement for the paths that have no engine
// transaction to join — an interrogation recording that it reached the device,
// a connection test. They are single statements about an asset that already
// exists, so a transaction of their own is the whole unit of work.
func upsertManagementOwnTx(ctx context.Context, db *sql.DB, tenantID, assetID uuid.UUID, in managementUpsert) error {
	return shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		return upsertManagement(ctx, tx, tenantID, assetID, in)
	})
}

// mergeAssetMetadata merges keys into assets.metadata without disturbing the
// pipeline keys the ingest path writes there.
//
// `||` rather than a whole-column write: assets.metadata is shared state — it
// carries the discovery-source attribution and the deferred-findings holding
// pen — and replacing it would silently drop an asset's pending findings the
// first time somebody renamed a device.
func mergeAssetMetadata(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID, patch map[string]interface{}) error {
	if len(patch) == 0 {
		return nil
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("marshal asset metadata patch: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE public.assets
		SET metadata = metadata || $3::jsonb, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, assetID, string(raw))
	return err
}

// mergeAssetTags merges tags into assets.tags, same reasoning as metadata.
func mergeAssetTags(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID, tags map[string]interface{}) error {
	if len(tags) == 0 {
		return nil
	}
	raw, err := json.Marshal(tags)
	if err != nil {
		return fmt.Errorf("marshal asset tags: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		UPDATE public.assets
		SET tags = tags || $3::jsonb, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, assetID, string(raw))
	return err
}

// setAssetAddress writes the hostname and primary address an operator supplied
// onto the asset, without blanking what is already there.
//
// "Empty never wins" (the discovery-envelope rule): a device edit that does not
// mention the hostname must not clear the hostname the sensor measured.
//
// The display name follows the NAME the operator typed, and only that. A
// person naming a device is the highest-provenance name it will ever have
// (ADR-0002 D4: declared over measured), and the old `coalesce(display_name,
// …)` let a measured name that happened to arrive first keep the label for
// good: on the dev lab the gateway was registered as "lab gateway" and kept
// displaying as "mbp-m3-alice.local", a laptop's mDNS name the sensor had
// pinned to it minutes earlier. The hostname column already took the declared
// value; the label a person reads did not. An ADDRESS typed into the form is
// not a name and still only fills an empty label — replacing "core-sw-1" with
// "10.0.0.1" because someone edited the management address would be the same
// mistake pointed the other way.
func setAssetAddress(ctx context.Context, tx *sql.Tx, tenantID, assetID uuid.UUID, hostname, ip string) error {
	hostname = strings.TrimSpace(hostname)
	ip = strings.TrimSpace(ip)
	// An address typed into the hostname field is an address, not a name. Same
	// rule as deviceObservation applies to the column, and for the same reason:
	// assets.hostname is what "hostname" renders and what a hostname search
	// looks at.
	if parsed := net.ParseIP(hostname); parsed != nil {
		if ip == "" {
			ip = hostname
		}
		hostname = ""
	}
	if hostname == "" && ip == "" {
		return nil
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE public.assets
		SET hostname         = coalesce(NULLIF($3, ''), hostname),
		    primary_address  = coalesce(NULLIF($4, '')::inet, primary_address),
		    display_name     = coalesce(NULLIF($5, ''), display_name, NULLIF($4, '')),
		    updated_at       = now()
		WHERE tenant_id = $1 AND id = $2`,
		tenantID, assetID, strings.ToLower(hostname), ip, hostname)
	return err
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// deviceTypeFromMetadata reads the interrogation driver name out of a raw
// assets.metadata blob.
func deviceTypeFromMetadata(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var meta map[string]interface{}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return ""
	}
	dt, _ := meta[deviceTypeKey].(string)
	return dt
}

func nullStringPtr(v sql.NullString) *string {
	if !v.Valid || v.String == "" {
		return nil
	}
	s := v.String
	return &s
}

// pgUUIDArrayLiteral renders ids as a Postgres uuid[] literal. The values come
// from uuid.UUID.String(), so nothing but hex and hyphens can reach it.
func pgUUIDArrayLiteral(ids []string) string {
	return "{" + strings.Join(ids, ",") + "}"
}

// pgTextArrayLiteral renders keys as a Postgres text[] literal, quoting each
// element so a key containing a comma cannot split into two.
func pgTextArrayLiteral(keys []string) string {
	quoted := make([]string, 0, len(keys))
	for _, k := range keys {
		quoted = append(quoted, `"`+strings.ReplaceAll(k, `"`, `""`)+`"`)
	}
	return "{" + strings.Join(quoted, ",") + "}"
}

// deviceFacts projects the identity fields of a device onto registered facts.
// An empty value produces no fact: the absence of a firmware version is not a
// firmware version of "".
func deviceFacts(vendor, model, firmware string, source identity.Source, at time.Time) []pgidentity.Fact {
	var out []pgidentity.Fact
	add := func(key, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		out = append(out, pgidentity.Fact{
			Key:        key,
			Value:      value,
			SourceKind: source.Kind,
			SourceRef:  source.Ref,
			Confidence: 1,
			ObservedAt: at,
		})
	}
	add(facts.KeyHWVendor, vendor)
	add(facts.KeyHWModel, model)
	add(facts.KeyHWFirmwareVersion, firmware)
	return out
}

// pinSSHHostKeyIfUnset records the SSH host key a device presented, but ONLY
// when the device has none pinned yet (H7).
//
// The `IS NULL` predicate is the load-bearing part, and it is in SQL rather
// than in a Go read-then-write for a reason: an automatic pin that can
// overwrite an existing one is not a pin. Two concurrent interrogations, or a
// Go check that raced the row it checked, would let the platform quietly re-pin
// itself to whatever answered on port 22 — which is the original defect wearing
// a different hat. Re-pinning is an operator decision and goes through
// clearSSHHostKeyPin.
//
// Returns whether a row was pinned, so a caller can tell "enrolled this device"
// from "it was already pinned".
func pinSSHHostKeyIfUnset(
	ctx context.Context,
	db *sql.DB,
	tenantID, assetID uuid.UUID,
	fingerprint, keyType string,
) (bool, error) {
	if fingerprint == "" {
		return false, nil
	}
	var pinned bool
	err := shareddatabase.WithTenantTx(ctx, db, tenantID, func(tx *sql.Tx) error {
		res, execErr := tx.ExecContext(ctx, `
			UPDATE public.asset_management
			   SET ssh_host_key_fingerprint = $3,
			       ssh_host_key_type        = nullif($4, ''),
			       ssh_host_key_pinned_at   = now(),
			       updated_at               = now()
			 WHERE tenant_id = $1
			   AND asset_id  = $2
			   AND ssh_host_key_fingerprint IS NULL`,
			tenantID, assetID, fingerprint, keyType)
		if execErr != nil {
			return fmt.Errorf("pin ssh host key: %w", execErr)
		}
		n, raErr := res.RowsAffected()
		if raErr != nil {
			return fmt.Errorf("pin ssh host key: %w", raErr)
		}
		pinned = n > 0
		return nil
	})
	return pinned, err
}

// clearSSHHostKeyPin unpins a device so the next interrogation enrols it again.
//
// The deliberate re-pin path. Without one, the first hardware swap makes an
// operator's only way forward turning the check off entirely — which is how a
// fail-closed control becomes a fail-open one in practice.
func clearSSHHostKeyPin(ctx context.Context, db *sql.DB, tenantID, assetID uuid.UUID) error {
	return upsertManagementOwnTx(ctx, db, tenantID, assetID, managementUpsert{ClearSSHHostKey: true})
}
