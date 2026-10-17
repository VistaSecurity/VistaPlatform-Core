// Package services provides business logic for the crypto inventory management system.
// It handles asset discovery, crypto configuration tracking, risk assessment,
// and compliance analysis for cryptographic assets across network infrastructure.
//
// Key Features:
// - Asset CRUD operations with multi-tenant isolation
// - Advanced search and filtering capabilities
// - Risk scoring based on crypto configuration strength
// - Protocol and cipher suite analysis
// - Compliance framework integration
package services

import (
	"context"
	"crypto/md5" //nolint:gosec // intentional — MD5 is used as a deterministic non-crypto suppression key (see fingerprintForSuppression), not a security primitive
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/assetclasshistory"
	sharedcerts "github.com/vistasecurity/vistaplatform/shared/certificates"
	"github.com/vistasecurity/vistaplatform/shared/classify"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type AssetService struct {
	db                       *database.DB
	serviceIdentificationSvc *ServiceIdentificationService // optional: used for service hints in IngestFindings
	// onLoadPrefixSet, when set, is called on every read of a tenant's prefix
	// set (prefix_context.go) — a test hook that counts reads per request.
	onLoadPrefixSet        func(uuid.UUID)
	certificateService     *CertificateService
	algorithmService       *AlgorithmService
	eventPublisher         *EventPublisherService
	weakCryptoDetector     *WeakCryptoDetector
	externalConnectionsSvc *ExternalConnectionsService // optional: routes third-party findings to external_connections
	integrationCipher      *credentials.Cipher         // protects integrations.auth_config — see newIntegrationCipher
	businessUnits          *BusinessUnitService        // resolves business_unit_id / name on asset writes (DCIM 1.1)
	sites                  *SiteService                // resolves site/location on asset writes (DCIM 2.1)

	// The identification engine (ADR-0002 D3) and its Postgres storage. Built
	// once, lazily, by identityEngine(); every intake path resolves through it
	// instead of the four ad hoc dedupe keys that preceded it.
	identityOnce sync.Once
	identityEng  *identity.Engine
	identityRepo *pgidentity.Repository
	identityErr  error

	// Decides which hostnames are generic for a tenant ( B2), with its
	// per-tenant cardinality cache. Built lazily by genericNames() over the
	// identity repository, because that only exists once identityEngine() has
	// run. Shared by every host-observation build in the process, which is the
	// point of the cache.
	genericNamesOnce sync.Once
	genericNamesVal  *identity.GenericNames

	// The one identity intake (platform ADR-0003): every builder in
	// this service turns what it saw into an identity.Sighting and lets this
	// decide scope, dynamic scopes, admission and hygiene. Built lazily by
	// intake() over the identity repository (intake_adapters.go).
	intakeOnce sync.Once
	intakeVal  *identity.Intake
	intakeErr  error

	// The rule-based classifier (ADR-0004 D6) over the CURATED
	// classification_rules table, reloaded on an interval so a rule an admin
	// adds in the console becomes live without a restart. Built once, lazily,
	// by classifier(); see asset_classify.go.
	classifyOnce sync.Once
	classifyRef  *classify.Refresher

	// auditLogger records the one thing on the identification path that no
	// person asked for: an auto-accepted merge (workstream 4.6). Optional —
	// without it the merge still happens and is still in `asset_history`; only
	// the audit trail is thinner. Wired by SetAuditLogger from main.go.
	auditLogger auditLogger

	// onCryptoChanged is called after ingest has written or refreshed a crypto
	// configuration, with the tenant whose posture just moved. It is how the
	// `crypto` finding producer learns to re-run without waiting for the
	// nightly pass (workstream 3.2).
	//
	// It replaced a direct per-asset risk recompute here. Since ADR-0005 D4 the
	// asset's score is MAX over its open risk-feeding FINDINGS, and at this
	// point in ingest there is no finding yet — the producer has not run — so
	// recomputing here would write a 0 the producer immediately overwrites,
	// making the asset flicker through "not assessed" on every observation.
	// Asking the producer to run is the honest ordering: judge first, then roll
	// up.
	//
	// Optional and nil-safe, and it MUST NOT block or fail ingest. Findings are
	// ours; the observation is the user's. FindingProducerJob.Trigger returns
	// immediately and coalesces per tenant.
	onCryptoChanged func(ctx context.Context, tenantID uuid.UUID)

	// cableIntake files a posted sighting's LLDP / CDP neighbours as proposed
	// cables, parked terminations and drift findings (DCIM row 3.3). Nil:
	// neighbours are not filed.
	cableIntake *CableIntake
}

// SetCableIntake wires the neighbour → cable intake (DCIM row 3.3).
func (s *AssetService) SetCableIntake(c *CableIntake) { s.cableIntake = c }

// OnCryptoChanged installs the post-ingest hook. See the field comment.
func (s *AssetService) OnCryptoChanged(fn func(ctx context.Context, tenantID uuid.UUID)) {
	s.onCryptoChanged = fn
}

// auditLogger is the one method of the audit middleware this service uses.
//
// An interface rather than the concrete *audit.Middleware so the service can be
// tested without an audit-service to POST to, and so a nil one is a documented
// state rather than a panic.
type auditLogger interface {
	LogActivity(ctx context.Context, req *auditmiddleware.ActivityLogRequest) error
}

// SetAuditLogger wires the audit middleware.
func (s *AssetService) SetAuditLogger(l auditLogger) { s.auditLogger = l }

func NewAssetService(db *database.DB) *AssetService {
	// Initialize event publisher (may be nil if NATS unavailable)
	eventPublisher, _ := NewEventPublisherService()

	return &AssetService{
		db:                 db,
		certificateService: NewCertificateService(db, eventPublisher),
		algorithmService:   NewAlgorithmService(db),
		eventPublisher:     eventPublisher,
		weakCryptoDetector: NewWeakCryptoDetector(eventPublisher),
		integrationCipher:  newIntegrationCipher(),
		businessUnits:      NewBusinessUnitService(db),
		sites:              NewSiteService(db),
	}
}

// SetSiteService shares one SiteService (and therefore one change recorder)
// between the Sites API and the asset write paths.
func (s *AssetService) SetSiteService(v *SiteService) {
	if v != nil {
		s.sites = v
	}
}

// SetBusinessUnitService shares one BusinessUnitService (and therefore one
// change recorder) between the Business Units API and the asset write paths.
func (s *AssetService) SetBusinessUnitService(b *BusinessUnitService) {
	if b != nil {
		s.businessUnits = b
	}
}

// newIntegrationCipher builds the cipher for public.integrations.auth_config.
//
// That table has TWO writers in different services — this one (tenant
// self-service, POST /inventory-service/integrations) and admin-service's MSP
// tenant-integration service — and until now they disagreed: admin-service
// encrypted, this one stored plaintext, so a tenant's credentials were
// protected or not depending purely on which endpoint they happened to hit.
// Both now share credentials.IntegrationAuthConfigPolicy so the column has one
// meaning regardless of writer.
//
// WithLegacyUnprefixedCiphertext is required here and not elsewhere: rows
// admin-service already wrote hold BARE ciphertext (its hand-rolled encryptor
// predates the enc:v1: tag). Without the option those rows would be read as
// plaintext and handed to a connector as a credential. See the option's doc for
// why the guess is safe.
func newIntegrationCipher() *credentials.Cipher {
	cipher, err := credentials.NewCipher(
		"integrations.auth_config",
		sharedconfig.GetEnv("ENCRYPTION_MASTER_KEY", ""),
		credentials.IntegrationAuthConfigPolicy,
		credentials.WithLegacyUnprefixedCiphertext(),
	)
	if err != nil {
		log.Printf("[inventory] ERROR: credential encryption unavailable (%v) — integration auth_config will be stored unencrypted", err)
		return nil
	}
	return cipher
}

// SetEnrichmentServices injects the optional service identification service
// for IngestFindings enrichment. Prefix context (classification, approval,
// environment and location) needs no service: it is read from `prefixes`
// (prefix_context.go).
func (s *AssetService) SetEnrichmentServices(idSvc *ServiceIdentificationService) {
	s.serviceIdentificationSvc = idSvc
}

// SetExternalConnectionsService injects the external connections service so
// IngestFindings can route third-party discoveries to the external_connections table.
func (s *AssetService) SetExternalConnectionsService(svc *ExternalConnectionsService) {
	s.externalConnectionsSvc = svc
}

// buildSuppressionKey generates the same suppression_key used in asset_suppressions
func buildSuppressionKey(hostname *string, ipAddress *string, port *int) string {
	h := ""
	if hostname != nil {
		h = *hostname
	}
	ip := ""
	if ipAddress != nil {
		ip = *ipAddress
	}
	p := ""
	if port != nil {
		p = fmt.Sprintf("%d", *port)
	}
	raw := h + "|" + ip + "|" + p
	sum := md5.Sum([]byte(raw)) //nolint:gosec // intentional — deterministic non-crypto suppression key, not a security primitive
	return hex.EncodeToString(sum[:])
}

// isSuppressed checks if a pending discovery matches a denied/suppressed fingerprint.
//
// B-42: this used to return (false, nil) for EVERY error, which is how the
// missing asset_suppressions table stayed invisible — `relation does not exist`
// read identically to "no matching fingerprint". Only sql.ErrNoRows means "not
// suppressed"; anything else is returned so a caller can tell a genuine miss
// from a broken query.
func (s *AssetService) isSuppressed(tenantID uuid.UUID, hostname *string, ipAddress *string, port *int) (bool, error) {
	return s.isSuppressedOn(nil, tenantID, hostname, ipAddress, port)
}

// isSuppressedOn is isSuppressed on the caller's transaction when tx is
// non-nil (the ingest gate reads it on the identity engine's). The read runs
// under a savepoint there, so a failure — reported, never fatal — does not
// leave the engine holding an aborted transaction.
func (s *AssetService) isSuppressedOn(tx *sqlx.Tx, tenantID uuid.UUID, hostname *string, ipAddress *string, port *int) (bool, error) {
	key := buildSuppressionKey(hostname, ipAddress, port)
	var exists bool
	// RLS-scoped read over asset_suppressions (tenant_isolation policy).
	query := `SELECT TRUE FROM asset_suppressions WHERE tenant_id = $1 AND suppression_key = $2 LIMIT 1`
	read := func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID, key).Scan(&exists)
	}
	var err error
	if tx != nil {
		err = withSavepoint(tx, "asset_suppression_lookup", func() error {
			rErr := read(tx)
			if errors.Is(rErr, sql.ErrNoRows) {
				// Not found is an answer, not a failure: keep the savepoint.
				return nil
			}
			return rErr
		})
	} else {
		err = database.WithTenantTx(context.Background(), s.db, tenantID, read)
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return exists, nil
}

func addSuppressionTx(tx *sqlx.Tx, tenantID uuid.UUID, hostname *string, ipAddress *string, port *int, userID *uuid.UUID, reason string) error {
	key := buildSuppressionKey(hostname, ipAddress, port)
	var h interface{}
	if hostname != nil {
		h = *hostname
	}
	var ip interface{}
	if ipAddress != nil {
		ip = *ipAddress
	}
	var p interface{}
	if port != nil {
		p = *port
	}
	query := `
		INSERT INTO asset_suppressions (tenant_id, hostname, ip_address, port, reason, created_by, suppression_key)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, suppression_key) DO NOTHING
	`
	var createdBy interface{} = nil
	if userID != nil {
		createdBy = *userID
	}
	_, err := tx.Exec(query, tenantID, h, ip, p, reason, createdBy, key)
	return err
}

func ptrString(v string) *string {
	return &v
}

// discoverySourceMetadata derives the canonical discovery_source / sensor_id /
// batch_id keys for an asset's metadata jsonb column from an incoming IngestFinding.
// The converter in discovery-processor-service stamps RawData["source"] with the
// internal name ("sensor_discovery" / "cloud_discovery"); this normalizes those to
// the plural form ("sensor_discoveries" / "cloud_discovery" / ...) that the
// approvals-tab UI filter buttons and the auto-approval rule conditions both expect.
func discoverySourceMetadata(f IngestFinding) models.JSONB {
	if f.RawData == nil {
		return models.JSONB{}
	}
	out := models.JSONB{}
	if raw, ok := f.RawData["source"].(string); ok && raw != "" {
		switch raw {
		// The converter now preserves a scan / PCAP row's own source (so
		// findingSource can rank it), but the Approvals filter buttons and the
		// auto-approval conditions know these rows as sensor discoveries.
		case "sensor_discovery", "sensor_discoveries", "active_scan", "discovery_jobs", "pcap", "pcap_upload":
			out["discovery_source"] = "sensor_discoveries"
		case "cloud_discovery":
			out["discovery_source"] = "cloud_discovery"
		case "device_interrogation":
			out["discovery_source"] = "device_interrogation"
		default:
			out["discovery_source"] = raw
		}
	}
	if sid, ok := f.RawData["sensor_id"].(string); ok && sid != "" {
		out["sensor_id"] = sid
	}
	if bid, ok := f.RawData["batch_id"].(string); ok && bid != "" {
		out["batch_id"] = bid
	}
	return out
}

// mapRiskScoreToLevel maps a 0-100 risk score to Critical/High/Medium/Low/Informational.
func mapRiskScoreToLevel(score int) string {
	return models.GetRiskLevel(score)
}

func nullStringToPtr(n sql.NullString) *string {
	if n.Valid {
		return &n.String
	}
	return nil
}

// applyCertQualityFlags applies the certificate quality flags (SCT, known-bad
// CA, OCSP, EV) carried in discovery RawData to the CertificateData. They are
// read by shared certificates.CertificateQualityFromMetadata — the same reader
// the external-connections writer uses, so the two tables cannot disagree
// about what a discovery said ( F16).
func (s *AssetService) applyCertQualityFlags(certData *models.CertificateData, rawData map[string]interface{}) {
	if rawData == nil {
		return
	}
	q := sharedcerts.CertificateQualityFromMetadata(rawData)
	if q.HasSCT != nil {
		certData.HasSCT = q.HasSCT
	}
	if q.SCTSource != nil {
		certData.SCTSource = *q.SCTSource
	}
	if q.KnownBadCA != nil {
		certData.KnownBadCA = *q.KnownBadCA
	}
	if _, stated := rawData["cert_is_ev"].(bool); stated {
		certData.IsEV = q.IsEV
	}
	if q.OCSPStatus != nil {
		certData.OCSPStatus = *q.OCSPStatus
	}
	if q.OCSPDetail != nil {
		certData.OCSPDetail = *q.OCSPDetail
	}
}

// atRestProtocolSentinel is the marker device-interrogation-service USED TO
// stamp in a finding's protocol column for a resource whose cryptography is at
// rest rather than negotiated on the wire.
//
// The producer stopped writing it in phase 1 (sub-task C): it was a sentinel in
// a column typed for protocols, and every consumer had to know the magic word
// to avoid materialising a phantom TLS endpoint from it. The producer now sets
// an explicit `at_rest: true` in the discovery metadata and leaves the protocol
// empty, which is independently true — nothing was negotiated.
//
// The string is still recognised on READ, for one release, because a
// sensor_discoveries row queued before the upgrade still carries it and a row
// in flight is not a backfill. Delete this constant and the second half of
// findingIsAtRest once no unprocessed row can hold it.
const atRestProtocolSentinel = "AT-REST"

// findingIsAtRest reports whether a finding describes an at-rest resource
// rather than a network endpoint.
//
// Two consequences, both of them "do less rather than invent something":
//
//   - No endpoint row. DATA_MODEL §2: an at-rest resource simply has no
//     asset_endpoints row, which is what retired the AT-REST PORT sentinel.
//   - No crypto configuration. A crypto configuration IS a protocol
//     observation; an S3 bucket negotiates nothing, and a row with every crypto
//     column NULL is the phantom TLS endpoint this replaces. Its encryption
//     posture belongs in crypto_applications (B-22).
func findingIsAtRest(f IngestFinding) bool {
	if v, ok := f.RawData["at_rest"].(bool); ok && v {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(f.Protocol), atRestProtocolSentinel)
}

// refusedHandshakeNote is the identification note the scan engine stamps on a
// TLS port that answered the ClientHello with an alert (shared/discovery
// identify.go). Such a finding names the protocol and measures nothing.
const refusedHandshakeNote = "tls-handshake-refused"

func findingIsRefusedHandshake(f IngestFinding) bool {
	note, _ := f.RawData["identification_note"].(string)
	return note == refusedHandshakeNote
}

// recordHandshakeOutcome keeps asset_endpoints.tls_handshake_outcome in step
// with the finding's endpoint, so the asset can say "TLS, handshake refused"
// instead of showing a bare TLS endpoint with nothing under it.
//
//   - A finding carrying the refused note sets it to 'refused'.
//   - Any other finding that names a modelled protocol on that endpoint clears
//     it: the endpoint has since been measured as something, and a refusal from
//     an earlier scan is no longer the latest word. (A later scan by name is the
//     usual way a refused port starts negotiating.)
//   - A finding that names no modelled protocol leaves it alone: an
//     unidentified sighting says nothing about the handshake either way.
//
// The endpoint is looked up, never created (resolveEndpointForFinding).
func (s *AssetService) recordHandshakeOutcome(ctx context.Context, tenantID, assetID uuid.UUID, f IngestFinding) bool {
	refused := findingIsRefusedHandshake(f)
	if !refused {
		if _, verdict := resolveProtocol(f.Protocol); verdict != protocolEnum {
			return false
		}
	}
	epID, err := s.resolveEndpointForFinding(ctx, tenantID, assetID, f)
	if err != nil || epID == uuid.Nil {
		// Not attached, or no socket: nothing to annotate. A lookup failure is
		// not worth failing the finding for; the next scan rewrites the state.
		if err != nil && !errors.Is(err, errEndpointNotAttached) {
			log.Printf("[AssetService] IngestFindings: resolving the endpoint to record the handshake outcome for %s failed: %v", findingLabel(f), err)
		}
		return false
	}
	var outcome interface{}
	if refused {
		outcome = handshakeOutcomeRefused
	}
	moved := false
	wErr := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		res, e := tx.Exec(`
			UPDATE asset_endpoints SET tls_handshake_outcome = $1::text, updated_at = NOW()
			WHERE id = $2 AND tenant_id = $3 AND tls_handshake_outcome IS DISTINCT FROM $1::text`,
			outcome, epID, tenantID)
		if e == nil {
			if n, nErr := res.RowsAffected(); nErr == nil && n > 0 {
				moved = true
			}
		}
		return e
	})
	if wErr != nil {
		log.Printf("[AssetService] IngestFindings: recording the handshake outcome on endpoint %s failed: %v", epID, wErr)
		return false
	}
	return moved
}

// handshakeOutcomeRefused is the value asset_endpoints.tls_handshake_outcome
// holds for a port that answered the ClientHello with a TLS alert.
const handshakeOutcomeRefused = "refused"

// protocolVerdict is what resolveProtocol answers with. Only protocolEnum
// carries a value a row may store in crypto_implementations.protocol; the other
// three each say "there is no protocol observation here", for a different
// reason, and each reason is worth logging differently.
type protocolVerdict int

const (
	// protocolEnum: the observed string names a protocol the enum models.
	protocolEnum protocolVerdict = iota
	// protocolTransport: the observed string names a TRANSPORT (tcp/udp), not
	// an application protocol. "The port answered a TCP handshake" is not a
	// cryptographic observation — nothing was negotiated.
	protocolTransport
	// protocolPlaintext: the observed string explicitly says no encryption was
	// in use (the database collectors' "NONE" when SSL is off). Recording that
	// as a crypto configuration inverts the finding.
	protocolPlaintext
	// protocolUnrecognized: we do not know what this protocol is. A crypto
	// configuration IS a protocol observation, so there is nothing to record.
	protocolUnrecognized
)

func (v protocolVerdict) String() string {
	switch v {
	case protocolEnum:
		return "modelled"
	case protocolTransport:
		return "a transport, not an application protocol"
	case protocolPlaintext:
		return "explicitly unencrypted"
	default:
		return "unrecognised"
	}
}

// resolveProtocol maps an observed protocol name onto the protocol_type enum.
// Keep the mapped set in sync with the CREATE TYPE protocol_type statement in
// scripts/database/schema.sql.
//
// The sensor emits protocol identifiers as it parses them from the wire (often
// with hyphenation or vendor casing); this function maps those aliases to the
// canonical enum literal.
//
// It does NOT invent an answer when it has none. It used to: the default arm
// returned "TLS" for every string it did not recognise, with only a warning
// log. crypto_implementations.protocol is NOT NULL and enum-typed, so the row
// that landed asserted a negotiated-TLS observation that never happened — empty
// protocol_version, empty cipher_suite — and fed the risk and PQC denominators.
// Three kinds of string went through that arm: transports (cluster-sensor
// stamps "tcp" on every scanned port whose probe does not reply, so a quiet
// Modbus segment became a wall of phantom TLS endpoints), the database
// collectors' explicit "NONE" (SSL is OFF — the exact inverse of what got
// stored), and genuinely unknown names. None of the three is a TLS measurement,
// and the enum has no honest value for any of them, so the caller is told there
// is nothing to record instead. See the short-circuit in
// processDiscoveryCryptoData, and the same correction for the AT-REST sentinel
// above.
//
// This is NOT the same job as cryptoparse.NormalizeProtocol, which runs at
// ingest on the three free-text protocol columns. That one only fixes SPELLING
// and passes an unknown protocol through untouched. This one is the semantic
// map onto the enum — it is allowed to decide that HTTPS is TLS and that
// WireGuard is a VPN. Its alias arms for the OT spellings are now
// belt-and-braces for freshly written rows and still load-bearing for rows
// written before that.
func resolveProtocol(protocol string) (string, protocolVerdict) {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "HTTPS", "HTTP/2", "HTTP2":
		return "TLS", protocolEnum // HTTPS is TLS over HTTP
	case "TLS", "SSL":
		return "TLS", protocolEnum
	// STARTTLS names the upgrade, not a different protocol: what the session
	// ends up speaking is TLS, and the sensor's STARTTLS assembler already
	// emits "TLS" (starttls_assembler.go). This arm is defensive — the string
	// is a routing label inside analyzePacket that no discovery currently
	// carries — but it is true, and being true costs nothing.
	case "STARTTLS":
		return "TLS", protocolEnum
	// A FortiGate SSL-VPN portal is TLS on 443/10443, and the collector reads a
	// real TLS version, cipher suite, key size and hash off it
	// (convertSSLVPNToAsset). Filing it as TLS is what puts those measurements
	// under the two protocol='TLS' compliance rules, which is where a portal
	// still offering TLS 1.0 has to be caught; filing it as VPN would hide it
	// from every one of them. That it is a VPN is not lost — the same asset
	// carries asset_type "vpn_gateway".
	case "SSL VPN", "SSL-VPN", "SSLVPN", "SSL_VPN":
		return "TLS", protocolEnum
	case "SSH":
		return "SSH", protocolEnum
	// QUIC gets its own enum value rather than a mapping. Its handshake is
	// TLS 1.3, but the record layer, version negotiation and transport are
	// QUIC's own and it runs over UDP, so calling it TLS asserts a TCP endpoint
	// that does not exist and hands the TLS-version rule a version string
	// ("QUIC v1 (TLS 1.3)") it cannot read.
	case "QUIC", "HTTP/3", "HTTP3", "H3":
		return "QUIC", protocolEnum
	// PPTP likewise. Mapping it to VPN would file the most dangerous VPN a
	// collector can report under the same label as WireGuard. Note that the
	// enum value alone scores nothing: PPTP carries no cipher or version to
	// link, so its risk comes from the PPTP row in the `algorithms` catalogue,
	// reached via the protocol_version the UniFi collector stamps.
	case "PPTP":
		return "PPTP", protocolEnum
	// IKE and IKEv2 are the key-exchange half of an IPSec association, which is
	// what the Cisco collector reports them as (parseIKEv2SA stamps "IKEv2").
	// IKEV2 had no arm, so every Cisco IKEv2 SA — a real, correctly identified
	// VPN association — was filed as TLS.
	// L2TP/IPSec is IPSec for every purpose this column serves: L2TP itself
	// carries no cryptography, IPSec provides all of it, and UniFi's
	// unifiFillIPsecCrypto populates encryption, hash, DH group and IKE version
	// from the same proposal set a plain IPSec tunnel reports. The L2TP framing
	// stays in metadata. Same treatment IKE/IKEv2 already get.
	case "IPSEC", "IP-SEC", "IKE", "IKEV2", "IKE-V2", "IKE_V2",
		"L2TP/IPSEC", "L2TP-IPSEC", "L2TP_IPSEC", "L2TPIPSEC", "L2TP OVER IPSEC":
		return "IPSec", protocolEnum
	case "VPN", "WIREGUARD", "OPENVPN":
		return "VPN", protocolEnum
	case "SMB":
		return "SMB", protocolEnum
	case "KERBEROS":
		return "Kerberos", protocolEnum
	case "DATABASE", "DB":
		return "Database", protocolEnum
	case "API", "REST", "GRAPHQL":
		return "API", protocolEnum
	// OT/ICS protocols. The sensor emits the protocol name directly
	// from its assemblers; we accept common vendor / standard aliases.
	case "MODBUS", "MODBUS/TCP", "MODBUS_TCP", "MODBUS-TCP":
		return "Modbus", protocolEnum
	case "DNP3", "DNP3.0", "DNP3-SAV5", "DNP3-SAV6", "DNP3_SAV5", "DNP3_SAV6":
		return "DNP3", protocolEnum
	case "OPC_UA", "OPC-UA", "OPCUA", "OPC UA":
		return "OPC_UA", protocolEnum
	case "ETHERNET_IP", "ETHERNET-IP", "ETHERNET/IP", "ENIP", "CIP":
		return "EtherNet_IP", protocolEnum
	case "BACNET":
		return "BACnet", protocolEnum
	case "BACNET_SC", "BACNET-SC", "BACNET/SC":
		return "BACnet_SC", protocolEnum
	case "HART_IP", "HART-IP", "HARTIP":
		return "HART_IP", protocolEnum
	case "S7", "S7COMM", "S7-COMM", "S7_COMM", "S7-PLUS", "S7PLUS", "S7_PLUS":
		return "S7", protocolEnum
	case "MMS", "IEC-61850-MMS", "IEC61850-MMS", "IEC61850_MMS":
		return "MMS", protocolEnum
	case "ICCP", "TASE.2", "TASE-2", "TASE_2":
		return "ICCP", protocolEnum
	case "IEC62351", "IEC-62351", "IEC_62351":
		return "IEC62351", protocolEnum

	// Transports. cluster-sensor's mapProtocol preserve-list covers only
	// TLS/SSH-shaped requests, so every other scanned port — including every OT
	// target whose protocol probe got no reply — comes back stamped with the
	// transport nmap reported.
	case "TCP", "UDP":
		return "", protocolTransport

	// Explicitly unencrypted. shared/deviceinterrogation/database.go stamps
	// "NONE" when the engine reports SSL is off; the CloudFront collector
	// stamps "HTTP" when the origin protocol policy is http-only, under a
	// comment reading "Do not report a TLS version it does not use" — which is
	// precisely what the old default then did. Both are measurements, and the
	// thing they measured is the absence of transport encryption.
	case "NONE", "HTTP":
		return "", protocolPlaintext

	// DELIBERATELY UNMODELLED, so it is not "fixed" by the next reader.
	//
	// SNMP. shared/deviceinterrogation/probers.go stamps it on the one asset
	// SNMPInterrogator emits, which represents the DEVICE and carries only
	// sysDescr/sysName OIDs — no cipher, no version, no key. There is no
	// cryptographic observation in it to record, and a row here would carry
	// empty crypto columns, score 0, and enlarge the risk and PQC denominators
	// with something never measured. The asset itself is still recorded by the
	// caller. (That a v2c interrogation SUCCEEDED does prove plaintext SNMP
	// management is enabled — a real security fact, but a finding about the
	// device's management plane, not a negotiated-protocol measurement.)
	default:
		return "", protocolUnrecognized
	}
}

// Health checks the database connection health
func (s *AssetService) Health() error {
	return s.db.Health()
}

// GetAssets, GetAssetByID, GetAssetHistory, GetRiskSummary, GetAssetStats, GetRecentAssetsCount -> asset_queries.go
// GetCryptoImplementations, AnalyzeCryptoRisk, Attach*, CreateLibrary, ListKeys, ListLibraries, GetExternalMappings, classifyAndLinkAlgorithms -> crypto_queries.go
// GetAssetFacets -> asset_facets_queries.go. EnrichAllAssets -> enrichment_service.go. IngestFinding -> discovery_queries.go. Certificate extraction -> certificate_queries.go.

// Integrations CRUD (tenant-scoped)
//
// AuthConfig / MappingConfig are database.JSONMap, not plain maps: these are
// jsonb columns, and database/sql cannot scan []byte into a Go map, so every
// ListIntegrations call failed at runtime before this. JSON encoding is
// identical, so the API response shape is unchanged.
type Integration struct {
	ID            uuid.UUID        `db:"id" json:"id"`
	TenantID      uuid.UUID        `db:"tenant_id" json:"tenant_id"`
	Name          string           `db:"name" json:"name"`
	Type          string           `db:"type" json:"type"`
	BaseURL       string           `db:"base_url" json:"base_url"`
	AuthType      string           `db:"auth_type" json:"auth_type"`
	AuthConfig    shareddb.JSONMap `db:"auth_config" json:"auth_config"`
	MappingConfig shareddb.JSONMap `db:"mapping_config" json:"mapping_config"`
	IsEnabled     bool             `db:"is_enabled" json:"is_enabled"`
	CreatedAt     time.Time        `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time        `db:"updated_at" json:"updated_at"`
}

func (s *AssetService) ListIntegrations(tenantID uuid.UUID) ([]Integration, error) {
	query := `SELECT id, tenant_id, name, type, base_url, auth_type, auth_config, mapping_config, is_enabled, created_at, updated_at FROM integrations WHERE tenant_id = $1`
	var list []Integration
	// RLS-scoped read over integrations.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&list, query, tenantID)
	}); err != nil {
		return nil, fmt.Errorf("failed to list integrations: %w", err)
	}
	// Decrypt credential fields. Rows predating this change are plaintext and
	// pass through; they are encrypted on their next save.
	for i := range list {
		decrypted, err := s.integrationCipher.DecryptMap(list[i].AuthConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt auth_config for integration %s: %w", list[i].ID, err)
		}
		list[i].AuthConfig = decrypted
	}
	return list, nil
}

// ListIntegrationsRedacted is what the HTTP list endpoint serves.
//
// ListIntegrations DECRYPTS auth_config, so the raw list carries plaintext
// third-party credentials (SIEM/CMDB/ITSM API keys, bearer tokens, passwords).
// A list is a browse surface: nobody browsing their integrations needs the
// secret back, and returning it means every caller of that route — including a
// read-only PAT — walks away with the credentials. So the list is redacted
// unconditionally, independently of the settings.read gate on the route. The
// gate decides who may look; this decides what looking can ever yield.
//
// Non-secret keys (host, username, region, index, auth style, …) survive, so
// the UI can still show the shape of a connection. The Update flow is
// unaffected: it takes the new auth_config from the request body and returns
// the decrypted result of its own write.
func (s *AssetService) ListIntegrationsRedacted(tenantID uuid.UUID) ([]Integration, error) {
	list, err := s.ListIntegrations(tenantID)
	if err != nil {
		return nil, err
	}
	for i := range list {
		list[i].AuthConfig = redactIntegrationAuthConfig(list[i].AuthConfig)
	}
	return list, nil
}

// redactIntegrationAuthConfig replaces secret-looking values by field name,
// reusing the same matcher that scrubs device-interrogation output
// (shared/deviceinterrogation.RedactMap) rather than growing a second list of
// what "looks like a secret" that would drift from the first.
func redactIntegrationAuthConfig(in shareddb.JSONMap) shareddb.JSONMap {
	if in == nil {
		return nil
	}
	return shareddb.JSONMap(deviceinterrogation.RedactMap(map[string]interface{}(in)))
}

func (s *AssetService) CreateIntegration(tenantID uuid.UUID, in Integration) (*Integration, error) {
	if in.Name == "" || in.Type == "" || in.BaseURL == "" || in.AuthType == "" {
		return nil, fmt.Errorf("name, type, base_url, auth_type are required")
	}
	in.TenantID = tenantID
	encryptedAuth, err := s.integrationCipher.EncryptMap(in.AuthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt auth_config: %w", err)
	}
	authJSON, _ := json.Marshal(encryptedAuth)
	mapJSON, _ := json.Marshal(in.MappingConfig)
	insert := `INSERT INTO integrations (tenant_id, name, type, base_url, auth_type, auth_config, mapping_config, is_enabled)
               VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id, created_at, updated_at`
	// RLS-scoped write over integrations.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(insert, tenantID, in.Name, in.Type, in.BaseURL, in.AuthType, authJSON, mapJSON, in.IsEnabled).Scan(&in.ID, &in.CreatedAt, &in.UpdatedAt)
	}); err != nil {
		return nil, fmt.Errorf("failed to create integration: %w", err)
	}
	return &in, nil
}

func (s *AssetService) UpdateIntegration(tenantID, id uuid.UUID, in Integration) (*Integration, error) {
	encryptedAuth, err := s.integrationCipher.EncryptMap(in.AuthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt auth_config: %w", err)
	}
	authJSON, _ := json.Marshal(encryptedAuth)
	mapJSON, _ := json.Marshal(in.MappingConfig)
	update := `UPDATE integrations SET name=COALESCE(NULLIF($1,''),name), type=COALESCE(NULLIF($2,''),type), base_url=COALESCE(NULLIF($3,''),base_url), auth_type=COALESCE(NULLIF($4,''),auth_type), auth_config=$5, mapping_config=$6, is_enabled=$7, updated_at=NOW() WHERE tenant_id=$8 AND id=$9 RETURNING id, tenant_id, name, type, base_url, auth_type, auth_config, mapping_config, is_enabled, created_at, updated_at`
	var out Integration
	// RLS-scoped write over integrations.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Get(&out, update, in.Name, in.Type, in.BaseURL, in.AuthType, authJSON, mapJSON, in.IsEnabled, tenantID, id)
	}); err != nil {
		return nil, fmt.Errorf("failed to update integration: %w", err)
	}
	// RETURNING hands back the stored (encrypted) row; decrypt so the caller's
	// response matches what it sent, as it did before encryption existed.
	decrypted, err := s.integrationCipher.DecryptMap(out.AuthConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt auth_config: %w", err)
	}
	out.AuthConfig = decrypted
	return &out, nil
}

func (s *AssetService) DeleteIntegration(tenantID, id uuid.UUID) error {
	// RLS-scoped write over integrations.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`DELETE FROM integrations WHERE tenant_id=$1 AND id=$2`, tenantID, id)
		return e
	}); err != nil {
		return fmt.Errorf("failed to delete integration: %w", err)
	}
	return nil
}

// isUnspecifiedIP reports whether ip is the "any"/placeholder address (0.0.0.0
// or ::) that cloud-API discovery writes for non-network resources instead of a
// routable address.
func isUnspecifiedIP(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.IsUnspecified()
}

// isCloudManagedPlaceholder reports whether a finding represents a cloud-API
// discovery of a non-network resource (KMS key, storage bucket, SQL database).
// Those carry a distinct per-resource hostname but only an unspecified
// placeholder IP (0.0.0.0 / ::) or no IP at all. They are managed cloud assets,
// NOT external endpoints, so callers must keep them on the managed-asset path
// (never route them to external_connections, where the shared placeholder IP
// would collapse every such resource onto one row). A finding with a real
// routable IP is never a placeholder, regardless of discovery method.
func isCloudManagedPlaceholder(f IngestFinding) bool {
	if f.IPAddress != nil && *f.IPAddress != "" && !isUnspecifiedIP(*f.IPAddress) {
		return false
	}
	return isCloudAPIFinding(f)
}

// isCloudAPIFinding reports whether a finding came from a cloud provider's API
// rather than from a sensor, a probe or an agent. Says nothing about the
// finding's address — see isCloudManagedPlaceholder for that.
func isCloudAPIFinding(f IngestFinding) bool {
	if f.RawData == nil {
		return false
	}
	if src, _ := f.RawData["source"].(string); src == "cloud_discovery" {
		return true
	}
	if dm, _ := f.RawData["discovery_method"].(string); dm == "cloud_api" {
		return true
	}
	return false
}

// isTenantOwnedCloudResource reports whether a finding describes a resource
// inside an account the tenant gave us credentials for — a CloudFront
// distribution, a load balancer, an API Gateway domain, a bucket, a key.
//
// This is the OWNERSHIP question, and it is a different question from
// isCloudManagedPlaceholder's, which is about addressability. Keeping them
// apart is the point:
//
//   - isCloudManagedPlaceholder stays exactly as it was. A finding with a real
//     routable IP is still never a placeholder, so the shared 0.0.0.0/:: can
//     still never become a match key and can still never collapse every bucket
//     and key store onto one external_connections row. That collapse is the bug
//     that helper was written to fix and nothing here reopens it: this
//     predicate feeds ONLY the ownership decision, never the effective IP,
//     never the identity lookup.
//
//   - Ownership is decided by provenance. A resource enumerated through the
//     tenant's OWN cloud credentials belongs to the tenant whatever its
//     address. Deciding it from the address instead is how a tenant's own CDN,
//     which necessarily has a public routable IP, was filed as a third-party
//     connection: classifyAsset saw a non-RFC-1918 address, said "third_party",
//     and the distribution's certificate went to external_connections instead
//     of onto the asset.
//
// The signal is on the finding already: the cloud collectors stamp
// `discovery_method = cloud_api` and the id of the integration whose
// credentials were used. Requiring the integration id as well as the method
// keeps this to resources reached through a credential the tenant supplied.
func isTenantOwnedCloudResource(f IngestFinding) bool {
	if !isCloudAPIFinding(f) {
		return false
	}
	integrationID, _ := f.RawData["integration_id"].(string)
	return strings.TrimSpace(integrationID) != ""
}

// IngestReport is what one ingest batch DID, beyond the count of rows it
// touched.
//
// It exists because the caller — discovery-processor-service — decided a
// requested status per discovery row and then had no way to learn what actually
// happened to it. A finding whose row matched no auto-approval rule but landed
// on an asset the tenant approved long ago is fully materialized here and was
// still being stamped `approval_status = 'pending'` over there, where nothing
// ever looks at it again: the Approvals page lists pending ASSETS, and there is
// no pending asset for an already-approved one.
type IngestReport struct {
	Results []identity.IngestResult
	// Imported is the count IngestFindings has always returned: assets
	// created, assets refreshed, and findings routed to external_connections.
	Imported int

	// EffectiveStatus is index-aligned with the findings passed in.
	// EffectiveStatus[i] is the asset_status the i-th finding's asset ACTUALLY
	// has — not the one the batch asked for — and is empty when the finding
	// landed on no asset at all: skipped for want of an identifier, held by a
	// merge proposal, or routed to external_connections.
	EffectiveStatus []string
}

// IngestFindings upserts assets and attaches crypto configurations for each finding
// assetStatus is optional and defaults to "pending_approval" if not provided.
//
// It is the count-only form of [AssetService.IngestFindingsReport], kept because
// most callers only ever wanted the count.
func (s *AssetService) IngestFindings(tenantID uuid.UUID, findings []IngestFinding, assetStatus ...string) (int, error) {
	report, err := s.IngestFindingsReport(tenantID, findings, assetStatus...)
	return report.Imported, err
}

// IngestFindingsReport is IngestFindings with the per-finding outcome the
// transport needs. See [IngestReport]. Every finding's new asset lands as
// assetStatus (default pending_approval): the caller decided it.
func (s *AssetService) IngestFindingsReport(tenantID uuid.UUID, findings []IngestFinding, assetStatus ...string) (IngestReport, error) {
	// Determine asset_status: use provided value or default to "pending_approval"
	status := "pending_approval"
	if len(assetStatus) > 0 && assetStatus[0] != "" {
		status = assetStatus[0]
	}
	return s.ingestFindings(tenantID, findings, fixedApproval(status), status)
}

// IngestPipelineFindingsReport is the discovery pipeline's import ( WP3):
// the status each finding's new asset lands as is decided HERE, per finding,
// by the tenant's auto-approval rules over this service's own classification
// (pipelineApproval). The rule that matched is reported per finding in
// IngestResult.AutoApprovalRuleID so the caller can credit it on the
// discovery row.
func (s *AssetService) IngestPipelineFindingsReport(tenantID uuid.UUID, findings []IngestFinding) (IngestReport, error) {
	return s.ingestFindings(tenantID, findings, s.pipelineApproval(tenantID), "per finding")
}

// Outcomes inventory-service stamps itself, beside the identity.Outcome set.
const (
	// ingestOutcomeRouted: the finding was written to external_connections.
	ingestOutcomeRouted = "routed"
	// ingestOutcomeDropped: the finding was recorded nowhere, for a property
	// of its own (IngestResult.Reason says which).
	ingestOutcomeDropped = "dropped"
	// ingestOutcomeError: the finding could not be settled THIS time, for a
	// reason that is not a property of the finding (a transient database
	// error, a resolver timeout, a failed upsert). IngestResult.Reason carries
	// the error. The caller must retry the finding, never settle it: unlike
	// "rejected" (a decision) and "dropped" (a permanent verdict) this one
	// records nothing and promises nothing.
	ingestOutcomeError = "error"
	// dropReasonThirdPartyNoSourceIP: a third-party connection with no source
	// address ( D2). A connection record needs both ends; the upsert key
	// (tenant, source_ip, dest_ip, dest_port, protocol) used to be filled with
	// 0.0.0.0, which merged every such finding for one destination into a row
	// claiming a source nothing measured.
	dropReasonThirdPartyNoSourceIP = "third_party_no_source_ip"
)

// ingestFindings is the one ingest loop; decide says what each finding's new
// asset lands as, and statusLabel names that decision in the summary log.
func (s *AssetService) ingestFindings(tenantID uuid.UUID, findings []IngestFinding, decide approvalDecider, statusLabel string) (IngestReport, error) {
	if len(findings) == 0 {
		return IngestReport{}, nil
	}

	inserted := 0
	// The per-finding answer the caller gets back, index-aligned with findings.
	// A finding that reaches none of the branches below keeps its empty string,
	// which the transport reads as "no asset, leave the row alone".
	effective := make([]string, len(findings))
	outcomes := make([]identity.IngestResult, len(findings))
	for i := range outcomes {
		outcomes[i].Outcome = "rejected"
	}
	// The rule that decided each finding's status, folded into its result
	// when the report is returned: the branches below overwrite outcomes[i]
	// wholesale with the engine's answer.
	ruleIDs := make([]string, len(findings))
	result := func() IngestReport {
		for i, id := range ruleIDs {
			if id != "" {
				outcomes[i].AutoApprovalRuleID = id
			}
		}
		return IngestReport{Imported: inserted, EffectiveStatus: effective, Results: outcomes}
	}
	// decideFor records the approval decision for finding i and returns the
	// status its new asset lands as.
	decideFor := func(i int, f IngestFinding, cls approval.Classification) string {
		d := decide(f, cls)
		if d.ruleID != nil {
			ruleIDs[i] = d.ruleID.String()
		}
		return d.status
	}
	// Observability counters for the end-of-run import summary ().
	// Without these, a third-party route that persists nothing looks identical to a
	// successful import — which is exactly how a vendor discovery silently vanished.
	var createdManaged, updatedManaged, routedExternal, failedRoute, droppedNoSource int
	// heldByProposal counts findings the identity floor refused to write: every
	// identifier belonged to somebody else, so a merge proposal is waiting and
	// no asset was created. Counted separately from `inserted` because nothing
	// was inserted, and separately from a failure because nothing failed.
	var heldByProposal int
	// Which resolved assets get an asset.changed event is decided by what the
	// ingest changed, not by the fact that it saw them; see
	// assetChangeTracker for the rule.
	changeTracker := newAssetChangeTracker()
	var lifecycleDiscovered []struct {
		assetID             uuid.UUID
		classKey            string
		hostname, ipAddress *string
		port                *int
	}
	var lifecycleEnriched []*events.AssetEnrichedPayload
	var lifecycleRiskChanged []*events.AssetRiskChangedPayload
	var lifecycleCryptoAdded []*events.CryptoConfigurationAddedPayload
	var lifecycleCertExpiring []*events.CertificateExpiringPayload
	ctx := context.Background()
	// A position in asset_history's append order taken before any finding is
	// resolved: rows this call writes are above it (assetChangeTracker).
	historyMark, historyMarkErr := s.historyWatermark(ctx, tenantID)
	if historyMarkErr != nil {
		log.Printf("[AssetService] IngestFindings: reading the asset_history position failed; asset.changed will be published for every resolved asset: %v", historyMarkErr)
	}
	// One read of the tenant's segments for the whole request, shared by
	// classification, tags, enrichment and the identity intake ( F4).
	segs := s.newImportPrefixes(tenantID)
	// Which cloud account each cloud finding is in, for its hosted_on edge.
	cloudAccounts := s.newCloudAccountResolver(tenantID)
	source := "discovery"
	if len(findings) > 0 && findings[0].RawData != nil {
		if v, ok := findings[0].RawData["source"].(string); ok {
			source = v
		}
	}

	for i, f := range findings {
		// Host observations branch FIRST, before anything reads a crypto field
		// off the finding.
		//
		// The branch is here rather than deeper in because everything below it
		// assumes a cryptographic measurement: ownership classification (which
		// calls an addressless observation third_party and routes it to
		// external_connections), the endpoint resolution, the deferred-finding
		// store, the certificate materialisation. None of those has anything to
		// do with a passive statement that a host exists, and three of them do
		// active harm — see host_observation_ingest.go's header.
		if isHostObservation(f) {
			// findingLabel renders a crypto finding — hostname, address, port —
			// and a host observation has none of those at the top level, so it
			// would log every one of them as "?(0.0.0.0)". The payload's own
			// most-specific identity is what a reader needs.
			label := findingLabel(f)
			if ho, ok := hostObservationPayload(f); ok {
				label = hostObservationLabel(ho)
			}
			// A passively observed host is never a third party, whatever its
			// address classifies as: `third_party` is a statement about a
			// FLOW out of the tenant, and an observation has no flow — it says
			// a device exists on a segment we watch. `unknown` keeps it
			// managed; a segment rule still has to match for it to
			// auto-approve, so this widens nothing.
			hoIP := f.IPAddress
			if hoIP != nil && (*hoIP == "" || isUnspecifiedIP(*hoIP)) {
				hoIP = nil
			}
			hoClass := s.classifyFindingIn(segs, tenantID, f, hoIP)
			if hoClass.Ownership == "third_party" {
				hoClass.Ownership = "unknown"
			}
			status := decideFor(i, f, hoClass)
			res, hErr := s.ingestHostObservationIn(ctx, segs, tenantID, f, status)
			if hErr != nil {
				// One unusable observation must not lose the rest of the batch.
				// A segment with fifty hosts on it produces fifty of these, and
				// the common failure — an observation whose only identity was a
				// rotating randomised MAC — is a property of that one device.
				if errors.Is(hErr, identity.ErrNoUsableIdentifier) || errors.Is(hErr, identity.ErrInvalidObservation) || errors.Is(hErr, errNoIdentifiers) {
					log.Printf("[AssetService] IngestFindings: rejecting host observation %s: %v", label, hErr)
					continue
				}
				return result(), fmt.Errorf("retaining host observation: %w", hErr)
			}
			outcomes[i] = res.IngestResult()
			if res.Asset.Zero() {
				// Contested: every identifier belongs to another asset and none
				// could decide, so a merge proposal is waiting and nothing was
				// written. An answer, not a failure — and the batch continues,
				// which is the bug that once discarded every finding after the
				// first contested one.
				heldByProposal++
				log.Printf("[AssetService] IngestFindings: host observation %s is held by merge proposal %s; the batch continues",
					label, res.Proposal.ID)
				continue
			}
			assetID, idErr := uuid.Parse(res.Asset.ID)
			if idErr != nil {
				return result(), fmt.Errorf("identification engine returned an unusable asset id %q: %w", res.Asset.ID, idErr)
			}
			logIdentityDecisions(label, res)
			// A passive host observation changes the asset only through the
			// identity engine, which records it in asset_history; a creation is
			// a change outright.
			changeTracker.touch(assetID)
			switch res.Outcome {
			case identity.OutcomeCreated, identity.OutcomeConflict, identity.OutcomeProvisional:
				changeTracker.changed(assetID)
			}
			inserted++
			// The status the asset actually HAS, which on a conflict is not the
			// one the segment rule asked for: ingestHostObservation declines to
			// apply it, because an observation the engine could not settle is
			// its own pending asset until a human does. Logging the rule's
			// answer here would report an approval that did not happen — the
			// same shape as `kubectl set image` leaving SERVICE_VERSION on the
			// chart default and the About page reporting a version nothing is
			// running. The crypto path a hundred lines down corrects it the
			// same way.
			effectiveStatus := status
			if res.Outcome == identity.OutcomeConflict {
				effectiveStatus = identity.StatusPendingApproval
			}
			if res.Outcome == identity.OutcomeMatched {
				// A MATCHED asset already has a status, and it is not the
				// batch's to overrule. The rule the batch ran decides what a
				// NEW asset lands as; an observation of a host the tenant
				// approved months ago does not put it back in Approvals, and
				// reporting `pending_approval` for it is how eighty of these
				// rows sat unprocessed while their assets were monitoring.
				//
				// Read on EVERY match, including a batch that asked for
				// monitoring: the asset may be archived, and
				// setStatusUnlessArchived has just declined to promote it, so
				// the requested status would be a report of something that did
				// not happen.
				effectiveStatus = s.matchedAssetStatus(tenantID, assetID, effectiveStatus)
			}
			effective[i] = effectiveStatus
			switch res.Outcome {
			case identity.OutcomeCreated, identity.OutcomeConflict, identity.OutcomeProvisional:
				createdManaged++
				// Provisional is a new asset too ( F9): it must mark the
				// tenant dirty for the auto-scan sweep like Created does.
				log.Printf("[AssetService] IngestFindings: created asset %s from host observation %s (status=%s, outcome=%s)",
					assetID, label, effectiveStatus, res.Outcome)
				if s.eventPublisher != nil {
					lifecycleDiscovered = append(lifecycleDiscovered, struct {
						assetID   uuid.UUID
						classKey  string
						hostname  *string
						ipAddress *string
						port      *int
					}{assetID, res.ClassKey, f.Hostname, nil, nil})
				}
			default:
				updatedManaged++
				log.Printf("[AssetService] IngestFindings: host observation %s matched asset %s on %s", label, assetID, res.DecidedBy)
			}
			// Nothing else. There is no crypto to materialize, no endpoint to
			// identify a service on, and no finding to defer until approval.
			continue
		}

		// Cloud-API discoveries of non-network resources (KMS keys, storage
		// buckets, SQL databases) carry an unspecified placeholder IP (0.0.0.0 /
		// ::) rather than a routable address — see WriteSensorDiscoveries in
		// device-interrogation-service. Treat that placeholder as absent
		// everywhere below: it must not be persisted as a fake address, must not
		// drive third-party classification (these are managed cloud assets, not
		// external endpoints), and — critically — must not be a match key, since
		// the (hostname OR ip_address) lookup would otherwise collapse every such
		// resource onto a single asset via the shared 0.0.0.0. Identity for these
		// rows is the per-resource hostname (bucket/db/key name) plus device_id.
		effectiveIP := f.IPAddress
		if effectiveIP != nil && (*effectiveIP == "" || isUnspecifiedIP(*effectiveIP)) {
			effectiveIP = nil
		}
		cloudManaged := isCloudManagedPlaceholder(f)

		// Ownership decides whether this is ours to manage at all, and it has
		// to be known before the engine runs: a third-party endpoint belongs in
		// external_connections, not in the inventory.
		classification := s.classifyFindingIn(segs, tenantID, f, effectiveIP)
		ownership := classification.Ownership
		// A cloud-managed placeholder has no routable IP, so ClassifyAsset falls
		// through to "third_party" (0.0.0.0 is not RFC-1918). Override: these
		// are managed cloud resources, not external endpoints, and must stay on
		// the managed-asset path rather than collapsing into a single shared
		// external_connections row.
		//
		// The same override applies for the opposite reason to a cloud resource
		// that DOES have a routable address. classifyAsset works from the
		// address, and a CloudFront distribution, a public ALB or an API
		// Gateway domain is public by design — so every one of them classified
		// as third_party and went to external_connections, filing the tenant's
		// own CDN as somebody else's endpoint and taking its certificate with
		// it. Ownership is not addressability: a resource enumerated through
		// the tenant's own cloud credentials is the tenant's.
		if (cloudManaged || isTenantOwnedCloudResource(f)) && ownership == "third_party" {
			ownership = "unknown"
			classification.Ownership = ownership
			if cloudManaged {
				classification.Type = "private"
			}
		}
		// Recorded on the finding's raw data, as the processor used to stamp
		// it, so the evidence retained for this finding says how it was
		// classified.
		if f.RawData != nil {
			f.RawData["network_ownership"] = classification.Ownership
			f.RawData["network_type"] = classification.Type
		}
		status := decideFor(i, f, classification)

		// An interrogation finding with no address, a public one, or one at
		// the device's OWN address belongs to the device that was
		// interrogated — not to external_connections, and not to a new asset
		// minted from a label, a tunnel's far end or the device's own
		// management plane. See interrogation_owned_ingest.go. Any other
		// private address keeps the ordinary path below.
		if _, _, claims := interrogationOwnerClaim(f); claims {
			owner, owned, claimed, ownerErr := s.interrogationOwner(ctx, tenantID, f)
			if ownerErr != nil {
				return result(), ownerErr
			}
			toDevice := ownedByInterrogatedDevice(effectiveIP, ownership)
			if !toDevice && owned {
				own, ownErr := s.isDeviceOwnAddress(ctx, tenantID, owner, *effectiveIP)
				if ownErr != nil {
					return result(), ownErr
				}
				toDevice = own
			}
			if !toDevice {
				owned, claimed = false, false
			}
			if claimed && !owned {
				// Claimed a device the claim does not check out for. Not
				// routed by address: a tunnel's far end or a rule label is
				// not a connection the tenant made. `rejected` tells
				// discovery-processor to settle the row as `suppressed` —
				// visible, never silently dropped.
				log.Printf("[AssetService] IngestFindings: rejecting %s: its interrogated-device claim did not verify", findingLabel(f))
				continue
			}
			if owned {
				landed, landedStatus, retired, attachErr := s.attachToInterrogatedDevice(ctx, tenantID, owner, f, func(assetID uuid.UUID, of IngestFinding) error {
					var cryptoChanged bool
					defer func() {
						if cryptoChanged {
							changeTracker.changed(assetID)
						}
					}()
					if err := s.processDiscoveryCryptoDataTracked(tenantID, assetID, of, &lifecycleRiskChanged, &lifecycleCryptoAdded, &lifecycleCertExpiring, &cryptoChanged); err != nil {
						// Same posture as the resolved path: one finding's
						// materialisation failure is logged, not fatal to
						// the batch.
						log.Printf("[AssetService] IngestFindings: materializing crypto data for interrogated device %s failed (batch continues): %v", assetID, err)
					}
					return nil
				})
				if attachErr != nil {
					return result(), fmt.Errorf("attach %s to interrogated device %s: %w", findingLabel(f), owner, attachErr)
				}
				if retired {
					// The tenant archived or denied the device: nothing was
					// materialised or deferred, so this is not a match. Left
					// `rejected` (discovery-processor settles the row
					// `suppressed`), with the reason in the log.
					log.Printf("[AssetService] IngestFindings: rejecting %s: interrogated device %s is %s; its findings are not materialised",
						findingLabel(f), landed, landedStatus)
					continue
				}
				outcomes[i] = identity.IngestResult{Outcome: string(identity.OutcomeMatched), AssetID: landed.String()}
				effective[i] = landedStatus
				changeTracker.touch(landed)
				inserted++
				updatedManaged++
				log.Printf("[AssetService] IngestFindings: %s is owned by interrogated device %s (status=%s); attached there",
					findingLabel(f), landed, landedStatus)
				continue
			}
		}

		obs, obsErr := s.discoveryObservationIn(segs, tenantID, f, effectiveIP, ownership)
		if obsErr != nil {
			// An observation with no identifier could never be matched again, so
			// every re-observation of the same thing would create another asset.
			// Skipping it loses one finding; accepting it corrupts the inventory
			// permanently.
			log.Printf("[AssetService] IngestFindings: skipping %s: %v", findingLabel(f), obsErr)
			continue
		}
		// What this finding's identifiers already belong to decides, before
		// anything is written, whether it is resolved at all: a denied asset
		// is only touched, a third-party endpoint that is not an elevated
		// asset goes to external_connections, and a suppressed fingerprint is
		// not re-created. The gate takes that decision on the engine's
		// transaction, from the SAME owner read the engine then resolves on
		// ( F5) — not from a separate lookup of every identifier ahead
		// of the engine's own.
		var decline discoveryDecline
		gate := func(ctx context.Context, tx *sqlx.Tx, existing existingAsset) (bool, error) {
			decline = discoveryProceed
			if existing.Found && existing.Status == identity.StatusDenied {
				// A denied asset stays denied; a re-discovery does not undo the
				// tenant's decision, and its crypto is never (re-)materialized —
				// same as `archived` below. But the re-observation model applies
				// here too: the device is still being seen, so last-seen still
				// moves even though nothing is enriched.
				//
				// Deliberately NOT resolved through the full identity engine the
				// way `archived` is: resolving can ATTACH new identifiers (a
				// fresh MAC, a new hostname alias) to a denied asset, and — since
				// ownership here is reclassified fresh from the current
				// observation, not read off the asset's stored column — can
				// reroute the observation to external_connections when the
				// fresh classification says third_party. Both are new evidence
				// accruing to a decision the tenant already made; a denied asset
				// should grow none. A minimal Touch (advance last_seen_at only,
				// never identifiers/endpoints), made by the caller once this
				// transaction has rolled back, is the honest amount of work for a
				// decision that is not being reopened.
				decline = discoveryDeniedAsset
				return false, nil
			}
			// Third-party routing. An ELEVATED (monitoring) vendor asset is
			// refreshed in place so re-discovery keeps the promoted asset
			// current; everything else third-party goes to
			// external_connections.
			elevated := existing.Found && existing.Status == "monitoring"
			if ownership == "third_party" && !elevated && s.externalConnectionsSvc != nil {
				decline = discoveryRouteExternal
				return false, nil
			}
			if ownership == "third_party" && elevated {
				log.Printf("[AssetService] IngestFindings: refreshing elevated third-party asset %s (%s) in place", existing.ID, findingLabel(f))
			}
			if !existing.Found {
				// Suppression blocks CREATION only: the fingerprint exists so a
				// denied host that was subsequently deleted does not come back as
				// a fresh pending asset. An asset that still exists is updated —
				// denied or not, and the branch above already handled denied.
				//
				// A suppression-lookup failure is not a reason to abort the whole
				// ingest batch, but it must not be discarded silently either
				// (B-42) — log it and fall through to creating the asset, which is
				// the safe direction: a re-created asset lands in Approvals for a
				// human, whereas wrongly suppressing one hides a real discovery.
				suppressed, suppErr := s.isSuppressedOn(tx, tenantID, f.Hostname, effectiveIP, f.Port)
				if suppErr != nil {
					log.Printf("[AssetService] Warning: suppression lookup failed for tenant %s: %v", tenantID, suppErr)
				}
				if suppressed {
					decline = discoverySuppressed
					return false, nil
				}
			}
			return true, nil
		}

		res, existing, resolved, durableMaterialization, resErr := s.resolveDiscoveryObservation(segs, cloudAccounts, tenantID, f, obs, effectiveIP, ownership, status, gate)
		if resErr != nil {
			return result(), fmt.Errorf("failed to upsert asset: %w", resErr)
		}
		if !resolved {
			switch decline {
			case discoveryDeniedAsset:
				if touchErr := s.identityRepo.Touch(ctx, identity.AssetRef{TenantID: tenantID.String(), ID: existing.ID.String()}, findingObservedAt(f)); touchErr != nil {
					log.Printf("[AssetService] IngestFindings: touching denied asset %s failed (batch continues): %v", existing.ID, touchErr)
				}
				// Same as the matched-path assignment below: the caller
				// (discovery-processor's BatchProcessor) reads EffectiveStatus
				// per finding to decide the discovery row's approval_status, and
				// needs to know this landed on a denied asset rather than
				// whatever the batch asked for.
				effective[i] = identity.StatusDenied
			case discoveryRouteExternal:
				if err := s.routeToExternalConnection(tenantID, f); errors.Is(err, errThirdPartyNoSourceIP) {
					// A decision about this finding, not a failure: counted, and
					// reported per finding so the caller settles its row with
					// the reason ( D2).
					droppedNoSource++
					outcomes[i] = identity.IngestResult{Outcome: ingestOutcomeDropped, Reason: dropReasonThirdPartyNoSourceIP}
					log.Printf("[AssetService] IngestFindings: dropped third-party %s: no source address", findingLabel(f))
				} else if err != nil {
					// Do NOT swallow, and do NOT leave the "rejected" the outcome
					// was initialised to: the caller settles that terminally, so a
					// transient failure here would permanently lose the finding.
					// Report it as an error the caller retries ( WP3).
					failedRoute++
					outcomes[i] = identity.IngestResult{Outcome: ingestOutcomeError, Reason: "external_connections route failed: " + err.Error()}
					log.Printf("[AssetService] IngestFindings: ERROR routing third-party %s to external_connections: %v", findingLabel(f), err)
				} else {
					routedExternal++
					outcomes[i].Outcome = ingestOutcomeRouted
					inserted++
					log.Printf("[AssetService] IngestFindings: routed third-party %s to external_connections", findingLabel(f))
				}
			case discoverySuppressed:
				// Skipped: nothing owns it and the tenant suppressed its
				// fingerprint.
			}
			continue
		}
		outcomes[i] = res.IngestResult()
		if res.Asset.Zero() {
			// The identity floor: every identifier this finding carries already
			// belongs to another asset and none could decide, so the engine
			// opened a merge proposal and created NOTHING. That is an answer,
			// not a failure — the work item is a human's.
			//
			// This used to reach uuid.Parse("") and abort the WHOLE batch with
			// "unusable asset id". One contested host in a thousand-finding
			// sensor run therefore discarded every finding after it, and the
			// operator saw a parse error naming no asset. The two sibling call
			// sites already checked Zero() first; this one did not.
			heldByProposal++
			log.Printf("[AssetService] IngestFindings: %s is held by merge proposal %s; the batch continues",
				findingLabel(f), res.Proposal.ID)
			continue
		}
		assetID, idErr := uuid.Parse(res.Asset.ID)
		if idErr != nil {
			return result(), fmt.Errorf("identification engine returned an unusable asset id %q: %w", res.Asset.ID, idErr)
		}
		// All post-resolution writes share the lifecycle guard, including service
		// endpoints and deferred buffering. A merge may have committed since
		// Resolve returned; use its survivor and current approval under the lock.
		if err := s.withResolvedAssetLifecycle(ctx, tenantID, assetID, func(current uuid.UUID, assetStatus string, deleted bool) error {
			assetID = current
			res.Asset.ID = current.String()
			outcomes[i] = res.IngestResult()
			effective[i] = assetStatus
			changeTracker.touch(assetID)
			inserted++
			switch res.Outcome {
			case identity.OutcomeCreated, identity.OutcomeConflict, identity.OutcomeProvisional:
				changeTracker.changed(assetID)
				createdManaged++
				// Provisional is a new asset too ( F9); the outcome is in the log.
				log.Printf("[AssetService] IngestFindings: created managed asset %s for %s (status=%s, outcome=%s)",
					assetID, findingLabel(f), assetStatus, res.Outcome)
				if s.eventPublisher != nil {
					lifecycleDiscovered = append(lifecycleDiscovered, struct {
						assetID   uuid.UUID
						classKey  string
						hostname  *string
						ipAddress *string
						port      *int
					}{assetID, res.ClassKey, f.Hostname, effectiveIP, f.Port})
				}
			default:
				updatedManaged++
				log.Printf("[AssetService] IngestFindings: %s matched asset %s on %s", findingLabel(f), assetID, res.DecidedBy)
			}

			if deleted || assetStatus == identity.StatusArchived || assetStatus == "denied" {
				return nil
			}

			// A cloud provider's listing hangs off its account asset
			// (ADR-0009 D1): the measured `hosted_on` edge, here for the
			// resources that reach inventory only as findings.
			if isCloudAPIFinding(f) {
				s.linkCloudAccount(ctx, cloudAccounts, tenantID, assetID, f)
			}

			// Endpoints follow the identity decision (platform ADR-0003 D2). When
			// the engine held this finding's evidence — supporting evidence for an
			// established asset — it attached no socket, so nothing hangs off one
			// here either: no identified service, no crypto configuration, no
			// deferred finding. An endpoint the asset already has is not refreshed
			// by this sighting. The sockets wait in the observation's evidence (and,
			// in enforce admission, its held row in deferred_crypto_findings) for an
			// operator's Link or Confirm.
			evidenceHeld := res.EvidenceHeld
			if evidenceHeld {
				log.Printf("[AssetService] IngestFindings: %s is supporting evidence for asset %s; its endpoint stays on observation %s until it is linked or confirmed",
					findingLabel(f), assetID, res.ObservationID)
			}

			// Enrich the asset from its prefix (environment, location,
			// business unit; DCIM row 1.6). A cloud-API resource is placed by
			// its listing instead: its environment is the listing's, and its
			// prefix, when it has an address, is the identity engine's. The
			// enriched event names the prefix only when it moved something.
			didPrefix := false
			if s.db != nil {
				var cloudProvider, cloudRegion string
				if f.RawData != nil {
					cloudProvider, _ = f.RawData["cloud_provider"].(string)
					cloudRegion, _ = f.RawData["cloud_region"].(string)
				}
				if cloudProvider != "" && cloudRegion != "" {
					// A cloud resource is placed in its stated environment and in
					// its region's location under its account's site (DCIM row
					// 2.1, ADR-0009 D1): its network is the prefix its address
					// falls in (DCIM row 1.5f).
					env, _ := f.RawData["environment"].(string)
					// RLS-scoped write over assets.
					_ = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
						var moved bool
						if e := tx.QueryRow(`
							WITH prior AS (SELECT environment FROM assets WHERE id = $2 AND tenant_id = $3)
							UPDATE assets a SET environment = $1::environment_type, updated_at = NOW()
							  FROM prior p WHERE a.id = $2 AND a.tenant_id = $3
							RETURNING p.environment IS DISTINCT FROM a.environment`,
							cloudEnvironment(env), assetID, tenantID).Scan(&moved); e == nil && moved {
							changeTracker.changed(assetID)
							didPrefix = true
						}
						return nil
					})
					if moved := s.placeCloudResource(ctx, cloudAccounts, tenantID, assetID, f, cloudRegion); moved {
						changeTracker.changed(assetID)
						didPrefix = true
					}
				} else if moved, _ := s.enrichAssetFromPrefix(segs, tenantID, assetID, effectiveIP); moved {
					changeTracker.changed(assetID)
					didPrefix = true
				}
			}
			var didService bool
			if s.serviceIdentificationSvc != nil && !evidenceHeld {
				port := 0
				if f.Port != nil {
					port = *f.Port
				}
				hints := s.serviceIdentificationSvc.IdentifyService(tenantID, port, f.Protocol, f.RawData)
				if hints != nil {
					ver := hints.ServiceVersion
					// The identified service belongs to the ENDPOINT it was
					// identified on (DATA_MODEL §2) — a host running HTTPS on 443
					// and Postgres on 5432 is one asset with two services, and the
					// asset-level columns this used to write no longer exist.
					//
					// Errors are logged, not discarded: the previous form swallowed
					// both the Exec error and the transaction error, so after the
					// columns moved this wrote nothing at all and still reported
					// the asset as enriched.
					epID, epErr := s.resolveEndpointForFinding(ctx, tenantID, assetID, f)
					switch {
					case errors.Is(epErr, errEndpointNotAttached):
						// The identity decision attached no endpoint for this
						// socket; a service name is not a reason to create one.
						log.Printf("[AssetService] IngestFindings: not recording the identified service for %s: %v", findingLabel(f), epErr)
					case epErr != nil:
						log.Printf("[AssetService] IngestFindings: resolving the endpoint to record the identified service for %s failed: %v", findingLabel(f), epErr)
					case epID == uuid.Nil:
						// No endpoint at all — an at-rest resource. There is no
						// socket for a service name to describe.
					default:
						wErr := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
							var moved bool
							e := tx.QueryRow(`
							WITH prior AS (
								SELECT service_name, service_version, service_confidence, service_identification_method
								  FROM asset_endpoints WHERE id = $5 AND tenant_id = $6
							)
							UPDATE asset_endpoints ae SET service_name = $1, service_version = NULLIF($2, ''),
								service_confidence = $3, service_identification_method = $4, updated_at = NOW()
							  FROM prior p
							WHERE ae.id = $5 AND ae.tenant_id = $6
							RETURNING p.service_name IS DISTINCT FROM ae.service_name OR p.service_version IS DISTINCT FROM ae.service_version
							       OR p.service_confidence IS DISTINCT FROM ae.service_confidence
							       OR p.service_identification_method IS DISTINCT FROM ae.service_identification_method`,
								hints.ServiceName, ver, hints.Confidence, hints.IdentificationMethod, epID, tenantID).Scan(&moved)
							if errors.Is(e, sql.ErrNoRows) {
								return nil
							}
							if e == nil && moved {
								changeTracker.changed(assetID)
							}
							return e
						})
						if wErr != nil {
							log.Printf("[AssetService] IngestFindings: recording the identified service on endpoint %s failed: %v", epID, wErr)
						} else {
							didService = true
						}
					}
				}
			}
			if !evidenceHeld {
				if s.recordHandshakeOutcome(ctx, tenantID, assetID, f) {
					changeTracker.changed(assetID)
				}
			}
			if s.eventPublisher != nil && (didPrefix || didService) {
				es := "prefix"
				if didPrefix && didService {
					es = "prefix,service_id"
				} else if didService {
					es = "service_id"
				}
				lifecycleEnriched = append(lifecycleEnriched, &events.AssetEnrichedPayload{
					AssetID:          assetID,
					ClassKey:         res.ClassKey,
					EnrichmentSource: es,
				})
			}

			if durableMaterialization || evidenceHeld {
				// Held evidence: see above. In enforce admission the finding was
				// held in deferred_crypto_findings on the same transaction as
				// identity resolution, waiting on its observation; the replay
				// (deferred_crypto.go) materializes it once identity and approval
				// are both settled. Ingestion success never depends on it.
				return nil
			}

			// Three answers, not two, and they are decided on the status the asset
			// HAS (see the effective-status block above) rather than the one the
			// batch requested.
			//
			//   monitoring       materialize now, whatever the batch asked for
			//   pending_approval defer into deferred_crypto_findings, replayed when
			//                    the asset is approved — this is what keeps
			//                    unapproved discoveries out of the certificates and
			//                    crypto_implementations tables
			//   archived         neither
			//
			// Archived is neither because both alternatives are wrong. Materializing
			// puts a retired device's crypto back into the live inventory; deferring
			// parks it where only an approval will replay it, and an archived asset
			// is not in Approvals — that is the same dead end this whole change is
			// about. Skipping matches what the `denied` branch above does, for the
			// same reason: the tenant decided, and a re-discovery does not re-open it.
			if assetStatus != identity.StatusMonitoring {
				if assetStatus == identity.StatusArchived {
					log.Printf("[AssetService] IngestFindings: %s matched archived asset %s; its crypto is neither materialized nor deferred", findingLabel(f), assetID)
					return nil
				}
				// A finding with nothing to replay is not parked: its port is
				// already an endpoint of the asset (identity resolution above), and
				// approval would materialize nothing from it (see
				// deferralMaterializesNothing). Parking it only spent a slot of the
				// capped array, so a busy pending host — a full-estate scan's open,
				// unidentified ports — pushed its TLS and SSH observations out
				// before anyone could approve it ( H12).
				if deferralMaterializesNothing(f) {
					return nil
				}
				s.deferCryptoFinding(tenantID, assetID, f)
				return nil
			}

			// Extract and process certificate chain from discovery finding.
			// Deliberately not propagated: this is a per-finding loop over a whole
			// ingest batch, and one finding whose certificates or crypto rows fail to
			// materialize must not abort the remaining findings. Logged rather than
			// dropped so a silently half-materialized batch is still visible.
			var cryptoChanged bool
			if err := s.processDiscoveryCryptoDataTracked(tenantID, assetID, f, &lifecycleRiskChanged, &lifecycleCryptoAdded, &lifecycleCertExpiring, &cryptoChanged); err != nil {
				log.Printf("[AssetService] IngestFindings: materializing crypto data for asset %s failed (batch continues): %v", assetID, err)
			}
			// Marked even when part of the pass failed: what it did write is
			// still a change an evaluator will read.
			if cryptoChanged {
				changeTracker.changed(assetID)
			}
			return nil
		}); err != nil {
			return result(), fmt.Errorf("post-resolution enrichment for asset %s: %w", assetID, err)
		}
	}

	// Refresh operational materialized views (location summary, remediation queue)
	// Non-blocking: if migration 011 not applied or refresh fails, log and continue
	go func() {
		if err := s.RefreshOperationalViews(); err != nil {
			log.Printf("[AssetService] RefreshOperationalViews (non-fatal): %v", err)
		}
	}()

	// Publish asset.changed (batch if many, individual if few) - but only for
	// assets whose ingest changed something a compliance evaluator can read.
	//
	// WHAT COUNTS AS A CHANGE (full list in
	// docsv4/internal/developer/design/asset-inventory/ASSET_EVENTS.md):
	// the asset was created; asset_history gained a row for it (identity,
	// attribute, endpoint, class, approval/status changes); the crypto
	// materialisation altered a configuration, certificate, risk score or
	// at-rest posture; segment enrichment, service identification or the TLS
	// handshake outcome moved a stored value. A pure re-sighting - only
	// last_seen / observation counters moved - publishes NOTHING: the
	// evaluation it would trigger can only reproduce the stored verdict. The
	// lifecycle events below (asset.discovered, crypto.configuration_added, ...)
	// are unaffected. Published asynchronously to avoid blocking the import.
	changedAssetIDs := s.changedByHistory(ctx, tenantID, changeTracker, historyMark, historyMarkErr == nil)
	if s.eventPublisher != nil && len(changedAssetIDs) > 0 {
		source := "discovery"
		if len(findings) > 0 && findings[0].RawData != nil {
			if sourceVal, ok := findings[0].RawData["source"].(string); ok {
				source = sourceVal
			}
		}

		// Publish events in background goroutine to avoid blocking import
		go func() {
			// Use bulk event if >10 assets changed, otherwise publish individually
			if len(changedAssetIDs) > 10 {
				if err := s.eventPublisher.PublishBulkAssetChanged(ctx, tenantID, changedAssetIDs, sharedevents.ChangeTypeUpdated, source); err != nil {
					log.Printf("[AssetService] Warning: Failed to publish bulk asset changed event: %v", err)
				}
			} else {
				for _, assetID := range changedAssetIDs {
					if err := s.eventPublisher.PublishAssetChanged(ctx, tenantID, assetID, sharedevents.ChangeTypeUpdated, source); err != nil {
						log.Printf("[AssetService] Warning: Failed to publish asset changed event: %v", err)
					}
				}
			}
		}()
	}

	// Publish lifecycle events (asset.discovered, asset.enriched, asset.risk_changed, crypto.configuration_added, certificate.expiring)
	if s.eventPublisher != nil {
		go func() {
			for _, e := range lifecycleDiscovered {
				_ = s.eventPublisher.PublishAssetDiscovered(ctx, tenantID, e.assetID, e.classKey, e.hostname, e.ipAddress, e.port, source)
			}
			for _, p := range lifecycleEnriched {
				_ = s.eventPublisher.PublishAssetEnriched(ctx, tenantID, p, source)
			}
			for _, p := range lifecycleRiskChanged {
				_ = s.eventPublisher.PublishAssetRiskChanged(ctx, tenantID, p, source)
			}
			for _, p := range lifecycleCryptoAdded {
				_ = s.eventPublisher.PublishCryptoConfigurationAdded(ctx, tenantID, p, source)
			}
			for _, p := range lifecycleCertExpiring {
				_ = s.eventPublisher.PublishCertificateExpiring(ctx, tenantID, p, source)
			}
		}()
	}

	// End-of-run summary so an import's real outcome is always visible in the logs,
	// not just the opaque "imported N" the handler returns ().
	failureNote := ""
	if failedRoute > 0 {
		failureNote = " (WITH FAILURES)"
	}
	log.Printf("[AssetService] IngestFindings summary%s: %d findings → managed created=%d, managed updated=%d, routed to external_connections=%d, dropped third-party without source address=%d, held by merge proposal=%d, route failures=%d (status=%s)",
		failureNote, len(findings), createdManaged, updatedManaged, routedExternal, droppedNoSource, heldByProposal, failedRoute, statusLabel)

	return result(), nil
}

// findingLabel renders a stable, human-readable identifier for a discovery finding
// for use in logs (host[:ip]:port). Avoids dereferencing nil pointers.
func findingLabel(f IngestFinding) string {
	host := "?"
	if f.Hostname != nil && *f.Hostname != "" {
		host = *f.Hostname
	}
	ip := ""
	if f.IPAddress != nil && *f.IPAddress != "" {
		ip = "(" + *f.IPAddress + ")"
	}
	port := ""
	if f.Port != nil {
		port = fmt.Sprintf(":%d", *f.Port)
	}
	return host + ip + port
}

// logIdentityDecisions says, in the ingest log, when the engine resolved an
// observation by a rule a reader would not otherwise be able to see: a
// floating address (a node announcing another asset's address — no proposal,
// the MAC deliberately not attached), or a proposal suppressed because a
// reviewer already kept the pair separate. Without these lines the outcome
// reads as a plain match, and "why did the VIP asset just get updated from a
// cluster node's MAC?" has no answer in the log.
func logIdentityDecisions(label string, res identity.Resolution) {
	if fa := res.FloatingAddress; fa != nil {
		log.Printf("[AssetService] IngestFindings: %s is a floating address: asset %s announces %v for asset %s (gratuitous_arp=%v); resolved to the address's asset, the announcer's MAC %v was not attached, and no merge proposal was opened",
			label, fa.AnnouncerAssetID, fa.Announcement.Addresses, res.Asset.ID, fa.Announcement.Gratuitous, fa.Announcement.MACs)
	}
	if res.Outcome == identity.OutcomeMatched && res.Proposal.ID != "" {
		// A host's own report, decided by its installation identity, that
		// also names identifiers another asset holds (shared/identity
		// installation_claims.go): matched AND proposed.
		log.Printf("[AssetService] IngestFindings: %s matched asset %s by %s and names identifiers %d other asset(s) hold; opened merge proposal %s",
			label, res.Asset.ID, res.DecidedBy, len(res.Candidates)-1, res.Proposal.ID)
	}
	if s := res.Suppressed; s != nil {
		when := "at an unrecorded time"
		if !s.DecidedAt.IsZero() {
			when = "on " + s.DecidedAt.UTC().Format("2006-01-02")
		}
		log.Printf("[AssetService] IngestFindings: %s would conflict between %d asset(s) (%s), but merge proposal %s was kept separate %s; suppressed, resolved to asset %s by %s",
			label, len(s.Candidates), s.Reason, s.ProposalID, when, res.Asset.ID, res.DecidedBy)
	}
}

// RefreshOperationalViews runs the database function refresh_operational_views()
// to refresh mv_location_finding_summary and mv_remediation_queue (migration 011).
// Returns nil if successful; error if the function does not exist or refresh fails.
func (s *AssetService) RefreshOperationalViews() error {
	// Cross-tenant by design: refreshes the platform-wide materialized views
	// (mv_location_finding_summary, mv_remediation_queue) for every tenant at
	// once. REFRESH requires matview OWNERSHIP, which neither crypto_app nor
	// crypto_bypass has — the function is SECURITY DEFINER (runs as the owner),
	// so it works from this plain-pool handle.
	_, err := s.db.Exec("SELECT refresh_operational_views()")
	return err
}

// dnsResolveTimeout bounds the per-finding hostname fallback lookup in
// routeToExternalConnection so a slow resolver can't stall an import batch.
const dnsResolveTimeout = 3 * time.Second

// lookupHost is the ONE name resolution this service performs, and it is a
// variable so a test can assert that a given intake path never reaches it.
//
// "This code sends nothing onto the wire" is not a claim a unit test can make
// about a function it does not call. Routing it through one seam means the
// passive-discovery paths can be held to it directly — see
// TestIntegration_HostObservation_IngestNeverResolves, which drives a real
// ingest with this swapped for a recorder that fails the test on any call.
var lookupHost = func(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// errThirdPartyNoSourceIP is routeToExternalConnection's refusal of a finding
// with no source address ( D2): a connection record needs both ends, and
// no retry supplies the missing one.
var errThirdPartyNoSourceIP = errors.New("third-party finding has no source_ip; a connection needs both ends")

// routeToExternalConnection converts an IngestFinding to an ExternalConnectionUpsert
// and writes it to the external_connections table. Used for third-party discoveries.
//
// It is the ONE writer of external_connections on the discovery path (
// WP3, F16). discovery-processor used to write third-party rows itself, with
// the certificate quality flags, while this writer — reached for the same
// findings when inventory's own classification said third_party — wrote the
// same table without them and with a 0.0.0.0 source. One writer now carries
// everything: the measured crypto, the leaf certificate, its validation
// verdict and quality flags (shared certificates.CertificateQualityFromMetadata,
// the same reader the certificates table uses), the destination hostname with
// its provenance, and no source it did not measure.
func (s *AssetService) routeToExternalConnection(tenantID uuid.UUID, f IngestFinding) error {
	upsert, err := s.externalConnectionUpsert(f)
	if err != nil {
		return err
	}
	_, err = s.externalConnectionsSvc.Upsert(tenantID, upsert)
	return err
}

// externalConnectionUpsert builds the one external_connections write for a
// third-party finding. See routeToExternalConnection.
func (s *AssetService) externalConnectionUpsert(f IngestFinding) (models.ExternalConnectionUpsert, error) {
	// A host observation must never reach this function, for two reasons that
	// are both about this one routine: `external_connections` records a
	// CONNECTION between two endpoints with a protocol and a cipher, and a
	// passive host observation has no flow to record; and the hostname fallback
	// twenty lines down performs a LIVE DNS LOOKUP, which for an observation
	// means resolving a name that exists only on the customer's LAN — from a
	// feature whose entire premise, and the reason it defaults on for air-gapped
	// profiles, is that it sends nothing onto the wire.
	//
	// IngestFindings branches on the kind long before it gets here, so this is a
	// second lock on a door that is already shut. It is a refusal rather than a
	// silent skip because reaching it means the branch upstream was removed or
	// bypassed, and that is a bug worth a loud failure rather than a quiet one.
	//
	// How the two locks are actually held, precisely — because "either one
	// failing is a red test" is the natural thing to write here and it is not
	// true, and a guard nobody has measured is the shape this codebase keeps
	// getting caught by. Each lock alone stops the resolver, so no single test
	// can fail on one removal:
	//
	//   - Remove THIS refusal and
	//     TestIntegration_HostObservation_IngestNeverResolves still passes,
	//     because the upstream branch never lets an observation reach here.
	//   - Remove the UPSTREAM branch and that test still passes too — for the
	//     same reason inverted — but six of its neighbours go red, because
	//     every observation is then diverted and becomes no asset at all.
	//   - Remove BOTH and the resolver test fails with the LAN-only hostname
	//     in the recorder, which is the bug itself.
	//
	// So the suite catches either removal; this comment says which test does.
	if isHostObservation(f) {
		return models.ExternalConnectionUpsert{}, fmt.Errorf("refusing to route a %s to external_connections: it records no connection, and resolving its LAN-only hostname would put it on the wire", KindHostObservation)
	}

	// No source, no connection ( D2). This used to fill the gap with
	// "0.0.0.0", which is part of the upsert key, so every source-less finding
	// for one destination collapsed into a row claiming a source nobody
	// measured. Refused instead; the caller counts it and reports it.
	sourceIP := strings.TrimSpace(rawDataString(f.RawData, "source_ip"))
	if sourceIP == "" {
		return models.ExternalConnectionUpsert{}, errThirdPartyNoSourceIP
	}

	destIP := ""
	if f.IPAddress != nil {
		destIP = *f.IPAddress
	}

	// Fallback: a hostname-only finding (e.g. www.yahoo.com) whose resolved IP
	// the sensor did not supply leaves the Upsert uniqueness key (source_ip,
	// dest_ip, dest_port, protocol) under-populated. Resolve it here, but bound
	// the lookup with a short timeout so a slow/hanging resolver can't stall an
	// import batch — the lookup runs per finding on the request path.
	if destIP == "" && f.Hostname != nil && *f.Hostname != "" {
		ctx, cancel := context.WithTimeout(context.Background(), dnsResolveTimeout)
		ips, err := lookupHost(ctx, *f.Hostname)
		cancel()
		if err == nil && len(ips) > 0 {
			destIP = ips[0]
			log.Printf("[AssetService] routeToExternalConnection: resolved %s → %s", *f.Hostname, destIP)
		} else {
			log.Printf("[AssetService] routeToExternalConnection: DNS lookup for %s failed (%v); dest_ip will be empty", *f.Hostname, err)
		}
	}

	destPort := 0
	if f.Port != nil {
		destPort = *f.Port
	}
	// external_connections.protocol is varchar, not the enum, so an
	// unrecognised protocol has somewhere honest to go: itself. Coercing it to
	// "TLS" here was the same fabrication as on the crypto_implementations path
	// — and it silently defeated the pass-through this table is documented to
	// provide (TestIntegration_ExternalConnectionUpsert_StoresCanonicalProtocol
	// asserts an unmodelled protocol is stored un-rewritten, but reached Upsert
	// directly, so it never saw this coercion upstream of it).
	//
	// Enum-modelled protocols still get the canonical literal, so the row's
	// UNIQUE key (tenant, source_ip, dest_ip, dest_port, protocol) keeps
	// collapsing spellings of the same protocol onto one row. Everything else
	// is passed through; Upsert canonicalizes its SPELLING via
	// cryptoparse.NormalizeProtocol without changing which protocol it is.
	protocol, verdict := resolveProtocol(f.Protocol)
	if verdict != protocolEnum {
		protocol = strings.TrimSpace(f.Protocol)
		if protocol == "" {
			// Upsert rejects an empty protocol, and "" would be a claim of its
			// own in a NOT NULL column. Say what is actually true.
			protocol = "unknown"
		}
	}

	upsert := models.ExternalConnectionUpsert{
		SourceIP: sourceIP,
		DestIP:   destIP,
		DestPort: destPort,
		Protocol: protocol,
	}
	upsert.SourceAssetID = hostConnectionSourceAssetID(f.RawData)

	if f.Hostname != nil {
		upsert.DestHostname = f.Hostname
		// Carry the producer's own statement about where that name came from,
		// when it made one. discovery-processor stamps it for every finding it
		// forwards (measured for a captured SNI or an announced name, inferred
		// for a reverse-DNS answer); anything else leaves it absent, which the
		// upsert reads as "provenance unstated" rather than guessing.
		//
		// Without this the inferred names that reach external_connections
		// through the INGEST path — rather than the direct third-party path —
		// would arrive unlabelled and outrank a stored measurement.
		if f.RawData != nil {
			if kind, ok := f.RawData["dest_hostname_source_kind"].(string); ok && kind != "" {
				k := kind
				upsert.DestHostnameSourceKind = &k
			}
		}
	}
	upsert.ProtocolVersion = nonEmptyPtr(f.ProtocolVersion)
	upsert.CipherSuite = nonEmptyPtr(f.CipherSuite)
	upsert.KeyExchangeAlgorithm = nonEmptyPtr(f.KeyExchangeAlgorithm)
	if upsert.KeyExchangeAlgorithm == nil {
		// A passive capture names the exchange only as the suite's label
		// ("ECDHE", "DHE_RSA") under key_exchange_algorithm, with no group
		// id, and the converter rightly does not promote a label to a
		// measured exchange for the managed path (tls_kex_group.go). An
		// external connection has always stored that label — the processor's
		// deleted writer did, and assessCrypto parses it — so the one writer
		// keeps it ( WP3).
		upsert.KeyExchangeAlgorithm = nonEmptyPtr(stringPtrOf(rawDataString(f.RawData, "key_exchange_algorithm")))
	}
	// Generic discovery KeySize can be cipher or certificate bits. Preserve
	// only explicitly attributed exchange measurements and offered versions.
	upsert.KeySize, upsert.SupportedTLSVersions = externalDiscoveryEvidence(f.RawData)

	// Extract certificate data from raw_data for the external_connections cert snapshot
	if f.RawData != nil {
		certs := s.extractCertificatesFromFinding(f)
		if len(certs) > 0 {
			leaf := certs[externalLeafIndex(f.RawData, certs)]
			if leaf.SubjectDN != "" {
				upsert.CertSubject = &leaf.SubjectDN
			}
			if leaf.IssuerDN != "" {
				upsert.CertIssuer = &leaf.IssuerDN
			}
			if len(leaf.SubjectAlternativeNames) > 0 {
				upsert.CertSAN = leaf.SubjectAlternativeNames
			}
			if !leaf.NotBefore.IsZero() {
				upsert.CertNotBefore = &leaf.NotBefore
			}
			if !leaf.NotAfter.IsZero() {
				upsert.CertNotAfter = &leaf.NotAfter
			}
			if leaf.FingerprintSHA256 != "" {
				upsert.CertFingerprintSHA256 = &leaf.FingerprintSHA256
			}
			if leaf.PublicKeyAlgorithm != "" {
				upsert.CertPublicKeyAlgorithm = &leaf.PublicKeyAlgorithm
			}
			if leaf.PublicKeySize > 0 {
				upsert.CertPublicKeySize = &leaf.PublicKeySize
			}
			if leaf.SignatureAlgorithm != "" {
				upsert.CertSignatureAlgorithm = &leaf.SignatureAlgorithm
			}
			if leaf.CertificatePEM != "" {
				upsert.CertPEM = &leaf.CertificatePEM
			}
		}
	}

	// The certificate's validation verdict and quality flags (CLAUDE.md:
	// "must be persisted for both internal assets and external connections").
	// An explicit cert_has_sct=false arrives as false, not as absent.
	quality := sharedcerts.CertificateQualityFromMetadata(f.RawData)
	upsert.CertValidationStatus = quality.ValidationStatus
	upsert.CertHasSCT = quality.HasSCT
	upsert.CertSCTSource = quality.SCTSource
	upsert.CertKnownBadCA = quality.KnownBadCA
	upsert.CertNoSubject = quality.NoSubject
	upsert.CertNoCommonName = quality.NoCommonName
	upsert.CertIsEV = quality.IsEV
	upsert.CertLargeSANCount = quality.LargeSANCount
	upsert.OCSPStatus = quality.OCSPStatus

	if f.SourceSensorID != nil {
		if u, err := uuid.Parse(*f.SourceSensorID); err == nil {
			upsert.SensorID = &u
		}
	}

	return upsert, nil
}

// externalLeafIndex is the index in certs of the leaf the metadata names: the
// certificates-array entry with the lowest chain_order, matched by
// fingerprint; the first certificate when it cannot be matched.
func externalLeafIndex(raw map[string]interface{}, certs []models.CertificateData) int {
	entry := sharedcerts.LeafCertificateEntry(raw)
	if entry == nil {
		return 0
	}
	fp, _ := entry["fingerprint_sha256"].(string)
	if fp == "" {
		return 0
	}
	for i := range certs {
		if strings.EqualFold(certs[i].FingerprintSHA256, fp) {
			return i
		}
	}
	return 0
}

func stringPtrOf(v string) *string { return &v }

// nonEmptyPtr is p, or nil when it points at an empty string: an empty
// measurement is no measurement, and the column should say NULL.
func nonEmptyPtr(p *string) *string {
	if p == nil || strings.TrimSpace(*p) == "" {
		return nil
	}
	return p
}

// hostConnectionSourceAssetID accepts an explicit source only from the host
// inventory connection projection. Other producers may carry arbitrary
// metadata named source_asset_id; treating that as measured identity would let
// a third-party payload choose the source asset for an external connection.
func hostConnectionSourceAssetID(raw map[string]interface{}) *uuid.UUID {
	if !isHostInventoryConnectionRawData(raw) {
		return nil
	}
	value, _ := raw["source_asset_id"].(string)
	id, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	return &id
}

func isHostInventoryConnectionRawData(raw map[string]interface{}) bool {
	return raw != nil && raw["discovery_type"] == "host_connection" && raw["discovery_method"] == "host_inventory"
}

// ElevateExternalConnection promotes a 3rd-party connection to a managed,
// monitored asset on par with internal assets. It creates a network_asset
// (ownership=third_party, status=monitoring), materializes the connection's leaf
// certificate through the same path approved discoveries use — so the vendor cert
// is linked and appears in the certificate lens identically to an internal one —
// and links the connection back to the new asset.
//
// Returns (nil, nil) when the connection does not exist (the handler maps that to
// 404). Idempotent: a connection already elevated returns its existing asset.
func (s *AssetService) ElevateExternalConnection(tenantID, connID uuid.UUID) (*models.Asset, error) {
	if s.externalConnectionsSvc == nil {
		return nil, fmt.Errorf("external connections service not configured")
	}
	conn, err := s.externalConnectionsSvc.GetByID(tenantID, connID)
	if err != nil {
		return nil, err
	}
	if conn == nil {
		return nil, nil
	}

	// Idempotent: already elevated → return the existing managed asset.
	if conn.ElevatedAssetID != nil {
		if existing, gErr := s.GetAssetByID(tenantID, *conn.ElevatedAssetID); gErr == nil && existing != nil {
			return existing, nil
		}
	}

	ownership := "third_party"
	transport := "tcp"
	input := models.AssetInput{
		// `external` is the class for a third party's endpoint (ADR-0002 D1),
		// and an elevated connection is exactly that: we have promoted it to
		// something we watch, not to something we own. The old code said
		// "server", which asserted a kind of machine nobody had observed.
		ClassKey:       assetclass.KeyExternal,
		Hostname:       conn.DestHostname,
		IPAddress:      &conn.DestIP,
		AssetOwnership: &ownership,
		Endpoints: []models.AssetEndpointInput{{
			Address:   &conn.DestIP,
			FQDN:      conn.DestHostname,
			Port:      &conn.DestPort,
			Transport: transport,
		}},
		Metadata: map[string]interface{}{
			"source":                      "connection_elevation",
			"elevated_from_connection_id": conn.ID.String(),
		},
	}
	// Elevation creates the asset as `monitoring` deliberately, and this is the
	// one place a status is asserted rather than evaluated: elevating is an
	// explicit, permission-gated, confirmed click on a specific connection — the
	// click IS the approval. Queuing it would ask the user to approve their own
	// deliberate action. It is not a caller-supplied status: nothing in the
	// request body reaches this value.
	f := buildElevationFinding(conn)
	asset, err := s.createAssetFromInput(tenantID, input,
		identity.Source{Kind: identity.SourceDeclared, Ref: "elevation"}, "monitoring")
	if err != nil {
		return nil, fmt.Errorf("create managed asset from connection %s: %w", conn.ID, err)
	}

	if err := s.withResolvedAssetLifecycle(context.Background(), tenantID, asset.ID, func(current uuid.UUID, status string, deleted bool) error {
		if deleted || status != identity.StatusMonitoring {
			return ErrAssetLifecycleConflict
		}
		if current != asset.ID {
			var err error
			asset, err = s.GetAssetByID(tenantID, current)
			if err != nil {
				return err
			}
			if asset == nil {
				return fmt.Errorf("merged connection survivor no longer exists")
			}
		}
		// Materialize the leaf certificate (if captured) via the canonical
		// approved-discovery path so the vendor cert is created, linked to the asset,
		// and assessed exactly like an internal one.
		if conn.CertSubject != nil && *conn.CertSubject != "" && conn.CertIssuer != nil && *conn.CertIssuer != "" {
			var lifecycleRiskChanged []*events.AssetRiskChangedPayload
			var lifecycleCryptoAdded []*events.CryptoConfigurationAddedPayload
			var lifecycleCertExpiring []*events.CertificateExpiringPayload
			// Non-fatal, same rationale as the MarkElevated back-link below: the
			// managed asset already exists and is the caller's return value, so a
			// failed cert materialization is repairable (re-ingest re-materializes)
			// and must not turn a successful elevation into an error. Surfaced, not
			// swallowed.
			if err := s.processDiscoveryCryptoData(tenantID, asset.ID, f, &lifecycleRiskChanged, &lifecycleCryptoAdded, &lifecycleCertExpiring); err != nil {
				log.Printf("[AssetService] ElevateExternalConnection: asset %s created but materializing certificate from connection %s failed: %v", asset.ID, conn.ID, err)
			}
		}

		if err := s.externalConnectionsSvc.MarkElevated(tenantID, conn.ID, asset.ID); err != nil {
			// Non-fatal: the managed asset exists; only the back-link failed and can
			// be repaired. Surface it rather than swallow it.
			log.Printf("[AssetService] ElevateExternalConnection: asset %s created but linking connection %s failed: %v", asset.ID, conn.ID, err)
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("finish connection elevation: %w", err)
	}
	log.Printf("[AssetService] ElevateExternalConnection: elevated connection %s → managed asset %s (%s)", conn.ID, asset.ID, findingLabel(f))
	return asset, nil
}

// buildElevationFinding reshapes an external connection's flat leaf-cert snapshot
// into the IngestFinding/RawData shape that processDiscoveryCryptoData consumes,
// so elevation reuses the canonical certificate materialization path.
func buildElevationFinding(conn *models.ExternalConnection) IngestFinding {
	cert := map[string]interface{}{}
	if conn.CertSubject != nil {
		cert["subject_dn"] = *conn.CertSubject
	}
	if conn.CertIssuer != nil {
		cert["issuer_dn"] = *conn.CertIssuer
	}
	if conn.CertFingerprintSHA256 != nil {
		cert["fingerprint_sha256"] = *conn.CertFingerprintSHA256
	}
	if conn.CertPEM != nil {
		cert["certificate_pem"] = *conn.CertPEM
	}
	if conn.CertPublicKeyAlgorithm != nil {
		cert["public_key_algorithm"] = *conn.CertPublicKeyAlgorithm
	}
	if conn.CertPublicKeySize != nil {
		cert["public_key_size"] = float64(*conn.CertPublicKeySize)
	}
	if conn.CertSignatureAlgorithm != nil {
		cert["signature_algorithm"] = *conn.CertSignatureAlgorithm
	}
	if conn.CertNotBefore != nil {
		cert["not_before"] = conn.CertNotBefore.Format(time.RFC3339)
	}
	if conn.CertNotAfter != nil {
		cert["not_after"] = conn.CertNotAfter.Format(time.RFC3339)
	}
	if len(conn.CertSAN) > 0 {
		sans := make([]interface{}, 0, len(conn.CertSAN))
		for _, san := range conn.CertSAN {
			sans = append(sans, san)
		}
		cert["subject_alternative_names"] = sans
	}

	ip := conn.DestIP
	port := conn.DestPort
	return IngestFinding{
		Hostname:             conn.DestHostname,
		IPAddress:            &ip,
		Port:                 &port,
		AssetType:            "server",
		Protocol:             conn.Protocol,
		ProtocolVersion:      conn.ProtocolVersion,
		CipherSuite:          conn.CipherSuite,
		KeyExchangeAlgorithm: conn.KeyExchangeAlgorithm,
		KeySize:              conn.KeySize,
		RawData: map[string]interface{}{
			"source":       "connection_elevation",
			"certificates": []interface{}{cert},
		},
	}
}

// insertCryptoImplementationSQL is the only production INSERT into
// crypto_implementations. It is a package-level constant so a test can assert
// that every component column is bound to a parameter: signature_algorithm and
// symmetric_encryption were literal NULLs here, which made four seeded
// compliance controls evaluate against permanently empty fields.
//
// discovery_method was a literal 'integration' for the same reason and with the
// same effect: every crypto configuration on the platform claimed to have come
// from a third-party integration, the documented
// `?discovery_method=passive|active|manual` filter returned nothing for any
// other value, and the wrong provenance was baked into exported CBOM evidence.
// It is now bound to $15 — see findingDiscoveryMethod.
//
// discovery_methods starts as the one-element array of that same method: it
// is the row's full provenance, and a fresh row has exactly one contributor.
// The subset-absorption paths in crypto_dedup.go append to it.
const insertCryptoImplementationSQL = `
		INSERT INTO crypto_implementations (
			id, tenant_id, asset_id, endpoint_id, protocol, protocol_version, cipher_suite,
			key_exchange_algorithm, signature_algorithm, symmetric_encryption,
			hash_algorithm, key_size, certificate_id, discovery_method, discovery_methods,
			confidence_score, source_sensor_id, raw_data, risk_score,
			compliance_status, first_discovered_at, last_verified_at, certificate_observed_at,
			created_at, updated_at
		) VALUES (
			$1,$2,$3,$16::uuid,$4,$5,$6,
			$12,$13,$14,
			$7,$8,$9,$15::public.discovery_method,ARRAY[$15::public.discovery_method],
			NULL,$10,$11,NULL,
			'{}'::jsonb, $17::timestamptz, $17::timestamptz, CASE WHEN $9::uuid IS NOT NULL THEN $17::timestamptz ELSE NULL END,
			NOW(), NOW()
		)`

// defaultDiscoveryMethod is what a finding that states no provenance is stored
// as. It is the value every row carried before provenance was threaded through,
// so an unattributable finding is no worse off than it already was — but it is
// deliberately NOT a guess: nothing maps an unknown producer string onto
// 'passive' or 'active'.
const defaultDiscoveryMethod = "integration"

// discoveryMethodByProducerString maps the provenance strings producers
// actually emit onto the `discovery_method` ENUM in schema.sql
// (passive | active | manual | integration | device_interrogation | cloud_api |
// source_code_scan | host_scan).
//
// A raw pass-through would violate the enum and abort the INSERT:
// "active_enrichment" and "pcap_upload" are both real producer values and
// neither is an enum member.
var discoveryMethodByProducerString = map[string]string{
	// Enum members producers already speak verbatim.
	"passive":              "passive",
	"active":               "active",
	"manual":               "manual",
	"integration":          "integration",
	"device_interrogation": "device_interrogation",
	"cloud_api":            "cloud_api",
	"source_code_scan":     "source_code_scan",
	"host_scan":            "host_scan",

	// Producer spellings with no enum member of their own.
	"active_enrichment": "active",  // sensor TLS enricher: an active probe
	"pcap_upload":       "passive", // a PCAP is captured traffic, never solicited
}

// discoveryMethodBySourceString maps the RawData "source" key for the cases
// where it unambiguously names the provenance. It is consulted only when the
// finding carries no explicit discovery_method. Ambiguous sources (e.g.
// "connection_elevation", which may stand behind either a passive observation
// or an active probe) are deliberately absent — they fall through to
// defaultDiscoveryMethod rather than being guessed at.
var discoveryMethodBySourceString = map[string]string{
	"cloud_discovery":      "cloud_api",
	"cloud_api":            "cloud_api",
	"device_interrogation": "device_interrogation",
	"ui":                   "manual",
}

// findingDiscoveryMethod resolves a finding's provenance to a `discovery_method`
// enum value. The sensor's own discovery_method wins; the source key is a
// second chance; anything unrecognised falls back to defaultDiscoveryMethod.
func findingDiscoveryMethod(f IngestFinding) string {
	if f.RawData == nil {
		return defaultDiscoveryMethod
	}
	if dm, _ := f.RawData["discovery_method"].(string); dm != "" {
		if mapped, ok := discoveryMethodByProducerString[strings.ToLower(strings.TrimSpace(dm))]; ok {
			return mapped
		}
	}
	if src, _ := f.RawData["source"].(string); src != "" {
		if mapped, ok := discoveryMethodBySourceString[strings.ToLower(strings.TrimSpace(src))]; ok {
			return mapped
		}
	}
	return defaultDiscoveryMethod
}

// deferralMaterializesNothing reports whether replaying f on approval would
// write nothing — the early returns of processDiscoveryCryptoData, in its
// order: an at-rest resource with a posture DOES materialize (an application
// row); one without, and any finding whose protocol names no crypto
// measurement (a transport such as "tcp", a plaintext service, an unrecognised
// name), does not.
func deferralMaterializesNothing(f IngestFinding) bool {
	if _, ok := atRestPostureFromFinding(f); ok {
		return false
	}
	if findingIsAtRest(f) {
		return true
	}
	_, verdict := resolveProtocol(f.Protocol)
	return verdict != protocolEnum
}

// processDiscoveryCryptoData extracts certificates and crypto configurations from
// a discovery finding and writes them to the database. This is the "materialization"
// step that only runs for approved (monitoring) assets.
func (s *AssetService) processDiscoveryCryptoData(
	tenantID uuid.UUID,
	assetID uuid.UUID,
	f IngestFinding,
	lifecycleRiskChanged *[]*events.AssetRiskChangedPayload,
	lifecycleCryptoAdded *[]*events.CryptoConfigurationAddedPayload,
	lifecycleCertExpiring *[]*events.CertificateExpiringPayload,
) error {
	return s.processDiscoveryCryptoDataTracked(tenantID, assetID, f, lifecycleRiskChanged, lifecycleCryptoAdded, lifecycleCertExpiring, nil)
}

// processDiscoveryCryptoDataTracked is processDiscoveryCryptoData that also
// reports, through changed (nil to ignore), whether the pass altered anything an
// evaluator can read: a new or enriched configuration, a moved leaf
// certificate, a new or content-changed certificate, a moved risk score, a new
// or changed at-rest posture. A configuration or certificate merely re-observed
// (only last-seen/evidence timestamps refreshed) is NOT a change. This is the
// materialisation half of the asset.changed rule documented at the publish site
// in IngestFindings.
func (s *AssetService) processDiscoveryCryptoDataTracked(
	tenantID uuid.UUID,
	assetID uuid.UUID,
	f IngestFinding,
	lifecycleRiskChanged *[]*events.AssetRiskChangedPayload,
	lifecycleCryptoAdded *[]*events.CryptoConfigurationAddedPayload,
	lifecycleCertExpiring *[]*events.CertificateExpiringPayload,
	changed *bool,
) error {
	var materializationErrs []error
	markChanged := func() {
		if changed != nil {
			*changed = true
		}
	}

	// AT-REST resources short-circuit here.
	//
	// An S3 bucket or an RDS instance is not a network endpoint: it negotiates
	// no protocol, no cipher suite and no version. Falling through would
	// manufacture a crypto_implementations row with every crypto column NULL —
	// which is precisely the phantom TLS endpoint this replaces. Its
	// encryption posture is at-rest, so it belongs in crypto_applications.
	if posture, ok := atRestPostureFromFinding(f); ok {
		atRestChanged, err := s.produceAtRestApplicationTracked(tenantID, assetID, posture, findingObservedAt(f))
		if atRestChanged {
			markChanged()
		}
		return err
	}

	// B-22: the same reasoning, for the at-rest resources that atRestResourceTypes
	// does NOT yet map — today the three cloud key stores (AWS KMS, Azure Key
	// Vault keys, GCP Cloud KMS keys). device-interrogation-service stamps their
	// findings with protocol "AT-REST" (atRestProtocolPort), and its comment
	// asserted that inventory-service routes them to crypto_applications by
	// resource_type. It does not: those three collectors write no resource_type
	// at all, so atRestPostureFromFinding returns false above and execution used
	// to fall through — protocol normalization had no AT-REST case, so it logged
	// "Unknown protocol, defaulting to TLS" and every discovered customer-managed
	// key became an asset carrying a TLS crypto configuration with NULL
	// protocol_version and NULL cipher_suite. A negotiated-protocol measurement
	// that never happened, feeding the risk and PQC denominators.
	//
	// Not measuring something is the honest answer here; inventing a TLS endpoint
	// is not. Surfacing key stores as first-class at-rest posture is separate
	// work: crypto_applications models "is this resource's DATA encrypted, and
	// whose key" — every rung of that ladder (Unencrypted / Provider key /
	// Customer key) is a category error for a resource that IS the key.
	//
	// Phase 1: the sentinel is retired on BOTH sides — an at-rest resource is an
	// asset with NO ENDPOINT, not an asset on a fake port, and the producer now
	// says so with an explicit `at_rest` flag instead of a magic word in the
	// protocol column. The old string is still accepted on read for rows queued
	// before the upgrade; see findingIsAtRest.
	if findingIsAtRest(f) {
		return nil
	}

	// And the general case, of which AT-REST was one instance.
	//
	// A crypto configuration IS a protocol observation: the row names a
	// protocol_type, and everything downstream — the weak-protocol check, the
	// OT-encryption measurement, the risk and PQC denominators — reads it as a
	// measurement of what the endpoint negotiated. If we cannot name the
	// protocol, there is nothing to measure, and the enum offers no value that
	// says so. Recording the finding anyway is what produced phantom TLS
	// endpoints: a "tcp"-stamped port that never answered a protocol probe, or a
	// database that reported SSL OFF, arriving in inventory as a TLS endpoint
	// with no version and no cipher suite.
	//
	// The asset itself is unaffected — "something answered on this port" is a
	// true fact and was already recorded by the caller. Only the crypto
	// configuration, which would be a fabricated one, is skipped.
	if _, verdict := resolveProtocol(f.Protocol); verdict != protocolEnum {
		log.Printf("[AssetService] asset %s: no crypto configuration materialized — protocol %q is %s",
			assetID, f.Protocol, verdict)
		return nil
	}

	// A TLS port that refused the handshake negotiated nothing either. The
	// scan engine names such a port TLS — the server answered the ClientHello
	// with a TLS alert, usually because it requires a server name an address
	// scan cannot offer — and the endpoint keeps that name. But there is no
	// version, cipher suite or certificate to record, and a configuration with
	// every component NULL is the same empty row as the cases above.
	if findingIsRefusedHandshake(f) {
		log.Printf("[AssetService] asset %s: no crypto configuration materialized for %s — the server refused the handshake",
			assetID, findingLabel(f))
		return nil
	}

	// The endpoint the observation was measured on. A configuration hangs off
	// the socket, not off the host (DATA_MODEL §2): resolving it here is what
	// makes :443 and :8443 on one host two configurations of one asset rather
	// than one row that flaps between them.
	//
	// uuid.Nil is a real answer, not a failure: an at-rest cloud resource has no
	// endpoint. That is exactly what retires the AT-REST port sentinel — there
	// is no fake port to invent, because there is no endpoint row.
	//
	// Looked up BEFORE anything is written, and never created (platform
	// ADR-0003 D2): a socket the identity decision did not attach to this asset
	// is not this asset's, so neither is the certificate it served or the
	// configuration it negotiated. Skipped with a log line rather than failed —
	// the evidence is still on its observation, and a Link or Confirm there is
	// what attaches the endpoint and materialises the rest.
	endpointID, epErr := s.resolveEndpointForFinding(context.Background(), tenantID, assetID, f)
	if errors.Is(epErr, errEndpointNotAttached) {
		log.Printf("[AssetService] asset %s: no crypto materialized for %s — %v", assetID, findingLabel(f), epErr)
		return nil
	}
	if epErr != nil {
		return fmt.Errorf("resolve endpoint before materializing crypto: %w", epErr)
	}

	// Extract and process certificate chain from discovery finding
	var certIDs []uuid.UUID
	var primaryCertID *uuid.UUID
	// producedCerts pairs each stored certificate with the extraction data that
	// carries its PEM + public-key metadata, so the key producer can derive a
	// public-key inventory row after the crypto implementation exists.
	var producedCerts []producedCertRef
	if f.RawData != nil {
		certificates := s.extractCertificatesFromFinding(f)
		for i, certData := range certificates {
			// Propagate quality flags from RawData to leaf cert
			if i == 0 {
				s.applyCertQualityFlags(&certData, f.RawData)
			}

			// A certificate a server presented in a handshake: chain_source
			// 'served'. Only a NEW row takes it — CreateCertificate
			// writes chain_source and UpdateCertificate never does, so a CA
			// first uploaded or copied from the bundle keeps its source.
			if certData.ChainSource == "" {
				certData.ChainSource = certtrust.ChainSourceServed
			}

			// Find or create certificate
			cert, certChanged, err := s.certificateService.findOrCreateCertificateTracked(tenantID, certData)
			if err == nil && certChanged {
				markChanged()
			}
			if err != nil {
				log.Printf("Warning: failed to find/create certificate (subject=%s, fingerprint=%s): %v",
					certData.SubjectDN, certData.FingerprintSHA256, err)
				materializationErrs = append(materializationErrs,
					fmt.Errorf("find/create certificate subject=%q fingerprint=%q: %w", certData.SubjectDN, certData.FingerprintSHA256, err))
			}
			if err == nil && cert != nil {
				certIDs = append(certIDs, cert.ID)
				producedCerts = append(producedCerts, producedCertRef{cert: cert, data: certData})

				// First certificate is leaf/primary
				if i == 0 {
					primaryCertID = &cert.ID
				}

				// Link to previous certificate (issuer relationship).
				//
				// Adjacency in the array is NOT on its own evidence of an
				// issuer relationship. The array is leaf-first for a chain
				// captured in one handshake, but a cloud discovery's array can
				// also carry a certificate the provider's API states is
				// CONFIGURED alongside the chain that was actually served, and
				// linking those by position asserts that a root certificate was
				// issued by an unrelated leaf. The DNs settle it: X issued Y
				// only if Y's issuer_dn is X's subject_dn, which holds for
				// every real chain and for nothing else.
				if i > 0 && len(certIDs) > 1 && certificates[i-1].IssuerDN != "" && certificates[i-1].IssuerDN == certData.SubjectDN {
					if err := s.certificateService.LinkCertificateIssuer(tenantID, certIDs[i-1], cert.ID); err != nil {
						log.Printf("Warning: failed to link certificate issuer: %v", err)
						materializationErrs = append(materializationErrs, fmt.Errorf("link certificate issuer: %w", err))
					}
				}
			}
		}
	}

	// Insert crypto configuration record.
	//
	// signature_algorithm and symmetric_encryption used to be hardcoded NULL and
	// hash_algorithm was only ever populated when the finding carried one
	// (in practice: WireGuard). Four seeded compliance controls read exactly
	// those columns, so they evaluated against permanently empty fields — a
	// silent pass on every asset. The cipher suite already tells us what was
	// negotiated, and ParseCipherSuite is already called a few lines below to
	// build the junction links; the same components now fill the columns.
	//
	// UPSERT, not INSERT. This used to mint a fresh uuid on every call, so an
	// endpoint re-observed hourly grew ~168 identical Crypto Configuration rows a
	// week — inflating the drawer, the tenant's configuration count, and the PQC
	// and risk denominators that divide by the number of implementations. The
	// natural key, and why each column is or is not in it, lives on
	// cryptoImplementationKey in crypto_dedup.go.
	// Guaranteed recordable: the short-circuit at the top of this function
	// returned for every other verdict. Checked again rather than assumed —
	// the enum column would reject an empty protocol, but only after the
	// certificate work above had already been committed.
	// endpointID was resolved above, before the certificates.
	key, recordable := s.cryptoKeyForFindingOnEndpoint(assetID, endpointID, f)
	if !recordable {
		return errors.Join(append(materializationErrs,
			fmt.Errorf("protocol %q names no modelled protocol; refusing to materialize a crypto configuration for it", f.Protocol))...)
	}
	protocol := key.Protocol

	raw := models.JSONB{}
	if f.RawData != nil {
		raw = models.JSONB(f.RawData)
	}
	// A cipher string the parser cannot fully resolve is a partial
	// assessment; record it where every reader can see it (cipher_assessment.go).
	raw, cipherPartial := annotateCipherAssessment(raw, f.CipherSuite)
	// So is a protocol version the producer says it did not measure
	// (component_assessment.go, W1.2).
	raw, versionUnmeasured := annotateComponentAssessment(raw, key.ProtocolVersion)
	key.VersionUnmeasured = versionUnmeasured
	partialAssessment := cipherPartial || versionUnmeasured
	rawJSON, _ := json.Marshal(raw)

	var sensor interface{}
	if f.SourceSensorID != nil {
		if u, perr := uuid.Parse(*f.SourceSensorID); perr == nil {
			sensor = u
		}
	}

	var cryptoID uuid.UUID
	var cryptoOutcome cryptoUpsertOutcome
	var leafMoved bool
	var keyExchangeAdopted bool
	// RLS-scoped write over crypto_implementations. The advisory lock
	// serializes the find-then-write for this asset across every replica, so
	// two workers ingesting the same endpoint cannot both miss and both insert;
	// the unique index on the natural key (uq_crypto_implementations_natural_key)
	// is the backstop that turns a missed case into an error, not a duplicate.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if _, e := tx.Exec(lockAssetMaterializationSQL, assetMaterializationLockKey(tenantID, assetID)); e != nil {
			return fmt.Errorf("lock asset materialization: %w", e)
		}
		// A suite-derived key-exchange label and a handshake's measured group
		// are one fact at two precisions; reconcile them before the natural-key
		// lookups or they split into two configurations (crypto_kex_refine.go).
		adopted, e := refineCryptoKeyExchange(tx, tenantID, &key)
		if e != nil {
			return e
		}
		keyExchangeAdopted = adopted
		id, outcome, moved, e := upsertCryptoImplementationTracked(tx, tenantID, key, primaryCertID, sensor, rawJSON, findingObservedAt(f))
		if e != nil {
			return e
		}
		cryptoID, cryptoOutcome, leafMoved = id, outcome, moved
		return nil
	}); err != nil {
		// Everything below writes against cryptoID — junction links, algorithm
		// classification, the risk update. Without a row they would either fail
		// on the foreign key or attach to uuid.Nil. Stop here and report.
		log.Printf("[AssetService] Warning: failed to materialize crypto implementation for asset %s: %v", assetID, err)
		materializationErrs = append(materializationErrs, fmt.Errorf("materialize crypto implementation: %w", err))
		return errors.Join(materializationErrs...)
	}

	// Only a refresh or partial re-observation leaves the configuration as it
	// was; every other outcome (created, enriched, version retracted) is a
	// change, and so is a refresh that moved the leaf certificate.
	if leafMoved || (cryptoOutcome != cryptoUpsertRefreshed && cryptoOutcome != cryptoUpsertPartialReobserved) {
		markChanged()
	}

	// Link the CHAIN certificates to the crypto configuration.
	//
	// The LEAF is deliberately absent from this loop: upsertCryptoImplementation
	// already wrote both halves of that link — the `certificate_id` column and
	// the `leaf` junction row — inside the transaction that created or refreshed
	// the row (see linkLeafCertificateSQL). It used to be linked here instead,
	// in a second transaction, best-effort: the column landed, the junction
	// insert was refused by the then-narrower `valid_certificate_role` CHECK,
	// only a warning was logged, and every sensor-discovered leaf certificate
	// became unreachable from its own asset. Two writers for one link is what
	// made that possible; there is now one.
	if primaryCertID != nil {
		for i, certID := range certIDs[1:] {
			role := "intermediate"
			if i == len(certIDs)-2 {
				role = "root"
			}
			if err := s.certificateService.LinkCertificateToImplementation(tenantID, cryptoID, certID, role); err != nil {
				log.Printf("Warning: failed to link certificate to implementation: %v", err)
				materializationErrs = append(materializationErrs, fmt.Errorf("link %s certificate to implementation: %w", role, err))
			}
		}
		if s.eventPublisher != nil && lifecycleCertExpiring != nil {
			var notAfter time.Time
			var commonName sql.NullString
			// RLS-scoped read over certificates.
			err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
				return tx.QueryRow(`SELECT not_after, common_name FROM certificates WHERE id = $1 AND tenant_id = $2`, *primaryCertID, tenantID).Scan(&notAfter, &commonName)
			})
			if err == nil && !notAfter.IsZero() && notAfter.Before(time.Now().Add(30*24*time.Hour)) {
				days := int(time.Until(notAfter).Hours() / 24)
				if days < 0 {
					days = 0
				}
				*lifecycleCertExpiring = append(*lifecycleCertExpiring, &events.CertificateExpiringPayload{
					CertificateID: *primaryCertID,
					AssetID:       assetID,
					CommonName:    nullStringToPtr(commonName),
					NotAfter:      notAfter,
					DaysRemaining: days,
				})
			}
		}
	}

	// A label-only observation that landed on a configuration whose key
	// exchange a handshake measured adopted that group for its key (see
	// refineCryptoKeyExchange). Link and score it with the group too, or the
	// suite parse below would re-link the classical label the refinement
	// removed — but link it as INFERRED, because this observation did not
	// measure it. Measured-over-parsed precedence is unchanged: a finding that
	// states its own key exchange is never touched here.
	if keyExchangeAdopted && (f.KeyExchangeAlgorithm == nil || strings.TrimSpace(*f.KeyExchangeAlgorithm) == "") && key.KeyExchange != nil {
		adopted := *key.KeyExchange
		f.KeyExchangeAlgorithm = &adopted
		f.keyExchangeInferred = true
	}

	// Classify and link algorithms.
	//
	// This runs for an ENRICHED row exactly as for a created one, and against
	// the same finding, so the junction an enriched row ends up with is the
	// junction a fresh insert of this observation would have — the links a
	// partial row already held are a subset of these and the insert is
	// ON CONFLICT DO NOTHING.
	if err := s.classifyAndLinkAlgorithms(cryptoID, f); err != nil {
		materializationErrs = append(materializationErrs, err)
	}

	// A less complete re-observation of a configuration already held is NOT
	// scored. The row's score was computed from a fuller observation than this
	// one; the detector below judges the finding it is handed, and handing it a
	// finding with no cipher suite and no key size would let a passive glimpse
	// of a protocol banner overwrite a verdict that had actually measured the
	// key. Nothing about the configuration changed, so nothing is written — the
	// same "no opinion, no write" rule persistCryptoRiskScore already applies
	// to a pass that resolved nothing. The next complete observation (the
	// daily active scan) re-scores as usual, so catalogue corrections still
	// propagate.
	scoreThisPass := cryptoOutcome != cryptoUpsertPartialReobserved

	// Populate the cryptographic-key inventory from the certificate public keys
	// on this implementation (metadata only; never key material). Failed
	// attachments leave a retained receipt eligible for retry.
	for _, pc := range producedCerts {
		if err := s.produceKeyFromCertificate(tenantID, cryptoID, pc.cert, pc.data); err != nil {
			materializationErrs = append(materializationErrs, fmt.Errorf("materialize certificate key: %w", err))
		}
	}

	// Risk score = the worse of two assessments:
	//
	//   1. The algorithm CATALOGUE (authoritative). Every component ingest just
	//      linked carries a curated risk_score/strength/deprecation_status, and
	//      the worst one wins. This is what makes a score traceable to a row a
	//      reviewer can read and correct, instead of to a hardcoded string match.
	//   2. The weak-crypto DETECTOR, which still covers what a per-algorithm
	//      catalogue cannot express — chiefly key SIZE (an RSA key below the
	//      SP 800-131A 2048-bit floor) — and is kept so nothing regresses.
	//
	// Taking the max means adding the catalogue can only ever raise a score,
	// never silently lower one.
	cryptoRiskScore := 0
	var riskSource string
	var catalogueFactors []string
	// cryptoRiskAssessed is the three-valued half of the answer: whether
	// ANYTHING was actually judged, independent of what the number came out as.
	// A score of 0 beside assessed=false is "nobody looked"; beside
	// assessed=true it is "somebody looked, and it is clean". See
	// persistCryptoRiskScore for where that distinction is recorded.
	cryptoRiskAssessed := false

	// RLS-scoped read; runs even when the detector is absent.
	if scoreThisPass {
		if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			worst, all, ok, e := catalogueRiskForImplementation(tx, cryptoID)
			if e != nil {
				return e
			}
			if ok {
				cryptoRiskScore = *worst.RiskScore
				riskSource = "algorithm_catalogue"
				catalogueFactors = catalogueRiskFactors(all)
				cryptoRiskAssessed = true
			}
			return nil
		}); err != nil {
			materializationErrs = append(materializationErrs, fmt.Errorf("read catalogue risk: %w", err))
		}
	}

	if scoreThisPass && s.weakCryptoDetector != nil {
		impl := &models.CryptoImplementation{
			ID:              cryptoID,
			TenantID:        tenantID,
			AssetID:         assetID,
			Protocol:        protocol,
			ProtocolVersion: f.ProtocolVersion,
			CipherSuite:     f.CipherSuite,
			HashAlgorithm:   f.HashAlgorithm,
			KeySize:         f.KeySize,
			// Without the key exchange the detector cannot tell an elliptic-curve
			// key from an RSA modulus, so it measured every 256-bit EC key against
			// the RSA floor and called it critically weak. The finding carries the
			// field; it simply was not being passed on.
			KeyExchangeAlgorithm: f.KeyExchangeAlgorithm,
			// The symmetric component exactly as the row stores it, so the
			// key-size rule here and its SQL twin (configurationWeakKeySizeSQL)
			// read the same value.
			SymmetricEncryption: s.deriveCipherComponents(f).Symmetric,
		}

		if issues := s.weakCryptoDetector.AnalyzeCryptoImplementation(tenantID, assetID, impl); len(issues) > 0 {
			// An issue is a judgement the detector was able to make, so it
			// counts as an assessment whatever the arithmetic comes to. Its
			// SILENCE does not: the detector is a string matcher, and "none of
			// my patterns matched" is not the same statement as "this is fine".
			cryptoRiskAssessed = true
			if detectorScore := s.weakCryptoDetector.CalculateRiskScore(issues); detectorScore > cryptoRiskScore {
				cryptoRiskScore = detectorScore
				riskSource = "weak_crypto"
			}
		}
	}

	// The write is gated on whether the configuration was ASSESSED, not on
	// whether the number came out above zero.
	//
	// Gating on `score > 0` meant a configuration could only ever climb: one
	// that first appeared negotiating TLS 1.0 kept its 75 through every later
	// observation that resolved to a clean set, because the clean answer was 0
	// and a 0 was never written. Remediation was invisible, and the stale number
	// went on feeding the finding, the asset roll-up and the band. The
	// three-valued honesty that guard was protecting is kept by
	// persistCryptoRiskScore's rule instead — for a configuration, ASSESSED is
	// "has a linked catalogue component" — so a written 0 and an unassessed 0
	// stay tellable apart without the guard. A pass that resolved nothing still
	// writes nothing.
	// A partial cipher assessment can raise a score, never clear one: below
	// Medium its number would claim "Low" for a set nobody resolved, so it is
	// stored as unassessed (NULL) — including over a score an earlier pass left
	// behind. Medium and worse, which known components support, stands.
	if scoreThisPass && partialAssessment && !partialAssessmentKeepsScore(cryptoRiskScore) {
		cryptoRiskAssessed = false
		if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			moves, e := cryptoRiskScoreMoves(tx, cryptoID, nil)
			if e != nil {
				return e
			}
			if moves {
				markChanged()
			}
			return clearCryptoRiskScore(tx, cryptoID)
		}); err != nil {
			materializationErrs = append(materializationErrs, fmt.Errorf("clear partially assessed crypto risk: %w", err))
		}
		if s.onCryptoChanged != nil {
			s.onCryptoChanged(context.Background(), tenantID)
		}
	}

	if cryptoRiskAssessed {
		if len(catalogueFactors) > 0 {
			log.Printf("[AssetService] Risk %d for implementation %s (source=%s): %v",
				cryptoRiskScore, cryptoID, riskSource, catalogueFactors)
		}
		{
			// RLS-scoped writes over crypto_implementations / assets.
			if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
				moved, e := persistCryptoRiskScore(tx, cryptoID, cryptoRiskScore)
				if moved {
					markChanged()
				}
				return e
			}); err != nil {
				materializationErrs = append(materializationErrs, fmt.Errorf("persist crypto risk: %w", err))
			}

			// The per-asset risk rollup is NOT computed here any more. It is
			// MAX over the asset's open risk-feeding findings, and the finding
			// for the configuration just scored is written by the `crypto`
			// producer — so this asks the producer to run and lets the pass's
			// own post-pass recompute roll the number up. See onCryptoChanged.
			if s.onCryptoChanged != nil {
				s.onCryptoChanged(context.Background(), tenantID)
			}
			if s.eventPublisher != nil && lifecycleRiskChanged != nil {
				*lifecycleRiskChanged = append(*lifecycleRiskChanged, &events.AssetRiskChangedPayload{
					AssetID:      assetID,
					RiskScore:    cryptoRiskScore,
					RiskLevel:    mapRiskScoreToLevel(cryptoRiskScore),
					ChangeSource: riskSource,
				})
			}
		}
	}

	// Only on creation. "crypto.configuration_added" for a configuration that
	// already existed is a false event, and before the upsert every hourly
	// re-observation raised one — the same burst the duplicate rows came from,
	// delivered to notification consumers.
	if s.eventPublisher != nil && lifecycleCryptoAdded != nil && cryptoOutcome == cryptoUpsertCreated {
		*lifecycleCryptoAdded = append(*lifecycleCryptoAdded, &events.CryptoConfigurationAddedPayload{
			AssetID:                assetID,
			CryptoImplementationID: cryptoID,
			Protocol:               protocol,
			ProtocolVersion:        f.ProtocolVersion,
			// What was stored: nil when the configuration is unassessed
			// (including a partial cipher assessment cleared above), never
			// the working number that was not written.
			RiskScore: storedRiskScore(cryptoRiskAssessed, cryptoRiskScore),
		})
	}
	return errors.Join(materializationErrs...)
}

type minimalAsset struct {
	ID        uuid.UUID `db:"id"`
	Hostname  *string   `db:"hostname"`
	IPAddress *string   `db:"ip_address"`
	Port      *int      `db:"port"`
}

// ErrNotFound is returned by a write that matched no row for the tenant: the
// id is unknown, belongs to another tenant, or the row is already deleted.
// Handlers answer it 404. A write that changed nothing must say so; reporting
// success for it published events and wrote audit rows for things that never
// happened.
var ErrNotFound = errors.New("not found")

// ErrInvalidInput marks an error caused by what the caller sent. Handlers
// answer it 400; any other error is the server's and answers 500.
var ErrInvalidInput = errors.New("invalid input")

// LifecycleChangeResult reports what an approve or deny actually did. Changed
// are the assets whose status moved; Skipped are requested ids that did not
// move (unknown or foreign to the tenant, deleted, or already in or past the
// target state). The count a caller shows must be len(Changed), never the
// length of the request.
type LifecycleChangeResult struct {
	Changed []uuid.UUID
	Skipped []uuid.UUID
}

// splitChanged partitions the requested ids by whether the UPDATE returned them.
func splitChanged(requested, changed []uuid.UUID) LifecycleChangeResult {
	moved := make(map[uuid.UUID]struct{}, len(changed))
	for _, id := range changed {
		moved[id] = struct{}{}
	}
	res := LifecycleChangeResult{Changed: []uuid.UUID{}, Skipped: []uuid.UUID{}}
	seen := make(map[uuid.UUID]struct{}, len(requested))
	for _, id := range requested {
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		if _, ok := moved[id]; ok {
			res.Changed = append(res.Changed, id)
		} else {
			res.Skipped = append(res.Skipped, id)
		}
	}
	return res
}

// ApproveAssets is ApproveAssetsReport without the report.
func (s *AssetService) ApproveAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, actorUserID uuid.UUID) error {
	_, err := s.ApproveAssetsReport(tenantID, assetIDs, actorUserID)
	return err
}

// ApproveAssetsReport moves assets to monitoring and reports which actually
// moved.
//
// The transition is deliberate: only `pending_approval` (the queue) and
// `denied` (a person reversing their own decision) are approvable. An asset
// already `monitoring` is skipped, so a repeated approve is a no-op that writes
// no history, emits no event and replays no deferred crypto. Without the
// predicate a second approve re-ran all three for every id.
func (s *AssetService) ApproveAssetsReport(tenantID uuid.UUID, assetIDs []uuid.UUID, actorUserID uuid.UUID) (LifecycleChangeResult, error) {
	if len(assetIDs) == 0 {
		return LifecycleChangeResult{Changed: []uuid.UUID{}, Skipped: []uuid.UUID{}}, nil
	}

	// Commit approval before materializing deferred crypto data so a failed status
	// update cannot leave certificates/crypto rows behind for an unapproved asset.
	// Approval is an administrative decision, not a new observation. Preserve
	// both observation freshness and its stale classification.
	query := `UPDATE assets SET asset_status = 'monitoring', updated_at = NOW()
		WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
		  AND asset_status IN ('pending_approval', 'denied')
		RETURNING id`
	// RLS-scoped write over assets + asset_relationships. The status change and
	// the edge promotion are ONE transaction: an approval that promoted no edges
	// because the second statement failed would leave a monitored asset whose
	// relationships are all invisible, with nothing to retry it.
	//
	// The HISTORY row is in the same transaction, for the same reason and one
	// more: approving is the single most consequential thing a person does to an
	// asset, and it wrote nothing to `asset_history` at all. The timeline said
	// the asset was discovered and then, with no entry in between, that it was
	// being monitored — no record that anybody decided, and none of who.
	var changed []uuid.UUID
	if err := withAssetLifecycleWriteTx(context.Background(), s.db, tenantID, assetIDs, func(tx *sqlx.Tx) error {
		changed = nil
		if err := checkAssetLifecycleMutable(context.Background(), tx, tenantID, assetIDs); err != nil {
			return err
		}
		if e := tx.Select(&changed, query, tenantID, pq.Array(assetIDs)); e != nil {
			return e
		}
		for _, assetID := range changed {
			s.recordAssetHistoryBy(tx, tenantID, assetID, actorUserID, identity.ActionApproved,
				identity.Source{Kind: identity.SourceDeclared, Ref: "approvals"},
				map[string]any{"asset_status": identity.StatusMonitoring})
		}
		if len(changed) == 0 {
			return nil
		}
		return promoteEdgesForApprovedAssets(tx, tenantID, changed)
	}); err != nil {
		return LifecycleChangeResult{}, err
	}
	result := splitChanged(assetIDs, changed)
	if len(result.Changed) == 0 {
		return result, nil
	}
	s.publishLifecycle(tenantID, result.Changed, actorUserID,
		events.EventTypeAssetApproved, identity.StatusMonitoring)

	// The ingestion-queue rows that produced these assets are waiting on THIS
	// decision. Settle them; see settleDiscoveryQueueRows.
	s.settleDiscoveryQueueRows(tenantID, result.Changed, "auto_approved")

	// Replay the crypto evidence held while each asset waited
	// (deferred_crypto.go).
	var materializationErrs []error
	for _, assetID := range result.Changed {
		if _, err := s.replayDeferredCrypto(context.Background(), tenantID, assetID); err != nil {
			materializationErrs = append(materializationErrs, fmt.Errorf("asset %s: %w", assetID, err))
		}
	}
	return result, errors.Join(materializationErrs...)
}

// AgentHostApprovalSourceRef is the `asset_history.source` an agent-driven
// approval is recorded under: `agent:<agent id>`, the same producer prefix the
// host inventory writes its facts and installs with, so the timeline attributes
// the approval to the thing that earned it.
func AgentHostApprovalSourceRef(agentID uuid.UUID) string {
	return "agent:" + agentID.String()
}

// AutoApproveAgentHost admits a host the tenant's own device agent runs on.
//
// This is the second automatic path into inventory, beside the auto-approving
// network segment, and it exists because the first one asked the wrong
// question of an agent host. A segment rule answers "is this address somewhere
// we trust?", which a discovery needs asked because the discovery is one
// packet's worth of evidence. A local host inventory is not a discovery: someone
// with administrative access to the machine installed the tenant's agent on it
// and enrolled it with the tenant's registration key. That IS the approval a
// person in Discovery → Approvals would be giving, already given, by the same
// person, with more authority — and asking for it a second time left the one
// host whose software inventory the platform had collected sitting outside the
// SBOM it was collected for.
//
// What it does is exactly what ApproveAssets does — the status, the history
// row, the edge promotion, the lifecycle event, the deferred-finding replay —
// through the same code, because an approval that skipped any of those would
// be an asset that is `monitoring` and still not in inventory. Two things
// differ, and both are the reason it is a separate method rather than a flag:
//
//   - It approves ONLY a `pending_approval` asset, and says so with `false`
//     rather than an error. A `denied` host is a decision a person took, and
//     installing an agent on it afterwards is not that person changing their
//     mind about the queue — it is the ordinary approval path's job to ask
//     them. An archived or merged asset is not in the queue at all. A host
//     already `monitoring` needs nothing. All three answer `false, nil`, and
//     the caller — an agent that reports on a schedule — asks again next run.
//   - The history row carries no actor and names the agent as its source, so
//     the timeline reads "approved · agent:<id>" rather than an approval by
//     nobody from "approvals".
func (s *AssetService) AutoApproveAgentHost(tenantID, assetID, agentID uuid.UUID) (bool, error) {
	if assetID == uuid.Nil {
		return false, errors.New("auto-approve agent host: asset id is required")
	}
	if agentID == uuid.Nil {
		return false, errors.New("auto-approve agent host: agent id is required")
	}
	source := identity.Source{Kind: identity.SourceMeasured, Ref: AgentHostApprovalSourceRef(agentID), Mode: identity.ModeActive}
	ids := []uuid.UUID{assetID}

	moved := false
	if err := withAssetLifecycleWriteTx(context.Background(), s.db, tenantID, ids, func(tx *sqlx.Tx) error {
		// Read-then-write inside the lifecycle lock, so the status this tests
		// is the one the UPDATE below acts on. The WHERE repeats the test as a
		// second guard rather than trusting the read alone.
		var current string
		err := tx.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
			tenantID, assetID).Scan(&current)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading asset status: %w", err)
		}
		if current != identity.StatusPendingApproval {
			log.Printf("[AssetService] agent %s host %s is %s, not pending; leaving it", agentID, assetID, current)
			return nil
		}
		if err := checkAssetLifecycleMutable(context.Background(), tx, tenantID, ids); err != nil {
			return err
		}
		res, err := tx.Exec(`UPDATE assets SET asset_status = 'monitoring', updated_at = NOW()
			WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL AND asset_status = 'pending_approval'`,
			tenantID, assetID)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return nil
		}
		moved = true
		s.recordAssetHistoryBy(tx, tenantID, assetID, uuid.Nil, identity.ActionApproved, source,
			map[string]any{"asset_status": identity.StatusMonitoring, "reason": "agent_installed", "agent_id": agentID.String()})
		return promoteEdgesForApprovedAssets(tx, tenantID, ids)
	}); err != nil {
		return false, err
	}
	if !moved {
		return false, nil
	}
	s.publishLifecycleFrom(tenantID, ids, uuid.Nil, events.EventTypeAssetApproved, identity.StatusMonitoring, source.Producer())

	// Same replay as a human approval: the findings a sensor deferred while the
	// host waited are what make an approved host's certificates and crypto
	// configurations appear. An agent-approved host with none of them would be
	// approved and still not in the lenses.
	if _, err := s.replayDeferredCrypto(context.Background(), tenantID, assetID); err != nil {
		return true, fmt.Errorf("asset %s approved but its deferred findings did not replay: %w", assetID, err)
	}
	return true, nil
}

// DenyAssets is DenyAssetsReport without the report.
func (s *AssetService) DenyAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, userID uuid.UUID) error {
	_, err := s.DenyAssetsReport(tenantID, assetIDs, userID)
	return err
}

// DenyAssetsReport denies assets waiting in the approval queue and reports
// which actually moved. Only `pending_approval` is deniable: an asset a person
// already approved (`monitoring`) is not silently flipped to denied, and a
// repeated deny is a no-op with no second suppression, history row or event.
func (s *AssetService) DenyAssetsReport(tenantID uuid.UUID, assetIDs []uuid.UUID, userID uuid.UUID) (LifecycleChangeResult, error) {
	if len(assetIDs) == 0 {
		return LifecycleChangeResult{Changed: []uuid.UUID{}, Skipped: []uuid.UUID{}}, nil
	}

	// Fetch asset fingerprints.
	//
	// One row per ENDPOINT, because the suppression fingerprint is
	// md5(hostname|ip|port) and the port lives there now. An asset with three
	// endpoints therefore records three fingerprints: denying the thing denies
	// every face of it, which is what the user asked for. An asset with none —
	// an at-rest resource — records one with a NULL port, exactly as a
	// port-less asset always did.
	var assets []minimalAsset
	selectQuery := `
		SELECT a.id, a.hostname, host(COALESCE(e.address, a.primary_address)) AS ip_address, e.port
		FROM assets a
		LEFT JOIN asset_endpoints e ON e.tenant_id = a.tenant_id AND e.asset_id = a.id
		WHERE a.tenant_id = $1 AND a.id = ANY($2) AND a.deleted_at IS NULL AND a.asset_status = 'pending_approval'`
	// Mark assets as denied and default ownership to third_party.
	// RLS-scoped write over assets + asset_relationships, in one transaction
	// for the same reason ApproveAssets is.
	update := `UPDATE assets SET asset_status = 'denied', asset_ownership = COALESCE(NULLIF(asset_ownership,''), 'third_party'), updated_at = NOW() WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL AND asset_status = 'pending_approval' RETURNING id`
	var changed []uuid.UUID
	if err := withAssetLifecycleWriteTx(context.Background(), s.db, tenantID, assetIDs, func(tx *sqlx.Tx) error {
		changed = nil
		assets = nil
		if err := checkAssetLifecycleMutable(context.Background(), tx, tenantID, assetIDs); err != nil {
			return err
		}
		if err := tx.Select(&assets, selectQuery, tenantID, pq.Array(assetIDs)); err != nil {
			return fmt.Errorf("failed to load assets for suppression: %w", err)
		}
		for _, a := range assets {
			if err := addSuppressionTx(tx, tenantID, a.Hostname, a.IPAddress, a.Port, &userID, "denied by user"); err != nil {
				return fmt.Errorf("failed to record deny suppression for asset %s: %w", a.ID, err)
			}
		}

		if e := tx.Select(&changed, update, tenantID, pq.Array(assetIDs)); e != nil {
			return e
		}
		// Same reason as the approval: a deny is a human decision, and the
		// timeline recorded neither the decision nor the decider.
		for _, assetID := range changed {
			s.recordAssetHistoryBy(tx, tenantID, assetID, userID, identity.ActionDenied,
				identity.Source{Kind: identity.SourceDeclared, Ref: "approvals"},
				map[string]any{"asset_status": identity.StatusDenied})
		}
		if len(changed) == 0 {
			return nil
		}
		return rejectEdgesForDeniedAssets(tx, tenantID, changed)
	}); err != nil {
		return LifecycleChangeResult{}, err
	}
	result := splitChanged(assetIDs, changed)
	if len(result.Changed) == 0 {
		return result, nil
	}
	s.publishLifecycle(tenantID, result.Changed, userID, events.EventTypeAssetDenied, identity.StatusDenied)
	s.settleDiscoveryQueueRows(tenantID, result.Changed, "suppressed")
	return result, nil
}

// settleDiscoveryQueueRows closes out the ingestion-queue rows whose approval
// decision has just been made.
//
// The missing half of the IngestReport/EffectiveStatus mechanism. That one
// answers "what status does this asset have RIGHT NOW", at ingest — and when
// the honest answer is `pending_approval`, discovery-processor correctly leaves
// the queue row `pending`, because at that instant there really is a pending
// asset awaiting a human. Nothing then told the queue row when that human
// answered. The row stayed `pending` for the rest of its retention window with
// its asset long since `monitoring`, and the only consumer of the value —
// cluster-sensor-service's per-job materialization summary — went on reporting
// it as "awaiting approval" (evidence item 7: four S3 rows in exactly
// this state on the demo host, stranded by the bulk approval that promoted
// their assets ninety seconds after they were written).
//
// Vocabulary, not new values: `auto_approved` with `auto_approval_rule_id`
// still NULL is what adoptEffectiveStatus already stamps for a row whose asset
// is `monitoring` — NULL saying truthfully that no rule fired — and
// `suppressed` is what it stamps for `archived`/`denied`. This brings a row to
// the state it would have been given had the approval preceded the ingest.
//
// Scoped by `asset_id`, which discovery-processor now records (adoptAssetID).
// Rows written before that are not reachable from here and are settled by the
// POST-MIGRATIONS backfill instead.
//
// AFTER the commit and best-effort, for the same reason publishLifecycle is:
// the decision happened, and failing the caller's approval because a queue row
// could not be tidied would be strictly worse than the stale row.
func (s *AssetService) settleDiscoveryQueueRows(tenantID uuid.UUID, assetIDs []uuid.UUID, approvalStatus string) {
	if len(assetIDs) == 0 || s.db == nil {
		return
	}
	var settled int64
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		res, e := tx.Exec(`
			UPDATE sensor_discoveries
			   SET approval_status = $3
			 WHERE tenant_id = $1
			   AND asset_id = ANY($2)
			   AND processed_at IS NOT NULL
			   AND approval_status = 'pending'`, tenantID, pq.Array(assetIDs), approvalStatus)
		if e != nil {
			return e
		}
		settled, _ = res.RowsAffected()
		return nil
	}); err != nil {
		log.Printf("[AssetService] settling discovery queue rows for %d asset(s) failed (the decision stands): %v", len(assetIDs), err)
		return
	}
	if settled > 0 {
		log.Printf("[AssetService] settled %d discovery queue row(s) to %s after the decision on %d asset(s)", settled, approvalStatus, len(assetIDs))
	}
}

// publishLifecycle announces a decision a person made about assets already in
// the inventory.
//
// AFTER the commit, and failure to publish is logged rather than returned: the
// decision happened, and telling the caller it did not would be worse than a
// subscriber learning about it on its next read. Nothing consumes these today —
// the edge promotion and deferred-finding materialisation that approval
// triggers are IN-PROCESS and stay that way, because an approval that depended
// on a subscriber would silently do nothing whenever NATS was down.
func (s *AssetService) publishLifecycle(tenantID uuid.UUID, assetIDs []uuid.UUID, actor uuid.UUID, eventType, status string) {
	s.publishLifecycleFrom(tenantID, assetIDs, actor, eventType, status, "approvals")
}

// publishLifecycleFrom is publishLifecycle with the event's source named by the
// caller. "approvals" is the human queue; an approval the platform reached on
// its own names what reached it, so a subscriber can tell the two apart.
func (s *AssetService) publishLifecycleFrom(tenantID uuid.UUID, assetIDs []uuid.UUID, actor uuid.UUID, eventType, status, source string) {
	if s.eventPublisher == nil {
		return
	}
	decided := ""
	if actor != uuid.Nil {
		decided = actor.String()
	}
	if err := s.eventPublisher.PublishAssetLifecycle(context.Background(), tenantID, eventType,
		&events.AssetLifecyclePayload{AssetIDs: assetIDs, Status: status, DecidedBy: decided},
		source); err != nil {
		log.Printf("[AssetService] %s committed but the event was not published: %v", eventType, err)
	}
}

// An edge is only as approved as the two assets it joins.
//
// `asset_relationships.status` starts at `pending` — the interrogation writer
// is the only thing that sets it, and it has no business promoting an edge to a
// host nobody has accepted into inventory yet. Until this, NOTHING promoted it
// afterwards either: an edge between two assets that were both subsequently
// approved stayed pending forever, so the Relationships tab and the map were
// empty on every freshly-approved asset while the customer doc said approving
// the asset would make its relationships live.
//
// The rule is stated in one place and in both directions:
//
//   - APPROVE: an edge becomes `active` when the asset at its OTHER end is
//     already `monitoring`. Both ends have to be in inventory for the edge to
//     describe anything; promoting on one end would surface an edge pointing at
//     a thing the user has not accepted.
//   - DENY: every edge touching the denied asset becomes `rejected`, whatever
//     the other end is. The user said this is not a thing they own; an edge to
//     it is not a thing either.
//
// An edge already `rejected` is left alone in both paths. A rejection is a
// human decision about that edge, and approving an unrelated asset must not
// quietly undo it. `stale` is likewise left for the staleness job to own.

// promoteEdgesForApprovedAssets activates the pending edges of newly approved
// assets whose other end is already monitored — EXCEPT inferred ones.
//
// ADR-0003 D3 grants this promotion on one ground: "Approving the asset
// approves what was observed about it." That reasoning covers `measured` and
// `imported` edges, which are records of something a collector saw or a system
// of record asserted. It does not cover `inferred`, which the same table says
// enters as `pending` and "appears in Approvals as a relationship proposal" —
// a belief the platform formed, not an observation, and the one provenance the
// ADR says a human has to sign off.
//
// Without the exclusion the relationship-proposal queue is nearly unreachable:
// an inferred edge drawn while either end was still pending would be silently
// activated by that asset's approval, so the proposal a reviewer was meant to
// see becomes a fact nobody agreed to. The queue's own predicate is "pending
// with both ends monitored", so this exclusion is exactly what routes those
// edges into it.
func promoteEdgesForApprovedAssets(tx *sqlx.Tx, tenantID uuid.UUID, assetIDs []uuid.UUID) error {
	// The statement lives in shared/identity/postgres so the cloud intake's
	// account-level auto-approval (ADR-0009 D5) promotes edges by the SAME
	// rule rather than a copy of it.
	return pgidentity.PromoteEdgesForApproved(context.Background(), tx.Tx, tenantID, assetIDs)
}

// rejectEdgesForDeniedAssets rejects every edge touching a denied asset.
func rejectEdgesForDeniedAssets(tx *sqlx.Tx, tenantID uuid.UUID, assetIDs []uuid.UUID) error {
	_, err := tx.Exec(`
		UPDATE asset_relationships
		   SET status = 'rejected', updated_at = NOW()
		 WHERE tenant_id = $1
		   AND status <> 'rejected'
		   AND (from_asset_id = ANY($2) OR to_asset_id = ANY($2))`,
		tenantID, pq.Array(assetIDs))
	if err != nil {
		return fmt.Errorf("failed to reject relationships for denied assets: %w", err)
	}
	return nil
}

// evaluateAssetApproval decides a new asset's approval status server-side.
//
// Auto-approval has one gate for an asset nobody observed: its address is in a
// prefix with auto-approve enabled. Those prefixes generate the rows in
// discovery_auto_approval_rules (prefix_approval_rules.go); shared/approval
// evaluates them, and it is the same evaluation the sensor pipeline runs — one
// implementation of the rule, not two.
//
// Default deny: anything that cannot be resolved to a matching, auto-approving
// prefix — a lookup error, no matching prefix, a non-internal address — lands
// in Discovery → Approvals.
func (s *AssetService) evaluateAssetApproval(tenantID uuid.UUID, ipAddress, hostname *string) string {
	return s.evaluateAssetApprovalIn(nil, tenantID, ipAddress, hostname)
}

// evaluateAssetApprovalOver is evaluateAssetApproval's decision over a prefix
// set already read — one read answers both the prefix and the ownership. The
// hostname places nothing: a prefix scopes addresses only.
func (s *AssetService) evaluateAssetApprovalOver(tenantID uuid.UUID, set *PrefixSet, ipAddress, _ *string) string {
	const pending = "pending_approval"
	p := set.Match(ipAddress)
	if p == nil || s.db == nil {
		return pending
	}
	id := p.ID
	classification := &approval.Classification{
		Ownership: set.Classify(ipAddress),
		Type:      classificationType(p, ipAddress),
		PrefixID:  &id,
	}
	// Metadata is deliberately nil: no metadata means "not a cloud discovery",
	// which is what a manually created or CMDB-pulled asset is. Confidence 1.0 —
	// the asset was asserted by a user or an authoritative system of record, not
	// inferred from an observation.
	autoApprove, _, err := approval.NewService(s.db.DB.DB).EvaluateAutoApproval(
		approval.Discovery{TenantID: tenantID}.WithConfidence(1.0),
		classification,
	)
	if err != nil || !autoApprove {
		return pending
	}
	return "monitoring"
}

// CreateAsset inserts a new asset for the tenant and returns the created record.
// Validates required fields and defaults JSONB maps to empty objects to avoid NULLs.
//
// The approval status is decided HERE, by evaluateAssetApproval, and
// input.AssetStatus is ignored. It used to be honoured verbatim, which made the
// tenant's own approval policy advisory on every caller-facing path that reaches
// this function — manual create (POST /assets), spreadsheet bulk import and CMDB
// pull (both via BulkCreateAssets). Callers that hold a status the server already
// evaluated — the discovery ingestion pipeline — use createAssetWithStatus.
func (s *AssetService) CreateAsset(tenantID uuid.UUID, input models.AssetInput) (*models.Asset, error) {
	// Custom fields (DCIM row 5.1) are checked BEFORE the asset exists, so a
	// refused value refuses the create rather than leaving a half-made asset.
	ctx := context.Background()
	if _, err := s.assetCustomFields(ctx, tenantID, uuid.Nil, input.CustomFields, true); err != nil {
		return nil, err
	}
	// A handler-created asset IS manual provenance — there is no request field
	// for it, deliberately: a client cannot claim its hand-entered asset was
	// sensor-observed.
	asset, err := s.createAssetFromInput(tenantID, input,
		identity.Source{Kind: identity.SourceDeclared, Ref: "manual"},
		s.evaluateAssetApproval(tenantID, input.IPAddress, input.Hostname))
	if err != nil || asset == nil {
		return asset, err
	}
	// Then written over what the row holds: a new asset gets the values and
	// the defaults; one the identity engine matched keeps its own values for
	// the fields this create did not name.
	cf, err := s.assetCustomFields(ctx, tenantID, asset.ID, input.CustomFields, true)
	if err != nil {
		return nil, err
	}
	if err := s.setAssetCustomFields(ctx, tenantID, asset.ID, cf); err != nil {
		return nil, err
	}
	asset.CustomFields = cf
	return asset, nil
}

// CreateAssetFromSource creates or matches ONE asset on behalf of an external
// source of truth — a connector pulling from NetBox, a CMDB import — and
// returns the identification engine's outcome alongside the asset.
//
// It differs from CreateAsset in two ways, both deliberate:
//
//   - the caller names its own source (`identity.Source{SourceImported,
//     "netbox:<connection-id>"}`), so the asset's provenance says WHICH
//     connection supplied it rather than a generic "import". The approval-rule
//     producer filter reads Source.Producer(), so the shape matters.
//   - the OUTCOME comes back, so an importer can report created / matched /
//     needs-review honestly instead of counting every row as an import.
//
// The approval decision is still the server's: evaluateAssetApproval runs the
// tenant's segment rules, so a connector cannot promote anything past the
// approval queue. That is the same guarantee CreateAsset makes, and it is why
// this takes a source rather than a status.
func (s *AssetService) CreateAssetFromSource(tenantID uuid.UUID, input models.AssetInput, source identity.Source) (*models.Asset, identity.Outcome, error) {
	if !source.Valid() {
		return nil, "", fmt.Errorf("an imported asset needs a valid source (kind and ref)")
	}
	return s.createAssetResolved(tenantID, input, source,
		s.evaluateAssetApproval(tenantID, input.IPAddress, input.Hostname))
}

// createAssetFromInput is the one place a declared or imported asset is created:
// manual create, spreadsheet import and the CMDB pull all land here.
//
// It builds an observation and resolves it, which is what makes those three
// paths dedupe at all. Manual create previously did not dedupe in any way, and
// import and CMDB matched host-or-IP without a scope — so the same host in two
// segments was one asset, and the same host imported twice was two.
// The asset's discovery_method is the engine's record of the observation's
// source ref, so this takes no separate discovery-method argument: one spelling
// of "how did this get here", carried by the same row the history points at.
func (s *AssetService) createAssetFromInput(tenantID uuid.UUID, input models.AssetInput, source identity.Source, assetStatus string) (*models.Asset, error) {
	asset, _, err := s.createAssetResolved(tenantID, input, source, assetStatus)
	return asset, err
}

// createAssetResolved is createAssetFromInput with the engine's OUTCOME, which
// the bulk import needs: `matched` is the row that used to be reported as
// "skipped, duplicate" by a separate pre-flight lookup. Deriving it from the
// resolution instead of a second query means the import's idea of a duplicate
// and the inventory's idea of one are the same idea — the old pre-check matched
// host-or-IP with no scope, so it called two different segments' `printer-2` a
// duplicate and missed a host whose only match was its serial.
func (s *AssetService) createAssetResolved(tenantID uuid.UUID, input models.AssetInput, source identity.Source, assetStatus string) (*models.Asset, identity.Outcome, error) {
	if strings.TrimSpace(input.ClassKey) == "" {
		return nil, "", fmt.Errorf("%w: class_key is required", ErrInvalidInput)
	}
	if _, ok := assetclass.Get(input.ClassKey); !ok {
		// A tenant leaf subclass is a runtime row the generated registry does
		// not carry, so an unknown key is checked against the table before it
		// is refused.
		known, err := s.classKeyExists(tenantID, input.ClassKey)
		if err != nil {
			return nil, "", err
		}
		if !known {
			return nil, "", fmt.Errorf("%w: class_key %q is not a known asset class", ErrInvalidInput, input.ClassKey)
		}
	}

	obs, err := s.manualObservation(tenantID, input, source)
	if err != nil {
		return nil, "", err
	}
	// The rules, for the case a declaration leaves open: a person or an importer
	// that named no class. applyClassProposal fills only a hint the builder did
	// not already have, so a class the user PICKED is never second-guessed —
	// ADR-0008 D4.2's rule, and the reason `declared` outranks everything.
	ctxBG := context.Background()
	classProp := s.applyClassProposal(ctxBG, &obs, manualClassEvidence(input))

	// Context, tags, class attributes and the approval status are not identity,
	// so the engine does not write them — but they are part of the SAME fact,
	// so they are written on the engine's transaction. Either the whole
	// observation lands or none of it does.
	var assetID uuid.UUID
	res, err := s.resolveObservationWith(context.Background(), obs, func(tx *sqlx.Tx, res identity.Resolution) error {
		if res.Asset.Zero() {
			// Every identifier belongs to another asset and none could decide:
			// the engine opened a merge proposal and wrote nothing. There is no
			// asset to apply context to.
			return nil
		}
		id, perr := uuid.Parse(res.Asset.ID)
		if perr != nil {
			return fmt.Errorf("identification engine returned an unusable asset id %q: %w", res.Asset.ID, perr)
		}
		assetID = id
		if cerr := s.applyAssetContext(tx, tenantID, assetID, input, source, res.Outcome); cerr != nil {
			return cerr
		}
		// The engine wrote the declared interfaces and addresses; the source's
		// own ids for them (NetBox's) go on the same rows (row 1.5f).
		if cerr := stampDeclaredExternalIDs(ctxBG, tx, tenantID, assetID, input.Interfaces); cerr != nil {
			return cerr
		}
		// Record only, never Promote, on this path. A declaration or an import
		// is a person's assertion about the asset, not evidence the platform
		// measured; on a match it re-states an asset that exists, and a rule
		// moving that asset's class as a side effect of somebody re-importing
		// a spreadsheet row is not what they asked for. The floor sweep
		// (class_floor_sweep.go) still re-asks the question for the asset.
		if cerr := s.recordClassOutcome(ctxBG, tx, tenantID, assetID, res.Outcome, classProp); cerr != nil {
			return cerr
		}
		// A person's spreadsheet listing the asset keeps it in scope for
		// automatic scanning, whatever a connection said about it first
		// (platform ADR-0002 D10; shared/identity/postgres import_only.go).
		// Read off the resolution, not off a history row, so it holds even
		// when the listing changed nothing.
		if source.Kind == identity.SourceImported && source.Ref == identity.SpreadsheetImportSourceRef {
			if cerr := pgidentity.ClearImportOnly(ctxBG, tx, tenantID.String(), assetID); cerr != nil {
				return cerr
			}
		}
		// The approval decision the caller reached stands, EXCEPT over a
		// conflict: a conflicting observation waits for the human who has to
		// settle the merge, whatever the segment rule said.
		if res.Outcome != identity.OutcomeConflict && assetStatus != "" && assetStatus != identity.StatusPendingApproval {
			return s.setAssetStatus(tx, tenantID, assetID, assetStatus, source)
		}
		return nil
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to create asset: %w", err)
	}
	if res.Asset.Zero() {
		// Nothing was created and nothing matched: the observation's
		// identifiers all belong to other assets, and a human has a merge
		// proposal to settle. Reporting it as a failure is the honest answer —
		// the caller asked for an asset and there is none to return.
		if res.ObservationID != "" {
			return nil, res.Outcome, &identity.RetainedObservation{Result: res.IngestResult()}
		}
		return nil, res.Outcome, fmt.Errorf("%w: this asset's identifiers already belong to %d existing asset(s); "+
			"a merge proposal was opened in Approvals for review", ErrInvalidInput, len(res.Candidates))
	}

	if s.eventPublisher != nil {
		ctx := context.Background()
		changeType := sharedevents.ChangeTypeCreated
		if res.Outcome == identity.OutcomeMatched {
			changeType = sharedevents.ChangeTypeUpdated
		}
		if err := s.eventPublisher.PublishAssetChanged(ctx, tenantID, assetID, changeType, source.Producer()); err != nil {
			log.Printf("[AssetService] Warning: Failed to publish asset created event: %v", err)
		}
	}
	asset, err := s.GetAssetByID(tenantID, assetID)
	if err != nil {
		return nil, res.Outcome, err
	}
	return asset, res.Outcome, nil
}

// classKeyExists checks the class registry table for a key the generated
// registry does not carry — that is, a tenant leaf subclass.
func (s *AssetService) classKeyExists(tenantID uuid.UUID, key string) (bool, error) {
	var exists bool
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM asset_classes
				WHERE key = $1 AND (tenant_id = $2 OR tenant_id IS NULL)
			)`, key, tenantID).Scan(&exists)
	})
	if err != nil {
		return false, fmt.Errorf("failed to validate class_key: %w", err)
	}
	return exists, nil
}

// discoveryDecline is why the ingest gate declined to resolve a finding.
type discoveryDecline int

const (
	// discoveryProceed: the finding was resolved.
	discoveryProceed discoveryDecline = iota
	// discoveryDeniedAsset: it belongs to an asset the tenant denied, whose
	// last-seen alone moves.
	discoveryDeniedAsset
	// discoveryRouteExternal: a third-party endpoint that is no elevated asset,
	// recorded in external_connections.
	discoveryRouteExternal
	// discoverySuppressed: nothing owns it and its fingerprint is suppressed.
	discoverySuppressed
)

// resolveDiscoveryObservation is the ingest path's call into the identification
// engine: one observation per finding, one transaction, one of three outcomes.
//
// It replaces the SELECT-then-INSERT the ingest used to do, whose match was
// "(hostname = $ OR ip = $) AND (port = $ OR port IS NULL)" — the key that made
// the same host on five ports five assets. The port is not part of identity any
// more; it is an endpoint under whichever asset the identifiers resolved.
//
// assetStatus is the decision discovery-processor-service already reached by
// running this tenant's segment auto-approval rules over the classified
// discovery. It is applied here rather than re-derived, so the two cannot
// disagree — EXCEPT over a conflict, where the observation waits for the human
// who has to settle the merge whatever the rule said.
func (s *AssetService) resolveDiscoveryObservation(segs *importPrefixes, cloudAccounts *cloudAccountResolver, tenantID uuid.UUID, f IngestFinding, obs identity.Observation, effectiveIP *string, ownership, assetStatus string, gate func(ctx context.Context, tx *sqlx.Tx, existing existingAsset) (bool, error)) (identity.Resolution, existingAsset, bool, bool, error) {
	ctxBG := context.Background()

	// The discovery-source attribution the Approvals filter buttons read. It
	// is not identity, so it does not belong in the observation — but it is
	// part of the SAME fact, so it is written on the engine's transaction.

	var classProp classify.ClassProposal
	// The observation as the engine will read it, class hint included.
	amended := obs
	discoveryGate := func(ctx context.Context, tx *sqlx.Tx, existing existingAsset, obs *identity.Observation) (bool, error) {
		if gate != nil {
			proceed, err := gate(ctx, tx, existing)
			if err != nil || !proceed {
				return proceed, err
			}
		}
		// The rules (ADR-0004 D6, workstream 2.10b). A class they decide
		// becomes a NEW asset's class with `rule` provenance; on an asset that
		// already exists it becomes a proposal in Approvals instead, because a
		// class is never overwritten. A class the finding itself carried — a
		// cloud resource type read through shared/assetclass — is left alone:
		// the collector's answer beats an inference. In memory: the rule
		// engine is refreshed in the background.
		classProp = s.applyClassProposal(ctx, obs, findingClassEvidence(f))
		amended = *obs
		return true, nil
	}
	ctxInputFor := func() models.AssetInput {
		in := models.AssetInput{
			Tags:     models.JSONB{},
			Metadata: discoverySourceMetadata(f),
		}
		if ownership != "" {
			in.AssetOwnership = &ownership
		}
		if os := strings.TrimSpace(derefString(f.OperatingSystem)); os != "" {
			// The OS is a class attribute now (ADR-0002 D2), not a column.
			in.Attributes = map[string]interface{}{"operating_system": os}
		}
		if attrs := cloudAccounts.attributes(f); len(attrs) > 0 {
			if in.Attributes == nil {
				in.Attributes = map[string]interface{}{}
			}
			for k, v := range attrs {
				in.Attributes[k] = v
			}
		}
		if attrs := kmsKeyStoreAttributesFromFinding(f); len(attrs) > 0 {
			// A cloud KMS key's Key Store asset shows the key's posture and
			// its provider, account and region (merged, so a refresh updates).
			if in.Attributes == nil {
				in.Attributes = map[string]interface{}{}
			}
			for k, v := range attrs {
				in.Attributes[k] = v
			}
		}
		return in
	}

	var assetID uuid.UUID
	var durableMaterialization bool
	res, existing, resolved, err := s.resolveObservationGated(ctxBG, obs, discoveryGate, operatorScanAttribution(tenantID, f, effectiveIP), func(repo *pgidentity.Repository, tx *sqlx.Tx, res identity.Resolution) error {
		mode, err := repo.AdmissionMode(ctxBG, tenantID.String())
		if err != nil {
			return err
		}
		durableMaterialization = res.ObservationID != "" && (mode == "enforce" || mode == "paused")
		if durableMaterialization {
			// Held on the engine's transaction, waiting on the observation
			// (deferred_crypto.go): replayed once it is linked to a monitoring
			// asset by a decision that attached its evidence.
			if err := deferCryptoForObservation(ctxBG, tx, tenantID, res.ObservationID, identity.ObservationReceiptKey(amended),
				amended.Source.Ref, f, res.OperatorScanJob, amended.ObservedAt); err != nil {
				return err
			}
		}
		if res.Asset.Zero() {
			return nil
		}
		id, perr := uuid.Parse(res.Asset.ID)
		if perr != nil {
			return fmt.Errorf("identification engine returned an unusable asset id %q: %w", res.Asset.ID, perr)
		}
		assetID = id
		if cerr := s.applyAssetContext(tx, tenantID, assetID, ctxInputFor(), obs.Source, res.Outcome); cerr != nil {
			return cerr
		}
		// On a MATCH, over the asset's accumulated evidence, promoting a
		// floor asset to a rule's class before recording any proposal — see
		// classOutcomeForResolution. Read here, after Resolve attached this
		// finding's identifiers and applyAssetContext wrote its context, on
		// the engine's transaction.
		if _, cerr := s.classOutcomeForResolution(ctxBG, tx, tenantID, assetID, res.Outcome, classProp,
			findingClassEvidence(f), true); cerr != nil {
			return cerr
		}
		if res.Outcome != identity.OutcomeConflict && assetStatus != "" && assetStatus != identity.StatusPendingApproval {
			return s.setStatusUnlessArchived(tx, tenantID, assetID, assetStatus, obs.Source)
		}
		return nil
	})
	if err != nil {
		return identity.Resolution{}, existing, false, false, err
	}
	if !resolved {
		return identity.Resolution{}, existing, false, false, nil
	}
	if res.OperatorScanJob != "" {
		log.Printf("[AssetService] IngestFindings: %s attached to asset %s, which a person scanned (Active Scan job %s)",
			findingLabel(f), res.Asset.ID, res.OperatorScanJob)
	}
	if res.OperatorScanRefused != "" {
		log.Printf("[AssetService] IngestFindings: %s came from a person's Active Scan but was not attributed to the scanned asset: %s",
			findingLabel(f), res.OperatorScanRefused)
	}
	if res.Asset.Zero() {
		// No asset: either every identifier this finding carries already
		// belongs to another asset and none could decide (a merge proposal is
		// the work item), or identity admission kept the evidence as an
		// unresolved observation (Discovery → Observations). Not an error
		// either way, but the caller must not treat it as an ingested asset.
		log.Print(noAssetIngestMessage(findingLabel(f), res))
		return res, existing, true, durableMaterialization, nil
	}

	if res.Outcome == identity.OutcomeConflict {
		log.Printf("[AssetService] IngestFindings: %s conflicts with %d existing asset(s); opened merge proposal %s and left asset %s pending",
			findingLabel(f), len(res.Candidates), res.Proposal.ID, assetID)
	}
	logIdentityDecisions(findingLabel(f), res)
	for _, un := range res.Unattached {
		// An identifier the engine declined to write belongs to another asset.
		// Reporting it is the difference between "we saw this and could not use
		// it" and an inventory that quietly became wrong.
		log.Printf("[AssetService] IngestFindings: %s carried %s=%q, which belongs to another asset; it was not attached",
			findingLabel(f), un.Kind, un.Value)
	}
	return res, existing, true, durableMaterialization, nil
}

// noAssetIngestMessage says what became of a finding that landed on no asset,
// in the terms of what actually happened. It used to always claim a
// merge proposal had been opened — printing an empty id — when the finding had
// in fact been kept as an unresolved observation (e.g. an address on a DHCP
// segment with no device binding) and no proposal existed.
func noAssetIngestMessage(label string, res identity.Resolution) string {
	if res.Proposal.ID != "" {
		return fmt.Sprintf("[AssetService] IngestFindings: %s matched nothing it may claim; its identifiers belong to %d existing asset(s) and merge proposal %s was opened",
			label, len(res.Candidates), res.Proposal.ID)
	}
	reason := res.AdmissionReason
	if reason == "" {
		reason = "none recorded"
	}
	observation := res.ObservationID
	if observation == "" {
		observation = "none"
	}
	msg := fmt.Sprintf("[AssetService] IngestFindings: %s: evidence retained as an unresolved observation (outcome %s, reason %s, observation %s); no asset was created and no merge proposal exists",
		label, res.Outcome, reason, observation)
	if n := len(res.Candidates); n > 0 {
		msg += fmt.Sprintf(" (its identifiers belong to %d existing asset(s))", n)
	}
	return msg
}

// bulkAssetKey returns a stable dedupe key for an import row: the lowercased
// hostname if present, otherwise the IP address. Empty when the row carries
// neither (such a row fails CreateAsset's own validation downstream).
func bulkAssetKey(in models.AssetInput) string {
	if in.Hostname != nil && strings.TrimSpace(*in.Hostname) != "" {
		return "h:" + strings.ToLower(strings.TrimSpace(*in.Hostname))
	}
	if in.IPAddress != nil && strings.TrimSpace(*in.IPAddress) != "" {
		return "i:" + strings.TrimSpace(*in.IPAddress)
	}
	return ""
}

// BulkCreateAssets creates many assets in one request, reusing CreateAsset for
// each row so behavior (validation, ownership classification, segment tagging,
// event emission) is identical to single creation. Rows are deduped both within
// the batch and against existing inventory. Partial success is the norm — a bad
// row is recorded as an error and the rest of the batch proceeds. The caller is
// responsible for enforcing the subscription asset cap before invoking this.
func (s *AssetService) BulkCreateAssets(tenantID uuid.UUID, inputs []models.AssetInput) *models.BulkImportResult {
	return s.BulkCreateAssetsFromSource(tenantID, inputs, identity.Source{Kind: identity.SourceImported, Ref: identity.SpreadsheetImportSourceRef})
}

func (s *AssetService) BulkCreateAssetsFromSource(tenantID uuid.UUID, inputs []models.AssetInput, source identity.Source) *models.BulkImportResult {
	res := models.NewBulkImportResult(len(inputs))
	runID, observedAt := uuid.NewString(), time.Now().UTC()
	seen := make(map[string]struct{}, len(inputs))
	for i, in := range inputs {
		if in.ObservationReceiptID == "" {
			in.ObservationReceiptID = fmt.Sprintf("%s:%d", runID, i)
		}
		if in.ObservationTime.IsZero() {
			in.ObservationTime = observedAt
		}
		// Within-file duplicates are still caught here: two rows for one host in
		// one upload are a data-entry mistake the importer should report, not an
		// asset observed twice.
		key := bulkAssetKey(in)
		if key != "" {
			if _, dup := seen[key]; dup {
				res.Add(i, models.BulkRowSkippedDuplicate, nil, "duplicate of an earlier row in this file")
				continue
			}
			seen[key] = struct{}{}
		}
		// Duplicates AGAINST EXISTING INVENTORY are the identification engine's
		// answer, not a separate lookup's. The old pre-check matched host-or-IP
		// with no scope: it called two segments' `printer-2` one asset and
		// missed a host whose only match was its serial number.
		asset, outcome, err := s.createAssetResolved(tenantID, in,
			source,
			s.evaluateAssetApproval(tenantID, in.IPAddress, in.Hostname))
		if err != nil {
			var retained *identity.RetainedObservation
			if errors.As(err, &retained) {
				res.AddObservation(i, retained.Result.ObservationID, retained.Result.Outcome)
				continue
			}
			res.Add(i, models.BulkRowError, nil, err.Error())
			continue
		}
		switch outcome {
		case identity.OutcomeMatched:
			res.Add(i, models.BulkRowSkippedDuplicate, &asset.ID, "an asset with these identifiers already exists; it was refreshed")
		case identity.OutcomeConflict:
			// A new pending asset AND a merge proposal. Reported as created,
			// because a row was created — and named as needing review, because
			// it does.
			res.Add(i, models.BulkRowCreated, &asset.ID, "identifiers matched more than one existing asset; a merge proposal is waiting in Approvals")
		default:
			res.Add(i, models.BulkRowCreated, &asset.ID, "")
		}
	}
	return res
}

// UpdateAsset updates provided fields for an existing asset, and — since this
// is the only write path a person drives by hand — its IDENTIFIERS.
//
// `identifiers` used to be accepted and dropped: the body carried it, the form
// sent it, and nothing read it. Worse, `hostname` and `primary_address` were
// rewritten by raw SQL with no identifier write at all, so a renamed host kept
// its old identity, gained none for the new name, and was minted afresh the
// next time a collector saw it. Both halves now go through the identification
// engine — see asset_update_identity.go for the rules and the reasons.
//
// actorUserID may be uuid.Nil (a caller with no session); the history entry
// then names the path rather than claiming a user it cannot prove.
func (s *AssetService) UpdateAsset(tenantID, assetID uuid.UUID, input models.AssetInput, actorUserID uuid.UUID) (*models.Asset, *models.IdentifierUpdateReport, error) {
	// The class the identifiers are scoped against: the one being set, else the
	// one the asset already has. A `name` identifier is scoped by class key, so
	// getting this wrong would file a service under the wrong identity.
	classKey := strings.TrimSpace(input.ClassKey)
	if classKey == "" {
		current, err := s.GetAssetByID(tenantID, assetID)
		if err != nil {
			return nil, nil, err
		}
		classKey = current.ClassKey
	}

	// Identity FIRST. A conflict refuses the whole edit, and refusing after the
	// columns had moved would leave the asset renamed but unmatchable.
	report, err := s.updateAssetIdentifiers(context.Background(), tenantID, assetID, classKey, input, actorUserID)
	if err != nil {
		return nil, nil, err
	}

	// Build dynamic SET clauses
	setClauses := []string{}
	args := []interface{}{}
	idx := 1

	if input.Hostname != nil {
		setClauses = append(setClauses, fmt.Sprintf("hostname = $%d", idx))
		args = append(args, input.Hostname)
		idx++
	}
	if input.DisplayName != nil {
		setClauses = append(setClauses, fmt.Sprintf("display_name = $%d", idx))
		args = append(args, input.DisplayName)
		idx++
	}
	if input.IPAddress != nil {
		setClauses = append(setClauses, fmt.Sprintf("primary_address = $%d::text::inet", idx))
		args = append(args, input.IPAddress)
		idx++
	}
	// There is no `port` here any more, deliberately. A port is an endpoint, and
	// an endpoint is observed or declared through the endpoints API — editing
	// the asset cannot move the socket the crypto configurations hang off.
	if input.ClassKey != "" {
		// VALIDATED, like create validates it. An unknown key used to be written
		// straight through — `classPathForKey` falls back to the key itself for
		// anything it does not know — so a typo produced an asset in a class no
		// facet can select, no CMDB sync can map and no identifier precedence
		// exists for. It is checked against the generated registry first and the
		// `asset_classes` table second, because a tenant leaf subclass is a
		// runtime row the generated hierarchy does not carry.
		if _, ok := assetclass.Get(input.ClassKey); !ok {
			known, err := s.classKeyExists(tenantID, input.ClassKey)
			if err != nil {
				return nil, nil, err
			}
			if !known {
				return nil, nil, fmt.Errorf("%w: class_key %q is not a known asset class", ErrInvalidInput, input.ClassKey)
			}
		}
		// A class a person set is `declared`, which outranks a measurement in
		// ADR-0002 D4's class table: the correction sticks.
		setClauses = append(setClauses, fmt.Sprintf("class_key = $%d", idx))
		args = append(args, input.ClassKey)
		idx++
		setClauses = append(setClauses, fmt.Sprintf("class_path = $%d", idx))
		args = append(args, classPathForKey(input.ClassKey))
		idx++
		setClauses = append(setClauses, "class_source_kind = 'declared'")
		// `class_source_ref` says WHO decided, and it was left NULL — so a
		// declared class was indistinguishable from one nobody set. The actor
		// when there is a session; "manual" when the caller had none, which is
		// still more than nothing.
		ref := "manual"
		if actorUserID != uuid.Nil {
			ref = actorUserID.String()
		}
		setClauses = append(setClauses, fmt.Sprintf("class_source_ref = $%d", idx))
		args = append(args, ref)
		idx++
	}
	if len(input.Attributes) > 0 {
		// MERGE, not replace: an edit that carries one attribute must not delete
		// the rest. "Empty never wins" (ADR-0002 D4).
		attrJSON, err := json.Marshal(input.Attributes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal attributes: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("attributes = COALESCE(attributes, '{}'::jsonb) || $%d::jsonb", idx))
		args = append(args, string(attrJSON))
		idx++
	}
	if input.Environment != nil {
		setClauses = append(setClauses, fmt.Sprintf("environment = $%d::environment_type", idx))
		args = append(args, nullableEnum(input.Environment))
		idx++
	}
	if input.SupportGroup != nil {
		setClauses = append(setClauses, fmt.Sprintf("support_group = $%d", idx))
		args = append(args, input.SupportGroup)
		idx++
	}
	// Custom fields (DCIM row 5.1): the fields named are merged over the
	// stored ones and the result checked against the tenant's definitions —
	// a required field left empty, or a choice outside its set, refuses the
	// whole edit (400).
	if input.CustomFields != nil {
		cf, err := s.assetCustomFields(context.Background(), tenantID, assetID, input.CustomFields, false)
		if err != nil {
			return nil, nil, err
		}
		cfJSON, err := json.Marshal(cf)
		if err != nil {
			return nil, nil, err
		}
		setClauses = append(setClauses, fmt.Sprintf("custom_fields = $%d::jsonb", idx))
		args = append(args, string(cfJSON))
		idx++
	}
	// A person editing the asset may assign, change or CLEAR its Business Unit
	// (business_unit_id "" clears it); an import-style name is resolved or
	// created. Resolved on its own short transaction because the SET clauses
	// are built before the write's transaction opens.
	var buID *uuid.UUID
	buSet := false
	if input.BusinessUnitID != nil || (input.BusinessUnit != nil && strings.TrimSpace(*input.BusinessUnit) != "") {
		if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
			var e error
			buID, buSet, e = s.businessUnits.ResolveID(context.Background(), tx, tenantID, actorUserID, input.BusinessUnitID, input.BusinessUnit, "", "", "declared", nil)
			return e
		}); err != nil {
			return nil, nil, businessUnitInputError(err)
		}
	}
	if buSet {
		setClauses = append(setClauses, fmt.Sprintf("business_unit_id = $%d", idx))
		args = append(args, buID)
		idx++
	}
	if input.OwnerEmail != nil {
		setClauses = append(setClauses, fmt.Sprintf("owner_email = $%d", idx))
		args = append(args, input.OwnerEmail)
		idx++
	}
	if input.Description != nil {
		setClauses = append(setClauses, fmt.Sprintf("description = $%d", idx))
		args = append(args, input.Description)
		idx++
	}
	if input.AssetOwnership != nil {
		setClauses = append(setClauses, fmt.Sprintf("asset_ownership = $%d", idx))
		args = append(args, *input.AssetOwnership)
		idx++
	}
	if input.AssetStatus != nil {
		// REFUSED, not honoured.
		//
		// Approval is a cascade, not a column: approving an asset promotes its
		// pending relationships and materialises the findings that were deferred
		// while it waited. Writing `asset_status` here did the column and none of
		// the cascade, so a PUT could move an asset to `monitoring` with its edges
		// still pending and its deferred findings never materialised — a monitored
		// asset with an empty Relationships tab and no compliance findings, and
		// nothing to retry it. It also walked straight past the deny suppression
		// that is half of what "denied" means.
		//
		// 400 naming the endpoints that DO the cascade, rather than silently
		// ignoring the field: a client that thought it was changing status has to
		// find out.
		return nil, nil, fmt.Errorf("%w: asset_status cannot be changed by an update: approving, denying and archiving each "+
			"do more than set a column. Use POST /infrastructure-assets/approve, "+
			"POST /infrastructure-assets/deny, or POST /infrastructure-assets/bulk-actions/archive", ErrInvalidInput)
	}
	if input.Tags != nil {
		// JSONB column: marshal the map to bytes — the database/sql driver
		// can't convert a raw map[string]interface{} (CreateAsset does the same).
		tagsJSON, err := json.Marshal(input.Tags)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal tags: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("tags = $%d", idx))
		args = append(args, tagsJSON)
		idx++
	}
	// Metadata replacement must preserve internal name provenance. A combined
	// name/metadata edit is ONE assignment; SQL does not permit two SETs.
	if input.Metadata != nil || input.Hostname != nil || input.DisplayName != nil {
		base := "COALESCE(metadata, '{}'::jsonb)"
		if input.Metadata != nil {
			payload := models.JSONB{}
			for k, v := range input.Metadata {
				if k != "name_source_kind" {
					payload[k] = v
				}
			}
			encoded, err := json.Marshal(payload)
			if err != nil {
				return nil, nil, fmt.Errorf("marshal metadata: %w", err)
			}
			base = fmt.Sprintf("$%d::jsonb || CASE WHEN metadata ? 'name_source_kind' THEN jsonb_build_object('name_source_kind', metadata->'name_source_kind') ELSE '{}'::jsonb END", idx)
			args = append(args, encoded)
			idx++
		}
		if input.Hostname != nil || input.DisplayName != nil {
			base += " || jsonb_build_object('name_source_kind', 'declared')"
		}
		setClauses = append(setClauses, "metadata = "+base)
	}

	// Placement (DCIM row 2.1) is decided on the write's own transaction below,
	// against the row as it stands; the no-op clause keeps an edit that only
	// moves the asset from being taken for an empty one.
	placementEdit := input.SiteID != nil || input.LocationID != nil || (input.Site != nil && strings.TrimSpace(*input.Site) != "")
	if placementEdit {
		setClauses = append(setClauses, "site_id = site_id")
	}
	var placedSite, placedLoc *uuid.UUID
	placed := false

	if len(setClauses) == 0 {
		// No COLUMN to update — but the identifier pass above may still have
		// attached or retired rows, so the report is returned either way.
		asset, err := s.GetAssetByID(tenantID, assetID)
		return asset, report, err
	}

	// Always update updated_at
	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", idx))
	args = append(args, time.Now())
	idx++

	// WHERE clause args
	whereTenantIdx := idx
	args = append(args, tenantID)
	idx++
	whereAssetIdx := idx
	args = append(args, assetID)

	query := fmt.Sprintf("UPDATE assets SET %s WHERE tenant_id = $%d AND id = $%d AND deleted_at IS NULL",
		strings.Join(setClauses, ", "), whereTenantIdx, whereAssetIdx)

	// RLS-scoped write over assets.
	ctx := context.Background()
	if err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// The class the asset held BEFORE this edit, read on the write's own
		// transaction and only when the edit touches the class. FOR UPDATE
		// because two concurrent edits would otherwise both read the same
		// previous class and write two history rows claiming the same
		// transition, one of which never happened.
		previousClass := ""
		if input.ClassKey != "" {
			if e := tx.QueryRowContext(ctx, `
				SELECT class_key FROM assets
				 WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL
				 FOR UPDATE`, tenantID, assetID).Scan(&previousClass); e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
		}
		var priorBU *uuid.UUID
		if buSet {
			var cur uuid.NullUUID
			if e := tx.QueryRowContext(ctx, `SELECT business_unit_id FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenantID, assetID).Scan(&cur); e != nil && !errors.Is(e, sql.ErrNoRows) {
				return e
			}
			if cur.Valid {
				priorBU = &cur.UUID
			}
		}
		res, e := tx.Exec(query, args...)
		if e != nil {
			return e
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		if buSet {
			if e := s.businessUnits.RecordAssetAssignment(ctx, tx, tenantID, actorUserID, assetID, priorBU, buID); e != nil {
				return fmt.Errorf("record business unit change: %w", e)
			}
		}
		if placementEdit {
			// A person may assign, change or clear (site_id "") the site and
			// location; the location must be in the site
			// (SiteService.ResolveAssetPlacement). A site NAME is resolved or
			// created like an import's.
			siteRef := input.SiteID
			if siteRef == nil && input.Site != nil && strings.TrimSpace(*input.Site) != "" {
				id, e := s.siteService().ResolveSiteByName(ctx, tx, tenantID, actorUserID, *input.Site, "declared", nil)
				if e != nil {
					return siteInputError(e)
				}
				if id != nil {
					v := id.String()
					siteRef = &v
				}
			}
			var curSite, curLoc uuid.NullUUID
			if e := tx.QueryRowContext(ctx, `SELECT site_id, location_id FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL FOR UPDATE`,
				tenantID, assetID).Scan(&curSite, &curLoc); e != nil {
				return e
			}
			site, loc, changed, e := ResolveAssetPlacement(ctx, tx, nullUUIDPtr(curSite), nullUUIDPtr(curLoc), siteRef, input.LocationID)
			if e != nil {
				return siteInputError(e)
			}
			if changed {
				// A racked asset's site and location are its rack's (row 2.3).
				if e := CheckRackConsistencyTx(ctx, tx, tenantID, assetID, site, loc); e != nil {
					return siteInputError(e)
				}
				if _, e := tx.ExecContext(ctx, `UPDATE assets SET site_id = $3, location_id = $4, updated_at = now() WHERE tenant_id = $1 AND id = $2`,
					tenantID, assetID, site, loc); e != nil {
					return e
				}
				if e := s.siteService().RecordAssetPlacement(ctx, tx, tenantID, actorUserID, assetID, nullUUIDPtr(curSite), nullUUIDPtr(curLoc), site, loc); e != nil {
					return fmt.Errorf("record placement change: %w", e)
				}
				placedSite, placedLoc, placed = site, loc, true
			}
		}
		if input.ClassKey == "" {
			return nil
		}
		// A person edited the class. `actorUserID` may be uuid.Nil — a caller
		// with no session — and the row then says a machine did it, which is
		// wrong in a knowable way rather than naming a user it cannot prove.
		return assetclasshistory.Record(ctx, tx, tenantID, assetID, assetclasshistory.Entry{
			From:     previousClass,
			To:       input.ClassKey,
			Source:   assetclasshistory.SourceManual,
			Actor:    actorUserID,
			Evidence: map[string]any{"class_source_kind": "declared"},
		})
	}); err != nil {
		return nil, nil, fmt.Errorf("failed to update asset: %w", err)
	}

	// Every attribute change is attributable (ADR-0002 D4). This is a person
	// editing an asset, so the source is declared and the actor is the session
	// the handler authenticated — which the handler does not pass down yet, so
	// the entry names the path rather than claiming a user it cannot prove.
	changes := map[string]any{}
	for k, v := range map[string]any{
		"hostname":        input.Hostname,
		"display_name":    input.DisplayName,
		"primary_address": input.IPAddress,
		"class_key":       input.ClassKey,
		"environment":     input.Environment,
		"owner_email":     input.OwnerEmail,
		"support_group":   input.SupportGroup,
		"description":     input.Description,
		"asset_ownership": input.AssetOwnership,
	} {
		if v == nil {
			continue
		}
		if sv, ok := v.(string); ok && sv == "" {
			continue
		}
		changes[k] = v
	}
	if buSet {
		if buID != nil {
			changes["business_unit_id"] = buID.String()
		} else {
			changes["business_unit_id"] = nil
		}
	}
	if placed {
		changes["site_id"], changes["location_id"] = uuidStr(placedSite), uuidStr(placedLoc)
	}
	if len(input.Attributes) > 0 {
		changes["attributes"] = input.Attributes
	}
	if len(input.Tags) > 0 {
		changes["tags"] = input.Tags
	}
	// The identifier change is part of the same edit and belongs in the same
	// history entry: "hostname: web-02" with no record of which identifiers
	// moved is exactly the gap that let a rename orphan an identity silently.
	if report != nil {
		if len(report.Attached) > 0 {
			changes["identifiers_attached"] = report.Attached
		}
		if len(report.Removed) > 0 {
			changes["identifiers_removed"] = report.Removed
		}
		if len(report.Kept) > 0 {
			changes["identifiers_kept"] = report.Kept
		}
	}
	if len(changes) > 0 {
		// nil tx: UpdateAsset is not resolving an observation, so it owns its
		// own transaction.
		s.recordAssetHistory(nil, tenantID, assetID, identity.ActionUpdated,
			identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}, changes)
	}

	// Publish asset updated event (only if relevant fields changed)
	relevantFieldsChanged := input.Hostname != nil || input.IPAddress != nil ||
		input.ClassKey != "" || input.Environment != nil

	if s.eventPublisher != nil && relevantFieldsChanged {
		if err := s.eventPublisher.PublishAssetChanged(ctx, tenantID, assetID, sharedevents.ChangeTypeUpdated, "manual"); err != nil {
			log.Printf("[AssetService] Warning: Failed to publish asset updated event: %v", err)
		}
	}

	asset, err := s.GetAssetByID(tenantID, assetID)
	return asset, report, err
}

// UpdateAssetService sets manual service identification on ONE endpoint of an
// asset (high confidence).
//
// # Why this takes an endpoint id
//
// The identified service lives on the endpoint. A host running SSH on 22 and
// HTTPS on 443 has two endpoints, and "the service of the host" is not a thing
// — so this used to write EVERY endpoint of the asset, which turned one
// correction ("that 443 is nginx, not Apache") into a claim about port 22 as
// well. It now writes exactly the endpoint named.
//
// `input.EndpointID` is optional on the legacy asset-scoped route and defaults
// to the asset's PRIMARY endpoint — the one a list row and the drawer display —
// so a correction typed against what the user is looking at lands there. An
// endpoint id that belongs to another asset, or to no asset, updates nothing
// and is reported as not-found rather than silently ignored.
//
// # An asset with no endpoints is a 404, by design
//
// There is nothing to correct: an at-rest cloud resource, a declared service
// with no socket, an asset whose endpoints were all retired. Creating an
// endpoint to hang the answer on would fabricate a listening port nobody
// observed — the thing the endpoint split exists to stop.
func (s *AssetService) UpdateAssetService(tenantID, assetID uuid.UUID, input models.UpdateAssetServiceInput) (*models.Asset, error) {
	var n int64
	// RLS-scoped write over asset_endpoints.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		var result sql.Result
		var e error
		if input.EndpointID != nil {
			result, e = tx.Exec(`
				UPDATE asset_endpoints SET
					service_name = $1, service_version = NULLIF($2, ''),
					service_confidence = 'high', service_identification_method = 'manual',
					updated_at = NOW()
				WHERE tenant_id = $3 AND asset_id = $4 AND id = $5`,
				input.ServiceName, input.ServiceVersion, tenantID, assetID, *input.EndpointID)
		} else {
			// The primary endpoint, chosen by the ONE rule the display uses
			// (endpointOrder) so the row being corrected is the row that was
			// shown. A sub-select rather than a second round trip keeps the
			// choice and the write in one statement, so a concurrent endpoint
			// insert cannot land between them.
			result, e = tx.Exec(`
				UPDATE asset_endpoints SET
					service_name = $1, service_version = NULLIF($2, ''),
					service_confidence = 'high', service_identification_method = 'manual',
					updated_at = NOW()
				WHERE tenant_id = $3 AND asset_id = $4
				  AND id = (
					SELECT id FROM asset_endpoints
					 WHERE tenant_id = $3 AND asset_id = $4
					 ORDER BY `+endpointOrder+`
					 LIMIT 1)`,
				input.ServiceName, input.ServiceVersion, tenantID, assetID)
		}
		if e != nil {
			return e
		}
		n, _ = result.RowsAffected()
		return nil
	})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	return s.GetAssetByID(tenantID, assetID)
}

// DeleteAsset performs a soft delete on an asset by setting deleted_at.
func (s *AssetService) DeleteAsset(tenantID, assetID uuid.UUID) error {
	query := `UPDATE assets SET deleted_at = NOW() WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`
	// RLS-scoped write over assets.
	if err := withAssetLifecycleWriteTx(context.Background(), s.db, tenantID, []uuid.UUID{assetID}, func(tx *sqlx.Tx) error {
		res, e := tx.Exec(query, tenantID, assetID)
		if e != nil {
			return e
		}
		if n, _ := res.RowsAffected(); n == 0 {
			return ErrNotFound
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to delete asset: %w", err)
	}
	// Publish only after the delete transaction commits.
	if s.eventPublisher != nil {
		ctx := context.Background()
		if err := s.eventPublisher.PublishAssetDeleted(ctx, tenantID, assetID, "manual"); err != nil {
			log.Printf("[AssetService] Warning: Failed to publish asset deleted event: %v", err)
		}
	}
	return nil
}

// RestoreAsset clears deleted_at to restore a previously soft-deleted asset.
func (s *AssetService) RestoreAsset(tenantID, assetID uuid.UUID) error {
	query := `UPDATE assets SET deleted_at = NULL WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NOT NULL`
	// RLS-scoped write over assets.
	if err := withAssetLifecycleWriteTx(context.Background(), s.db, tenantID, []uuid.UUID{assetID}, func(tx *sqlx.Tx) error {
		if err := checkAssetRestoreMutable(context.Background(), tx, tenantID, assetID); err != nil {
			return err
		}
		res, e := tx.Exec(query, tenantID, assetID)
		if e != nil {
			return e
		}
		if n, _ := res.RowsAffected(); n > 0 {
			return nil
		}
		// Nothing was un-deleted. An asset that exists and is simply not
		// deleted (an archived one is hidden by status, not by deleted_at) is
		// already in the state restore asks for: success, with nothing to
		// report. An id that matches no row at all is a 404.
		var exists bool
		if e := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM assets WHERE tenant_id = $1 AND id = $2)`, tenantID, assetID).Scan(&exists); e != nil {
			return e
		}
		if !exists {
			return ErrNotFound
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to restore asset: %w", err)
	}
	return nil
}

// HardDeleteAsset permanently deletes an asset from the database (admin-only).
// This is a destructive operation that cannot be undone.
func (s *AssetService) HardDeleteAsset(tenantID, assetID uuid.UUID) error {
	// RLS-scoped reads/writes over assets / crypto_implementations — the
	// verify + cascade-delete + delete run in one tenant tx.
	return withAssetLifecycleWriteTx(context.Background(), s.db, tenantID, []uuid.UUID{assetID}, func(tx *sqlx.Tx) error {
		// First verify the asset exists and belongs to the tenant
		var exists bool
		checkQuery := `SELECT EXISTS(SELECT 1 FROM assets WHERE tenant_id = $1 AND id = $2)`
		if err := tx.QueryRow(checkQuery, tenantID, assetID).Scan(&exists); err != nil {
			return fmt.Errorf("failed to verify asset: %w", err)
		}

		if !exists {
			return fmt.Errorf("asset not found")
		}

		// Delete associated crypto configurations first (CASCADE should handle this, but being explicit)
		deleteCryptoQuery := `DELETE FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2`
		if _, err := tx.Exec(deleteCryptoQuery, tenantID, assetID); err != nil {
			return fmt.Errorf("failed to delete crypto implementations: %w", err)
		}

		// Permanently delete the asset
		query := `DELETE FROM assets WHERE tenant_id = $1 AND id = $2`
		if _, err := tx.Exec(query, tenantID, assetID); err != nil {
			return fmt.Errorf("failed to hard delete asset: %w", err)
		}

		return nil
	})
}

// TenantActivitySummary represents activity metrics for a tenant
type TenantActivitySummary struct {
	TenantID       uuid.UUID      `json:"tenant_id"`
	ActiveUsers    int            `json:"active_users"`    // Users who have interacted (estimate from asset updates)
	APICalls       int            `json:"api_calls"`       // API calls over the last 30 days, read from the tenant_resource_usage metering table
	FeatureUsage   map[string]int `json:"feature_usage"`   // Feature usage counts
	UserEngagement float64        `json:"user_engagement"` // Engagement score (0-100)
	LastUpdated    time.Time      `json:"last_updated"`
	// UnavailableSources names peer services this summary could not reach.
	// Its consumer (tenant-health-service) relays these so an unreachable peer
	// reads as UNKNOWN rather than as a measured value.
	UnavailableSources []string `json:"unavailable_sources,omitempty"`
}

// GetTenantActivitySummary returns activity metrics for a specific tenant
func (s *AssetService) GetTenantActivitySummary(tenantID uuid.UUID) (*TenantActivitySummary, error) {
	summary := &TenantActivitySummary{
		TenantID:       tenantID,
		LastUpdated:    time.Now(),
		FeatureUsage:   make(map[string]int),
		UserEngagement: 50.0, // Default engagement
	}

	// Query activity metrics
	query := `
		SELECT
			COUNT(DISTINCT a.id) as asset_count,
			COUNT(DISTINCT ci.id) as crypto_count,
			COUNT(DISTINCT k.id) as key_count,
			COUNT(DISTINCT cl.id) as library_count,
			COUNT(DISTINCT i.id) as integration_count,
			COUNT(DISTINCT CASE WHEN a.updated_at > NOW() - INTERVAL '7 days' THEN a.id END) as recent_asset_updates,
			COUNT(DISTINCT CASE WHEN a.created_at > NOW() - INTERVAL '7 days' THEN a.id END) as new_assets
		FROM assets a
		LEFT JOIN crypto_implementations ci ON a.id = ci.asset_id AND ci.deleted_at IS NULL
		LEFT JOIN keys k ON k.tenant_id = a.tenant_id
		LEFT JOIN crypto_libraries cl ON cl.tenant_id = a.tenant_id
		LEFT JOIN integrations i ON i.tenant_id = a.tenant_id AND i.is_enabled = true
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
	`

	var assetCount, cryptoCount, keyCount, libraryCount, integrationCount, recentUpdates, newAssets int
	var apiCalls int64

	// RLS-scoped read over assets / crypto_implementations / keys /
	// crypto_libraries / integrations (single-tenant aggregate, WHERE a.tenant_id = $1),
	// plus the tenant's metered API calls over the last 30 days from
	// tenant_resource_usage (written by auth-service's resource-metrics
	// ingest; also RLS-policied, same tenant context).
	//
	// There is deliberately NO estimation fallback for api_calls. The previous
	// one derived a number from inventory size — a formula that has nothing to
	// do with API traffic — and it was indistinguishable from a measurement
	// downstream. A read failure fails the summary, which tenant-health reports
	// as inventory-service unavailable (UNKNOWN), never as a plausible count.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if err := tx.QueryRow(query, tenantID).Scan(
			&assetCount,
			&cryptoCount,
			&keyCount,
			&libraryCount,
			&integrationCount,
			&recentUpdates,
			&newAssets,
		); err != nil {
			return err
		}
		return tx.QueryRow(`
			SELECT COALESCE(SUM(api_calls), 0)
			FROM tenant_resource_usage
			WHERE tenant_id = $1 AND "timestamp" >= NOW() - INTERVAL '30 days'
		`, tenantID).Scan(&apiCalls)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to query tenant activity metrics: %w", err)
	}

	// Build feature usage map
	summary.FeatureUsage["assets"] = assetCount
	summary.FeatureUsage["crypto_implementations"] = cryptoCount
	summary.FeatureUsage["keys"] = keyCount
	summary.FeatureUsage["libraries"] = libraryCount
	summary.FeatureUsage["integrations"] = integrationCount

	// Estimate active users based on recent activity
	// In production, would track actual user interactions
	// For now, estimate based on asset updates
	if recentUpdates > 0 {
		// Assume each update represents an active user interaction
		summary.ActiveUsers = recentUpdates
		if summary.ActiveUsers > 100 {
			summary.ActiveUsers = 100 // Cap at reasonable number
		}
	} else {
		summary.ActiveUsers = 0
	}

	summary.APICalls = int(apiCalls)

	// Calculate user engagement score (0-100)
	// Based on recent activity: new assets, updates, feature diversity
	engagementScore := 0.0
	if assetCount > 0 {
		engagementScore += 30.0 // Base score for having assets
	}
	if cryptoCount > 0 {
		engagementScore += 20.0 // Bonus for crypto configurations
	}
	if integrationCount > 0 {
		engagementScore += 15.0 // Bonus for integrations
	}
	if libraryCount > 0 || keyCount > 0 {
		engagementScore += 10.0 // Bonus for keys/libraries
	}

	// Activity recency bonus
	if recentUpdates > 0 {
		activityBonus := float64(recentUpdates) * 2.0 // 2 points per recent update
		if activityBonus > 15.0 {
			activityBonus = 15.0
		}
		engagementScore += activityBonus
	}
	if newAssets > 0 {
		newAssetBonus := float64(newAssets) * 3.0 // 3 points per new asset
		if newAssetBonus > 10.0 {
			newAssetBonus = 10.0
		}
		engagementScore += newAssetBonus
	}

	if engagementScore > 100.0 {
		engagementScore = 100.0
	}
	summary.UserEngagement = engagementScore

	return summary, nil
}
