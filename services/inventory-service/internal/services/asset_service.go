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
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
)

type AssetService struct {
	db                       *database.DB
	networkSegmentService    *NetworkSegmentService        // optional: classification, tags, segment enrichment in IngestFindings
	serviceIdentificationSvc *ServiceIdentificationService // optional: used for service hints in IngestFindings
	certificateService       *CertificateService
	algorithmService         *AlgorithmService
	eventPublisher           *EventPublisherService
	weakCryptoDetector       *WeakCryptoDetector
	externalConnectionsSvc   *ExternalConnectionsService // optional: routes third-party findings to external_connections
	integrationCipher        *credentials.Cipher         // protects integrations.auth_config — see newIntegrationCipher
}

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

// SetEnrichmentServices injects optional network segment and service identification services for IngestFindings enrichment, classification, and tags.
func (s *AssetService) SetEnrichmentServices(segmentSvc *NetworkSegmentService, idSvc *ServiceIdentificationService) {
	s.networkSegmentService = segmentSvc
	s.serviceIdentificationSvc = idSvc
}

// SetExternalConnectionsService injects the external connections service so
// IngestFindings can route third-party discoveries to the external_connections table.
func (s *AssetService) SetExternalConnectionsService(svc *ExternalConnectionsService) {
	s.externalConnectionsSvc = svc
}

// classifyAsset returns ownership (internal, third_party, unknown) via NetworkSegmentService when set; otherwise "unknown".
func (s *AssetService) classifyAsset(tenantID uuid.UUID, ipAddress *string, hostname *string) (string, error) {
	if s.networkSegmentService != nil {
		return s.networkSegmentService.ClassifyAsset(tenantID, ipAddress, hostname, []string{})
	}
	return "unknown", nil
}

// getTagsForAsset returns tags from the matching network segment when NetworkSegmentService is set; otherwise nil map.
func (s *AssetService) getTagsForAsset(tenantID uuid.UUID, ipAddress *string, hostname *string) (map[string]interface{}, error) {
	if s.networkSegmentService != nil {
		return s.networkSegmentService.GetTagsForAsset(tenantID, ipAddress, hostname, []string{})
	}
	return make(map[string]interface{}), nil
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
	key := buildSuppressionKey(hostname, ipAddress, port)
	var exists bool
	// RLS-scoped read over asset_suppressions (tenant_isolation policy).
	query := `SELECT TRUE FROM asset_suppressions WHERE tenant_id = $1 AND suppression_key = $2 LIMIT 1`
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID, key).Scan(&exists)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return exists, nil
}

func (s *AssetService) addSuppression(tenantID uuid.UUID, hostname *string, ipAddress *string, port *int, userID *uuid.UUID, reason string) error {
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
	// RLS-scoped write over asset_suppressions (tenant_isolation policy).
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, tenantID, h, ip, p, reason, createdBy, key)
		return e
	})
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
		case "sensor_discovery", "sensor_discoveries":
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

// applyCertQualityFlags extracts certificate quality flags (SCT, known-bad CA,
// OCSP, EV) from discovery RawData and applies them to the CertificateData.
// These flags are computed by the sensor's active prober/enricher and stored
// at the top level of the discovery metadata alongside the certificates array.
func (s *AssetService) applyCertQualityFlags(certData *models.CertificateData, rawData map[string]interface{}) {
	if rawData == nil {
		return
	}
	if v, ok := rawData["cert_has_sct"].(bool); ok {
		certData.HasSCT = &v
	}
	if v, ok := rawData["cert_known_bad_ca"].(string); ok && v != "" {
		certData.KnownBadCA = v
	}
	if v, ok := rawData["cert_is_ev"].(bool); ok {
		certData.IsEV = v
	}
	if v, ok := rawData["ocsp_status"].(string); ok && v != "" {
		certData.OCSPStatus = v
	}
	if v, ok := rawData["ocsp_detail"].(string); ok && v != "" {
		certData.OCSPDetail = v
	}
}

// atRestProtocolSentinel is the marker device-interrogation-service stamps on a
// finding whose cryptography is at rest rather than negotiated on the wire
// (atRestProtocolPort in cloud_discovery_service.go). It is deliberately NOT a
// protocol_type enum value: nothing may persist it as a protocol.
const atRestProtocolSentinel = "AT-REST"

// isAtRestProtocol reports whether a finding is an at-rest resource rather than
// a network endpoint. Such a finding must never be materialized as a crypto
// configuration — see the call site in processDiscoveryCryptoData (B-22).
// resolveProtocol now backstops this generically (AT-REST is unrecognised, and
// unrecognised no longer means TLS), but this stays because it says WHY at-rest
// findings leave early: their posture belongs in crypto_applications.
func isAtRestProtocol(protocol string) bool {
	return strings.EqualFold(strings.TrimSpace(protocol), atRestProtocolSentinel)
}

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
	case "SSH":
		return "SSH", protocolEnum
	// IKE and IKEv2 are the key-exchange half of an IPSec association, which is
	// what the Cisco collector reports them as (parseIKEv2SA stamps "IKEv2").
	// IKEV2 had no arm, so every Cisco IKEv2 SA — a real, correctly identified
	// VPN association — was filed as TLS.
	case "IPSEC", "IP-SEC", "IKE", "IKEV2", "IKE-V2", "IKE_V2":
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
	if f.RawData != nil {
		if src, _ := f.RawData["source"].(string); src == "cloud_discovery" {
			return true
		}
		if dm, _ := f.RawData["discovery_method"].(string); dm == "cloud_api" {
			return true
		}
	}
	return false
}

// IngestFindings upserts assets and attaches crypto configurations for each finding
// assetStatus is optional and defaults to "pending_approval" if not provided
func (s *AssetService) IngestFindings(tenantID uuid.UUID, findings []IngestFinding, assetStatus ...string) (int, error) {
	if len(findings) == 0 {
		return 0, nil
	}

	// Determine asset_status: use provided value or default to "pending_approval"
	status := "pending_approval"
	if len(assetStatus) > 0 && assetStatus[0] != "" {
		status = assetStatus[0]
	}

	inserted := 0
	// Observability counters for the end-of-run import summary ().
	// Without these, a third-party route that persists nothing looks identical to a
	// successful import — which is exactly how a vendor discovery silently vanished.
	var createdManaged, updatedManaged, routedExternal, failedRoute int
	var changedAssetIDs []uuid.UUID
	var lifecycleDiscovered []struct {
		assetID             uuid.UUID
		hostname, ipAddress *string
		port                *int
	}
	var lifecycleEnriched []*events.AssetEnrichedPayload
	var lifecycleRiskChanged []*events.AssetRiskChangedPayload
	var lifecycleCryptoAdded []*events.CryptoConfigurationAddedPayload
	var lifecycleCertExpiring []*events.CertificateExpiringPayload
	ctx := context.Background()
	source := "discovery"
	if len(findings) > 0 && findings[0].RawData != nil {
		if v, ok := findings[0].RawData["source"].(string); ok {
			source = v
		}
	}

	for _, f := range findings {
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

		// Try to find an existing asset by (hostname or ip) and port.
		// When both hostname and ip are nil, skip lookup to avoid NULL IS NOT DISTINCT FROM NULL
		// matching every row and collapsing unrelated assets.
		var assetID uuid.UUID
		var assetStatus string
		var err error

		var hostname sql.NullString
		if f.Hostname != nil && *f.Hostname != "" {
			hostname = sql.NullString{String: *f.Hostname, Valid: true}
		}

		var ip sql.NullString
		if effectiveIP != nil && *effectiveIP != "" {
			ip = sql.NullString{String: *effectiveIP, Valid: true}
		}

		var port sql.NullInt64
		if f.Port != nil {
			port = sql.NullInt64{Int64: int64(*f.Port), Valid: true}
		}

		if !hostname.Valid && !ip.Valid {
			err = sql.ErrNoRows
		} else {
			// Plain `=`, not `IS NOT DISTINCT FROM`.
			//
			// Every parameter interpolated below is known non-NULL at this
			// point — hostname/ip are only bound when .Valid, and the
			// both-NULL case returned above — so the two forms are
			// semantically identical here. They are not identical to the
			// planner: `IS NOT DISTINCT FROM` is not an indexable operator, so
			// this lookup degraded to a sequential scan of the tenant's entire
			// asset set, once per finding, on the hottest path in ingest.
			//
			// Parenthesisation is explicit: the hostname/ip alternation is
			// wrapped as a unit so the port predicate ANDs against the whole
			// disjunction rather than binding to the right-hand side of the OR
			// (SQL's AND binds tighter than OR).
			var matchClause string
			args := []interface{}{tenantID}
			argIdx := 2
			if hostname.Valid && ip.Valid {
				matchClause = `((hostname = $` + strconv.Itoa(argIdx) + `) OR (ip_address = $` + strconv.Itoa(argIdx+1) + `))`
				args = append(args, hostname, ip)
				argIdx += 2
			} else if hostname.Valid {
				matchClause = `(hostname = $` + strconv.Itoa(argIdx) + `)`
				args = append(args, hostname)
				argIdx++
			} else {
				matchClause = `(ip_address = $` + strconv.Itoa(argIdx) + `)`
				args = append(args, ip)
				argIdx++
			}

			// port, unlike the above, CAN be absent (a finding with no port).
			// Keep the NULL-matching semantics — a NULL-port finding matches a
			// NULL-port asset — but express it as an indexable `IS NULL`
			// instead of an unindexable `IS NOT DISTINCT FROM NULL`.
			portClause := `(port IS NULL)`
			if port.Valid {
				portClause = `(port = $` + strconv.Itoa(argIdx) + `)`
				args = append(args, port)
			}

			queryFind := `
			SELECT id, asset_status FROM network_assets
			WHERE tenant_id = $1
			  AND deleted_at IS NULL
			  AND ` + matchClause + `
			  AND ` + portClause + `
			LIMIT 1`
			// RLS-scoped read over network_assets.
			err = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
				return tx.QueryRow(queryFind, args...).Scan(&assetID, &assetStatus)
			})
		}
		if err != nil {
			if err != sql.ErrNoRows {
				return inserted, fmt.Errorf("failed to find existing asset: %w", err)
			}

			// If suppressed/denied, skip creation. A suppression-lookup failure
			// is not a reason to abort the whole ingest batch, but it must not
			// be discarded silently either (B-42) — log it and fall through to
			// creating the asset, which is the safe direction: a re-created
			// asset lands in Approvals for a human, whereas wrongly suppressing
			// one hides a real discovery.
			suppressed, suppErr := s.isSuppressed(tenantID, f.Hostname, effectiveIP, f.Port)
			if suppErr != nil {
				log.Printf("[AssetService] Warning: suppression lookup failed for tenant %s: %v", tenantID, suppErr)
			}
			if suppressed {
				continue
			}

			ownership, _ := s.classifyAsset(tenantID, effectiveIP, f.Hostname)
			// A cloud-managed placeholder has no routable IP, so ClassifyAsset
			// falls through to "third_party" (0.0.0.0 is not RFC-1918). Override:
			// these are managed cloud resources, not external endpoints, and must
			// stay on the managed-asset path rather than collapsing into a single
			// shared external_connections row.
			if cloudManaged && ownership == "third_party" {
				ownership = "unknown"
			}
			log.Printf("[AssetService] IngestFindings: %s classified ownership=%q (new)", findingLabel(f), ownership)

			// Route third-party discoveries to external_connections table instead of
			// creating managed assets. This mirrors the BatchProcessor routing logic
			// from discovery-processor-service, ensuring manual discoveries of
			// external targets (e.g. www.yahoo.com) end up in the 3rd-party lens.
			if ownership == "third_party" && s.externalConnectionsSvc != nil {
				if err := s.routeToExternalConnection(tenantID, f); err != nil {
					// Do NOT swallow: a failed route means the finding is dropped.
					// Surface it loudly so a vendor discovery can't vanish silently.
					failedRoute++
					log.Printf("[AssetService] IngestFindings: ERROR routing third-party %s to external_connections: %v", findingLabel(f), err)
				} else {
					routedExternal++
					inserted++
					log.Printf("[AssetService] IngestFindings: routed third-party %s to external_connections", findingLabel(f))
				}
				continue
			}

			networkTags, _ := s.getTagsForAsset(tenantID, effectiveIP, f.Hostname)
			// Merge with any tags from discovery finding (if any)
			mergedTags := mergeTags(models.JSONB{}, networkTags)

			input := models.AssetInput{
				Hostname:  f.Hostname,
				IPAddress: effectiveIP,
				Port:      f.Port,
				AssetType: func() string {
					if f.AssetType != "" {
						return f.AssetType
					}
					return "server"
				}(),
				OperatingSystem: f.OperatingSystem,
				Tags:            mergedTags,
				Metadata:        discoverySourceMetadata(f),
				AssetOwnership:  &ownership,
			}
			// createAssetWithStatus, not CreateAsset: `status` is the decision
			// discovery-processor already reached by evaluating this tenant's
			// segment auto-approval rules against the classified discovery.
			// Re-deriving it here would evaluate the rules twice and could
			// disagree with what the pipeline recorded on the discovery row.
			asset, createErr := s.createAssetWithStatus(tenantID, input, status, findingDiscoveryMethod(f))
			if createErr != nil {
				return inserted, fmt.Errorf("failed to upsert asset: %w", createErr)
			}
			assetID = asset.ID
			assetStatus = status
			changedAssetIDs = append(changedAssetIDs, assetID)
			inserted++
			createdManaged++
			log.Printf("[AssetService] IngestFindings: created managed asset %s for %s (status=%s)", assetID, findingLabel(f), status)
			if s.eventPublisher != nil {
				lifecycleDiscovered = append(lifecycleDiscovered, struct {
					assetID   uuid.UUID
					hostname  *string
					ipAddress *string
					port      *int
				}{assetID, f.Hostname, effectiveIP, f.Port})
			}
		} else {
			// If denied/suppressed, ignore
			if assetStatus == "denied" {
				continue
			}

			ownership, _ := s.classifyAsset(tenantID, effectiveIP, f.Hostname)
			// Keep cloud-managed placeholders on the managed-asset path (see the
			// new-asset branch above for why ClassifyAsset returns third_party here).
			if cloudManaged && ownership == "third_party" {
				ownership = "unknown"
			}
			log.Printf("[AssetService] IngestFindings: %s classified ownership=%q (existing asset %s)", findingLabel(f), ownership, assetID)

			// If an existing asset is now classified as third-party, route to
			// external_connections instead of updating the managed asset —
			// UNLESS it's an elevated (monitoring) asset. An elevated vendor
			// asset is refreshed in place so re-discovery keeps the promoted asset
			// current rather than dumping the observation back to the noise table.
			if ownership == "third_party" && assetStatus != "monitoring" && s.externalConnectionsSvc != nil {
				if err := s.routeToExternalConnection(tenantID, f); err != nil {
					failedRoute++
					log.Printf("[AssetService] IngestFindings: ERROR routing third-party %s (existing) to external_connections: %v", findingLabel(f), err)
				} else {
					routedExternal++
					inserted++
					log.Printf("[AssetService] IngestFindings: routed third-party %s (existing) to external_connections", findingLabel(f))
				}
				continue
			}
			if ownership == "third_party" && assetStatus == "monitoring" {
				log.Printf("[AssetService] IngestFindings: refreshing elevated third-party asset %s (%s) in place", assetID, findingLabel(f))
			}
			updatedManaged++

			networkTags, _ := s.getTagsForAsset(tenantID, effectiveIP, f.Hostname)
			sourceMeta := discoverySourceMetadata(f)

			// RLS-scoped writes/reads over network_assets — the existing-asset
			// refresh (ownership, tags, metadata backfill, status) runs inside one
			// tenant tx (sets app.tenant_id).
			_ = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
				updateOwnership := `UPDATE network_assets SET asset_ownership = $1, updated_at = NOW() WHERE id = $2`
				_, _ = tx.Exec(updateOwnership, ownership, assetID)

				if len(networkTags) > 0 {
					// Get current tags
					var currentTagsJSON []byte
					_ = tx.QueryRow(`SELECT tags FROM network_assets WHERE id = $1`, assetID).Scan(&currentTagsJSON)
					var currentTags models.JSONB
					if len(currentTagsJSON) > 0 {
						_ = json.Unmarshal(currentTagsJSON, &currentTags)
					}
					// Merge and update
					mergedTags := mergeTags(currentTags, networkTags)
					tagsJSON, _ := json.Marshal(mergedTags)
					_, _ = tx.Exec(`UPDATE network_assets SET tags = $1, updated_at = NOW() WHERE id = $2`, tagsJSON, assetID)
				}

				// Backfill discovery source attribution into metadata if the existing row
				// lacks it. Repeat sensor hits on the same asset stamp the missing keys
				// (discovery_source / sensor_id / batch_id) without overwriting any fields
				// that are already set, so previously-attributed assets aren't touched.
				if len(sourceMeta) > 0 {
					var currentMetaJSON []byte
					_ = tx.QueryRow(`SELECT metadata FROM network_assets WHERE id = $1`, assetID).Scan(&currentMetaJSON)
					var currentMeta models.JSONB
					if len(currentMetaJSON) > 0 {
						_ = json.Unmarshal(currentMetaJSON, &currentMeta)
					}
					if currentMeta == nil {
						currentMeta = models.JSONB{}
					}
					patched := false
					for k, v := range sourceMeta {
						if _, exists := currentMeta[k]; !exists {
							currentMeta[k] = v
							patched = true
						}
					}
					if patched {
						if metaJSON, err := json.Marshal(currentMeta); err == nil {
							_, _ = tx.Exec(`UPDATE network_assets SET metadata = $1, updated_at = NOW() WHERE id = $2`, metaJSON, assetID)
						}
					}
				}

				// When importing discovery results, update asset status based on provided status.
				// If existing asset status differs from provided status, update it.
				if assetStatus != status {
					if _, e := tx.Exec(`UPDATE network_assets SET asset_status = $1, last_seen_at = NOW(), stale_status = NULL, updated_at = NOW() WHERE id = $2`, status, assetID); e != nil {
						log.Printf("Warning: failed to update asset status to %s for asset %s: %v", status, assetID, e)
					} else {
						assetStatus = status
						inserted++ // Count as inserted/updated for import purposes
					}
				} else if assetStatus == "pending_approval" || status == "pending_approval" {
					// Update last_seen for pending assets and clear stale_status if set
					if _, e := tx.Exec(`UPDATE network_assets SET last_seen_at = NOW(), stale_status = NULL, updated_at = NOW() WHERE id = $1`, assetID); e != nil {
						log.Printf("Warning: failed to update last_seen for asset %s: %v", assetID, e)
					} else {
						inserted++ // Count as inserted/updated for import purposes
					}
				}
				return nil
			})
			changedAssetIDs = append(changedAssetIDs, assetID)
		}

		// Enrich asset with network segment (environment, location) and service identification when services are wired
		if s.networkSegmentService != nil {
			var cloudProvider, cloudRegion string
			if f.RawData != nil {
				cloudProvider, _ = f.RawData["cloud_provider"].(string)
				cloudRegion, _ = f.RawData["cloud_region"].(string)
			}
			if cloudProvider != "" && cloudRegion != "" {
				vpcID, _ := f.RawData["vpc_id"].(string)
				env, _ := f.RawData["environment"].(string)
				if env == "" {
					env = "production"
				}
				seg, err := s.networkSegmentService.FindOrCreateCloudSegment(tenantID, cloudProvider, cloudRegion, vpcID, env)
				if err == nil && seg != nil {
					// RLS-scoped write over network_assets.
					_ = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
						_, _ = tx.Exec(`UPDATE network_assets SET environment = $1, location_id = COALESCE($2, location_id), network_segment_id = $3, updated_at = NOW() WHERE id = $4 AND tenant_id = $5`,
							seg.Environment, seg.LocationID, seg.ID, assetID, tenantID)
						return nil
					})
				}
			} else {
				_ = s.networkSegmentService.EnrichAssetByID(tenantID, assetID, effectiveIP, f.Hostname)
			}
		}
		var didSegment, didService bool
		if s.serviceIdentificationSvc != nil {
			port := 0
			if f.Port != nil {
				port = *f.Port
			}
			hints := s.serviceIdentificationSvc.IdentifyService(tenantID, port, f.Protocol, f.RawData)
			if hints != nil {
				didService = true
				ver := hints.ServiceVersion
				// RLS-scoped write over network_assets.
				_ = database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
					_, _ = tx.Exec(`
						UPDATE network_assets SET service_name = $1, service_version = NULLIF($2, ''),
							service_confidence = $3, service_identification_method = $4, updated_at = NOW()
						WHERE id = $5 AND tenant_id = $6`,
						hints.ServiceName, ver, hints.Confidence, hints.IdentificationMethod, assetID, tenantID)
					return nil
				})
			}
		}
		if s.networkSegmentService != nil {
			didSegment = true
		}
		if s.eventPublisher != nil && (didSegment || didService) {
			es := "segment"
			if didSegment && didService {
				es = "segment,service_id"
			} else if didService {
				es = "service_id"
			}
			lifecycleEnriched = append(lifecycleEnriched, &events.AssetEnrichedPayload{
				AssetID:          assetID,
				EnrichmentSource: es,
			})
		}

		// When asset is pending approval, defer certificate and crypto configuration
		// creation. Store the raw finding data in the asset's metadata so it can be
		// processed when the asset is approved. This prevents unapproved discoveries
		// from leaking data into the certificates and crypto_implementations tables.
		if assetStatus == "pending_approval" {
			s.storeDeferredFinding(tenantID, assetID, f)
			continue
		}

		// Extract and process certificate chain from discovery finding.
		// Deliberately not propagated: this is a per-finding loop over a whole
		// ingest batch, and one finding whose certificates or crypto rows fail to
		// materialize must not abort the remaining findings. Logged rather than
		// dropped so a silently half-materialized batch is still visible.
		if err := s.processDiscoveryCryptoData(tenantID, assetID, f, &lifecycleRiskChanged, &lifecycleCryptoAdded, &lifecycleCertExpiring); err != nil {
			log.Printf("[AssetService] IngestFindings: materializing crypto data for asset %s failed (batch continues): %v", assetID, err)
		}
	}

	// Refresh operational materialized views (location summary, remediation queue)
	// Non-blocking: if migration 011 not applied or refresh fails, log and continue
	go func() {
		if err := s.RefreshOperationalViews(); err != nil {
			log.Printf("[AssetService] RefreshOperationalViews (non-fatal): %v", err)
		}
	}()

	// Publish events for changed assets (batch if many, individual if few)
	// Publish asynchronously to avoid blocking the import response
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
				_ = s.eventPublisher.PublishAssetDiscovered(ctx, tenantID, e.assetID, e.hostname, e.ipAddress, e.port, source)
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
	log.Printf("[AssetService] IngestFindings summary%s: %d findings → managed created=%d, managed updated=%d, routed to external_connections=%d, route failures=%d (status=%s)",
		failureNote, len(findings), createdManaged, updatedManaged, routedExternal, failedRoute, status)

	return inserted, nil
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

// routeToExternalConnection converts an IngestFinding to an ExternalConnectionUpsert
// and writes it to the external_connections table. Used for third-party discoveries.
func (s *AssetService) routeToExternalConnection(tenantID uuid.UUID, f IngestFinding) error {
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
		ips, err := net.DefaultResolver.LookupHost(ctx, *f.Hostname)
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

	// For manual discoveries, there is no source IP (it originates from the platform).
	// Use "0.0.0.0" as a sentinel indicating a platform-initiated discovery.
	sourceIP := "0.0.0.0"
	if f.RawData != nil {
		if src, ok := f.RawData["source_ip"].(string); ok && src != "" {
			sourceIP = src
		}
	}

	upsert := models.ExternalConnectionUpsert{
		SourceIP: sourceIP,
		DestIP:   destIP,
		DestPort: destPort,
		Protocol: protocol,
	}

	if f.Hostname != nil {
		upsert.DestHostname = f.Hostname
	}
	upsert.ProtocolVersion = f.ProtocolVersion
	upsert.CipherSuite = f.CipherSuite
	upsert.KeyExchangeAlgorithm = f.KeyExchangeAlgorithm
	upsert.KeySize = f.KeySize

	// Extract certificate data from raw_data for the external_connections cert snapshot
	if f.RawData != nil {
		certs := s.extractCertificatesFromFinding(f)
		if len(certs) > 0 {
			leaf := certs[0]
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

	if f.SourceSensorID != nil {
		if u, err := uuid.Parse(*f.SourceSensorID); err == nil {
			upsert.SensorID = &u
		}
	}

	_, err := s.externalConnectionsSvc.Upsert(tenantID, upsert)
	return err
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
	input := models.AssetInput{
		Hostname:       conn.DestHostname,
		IPAddress:      &conn.DestIP,
		Port:           &conn.DestPort,
		AssetType:      "server",
		AssetOwnership: &ownership,
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
	asset, err := s.createAssetWithStatus(tenantID, input, "monitoring", findingDiscoveryMethod(f))
	if err != nil {
		return nil, fmt.Errorf("create managed asset from connection %s: %w", conn.ID, err)
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
const insertCryptoImplementationSQL = `
		INSERT INTO crypto_implementations (
			id, tenant_id, asset_id, protocol, protocol_version, cipher_suite,
			key_exchange_algorithm, signature_algorithm, symmetric_encryption,
			hash_algorithm, key_size, certificate_id, discovery_method,
			confidence_score, source_sensor_id, raw_data, risk_score,
			compliance_status, first_discovered_at, last_verified_at,
			created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,
			$12,$13,$14,
			$7,$8,$9,$15::public.discovery_method,
			NULL,$10,$11,NULL,
			'{}'::jsonb, NOW(), NOW(),
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

// maxDeferredFindings caps network_assets.metadata->'deferred_findings'.
//
// With dedup in place an asset reaches this only by producing that many
// genuinely distinct observations while pending, which is pathological — the
// cap is a backstop against unbounded JSONB growth, not a routine trim. Oldest
// entries are dropped first: the newest observations are the ones that describe
// the asset's current posture.
const maxDeferredFindings = 50

// storeDeferredFinding saves the raw finding data in the asset's metadata under
// the "deferred_findings" key. When the asset is later approved, ApproveAssets
// processes these deferred findings to create certificates and crypto configurations.
//
// Deduplicated and capped. This used to be a blind `||` append that rewrote the
// whole JSONB document on every ingest, so an asset left in Discovery →
// Approvals accumulated one complete copy of every re-observation — full
// certificate PEM chains included — for as long as nobody clicked Approve, and
// then fired all of them in a single burst on approval. Findings that
// materialize to the same thing now REPLACE their predecessor in place rather
// than stacking, so the newest observation wins and the array stays the size of
// the asset's distinct posture.
//
// Note the fingerprint deliberately does not compare whole findings: several
// producers stamp per-observation timestamps into RawData, so a blob comparison
// never matches and would dedup nothing. See deferredFindingFingerprint.
func (s *AssetService) storeDeferredFinding(tenantID, assetID uuid.UUID, f IngestFinding) {
	findingJSON, err := json.Marshal(f)
	if err != nil {
		log.Printf("Warning: failed to marshal deferred finding for asset %s: %v", assetID, err)
		return
	}
	fingerprint := s.deferredFindingFingerprint(f)

	// Read-modify-write, so it must be serialized: two concurrent ingests of the
	// same asset would otherwise each read the array, each append, and the second
	// write would drop the first. The same per-asset advisory lock the crypto
	// upsert uses does that, cluster-wide.
	// RLS-scoped write over network_assets.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if _, e := tx.Exec(lockAssetMaterializationSQL, assetMaterializationLockKey(tenantID, assetID)); e != nil {
			return fmt.Errorf("lock asset materialization: %w", e)
		}

		var existingJSON []byte
		if e := tx.QueryRow(
			`SELECT COALESCE(metadata->'deferred_findings', '[]'::jsonb) FROM network_assets WHERE id = $1 AND tenant_id = $2`,
			assetID, tenantID,
		).Scan(&existingJSON); e != nil {
			return fmt.Errorf("read deferred findings: %w", e)
		}

		var existing []json.RawMessage
		if len(existingJSON) > 0 {
			if e := json.Unmarshal(existingJSON, &existing); e != nil {
				// A malformed array is not a reason to lose the new observation,
				// but it IS a reason to say so rather than silently reset.
				log.Printf("Warning: deferred findings for asset %s are unreadable (%v); starting a fresh array", assetID, e)
				existing = nil
			}
		}

		replaced := false
		for i, entry := range existing {
			var prev IngestFinding
			if e := json.Unmarshal(entry, &prev); e != nil {
				continue
			}
			if s.deferredFindingFingerprint(prev) != fingerprint {
				continue
			}
			// Same finding, seen again: keep its position (so ordering stays
			// first-seen) and take the newer body.
			existing[i] = json.RawMessage(findingJSON)
			replaced = true
			break
		}
		if !replaced {
			existing = append(existing, json.RawMessage(findingJSON))
		}
		if len(existing) > maxDeferredFindings {
			dropped := len(existing) - maxDeferredFindings
			log.Printf("Warning: asset %s holds more than %d distinct deferred findings; dropping the %d oldest",
				assetID, maxDeferredFindings, dropped)
			existing = existing[dropped:]
		}

		merged, e := json.Marshal(existing)
		if e != nil {
			return fmt.Errorf("marshal deferred findings: %w", e)
		}
		_, e = tx.Exec(`
			UPDATE network_assets
			SET metadata = jsonb_set(
				COALESCE(metadata, '{}'::jsonb),
				'{deferred_findings}',
				$1::jsonb,
				true
			),
			updated_at = NOW()
			WHERE id = $2`,
			string(merged), assetID)
		return e
	})
	if err != nil {
		log.Printf("Warning: failed to store deferred finding for asset %s: %v", assetID, err)
	}
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
	var materializationErrs []error

	// AT-REST resources short-circuit here.
	//
	// An S3 bucket or an RDS instance is not a network endpoint: it negotiates
	// no protocol, no cipher suite and no version. Falling through would
	// manufacture a crypto_implementations row with every crypto column NULL —
	// which is precisely the phantom TLS endpoint this replaces. Its
	// encryption posture is at-rest, so it belongs in crypto_applications.
	if posture, ok := atRestPostureFromFinding(f); ok {
		s.produceAtRestApplication(tenantID, assetID, posture)
		return nil
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
	if isAtRestProtocol(f.Protocol) {
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

			// Find or create certificate
			cert, err := s.certificateService.FindOrCreateCertificate(tenantID, certData)
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

				// Link to previous certificate (issuer relationship)
				if i > 0 && len(certIDs) > 1 {
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
	key, recordable := s.cryptoKeyForFinding(assetID, f)
	if !recordable {
		return errors.Join(append(materializationErrs,
			fmt.Errorf("protocol %q names no modelled protocol; refusing to materialize a crypto configuration for it", f.Protocol))...)
	}
	protocol := key.Protocol

	raw := models.JSONB{}
	if f.RawData != nil {
		raw = models.JSONB(f.RawData)
	}
	rawJSON, _ := json.Marshal(raw)

	var sensor interface{}
	if f.SourceSensorID != nil {
		if u, perr := uuid.Parse(*f.SourceSensorID); perr == nil {
			sensor = u
		}
	}

	var cryptoID uuid.UUID
	var cryptoCreated bool
	// RLS-scoped write over crypto_implementations. The advisory lock is what
	// stands in for the unique constraint this table deliberately does not have:
	// it serializes the find-then-write for this asset across every replica, so
	// two workers ingesting the same endpoint cannot both miss and both insert.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		if _, e := tx.Exec(lockAssetMaterializationSQL, assetMaterializationLockKey(tenantID, assetID)); e != nil {
			return fmt.Errorf("lock asset materialization: %w", e)
		}
		id, created, e := upsertCryptoImplementation(tx, tenantID, key, primaryCertID, sensor, rawJSON)
		if e != nil {
			return e
		}
		cryptoID, cryptoCreated = id, created
		return nil
	}); err != nil {
		// Everything below writes against cryptoID — junction links, algorithm
		// classification, the risk update. Without a row they would either fail
		// on the foreign key or attach to uuid.Nil. Stop here and report.
		log.Printf("[AssetService] Warning: failed to materialize crypto implementation for asset %s: %v", assetID, err)
		materializationErrs = append(materializationErrs, fmt.Errorf("materialize crypto implementation: %w", err))
		return errors.Join(materializationErrs...)
	}

	// Link certificates to crypto configuration
	if primaryCertID != nil {
		if err := s.certificateService.LinkCertificateToImplementation(tenantID, cryptoID, *primaryCertID, "leaf"); err != nil {
			log.Printf("Warning: failed to link certificate to implementation: %v", err)
			materializationErrs = append(materializationErrs, fmt.Errorf("link leaf certificate to implementation: %w", err))
		}
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

	// Classify and link algorithms
	s.classifyAndLinkAlgorithms(cryptoID, f)

	// Populate the cryptographic-key inventory from the certificate public keys
	// on this implementation (metadata only; never key material). Best-effort:
	// a failure here must not fail crypto ingest.
	for _, pc := range producedCerts {
		s.produceKeyFromCertificate(tenantID, cryptoID, pc.cert, pc.data)
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

	// RLS-scoped read; runs even when the detector is absent.
	_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		worst, all, ok, e := catalogueRiskForImplementation(tx, cryptoID)
		if e != nil {
			log.Printf("[AssetService] Warning: catalogue risk lookup failed for %s: %v", cryptoID, e)
			return nil
		}
		if ok {
			cryptoRiskScore = worst.RiskScore
			riskSource = "algorithm_catalogue"
			catalogueFactors = catalogueRiskFactors(all)
		}
		return nil
	})

	if s.weakCryptoDetector != nil {
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
		}

		if issues := s.weakCryptoDetector.AnalyzeCryptoImplementation(tenantID, assetID, impl); len(issues) > 0 {
			if detectorScore := s.weakCryptoDetector.CalculateRiskScore(issues); detectorScore > cryptoRiskScore {
				cryptoRiskScore = detectorScore
				riskSource = "weak_crypto"
			}
		}
	}

	// Score 0 means "not assessed" — nothing resolved against the catalogue and
	// the detector found nothing. Persisting a 0 would be indistinguishable from
	// a clean assessment, so skip the write and let the Informational band keep
	// meaning unassessed.
	if cryptoRiskScore > 0 {
		if len(catalogueFactors) > 0 {
			log.Printf("[AssetService] Risk %d for implementation %s (source=%s): %v",
				cryptoRiskScore, cryptoID, riskSource, catalogueFactors)
		}
		{
			// RLS-scoped writes over crypto_implementations / network_assets.
			_ = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
				if _, e := tx.Exec(
					`UPDATE crypto_implementations SET risk_score = $1, updated_at = NOW() WHERE id = $2`,
					cryptoRiskScore, cryptoID,
				); e != nil {
					log.Printf("[AssetService] Warning: Failed to update crypto implementation risk score: %v", e)
				}

				if _, e := tx.Exec(
					`UPDATE network_assets SET risk_score = GREATEST(risk_score, $1), updated_at = NOW() WHERE id = $2`,
					cryptoRiskScore, assetID,
				); e != nil {
					log.Printf("[AssetService] Warning: Failed to update asset risk score: %v", e)
				}
				return nil
			})
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
	if s.eventPublisher != nil && lifecycleCryptoAdded != nil && cryptoCreated {
		*lifecycleCryptoAdded = append(*lifecycleCryptoAdded, &events.CryptoConfigurationAddedPayload{
			AssetID:                assetID,
			CryptoImplementationID: cryptoID,
			Protocol:               protocol,
			ProtocolVersion:        f.ProtocolVersion,
			RiskScore:              cryptoRiskScore,
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

func (s *AssetService) ApproveAssets(tenantID uuid.UUID, assetIDs []uuid.UUID) error {
	if len(assetIDs) == 0 {
		return nil
	}

	// Commit approval before materializing deferred crypto data so a failed status
	// update cannot leave certificates/crypto rows without clearing deferred_findings.
	query := `UPDATE network_assets SET asset_status = 'monitoring', updated_at = NOW(), last_seen_at = NOW(), stale_status = NULL WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL`
	// RLS-scoped write over network_assets.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, tenantID, pq.Array(assetIDs))
		return e
	}); err != nil {
		return err
	}

	// Process deferred findings for each asset being approved.
	// These were stored during IngestFindings when the asset was pending_approval.
	var materializationErrs []error
	for _, assetID := range assetIDs {
		if err := s.processDeferredFindings(tenantID, assetID); err != nil {
			materializationErrs = append(materializationErrs, fmt.Errorf("asset %s: %w", assetID, err))
		}
	}
	return errors.Join(materializationErrs...)
}

// processDeferredFindings reads the deferred_findings array from asset metadata,
// processes each finding to create certificates and crypto configurations, then
// clears the deferred_findings from metadata only after every finding succeeds.
func (s *AssetService) processDeferredFindings(tenantID uuid.UUID, assetID uuid.UUID) error {
	var metadataJSON []byte
	// RLS-scoped read over network_assets.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`SELECT metadata FROM network_assets WHERE id = $1 AND tenant_id = $2`, assetID, tenantID).Scan(&metadataJSON)
	})
	if err != nil || len(metadataJSON) == 0 {
		return err
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(metadataJSON, &metadata); err != nil {
		return fmt.Errorf("unmarshal metadata: %w", err)
	}

	deferredRaw, ok := metadata["deferred_findings"]
	if !ok {
		return nil
	}

	deferredJSON, err := json.Marshal(deferredRaw)
	if err != nil {
		return fmt.Errorf("marshal deferred findings: %w", err)
	}

	var findings []IngestFinding
	if err := json.Unmarshal(deferredJSON, &findings); err != nil {
		log.Printf("[AssetService] Warning: failed to unmarshal deferred findings for asset %s: %v", assetID, err)
		return fmt.Errorf("unmarshal deferred findings: %w", err)
	}

	source := "discovery"
	for _, f := range findings {
		if f.RawData != nil {
			if v, ok := f.RawData["source"].(string); ok && v != "" {
				source = v
				break
			}
		}
	}

	// Collapse duplicates before replaying. storeDeferredFinding now dedups on
	// the way in, but an asset that has been sitting in Approvals since before
	// that landed still carries one copy per re-observation — and approving it
	// replayed every one of them, each doing the same certificate lookups and
	// the same risk pass. The crypto upsert would converge them onto one row
	// anyway; this stops the redundant work (and the redundant events) rather
	// than undoing it afterwards.
	findings = s.dedupDeferredFindings(findings)

	var lifecycleRiskChanged []*events.AssetRiskChangedPayload
	var lifecycleCryptoAdded []*events.CryptoConfigurationAddedPayload
	var lifecycleCertExpiring []*events.CertificateExpiringPayload

	var materializationErrs []error
	for i, f := range findings {
		if err := s.processDiscoveryCryptoData(tenantID, assetID, f, &lifecycleRiskChanged, &lifecycleCryptoAdded, &lifecycleCertExpiring); err != nil {
			materializationErrs = append(materializationErrs, fmt.Errorf("deferred finding %d: %w", i, err))
		}
	}

	if s.eventPublisher != nil && (len(lifecycleRiskChanged) > 0 || len(lifecycleCryptoAdded) > 0 || len(lifecycleCertExpiring) > 0) {
		ctx := context.Background()
		go func() {
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

	if err := errors.Join(materializationErrs...); err != nil {
		log.Printf("[AssetService] Warning: preserving deferred findings for asset %s because materialization failed: %v", assetID, err)
		return err
	}

	// Clear deferred_findings from metadata.
	// RLS-scoped write over network_assets.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`
			UPDATE network_assets
			SET metadata = metadata - 'deferred_findings',
			    updated_at = NOW()
			WHERE id = $1 AND tenant_id = $2`,
			assetID, tenantID)
		return e
	})
	if err != nil {
		log.Printf("[AssetService] Warning: failed to clear deferred findings for asset %s: %v", assetID, err)
		return err
	}
	return nil
}

// dedupDeferredFindings collapses deferred findings that materialize to the
// same thing, keeping the LAST occurrence of each (the most recent observation)
// at the position of the first (so replay order stays first-seen).
func (s *AssetService) dedupDeferredFindings(findings []IngestFinding) []IngestFinding {
	if len(findings) < 2 {
		return findings
	}
	pos := make(map[string]int, len(findings))
	out := make([]IngestFinding, 0, len(findings))
	for _, f := range findings {
		fp := s.deferredFindingFingerprint(f)
		if i, seen := pos[fp]; seen {
			out[i] = f
			continue
		}
		pos[fp] = len(out)
		out = append(out, f)
	}
	return out
}

func (s *AssetService) DenyAssets(tenantID uuid.UUID, assetIDs []uuid.UUID, userID uuid.UUID) error {
	if len(assetIDs) == 0 {
		return nil
	}

	// Fetch asset fingerprints
	var assets []minimalAsset
	selectQuery := `SELECT id, hostname, ip_address, port FROM network_assets WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL`
	// RLS-scoped read over network_assets.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.Select(&assets, selectQuery, tenantID, pq.Array(assetIDs))
	}); err != nil {
		return fmt.Errorf("failed to load assets for suppression: %w", err)
	}

	// Suppress fingerprints.
	//
	// B-42: a failure here used to go to a bare stdout Printf while DenyAssets
	// still returned nil, so the deny reported success with no suppression
	// recorded — invisible to the user and to any caller. Suppression is half
	// of what "deny" means, so its failure is the operation's failure.
	for _, a := range assets {
		if err := s.addSuppression(tenantID, a.Hostname, a.IPAddress, a.Port, &userID, "denied by user"); err != nil {
			return fmt.Errorf("failed to record deny suppression for asset %s: %w", a.ID, err)
		}
	}

	// Mark assets as denied and default ownership to third_party.
	// RLS-scoped write over network_assets.
	update := `UPDATE network_assets SET asset_status = 'denied', asset_ownership = COALESCE(NULLIF(asset_ownership,''), 'third_party'), updated_at = NOW() WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL`
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(update, tenantID, pq.Array(assetIDs))
		return e
	})
}

// evaluateAssetApproval decides a new asset's approval status server-side.
//
// Auto-approval has exactly one gate: the asset is on a user-defined network
// segment with auto-approve enabled. Those segments generate the rows in
// discovery_auto_approval_rules (ManageAutoApprovalRules); shared/approval
// evaluates them, and it is the same evaluation the sensor pipeline runs — one
// implementation of the rule, not two.
//
// Default deny: anything that cannot be resolved to a matching, auto-approving
// segment — no segment service wired, a lookup error, no matching segment, a
// non-internal address — lands in Discovery → Approvals.
func (s *AssetService) evaluateAssetApproval(tenantID uuid.UUID, ipAddress, hostname *string) string {
	const pending = "pending_approval"
	if s.networkSegmentService == nil {
		return pending
	}
	seg, err := s.networkSegmentService.GetSegmentForIP(tenantID, ipAddress, hostname)
	if err != nil || seg == nil {
		return pending
	}
	ownership, err := s.networkSegmentService.ClassifyAsset(tenantID, ipAddress, hostname, nil)
	if err != nil {
		return pending
	}
	segID := seg.ID
	segName := seg.Name
	classification := &approval.Classification{
		Ownership:   ownership,
		Type:        seg.NetworkType,
		SegmentID:   &segID,
		SegmentName: &segName,
	}
	// Metadata is deliberately nil: no metadata means "not a cloud discovery",
	// which is what a manually created or CMDB-pulled asset is. Confidence 1.0 —
	// the asset was asserted by a user or an authoritative system of record, not
	// inferred from an observation.
	autoApprove, _, err := approval.NewService(s.db.DB.DB).EvaluateAutoApproval(
		approval.Discovery{TenantID: tenantID, Confidence: 1.0},
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
	// A handler-created asset IS manual provenance — there is no request field
	// for it, deliberately: a client cannot claim its hand-entered asset was
	// sensor-observed.
	return s.createAssetWithStatus(tenantID, input, s.evaluateAssetApproval(tenantID, input.IPAddress, input.Hostname), "manual")
}

// createAssetWithStatus is CreateAsset with the approval decision already made.
//
// The ONLY legitimate caller is the discovery ingestion path (IngestFindings),
// which receives a status that discovery-processor-service produced by running
// the same segment auto-approval rules over the classified discovery. It is
// unexported so no handler can reach it.
// discoveryMethod is the resolved `discovery_method` enum value for the asset
// row; it was omitted from the INSERT entirely, so the asset drawer's Discovery
// line was blank for every asset on the platform.
func (s *AssetService) createAssetWithStatus(tenantID uuid.UUID, input models.AssetInput, assetStatus, discoveryMethod string) (*models.Asset, error) {
	// Validate minimal requirements
	if input.AssetType == "" {
		return nil, fmt.Errorf("asset_type is required")
	}
	if (input.Hostname == nil || *input.Hostname == "") && (input.IPAddress == nil || *input.IPAddress == "") {
		return nil, fmt.Errorf("either hostname or ip_address is required")
	}

	// Default JSONB maps if nil to avoid NULL scans later
	if input.Tags == nil {
		input.Tags = models.JSONB{}
	}
	if input.Metadata == nil {
		input.Metadata = models.JSONB{}
	}

	// Apply tags from matching network segments (merge with provided tags)
	networkTags, _ := s.getTagsForAsset(tenantID, input.IPAddress, input.Hostname)
	input.Tags = mergeTags(input.Tags, networkTags)

	// Marshal JSONB fields for insertion
	tagsJSON, _ := json.Marshal(input.Tags)
	metadataJSON, _ := json.Marshal(input.Metadata)

	// Classify asset ownership if not manually provided
	assetOwnership := "unknown"
	if input.AssetOwnership != nil {
		assetOwnership = *input.AssetOwnership
	} else {
		ownership, _ := s.classifyAsset(tenantID, input.IPAddress, input.Hostname)
		assetOwnership = ownership
	}

	if assetStatus == "" {
		assetStatus = "pending_approval"
	}

	if discoveryMethod == "" {
		discoveryMethod = defaultDiscoveryMethod
	}

	insert := `
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type,
            operating_system, environment, business_unit, owner_email,
            description, tags, metadata, asset_ownership, asset_status,
            discovery_method
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
        RETURNING id
    `

	var assetID uuid.UUID
	// RLS-scoped write over network_assets.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(insert,
			tenantID,
			input.Hostname,
			input.IPAddress,
			input.Port,
			input.AssetType,
			input.OperatingSystem,
			input.Environment,
			input.BusinessUnit,
			input.OwnerEmail,
			input.Description,
			tagsJSON,
			metadataJSON,
			assetOwnership,
			assetStatus,
			discoveryMethod,
		).Scan(&assetID)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create asset: %w", err)
	}

	// Publish asset created event
	if s.eventPublisher != nil {
		ctx := context.Background()
		if err := s.eventPublisher.PublishAssetChanged(ctx, tenantID, assetID, sharedevents.ChangeTypeCreated, "manual"); err != nil {
			log.Printf("[AssetService] Warning: Failed to publish asset created event: %v", err)
		}
	}

	return s.GetAssetByID(tenantID, assetID)
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

// assetExists reports whether a non-deleted asset already exists for the tenant
// matching either the given hostname or IP address. Used by bulk import to skip
// rows that duplicate existing inventory.
func (s *AssetService) assetExists(tenantID uuid.UUID, hostname, ip *string) (bool, error) {
	var exists bool
	// host(ip_address) rather than ::text: casting inet to text renders the
	// netmask ("10.0.0.5/32"), which never equals a bare imported IP, so the
	// IP arm of this dedup matched nothing. NULL parameters are simply
	// skipped rather than matching everything.
	// RLS-scoped read over network_assets.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(`
			SELECT EXISTS (
				SELECT 1 FROM network_assets
				WHERE tenant_id = $1 AND deleted_at IS NULL
				  AND (
				    ($2::text IS NOT NULL AND hostname = $2::text) OR
				    ($3::text IS NOT NULL AND host(ip_address) = $3::text)
				  )
			)`, tenantID, hostname, ip).Scan(&exists)
	})
	return exists, err
}

// BulkCreateAssets creates many assets in one request, reusing CreateAsset for
// each row so behavior (validation, ownership classification, segment tagging,
// event emission) is identical to single creation. Rows are deduped both within
// the batch and against existing inventory. Partial success is the norm — a bad
// row is recorded as an error and the rest of the batch proceeds. The caller is
// responsible for enforcing the subscription asset cap before invoking this.
func (s *AssetService) BulkCreateAssets(tenantID uuid.UUID, inputs []models.AssetInput) *models.BulkImportResult {
	res := models.NewBulkImportResult(len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for i, in := range inputs {
		key := bulkAssetKey(in)
		if key != "" {
			if _, dup := seen[key]; dup {
				res.Add(i, models.BulkRowSkippedDuplicate, nil, "duplicate of an earlier row in this file")
				continue
			}
			seen[key] = struct{}{}
		}
		exists, err := s.assetExists(tenantID, in.Hostname, in.IPAddress)
		if err != nil {
			res.Add(i, models.BulkRowError, nil, "failed to check for an existing asset")
			continue
		}
		if exists {
			res.Add(i, models.BulkRowSkippedDuplicate, nil, "an asset with this hostname or IP already exists")
			continue
		}
		asset, err := s.CreateAsset(tenantID, in)
		if err != nil {
			res.Add(i, models.BulkRowError, nil, err.Error())
			continue
		}
		res.Add(i, models.BulkRowCreated, &asset.ID, "")
	}
	return res
}

// UpdateAsset updates provided fields for an existing asset.
// Builds a dynamic UPDATE statement to only modify provided fields and touches updated_at.
func (s *AssetService) UpdateAsset(tenantID, assetID uuid.UUID, input models.AssetInput) (*models.Asset, error) {
	// Build dynamic SET clauses
	setClauses := []string{}
	args := []interface{}{}
	idx := 1

	if input.Hostname != nil {
		setClauses = append(setClauses, fmt.Sprintf("hostname = $%d", idx))
		args = append(args, input.Hostname)
		idx++
	}
	if input.IPAddress != nil {
		setClauses = append(setClauses, fmt.Sprintf("ip_address = $%d", idx))
		args = append(args, input.IPAddress)
		idx++
	}
	if input.Port != nil {
		setClauses = append(setClauses, fmt.Sprintf("port = $%d", idx))
		args = append(args, input.Port)
		idx++
	}
	if input.AssetType != "" {
		setClauses = append(setClauses, fmt.Sprintf("asset_type = $%d", idx))
		args = append(args, input.AssetType)
		idx++
	}
	if input.OperatingSystem != nil {
		setClauses = append(setClauses, fmt.Sprintf("operating_system = $%d", idx))
		args = append(args, input.OperatingSystem)
		idx++
	}
	if input.Environment != nil {
		setClauses = append(setClauses, fmt.Sprintf("environment = $%d", idx))
		args = append(args, input.Environment)
		idx++
	}
	if input.BusinessUnit != nil {
		setClauses = append(setClauses, fmt.Sprintf("business_unit = $%d", idx))
		args = append(args, input.BusinessUnit)
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
		setClauses = append(setClauses, fmt.Sprintf("asset_status = $%d", idx))
		args = append(args, *input.AssetStatus)
		idx++
	}
	if input.Tags != nil {
		// JSONB column: marshal the map to bytes — the database/sql driver
		// can't convert a raw map[string]interface{} (CreateAsset does the same).
		tagsJSON, err := json.Marshal(input.Tags)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal tags: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("tags = $%d", idx))
		args = append(args, tagsJSON)
		idx++
	}
	if input.Metadata != nil {
		metadataJSON, err := json.Marshal(input.Metadata)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal metadata: %w", err)
		}
		setClauses = append(setClauses, fmt.Sprintf("metadata = $%d", idx))
		args = append(args, metadataJSON)
		idx++
	}

	if len(setClauses) == 0 {
		// Nothing to update
		return s.GetAssetByID(tenantID, assetID)
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

	query := fmt.Sprintf("UPDATE network_assets SET %s WHERE tenant_id = $%d AND id = $%d AND deleted_at IS NULL",
		strings.Join(setClauses, ", "), whereTenantIdx, whereAssetIdx)

	// RLS-scoped write over network_assets.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, args...)
		return e
	}); err != nil {
		return nil, fmt.Errorf("failed to update asset: %w", err)
	}

	// Publish asset updated event (only if relevant fields changed)
	// Relevant fields: hostname, ip_address, port, asset_type, environment, asset_status
	relevantFieldsChanged := input.Hostname != nil || input.IPAddress != nil || input.Port != nil ||
		input.AssetType != "" || input.Environment != nil || input.AssetStatus != nil

	if s.eventPublisher != nil && relevantFieldsChanged {
		ctx := context.Background()
		if err := s.eventPublisher.PublishAssetChanged(ctx, tenantID, assetID, sharedevents.ChangeTypeUpdated, "manual"); err != nil {
			log.Printf("[AssetService] Warning: Failed to publish asset updated event: %v", err)
		}
	}

	return s.GetAssetByID(tenantID, assetID)
}

// UpdateAssetService sets manual service identification on an asset (high confidence).
func (s *AssetService) UpdateAssetService(tenantID, assetID uuid.UUID, input models.UpdateAssetServiceInput) (*models.Asset, error) {
	var n int64
	// RLS-scoped write over network_assets.
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		result, e := tx.Exec(`
			UPDATE network_assets SET
				service_name = $1, service_version = NULLIF($2, ''),
				service_confidence = 'high', service_identification_method = 'manual',
				updated_at = NOW()
			WHERE tenant_id = $3 AND id = $4 AND deleted_at IS NULL`,
			input.ServiceName, input.ServiceVersion, tenantID, assetID)
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
	// Publish asset deleted event before deletion
	if s.eventPublisher != nil {
		ctx := context.Background()
		if err := s.eventPublisher.PublishAssetDeleted(ctx, tenantID, assetID, "manual"); err != nil {
			log.Printf("[AssetService] Warning: Failed to publish asset deleted event: %v", err)
		}
	}

	query := `UPDATE network_assets SET deleted_at = NOW() WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`
	// RLS-scoped write over network_assets.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, tenantID, assetID)
		return e
	}); err != nil {
		return fmt.Errorf("failed to delete asset: %w", err)
	}
	return nil
}

// RestoreAsset clears deleted_at to restore a previously soft-deleted asset.
func (s *AssetService) RestoreAsset(tenantID, assetID uuid.UUID) error {
	query := `UPDATE network_assets SET deleted_at = NULL WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NOT NULL`
	// RLS-scoped write over network_assets.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(query, tenantID, assetID)
		return e
	}); err != nil {
		return fmt.Errorf("failed to restore asset: %w", err)
	}
	return nil
}

// HardDeleteAsset permanently deletes an asset from the database (admin-only).
// This is a destructive operation that cannot be undone.
func (s *AssetService) HardDeleteAsset(tenantID, assetID uuid.UUID) error {
	// RLS-scoped reads/writes over network_assets / crypto_implementations — the
	// verify + cascade-delete + delete run in one tenant tx.
	return database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// First verify the asset exists and belongs to the tenant
		var exists bool
		checkQuery := `SELECT EXISTS(SELECT 1 FROM network_assets WHERE tenant_id = $1 AND id = $2)`
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
		query := `DELETE FROM network_assets WHERE tenant_id = $1 AND id = $2`
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
	APICalls       int            `json:"api_calls"`       // API calls, measured by resource-tracker-service; 0 with the source listed in UnavailableSources when it could not be reached
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
		FROM network_assets a
		LEFT JOIN crypto_implementations ci ON a.id = ci.asset_id AND ci.deleted_at IS NULL
		LEFT JOIN keys k ON k.tenant_id = a.tenant_id
		LEFT JOIN crypto_libraries cl ON cl.tenant_id = a.tenant_id
		LEFT JOIN integrations i ON i.tenant_id = a.tenant_id AND i.is_enabled = true
		WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
	`

	var assetCount, cryptoCount, keyCount, libraryCount, integrationCount, recentUpdates, newAssets int

	// RLS-scoped read over network_assets / crypto_implementations / keys /
	// crypto_libraries / integrations (single-tenant aggregate, WHERE a.tenant_id = $1).
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRow(query, tenantID).Scan(
			&assetCount,
			&cryptoCount,
			&keyCount,
			&libraryCount,
			&integrationCount,
			&recentUpdates,
			&newAssets,
		)
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

	// Query API calls from resource-tracker-service.
	//
	// There is deliberately NO estimation fallback. The previous one derived a
	// number from inventory size — a formula that has nothing to do with API
	// traffic — and it was indistinguishable from a measurement downstream, so
	// an unreachable peer silently became a plausible metric on every tenant's
	// health score. When the peer cannot be reached the count is 0 and the
	// source is named, which the consumer reads as UNKNOWN.
	apiCalls, err := s.getAPICallsFromResourceTracker(tenantID)
	if err != nil {
		log.Printf("[AssetService] resource-tracker-service unreachable for tenant %s: %v — reporting api_calls as UNKNOWN", tenantID, err)
		summary.APICalls = 0
		summary.UnavailableSources = append(summary.UnavailableSources, "resource-tracker-service")
	} else {
		summary.APICalls = apiCalls
	}

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

// peerHTTPClientOnce guards the lazily-built S2S client below.
var (
	peerHTTPClientOnce sync.Once
	peerHTTPClientVal  *http.Client
)

// peerHTTPClient returns the HTTP client used for service-to-service polls.
//
// Under serviceMtls the peer URL resolves to https://<svc>:8443, which is
// RequireAndVerifyClientCert: a bare &http.Client{} fails the handshake on
// every call. Built once, from the same CLIENT_CERT_PATH / CLIENT_KEY_PATH /
// PLATFORM_CA_CERT_PATH the chart already mounts for this service.
func peerHTTPClient() *http.Client {
	peerHTTPClientOnce.Do(func() {
		peerHTTPClientVal = newPeerHTTPClient(
			sharedconfig.GetEnvAsBool("USE_MTLS", true),
			sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
			sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
			sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),
		)
	})
	return peerHTTPClientVal
}

// newPeerHTTPClient is peerHTTPClient's construction step, split out so it can
// be exercised without the package-level sync.Once.
func newPeerHTTPClient(useMTLS bool, certPath, keyPath, caPath string) *http.Client {
	plain := &http.Client{Timeout: 5 * time.Second}
	if !useMTLS {
		return plain
	}
	c, err := sharedhttp.NewMTLSClient(certPath, keyPath, caPath)
	if err != nil {
		// Not fatal — the caller reports the peer as unavailable rather than
		// inventing a value, so this degrades visibly.
		log.Printf("[AssetService] USE_MTLS is set but the mTLS client could not be built: %v — peer polls will fail and report UNKNOWN", err)
		return plain
	}
	c.Timeout = 5 * time.Second
	return c
}

// getAPICallsFromResourceTracker queries the resource-tracker-service for API call count
func (s *AssetService) getAPICallsFromResourceTracker(tenantID uuid.UUID) (int, error) {
	trackerURL := os.Getenv("RESOURCE_TRACKER_URL")
	if trackerURL == "" {
		trackerURL = sharedconfig.PeerURL("resource-tracker-service", sharedconfig.MTLSEnabled())
	}

	// Query for last 30 days of usage
	url := fmt.Sprintf("%s/api/v1/resource-tracker-service/tenants/%s/usage?period=30d", trackerURL, tenantID.String())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil) //nolint:gosec // intentional — internal service-to-service call to resource-tracker URL from trusted config, not user input
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	serviceauth.SignRequestFromEnv(req)

	resp, err := peerHTTPClient().Do(req) //nolint:gosec // intentional — internal service-to-service call, URL from trusted config not user input
	if err != nil {
		return 0, fmt.Errorf("failed to query resource-tracker: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("resource-tracker returned status %d", resp.StatusCode)
	}

	var usageResponse struct {
		CurrentUsage struct {
			TotalAPICalls int `json:"total_api_calls"`
		} `json:"current_usage"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&usageResponse); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}

	return usageResponse.CurrentUsage.TotalAPICalls, nil
}
