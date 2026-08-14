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
	"time"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	sharedevents "github.com/vistasecurity/vistaplatform/shared/events"
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

// isSuppressed checks if a pending discovery matches a denied/suppressed fingerprint
func (s *AssetService) isSuppressed(tenantID uuid.UUID, hostname *string, ipAddress *string, port *int) (bool, error) {
	key := buildSuppressionKey(hostname, ipAddress, port)
	var exists bool
	// asset_suppressions has no RLS policy (not in the tenant_isolation set), so
	// this read stays on the plain handle — the WHERE tenant_id is the isolation.
	query := `SELECT TRUE FROM asset_suppressions WHERE tenant_id = $1 AND suppression_key = $2 LIMIT 1`
	err := s.db.QueryRow(query, tenantID, key).Scan(&exists)
	if err != nil {
		// if no rows, not suppressed
		return false, nil
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
	// asset_suppressions has no RLS policy — plain handle, WHERE/INSERT tenant_id
	// is the isolation.
	_, err := s.db.Exec(query, tenantID, h, ip, p, reason, createdBy, key)
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

// normalizeProtocol returns a value valid for the protocol_type enum.
// Keep this set in sync with ALTER TYPE protocol_type ADD VALUE
// statements in scripts/database/schema.sql.
//
// The sensor emits protocol identifiers as it parses them from the wire
// (often with hyphenation or vendor casing). This function maps those
// aliases to the canonical enum literal. Unknown protocols fall through
// to "TLS" with a warning log — that log is intentional as a tripwire
// for the next time the sensor adds a protocol we forgot to wire here.
func normalizeProtocol(protocol string) string {
	protocolUpper := strings.ToUpper(protocol)
	switch protocolUpper {
	case "HTTPS", "HTTP/2", "HTTP2":
		return "TLS" // HTTPS is TLS over HTTP
	case "TLS", "SSL":
		return "TLS"
	case "SSH":
		return "SSH"
	case "IPSEC", "IP-SEC", "IKE":
		return "IPSec"
	case "VPN", "WIREGUARD", "OPENVPN":
		return "VPN"
	case "SMB":
		return "SMB"
	case "KERBEROS":
		return "Kerberos"
	case "DATABASE", "DB":
		return "Database"
	case "API", "REST", "GRAPHQL":
		return "API"
	// OT/ICS protocols. The sensor emits the protocol name directly
	// from its assemblers; we accept common vendor / standard aliases.
	case "MODBUS", "MODBUS/TCP", "MODBUS_TCP", "MODBUS-TCP":
		return "Modbus"
	case "DNP3", "DNP3.0", "DNP3-SAV5", "DNP3-SAV6", "DNP3_SAV5", "DNP3_SAV6":
		return "DNP3"
	case "OPC_UA", "OPC-UA", "OPCUA", "OPC UA":
		return "OPC_UA"
	case "ETHERNET_IP", "ETHERNET-IP", "ETHERNET/IP", "ENIP", "CIP":
		return "EtherNet_IP"
	case "BACNET":
		return "BACnet"
	case "BACNET_SC", "BACNET-SC", "BACNET/SC":
		return "BACnet_SC"
	case "HART_IP", "HART-IP", "HARTIP":
		return "HART_IP"
	case "S7", "S7COMM", "S7-COMM", "S7_COMM", "S7-PLUS", "S7PLUS", "S7_PLUS":
		return "S7"
	case "MMS", "IEC-61850-MMS", "IEC61850-MMS", "IEC61850_MMS":
		return "MMS"
	case "ICCP", "TASE.2", "TASE-2", "TASE_2":
		return "ICCP"
	case "IEC62351", "IEC-62351", "IEC_62351":
		return "IEC62351"
	default:
		// Default to TLS for unknown protocols (most common case)
		// Log a warning for unexpected protocols
		if protocolUpper != "TLS" {
			log.Printf("Warning: Unknown protocol '%s', defaulting to TLS", protocol)
		}
		return "TLS"
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

			// If suppressed/denied, skip creation
			suppressed, _ := s.isSuppressed(tenantID, f.Hostname, effectiveIP, f.Port)
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
				AssetStatus:     ptrString(status),
			}
			asset, createErr := s.CreateAsset(tenantID, input)
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

		// Extract and process certificate chain from discovery finding
		s.processDiscoveryCryptoData(tenantID, assetID, f, &lifecycleRiskChanged, &lifecycleCryptoAdded, &lifecycleCertExpiring)
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
	protocol := normalizeProtocol(f.Protocol)

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
	monitoring := "monitoring"
	input := models.AssetInput{
		Hostname:       conn.DestHostname,
		IPAddress:      &conn.DestIP,
		Port:           &conn.DestPort,
		AssetType:      "server",
		AssetOwnership: &ownership,
		AssetStatus:    &monitoring,
		Metadata: map[string]interface{}{
			"source":                      "connection_elevation",
			"elevated_from_connection_id": conn.ID.String(),
		},
	}
	asset, err := s.CreateAsset(tenantID, input)
	if err != nil {
		return nil, fmt.Errorf("create managed asset from connection %s: %w", conn.ID, err)
	}

	// Materialize the leaf certificate (if captured) via the canonical
	// approved-discovery path so the vendor cert is created, linked to the asset,
	// and assessed exactly like an internal one.
	f := buildElevationFinding(conn)
	if conn.CertSubject != nil && *conn.CertSubject != "" && conn.CertIssuer != nil && *conn.CertIssuer != "" {
		var lifecycleRiskChanged []*events.AssetRiskChangedPayload
		var lifecycleCryptoAdded []*events.CryptoConfigurationAddedPayload
		var lifecycleCertExpiring []*events.CertificateExpiringPayload
		s.processDiscoveryCryptoData(tenantID, asset.ID, f, &lifecycleRiskChanged, &lifecycleCryptoAdded, &lifecycleCertExpiring)
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
			$7,$8,$9,'integration',
			NULL,$10,$11,NULL,
			'{}'::jsonb, NOW(), NOW(),
			NOW(), NOW()
		)`

// storeDeferredFinding saves the raw finding data in the asset's metadata under
// the "deferred_findings" key. When the asset is later approved, ApproveAssets
// processes these deferred findings to create certificates and crypto configurations.
func (s *AssetService) storeDeferredFinding(tenantID, assetID uuid.UUID, f IngestFinding) {
	findingJSON, err := json.Marshal(f)
	if err != nil {
		log.Printf("Warning: failed to marshal deferred finding for asset %s: %v", assetID, err)
		return
	}

	// Append to existing deferred_findings array in metadata, or create a new one.
	// RLS-scoped write over network_assets.
	err = database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(`
			UPDATE network_assets
			SET metadata = jsonb_set(
				COALESCE(metadata, '{}'::jsonb),
				'{deferred_findings}',
				COALESCE(metadata->'deferred_findings', '[]'::jsonb) || $1::jsonb,
				true
			),
			updated_at = NOW()
			WHERE id = $2`,
			string(findingJSON), assetID)
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
	cryptoID := uuid.New()
	derived := s.deriveCipherComponents(f)
	insertCrypto := insertCryptoImplementationSQL

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

	protocol := normalizeProtocol(f.Protocol)

	// RLS-scoped write over crypto_implementations.
	if err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		_, e := tx.Exec(
			insertCrypto,
			cryptoID, tenantID, assetID, protocol, derived.ProtocolVersion, f.CipherSuite,
			derived.Hash, f.KeySize, primaryCertID, sensor, rawJSON,
			derived.KeyExchange, derived.Signature, derived.Symmetric,
		)
		return e
	}); err != nil {
		log.Printf("[AssetService] Warning: failed to insert crypto implementation for asset %s: %v", assetID, err)
		materializationErrs = append(materializationErrs, fmt.Errorf("insert crypto implementation: %w", err))
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

	if s.eventPublisher != nil && lifecycleCryptoAdded != nil {
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

	// Suppress fingerprints
	for _, a := range assets {
		if err := s.addSuppression(tenantID, a.Hostname, a.IPAddress, a.Port, &userID, "denied by user"); err != nil {
			fmt.Printf("Warning: failed to add suppression for asset %s: %v\n", a.ID, err)
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

// CreateAsset inserts a new asset for the tenant and returns the created record.
// Validates required fields and defaults JSONB maps to empty objects to avoid NULLs.
func (s *AssetService) CreateAsset(tenantID uuid.UUID, input models.AssetInput) (*models.Asset, error) {
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

	assetStatus := "pending_approval"
	if input.AssetStatus != nil && *input.AssetStatus != "" {
		assetStatus = *input.AssetStatus
	}

	insert := `
        INSERT INTO network_assets (
            tenant_id, hostname, ip_address, port, asset_type,
            operating_system, environment, business_unit, owner_email,
            description, tags, metadata, asset_ownership, asset_status
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
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
	APICalls       int            `json:"api_calls"`       // API calls (could query resource-tracker)
	FeatureUsage   map[string]int `json:"feature_usage"`   // Feature usage counts
	UserEngagement float64        `json:"user_engagement"` // Engagement score (0-100)
	LastUpdated    time.Time      `json:"last_updated"`
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

	// Query API calls from resource-tracker-service
	apiCalls, err := s.getAPICallsFromResourceTracker(tenantID)
	if err != nil {
		// Fallback to estimation if resource-tracker is unavailable
		summary.APICalls = assetCount*2 + cryptoCount + keyCount + libraryCount + integrationCount*5
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

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req) //nolint:gosec // intentional — internal service-to-service call, URL from trusted config not user input
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
