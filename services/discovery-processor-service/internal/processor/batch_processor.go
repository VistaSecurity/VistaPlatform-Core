package processor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/approval"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// ErrNoValidFindings marks a batch that produced nothing importable — every
// discovery was skipped for missing data. It is terminal: retrying cannot make
// the same rows importable. A sentinel rather than a magic substring, so the
// poller classifies it with errors.Is instead of grepping err.Error().
var ErrNoValidFindings = errors.New("no valid findings to import")

// BatchProcessor processes batches of sensor discoveries
type BatchProcessor struct {
	db              *sqlx.DB
	converter       *converter.SensorDiscoveryConverter
	approvalService *approval.AutoApprovalService
	inventoryClient *client.InventoryClient
}

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor(
	db *sqlx.DB,
	converter *converter.SensorDiscoveryConverter,
	approvalService *approval.AutoApprovalService,
	inventoryClient *client.InventoryClient,
) *BatchProcessor {
	return &BatchProcessor{
		db:              db,
		converter:       converter,
		approvalService: approvalService,
		inventoryClient: inventoryClient,
	}
}

// ProcessBatch processes a batch of discoveries.
// Discoveries are split into two tracks:
//   - third_party (public internet) → external_connections table via UpsertExternalConnection
//   - everything else               → managed asset lifecycle (approval, compliance, findings)
func (p *BatchProcessor) ProcessBatch(batchID string, tenantID uuid.UUID) error {
	// ProcessBatch is invoked per-(batch, tenant) by the poller, which already
	// resolved tenantID. No ctx is threaded into this method, so use
	// context.Background() to match the existing pattern.
	ctx := context.Background()

	query := `
		SELECT id, sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence,
		       metadata, timestamp, created_at, processed_at, approval_status,
		       auto_approval_rule_id, asset_id, hostname, source_ip
		FROM sensor_discoveries
		WHERE batch_id = $1 AND tenant_id = $2 AND processed_at IS NULL
		ORDER BY created_at ASC
	`

	// RLS-scoped read: sensor_discoveries is a security_invoker view over
	// sensor_discoveries_partitioned, which carries a tenant_isolation policy.
	// WithTenantTx sets app.tenant_id; the explicit WHERE tenant_id = $2 is kept
	// as the primary control (belt-and-suspenders).
	var discoveries []*models.SensorDiscovery
	err := shareddatabase.WithTenantTx(ctx, p.db.DB, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx, query, batchID, tenantID)
		if qErr != nil {
			return fmt.Errorf("failed to query discoveries: %w", qErr)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var sd models.SensorDiscovery
			var metadataJSON []byte

			if scanErr := rows.Scan(
				&sd.ID, &sd.SensorID, &sd.TenantID, &sd.BatchID,
				&sd.Protocol, &sd.DestIP, &sd.Port, &sd.Confidence,
				&metadataJSON, &sd.Timestamp, &sd.CreatedAt, &sd.ProcessedAt,
				&sd.ApprovalStatus, &sd.AutoApprovalRuleID, &sd.AssetID,
				&sd.Hostname, &sd.SourceIP,
			); scanErr != nil {
				continue // skip rows with scan errors
			}
			sd.Metadata = metadataJSON
			discoveries = append(discoveries, &sd)
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}

	if len(discoveries) == 0 {
		return fmt.Errorf("no discoveries found for batch %s", batchID)
	}

	// Auto-approval rules are per-tenant and do not change mid-batch, so load
	// them ONCE here rather than re-querying (a fresh WithTenantTx round-trip)
	// for every discovery. A rule-load failure is not fatal: it degrades the
	// batch to "nothing auto-approves", which is what the previous per-discovery
	// code did on error too.
	rules, err := p.approvalService.GetActiveRulesForTenant(tenantID)
	if err != nil {
		fmt.Printf("Warning: failed to load auto-approval rules for tenant %s: %v\n", tenantID, err)
		rules = nil
	}

	// Split discoveries into two tracks:
	//   1. third_party → external connections path (new lightweight table)
	//   2. everything else → managed asset lifecycle (approval, compliance, findings)
	type externalEntry struct {
		Discovery      *models.SensorDiscovery
		Classification *models.NetworkClassification
	}
	type FindingWithStatus struct {
		Finding     converter.IngestFinding
		AssetStatus string
		Discovery   *models.SensorDiscovery
	}

	var externalEntries []externalEntry
	var findingsWithStatus []FindingWithStatus

	// Third-party upserts that failed. Their discoveries are deliberately left
	// unprocessed (see below) and the batch is reported as failed so the poller
	// retries it with backoff instead of treating a dropped connection as done.
	externalFailed := 0
	var externalErr error

	for _, discovery := range discoveries {
		// Attempt reverse DNS if no hostname was captured by the sensor.
		if discovery.Hostname == nil || *discovery.Hostname == "" {
			if resolved := reverseDNSLookup(discovery.DestIP); resolved != "" {
				discovery.Hostname = &resolved
			}
		}

		classification := p.classifyNetwork(tenantID, discovery.DestIP, discovery.Hostname)
		if shouldKeepCloudPlaceholderManaged(discovery, classification) {
			classification.Ownership = "unknown"
			classification.Type = "private"
		}

		// Third-party public internet connections bypass the asset lifecycle entirely.
		// They are written to external_connections for 3rd party crypto visibility.
		// Skip third-party discoveries without a source IP (cannot create a connection row).
		if classification.Ownership == "third_party" {
			if discovery.SourceIP != nil && *discovery.SourceIP != "" {
				externalEntries = append(externalEntries, externalEntry{
					Discovery:      discovery,
					Classification: classification,
				})
			} else {
				fmt.Printf("Warning: skipping third-party discovery %s (no source IP)\n", discovery.ID)
			}
			continue
		}

		// Evaluate auto-approval rules for managed assets against the
		// batch-scoped rule set loaded above.
		autoApprove, ruleID, err := p.approvalService.EvaluateAutoApprovalWithRules(rules, discovery, classification)
		if err != nil {
			fmt.Printf("Warning: failed to evaluate auto-approval for discovery %s: %v\n", discovery.ID, err)
		}

		finding, err := p.converter.ToIngestFinding(discovery)
		if err != nil {
			fmt.Printf("Warning: failed to convert discovery %s: %v\n", discovery.ID, err)
			continue
		}

		// Promote fields nested inside "raw_metadata" (the sensor-manager envelope)
		// to the top level of RawData so inventory-service's certificate extractor
		// can find the "certificates" array. This mirrors what extractCryptoDetails()
		// already does for the external-connections path.
		if finding.RawData != nil {
			finding.RawData = flattenSensorDiscoveryMetadata(finding.RawData)
		}

		assetStatus := "pending_approval"
		if autoApprove {
			assetStatus = "monitoring"
		}

		if finding.RawData == nil {
			finding.RawData = make(map[string]interface{})
		}
		finding.RawData["network_ownership"] = classification.Ownership
		finding.RawData["network_type"] = classification.Type
		if discovery.SourceIP != nil && *discovery.SourceIP != "" {
			finding.RawData["source_ip"] = *discovery.SourceIP
		}

		findingsWithStatus = append(findingsWithStatus, FindingWithStatus{
			Finding:     *finding,
			AssetStatus: assetStatus,
			Discovery:   discovery,
		})

		if autoApprove && ruleID != nil {
			discovery.ApprovalStatus = "auto_approved"
			discovery.AutoApprovalRuleID = ruleID
		} else {
			discovery.ApprovalStatus = "pending"
		}
	}

	now := time.Now()

	// Discoveries whose outcome is settled, grouped by the exact row state they
	// should be stamped with. Every group is written with ONE
	// `WHERE tenant_id = $ AND id = ANY($)` UPDATE at the end of the batch —
	// see markProcessed. Rows that are NOT added here stay unprocessed and are
	// re-polled.
	marks := newProcessedMarks()

	// --- External connections path ---
	for _, entry := range externalEntries {
		d := entry.Discovery
		crypto := extractCryptoDetails(d.Metadata)

		req := client.ExternalConnectionUpsert{
			SourceIP: *d.SourceIP,
			DestIP:   d.DestIP,
			DestPort: d.Port,
			Protocol: d.Protocol,
			SensorID: &d.SensorID,
		}
		if d.Hostname != nil {
			req.DestHostname = d.Hostname
		}
		if crypto != nil {
			req.ProtocolVersion = crypto.ProtocolVersion
			req.CipherSuite = crypto.CipherSuite
			req.KeyExchangeAlgorithm = crypto.KeyExchangeAlgorithm
			req.KeySize = crypto.KeySize
			req.SupportedTLSVersions = crypto.SupportedTLSVersions
			req.CertSubject = crypto.CertSubject
			req.CertIssuer = crypto.CertIssuer
			req.CertSAN = crypto.CertSAN
			req.CertNotBefore = crypto.CertNotBefore
			req.CertNotAfter = crypto.CertNotAfter
			req.CertFingerprintSHA256 = crypto.CertFingerprintSHA256
			req.CertPublicKeyAlgorithm = crypto.CertPublicKeyAlgorithm
			req.CertPublicKeySize = crypto.CertPublicKeySize
			req.CertSignatureAlgorithm = crypto.CertSignatureAlgorithm
			req.CertValidationStatus = crypto.CertValidationStatus
			req.CertPEM = crypto.CertPEM
			req.CertHasSCT = crypto.CertHasSCT
			req.CertKnownBadCA = crypto.CertKnownBadCA
			req.CertNoSubject = crypto.CertNoSubject
			req.CertNoCommonName = crypto.CertNoCommonName
			req.CertIsEV = crypto.CertIsEV
			req.CertLargeSANCount = crypto.CertLargeSANCount
			req.OCSPStatus = crypto.OCSPStatus
		}

		if err := p.inventoryClient.UpsertExternalConnection(tenantID, req); err != nil {
			// Do NOT stamp processed_at here. A failed upsert means the
			// connection was never recorded anywhere; marking the discovery
			// processed would drop it permanently, so a transient
			// inventory-service outage silently erased every third-party
			// discovery in the batch. Leaving the row unprocessed lets the
			// poller pick the batch up again.
			externalFailed++
			externalErr = err
			fmt.Printf("Warning: failed to upsert external connection for discovery %s (left unprocessed for retry): %v\n", d.ID, err)
			continue
		}

		marks.add(d.ID, "auto_approved", nil)
	}

	// --- Managed asset pipeline ---
	if len(findingsWithStatus) == 0 && len(externalEntries) == 0 {
		return fmt.Errorf("%w for batch %s", ErrNoValidFindings, batchID)
	}

	if len(findingsWithStatus) > 0 {
		monitoringFindings := []converter.IngestFinding{}
		pendingFindings := []converter.IngestFinding{}
		var monitoringDiscoveries []*models.SensorDiscovery
		var pendingDiscoveries []*models.SensorDiscovery

		for _, fws := range findingsWithStatus {
			if fws.AssetStatus == "monitoring" {
				monitoringFindings = append(monitoringFindings, fws.Finding)
				monitoringDiscoveries = append(monitoringDiscoveries, fws.Discovery)
			} else {
				pendingFindings = append(pendingFindings, fws.Finding)
				pendingDiscoveries = append(pendingDiscoveries, fws.Discovery)
			}
		}

		batchJobID := uuid.New()
		totalImported := 0

		if len(monitoringFindings) > 0 {
			response, err := p.inventoryClient.ImportFindings(tenantID, batchJobID, monitoringFindings, "monitoring")
			if err != nil {
				// Flush what IS settled (the external connections already
				// upserted above) before bailing, so the retry does not redo
				// them.
				p.markProcessed(ctx, tenantID, now, marks)
				return fmt.Errorf("failed to import monitoring findings: %w", err)
			}
			totalImported += response.Imported
		}

		if len(pendingFindings) > 0 {
			response, err := p.inventoryClient.ImportFindings(tenantID, batchJobID, pendingFindings, "pending_approval")
			if err != nil {
				p.markProcessed(ctx, tenantID, now, marks)
				return fmt.Errorf("failed to import pending findings: %w", err)
			}
			totalImported += response.Imported
		}

		allDiscoveries := append(monitoringDiscoveries, pendingDiscoveries...)
		for _, discovery := range allDiscoveries {
			marks.add(discovery.ID, discovery.ApprovalStatus, discovery.AutoApprovalRuleID)
		}

		fmt.Printf("Successfully processed batch %s: %d findings imported (%d monitoring, %d pending), %d external connections (%d failed)\n",
			batchID, totalImported, len(monitoringFindings), len(pendingFindings), len(externalEntries)-externalFailed, externalFailed)
	} else {
		fmt.Printf("Successfully processed batch %s: 0 asset findings, %d external connections (%d failed)\n",
			batchID, len(externalEntries)-externalFailed, externalFailed)
	}

	// One transaction, one UPDATE per distinct outcome — see markProcessed.
	p.markProcessed(ctx, tenantID, now, marks)

	if externalFailed > 0 {
		// Their rows are still unprocessed. Report the batch as failed so the
		// poller retries with backoff (and, if the failure is permanent,
		// terminates it via markBatchAsFailed) rather than leaving the rows to
		// be rediscovered every poll cycle forever.
		return fmt.Errorf("%d of %d external connection upserts failed: %w",
			externalFailed, len(externalEntries), externalErr)
	}

	return nil
}

// processedMark is the row state a settled discovery should be stamped with.
// Discoveries sharing a mark are updated together in one statement.
type processedMark struct {
	approvalStatus string
	ruleID         string // "" == NULL
}

// processedMarks groups settled discovery ids by their outcome.
type processedMarks struct {
	order []processedMark
	ids   map[processedMark][]string
}

func newProcessedMarks() *processedMarks {
	return &processedMarks{ids: make(map[processedMark][]string)}
}

func (m *processedMarks) add(id uuid.UUID, approvalStatus string, ruleID *uuid.UUID) {
	key := processedMark{approvalStatus: approvalStatus}
	if ruleID != nil {
		key.ruleID = ruleID.String()
	}
	if _, seen := m.ids[key]; !seen {
		m.order = append(m.order, key)
	}
	m.ids[key] = append(m.ids[key], id.String())
}

func (m *processedMarks) empty() bool { return len(m.order) == 0 }

// markProcessed stamps every settled discovery in one transaction, with one
// UPDATE per distinct (approval_status, auto_approval_rule_id) outcome.
//
// It used to be one WithTenantTx — and therefore one transaction, one
// BEGIN/SET app.tenant_id/COMMIT round-trip — PER DISCOVERY, each running
// `WHERE id = $1` with no tenant_id predicate. sensor_discoveries is a view
// over an 8-way HASH-partitioned table, so an id-only predicate cannot prune
// partitions: every single-row update scanned all eight. Including tenant_id
// lets the planner prune to the one partition that can hold the row, and
// `id = ANY(...)` collapses a batch into a handful of statements.
//
// Failures are logged, not returned: the rows simply stay unprocessed and the
// batch is re-polled, which is the same outcome the per-row version produced.
func (p *BatchProcessor) markProcessed(ctx context.Context, tenantID uuid.UUID, now time.Time, marks *processedMarks) {
	if marks == nil || marks.empty() {
		return
	}

	// RLS-scoped write on sensor_discoveries (security_invoker view over the
	// partitioned table). All rows belong to tenantID; WithTenantTx sets
	// app.tenant_id so the UPDATEs satisfy the policy.
	err := shareddatabase.WithTenantTx(ctx, p.db.DB, tenantID, func(tx *sql.Tx) error {
		for _, key := range marks.order {
			ids := marks.ids[key]
			var ruleID interface{}
			if key.ruleID != "" {
				ruleID = key.ruleID
			}
			if _, e := tx.ExecContext(ctx, `
				UPDATE sensor_discoveries
				SET processed_at = $1, approval_status = $2, auto_approval_rule_id = $3::uuid
				WHERE tenant_id = $4 AND id = ANY($5::uuid[])`,
				now, key.approvalStatus, ruleID, tenantID, pq.Array(ids),
			); e != nil {
				return e
			}
		}
		return nil
	})
	if err != nil {
		fmt.Printf("Warning: failed to mark discoveries processed for tenant %s: %v\n", tenantID, err)
	}
}

// classifyNetwork classifies via inventory-service network-segments/classify-asset; falls back to RFC 1918 on error.
// Returns one of three Ownership values:
//   - "internal"    — IP matches a known tenant segment
//   - "third_party" — IP is a public internet address not in any registered segment
//   - "unknown"     — IP is RFC 1918 private but not in any known segment
func (p *BatchProcessor) classifyNetwork(tenantID uuid.UUID, ipAddress string, hostname *string) *models.NetworkClassification {
	classification := &models.NetworkClassification{
		Type: "public",
	}

	resp, err := p.inventoryClient.ClassifyAsset(tenantID, ipAddress, hostname)
	if err != nil {
		// Fallback: RFC 1918 private → unknown (unregistered internal subnet),
		// public → third_party.
		ip := net.ParseIP(ipAddress)
		if ip != nil && ip.IsPrivate() {
			classification.Ownership = "unknown"
			classification.Type = "private"
		} else {
			classification.Ownership = "third_party"
		}
		return classification
	}

	switch resp.Ownership {
	case "internal":
		classification.Ownership = "internal"
	case "third_party":
		classification.Ownership = "third_party"
	default:
		// inventory-service returned "unknown" or anything else — determine via RFC 1918
		ip := net.ParseIP(ipAddress)
		if ip != nil && ip.IsPrivate() {
			classification.Ownership = "unknown"
		} else {
			classification.Ownership = "third_party"
		}
	}
	classification.Type = resp.NetworkType
	if classification.Type == "" {
		if classification.Ownership == "internal" || classification.Ownership == "unknown" {
			classification.Type = "private"
		} else {
			classification.Type = "public"
		}
	}
	if resp.SegmentID != nil && *resp.SegmentID != "" {
		if id, err := uuid.Parse(*resp.SegmentID); err == nil {
			classification.SegmentID = &id
		}
	}
	classification.SegmentName = resp.SegmentName
	return classification
}

// shouldKeepCloudPlaceholderManaged returns true for cloud API discoveries that
// represent non-network resources (KMS keys, storage buckets, SQL databases)
// rather than an observed network connection. WriteSensorDiscoveries uses an
// unspecified IP placeholder for those rows; routing them to the third-party
// connection path would require source_ip and drop/reject the asset instead of
// importing it.
func shouldKeepCloudPlaceholderManaged(discovery *models.SensorDiscovery, classification *models.NetworkClassification) bool {
	if discovery == nil || classification == nil || classification.Ownership != "third_party" {
		return false
	}
	if discovery.SourceIP != nil && *discovery.SourceIP != "" {
		return false
	}
	ip := net.ParseIP(discovery.DestIP)
	if ip == nil || !ip.IsUnspecified() {
		return false
	}

	var metadata map[string]interface{}
	if err := json.Unmarshal(discovery.Metadata, &metadata); err != nil {
		return false
	}
	method, _ := metadata["discovery_method"].(string)
	return method == "cloud_api"
}

// reverseDNSLookup performs a PTR lookup for the given IP address with a 3s timeout.
// Returns the first resolved hostname (with trailing dot stripped), or empty string on failure/timeout.
func reverseDNSLookup(ipAddress string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(ctx, ipAddress)
	if err != nil || len(names) == 0 {
		return ""
	}
	// net.LookupAddr returns FQDNs with a trailing dot; strip it.
	name := names[0]
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}
	return name
}
