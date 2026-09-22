package processor

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// ErrNoValidFindings marks a batch that produced nothing importable — every
// discovery was skipped for missing data. It is terminal: retrying cannot make
// the same rows importable. A sentinel rather than a magic substring, so the
// poller classifies it with errors.Is instead of grepping err.Error().
var ErrNoValidFindings = errors.New("no valid findings to import")

// AuditSink records one unit of consumer work on the shared audit path.
// *auditmiddleware.Middleware satisfies it; tests substitute a recorder.
type AuditSink interface {
	LogConsumerEvent(ctx context.Context, ev auditmiddleware.ConsumerEvent) error
}

// BatchProcessor processes batches of sensor discoveries
type BatchProcessor struct {
	db              *sqlx.DB
	converter       *converter.SensorDiscoveryConverter
	approvalService *approval.Service
	inventoryClient *client.InventoryClient
	audit           AuditSink
}

// NewBatchProcessor creates a new batch processor.
//
// auditSink may be nil (no audit-service configured); the batch then records
// nothing rather than failing.
func NewBatchProcessor(
	db *sqlx.DB,
	converter *converter.SensorDiscoveryConverter,
	approvalService *approval.Service,
	inventoryClient *client.InventoryClient,
	auditSink AuditSink,
) *BatchProcessor {
	return &BatchProcessor{
		db:              db,
		converter:       converter,
		approvalService: approvalService,
		inventoryClient: inventoryClient,
		audit:           auditSink,
	}
}

// batchAudit accumulates what a batch materialized, for the audit record
// emitted when ProcessBatch returns.
//
// Counts only — never a discovery's contents. A sensor discovery carries
// certificates, hostnames and negotiated crypto; the audit trail's job is to
// say a batch for tenant T turned N discoveries into M assets, not to become a
// second copy of the discovery data.
type batchAudit struct {
	started  time.Time
	counts   map[string]int
	imported int
}

// classifyBatchError maps a batch failure to a short, payload-free label.
// err.Error() routinely quotes the finding that failed, which is exactly what
// must not reach the audit store.
func classifyBatchError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, ErrNoValidFindings) {
		return "no_valid_findings"
	}
	var statusErr *client.HTTPStatusError
	if errors.As(err, &statusErr) {
		return fmt.Sprintf("inventory_http_%d", statusErr.StatusCode)
	}
	return "batch_failed"
}

// logBatchAudit records the outcome of one discovery batch.
//
// discovery-processor-service materializes sensor discoveries into tenant
// assets, certificates and external connections. Its HTTP surface is
// /health, /metrics and /status only, so the LogRequest middleware the HTTP
// services mount has nothing to attach to — every asset it created was
// invisible to the audit trail. This is the consumer-path equivalent.
func (p *BatchProcessor) logBatchAudit(ctx context.Context, tenantID uuid.UUID, batchID string, ba *batchAudit, err error) {
	if p.audit == nil {
		return
	}

	eventType := "discovery.batch.processed"
	if err != nil {
		eventType = "discovery.batch.failed"
	}
	ba.counts["assets_imported"] = ba.imported

	tid := tenantID
	if logErr := p.audit.LogConsumerEvent(ctx, auditmiddleware.ConsumerEvent{
		TenantID:      &tid,
		Source:        "discovery-batch",
		EventCategory: "discovery",
		EventType:     eventType,
		Action:        "process",
		ResourceType:  "discovery_batch",
		ResourceRef:   batchID,
		Counts:        ba.counts,
		Duration:      time.Since(ba.started),
		Success:       err == nil,
		ErrorKind:     classifyBatchError(err),
	}); logErr != nil {
		fmt.Printf("Warning: failed to record audit event for batch %s: %v\n", batchID, logErr)
	}
}

// ProcessBatch processes a batch of discoveries.
// Discoveries are split into two tracks:
//   - third_party (public internet) → external_connections table via UpsertExternalConnection
//   - everything else               → managed asset lifecycle (approval, compliance, findings)
func (p *BatchProcessor) ProcessBatch(batchID string, tenantID uuid.UUID) (err error) {
	// ProcessBatch is invoked per-(batch, tenant) by the poller, which already
	// resolved tenantID. No ctx is threaded into this method, so use
	// context.Background() to match the existing pattern.
	ctx := context.Background()

	// One audit record per batch, on every exit path. The named return is what
	// lets the deferred emit see the outcome — ProcessBatch returns from a
	// dozen places and an emit at the bottom would miss most of the failures,
	// which are the ones worth recording.
	ba := &batchAudit{started: time.Now(), counts: map[string]int{}}
	defer func() { p.logBatchAudit(ctx, tenantID, batchID, ba, err) }()

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
	err = shareddatabase.WithTenantTx(ctx, p.db.DB, tenantID, func(tx *sql.Tx) error {
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

	ba.counts["discoveries_read"] = len(discoveries)

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
		// HostnameSourceKind is the provenance of Discovery.Hostname in the
		// ADR-0005 vocabulary, or "" when nothing stated it. Carried beside
		// the discovery rather than on it because sensor_discoveries has no
		// column for it — it exists to travel to external_connections, which
		// does.
		HostnameSourceKind string
	}
	var externalEntries []externalEntry
	var findingsWithStatus []FindingWithStatus

	// Third-party upserts that failed. Their discoveries are deliberately left
	// unprocessed (see below) and the batch is reported as failed so the poller
	// retries it with backoff instead of treating a dropped connection as done.
	externalFailed := 0
	var externalErr error

	// What each destination in this batch was actually asked for, before any
	// row is looked at on its own. The active enricher's row cannot answer that
	// question about itself — its passive sibling can. See batchSNIIndex.
	sniIndex := buildBatchSNIIndex(discoveries)

	for _, discovery := range discoveries {
		// Host observations (asset-inventory ADR-0004 D2) travel through this
		// loop untouched by two steps that would otherwise misread them.
		hostObservation := isHostObservationDiscovery(discovery)

		// Fill a missing hostname, preferring measured facts over inference.
		//
		// Not for a host observation. Its names are the measurement — what the
		// host called itself over DHCP, mDNS or NetBIOS — and a resolver answer
		// (or a TLS SNI, which is meaningless for a non-TLS observation) is a
		// different claim from a different source. Mixing the two into one
		// hostname field destroys the provenance the identification engine
		// needs, and for an observation whose dest_ip is 0.0.0.0 ("no address
		// observed") a lookup is a wasted query as well.
		//
		// The provenance of whatever name the row ends up with is tracked
		// alongside it. A name the row ALREADY carried is measured: every
		// producer that fills sensor_discoveries.hostname fills it from
		// something read off the wire — the sensor's own reported hostname,
		// raw_metadata's hostname, or the captured SNI (sensor-manager's
		// StoreDiscoveries), or the SNI alone (pcap-processor). None of them
		// resolves anything. The only inference in this pipeline is the PTR
		// lookup below, and it is the only thing labelled `inferred`.
		hostnameSourceKind := ""
		if discovery.Hostname != nil && strings.TrimSpace(*discovery.Hostname) != "" {
			hostnameSourceKind = string(identity.SourceMeasured)
		} else if !hostObservation {
			if resolved := resolveMissingHostname(discovery.Metadata, discovery.DestIP, sniIndex.lookup(discovery), lookupPTR); resolved.Name != "" {
				name := resolved.Name
				discovery.Hostname = &name
				hostnameSourceKind = resolved.SourceKind
			}
		}

		classification := p.classifyNetwork(tenantID, discovery.DestIP, discovery.Hostname, cloudResourceHint(discovery))
		if shouldKeepCloudPlaceholderManaged(discovery, classification) {
			classification.Ownership = "unknown"
			classification.Type = "private"
		}
		if hostObservation && classification.Ownership == "third_party" {
			// A passively observed host is never a third party, whatever its
			// address classifies as.
			//
			// `third_party` means "a public endpoint something here connected
			// OUT to", and that is a statement about a FLOW. A host observation
			// is a statement that a device exists on a segment we are watching:
			// there is no flow, no far end, and the device is on our own wire.
			// Two ways it reached third_party — an observation with no address
			// at all (dest_ip 0.0.0.0, which is not RFC 1918) and one carrying a
			// public address that is simply not in a registered segment — and
			// both are the classifier answering a question it was not asked.
			//
			// `unknown` rather than `internal`, because we genuinely do not know
			// it is in a registered segment; that is what `unknown` means, and
			// it keeps the row on the managed-asset path where it belongs.
			// Auto-approval still has to find a matching segment rule to fire,
			// so this widens nothing.
			classification.Ownership = "unknown"
		}

		// Third-party public internet connections bypass the asset lifecycle entirely.
		// They are written to external_connections for 3rd party crypto visibility.
		// Skip third-party discoveries without a source IP (cannot create a connection row).
		//
		// A host observation is never one of these, whatever its address
		// classifies as. external_connections records a CONNECTION — a flow
		// between two endpoints with a protocol and a cipher — and a host
		// observation has no flow, no source and no cryptography. Without this
		// guard an observation of a host with a public address would be routed
		// there and then dropped for having no source IP, logging a warning
		// about a row that was never a connection.
		if !hostObservation && classification.Ownership == "third_party" {
			if discovery.SourceIP != nil && *discovery.SourceIP != "" {
				externalEntries = append(externalEntries, externalEntry{
					Discovery:          discovery,
					Classification:     classification,
					HostnameSourceKind: hostnameSourceKind,
				})
			} else {
				fmt.Printf("Warning: skipping third-party discovery %s (no source IP)\n", discovery.ID)
			}
			continue
		}

		// Evaluate auto-approval rules for managed assets against the
		// batch-scoped rule set loaded above.
		//
		// The observation's KIND is part of the rule vocabulary, so a tenant can
		// write `kind:host_observation and network.segment_id=…` — auto-approve
		// the passively seen hosts on a segment I own — without that rule also
		// approving every TLS endpoint the same sensor reports. `source` cannot
		// express it: both come from the sensor.
		approvalInput := discovery.ApprovalInput().WithKind(approvalKindOf(hostObservation))
		autoApprove, ruleID, err := p.approvalService.EvaluateAutoApprovalWithRules(rules, approvalInput, classification)
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
		if hostnameSourceKind != "" {
			// inventory-service can also route a finding to
			// external_connections from the INGEST side (AssetService's
			// routeToExternalConnection), on its own classification rather than
			// ours. A name that reached this row by reverse DNS must still be
			// labelled an inference when it arrives there, or it outranks a
			// stored measurement and we are back where we started by a
			// different door.
			finding.RawData["dest_hostname_source_kind"] = hostnameSourceKind
		}
		if discovery.SourceIP != nil && *discovery.SourceIP != "" {
			finding.RawData["source_ip"] = *discovery.SourceIP
		}

		findingsWithStatus = append(findingsWithStatus, FindingWithStatus{
			Finding:     *finding,
			AssetStatus: assetStatus,
			Discovery:   discovery,
		})

		if hostObservation {
			// A host observation is identity evidence — "this device exists on
			// a segment we watch" — not a cryptographic finding awaiting a
			// human's approval. `assetStatus` above still decides what a NEW
			// asset lands as; this is the separate, row-level answer to "does
			// this discovery need an approval decision", and for a host
			// observation the honest answer is that none will ever be made,
			// whatever the resulting asset's own status is. `observed` says
			// so as a terminal value, rather than leaving the row `pending`
			// (or crediting a rule with `auto_approved`) where nothing —
			// Discovery → Approvals included — will ever clear it.
			discovery.ApprovalStatus = "observed"
		} else if autoApprove && ruleID != nil {
			discovery.ApprovalStatus = "auto_approved"
			discovery.AutoApprovalRuleID = ruleID
		} else {
			discovery.ApprovalStatus = "pending"
		}
	}

	// Host observations are forwarded to inventory-service like everything else
	// now — the consumer exists (asset-inventory workstream 2.5, consumer half).
	//
	// They used to be REMOVED from the batch here by splitHeldHostObservations,
	// because inventory-service re-bound every finding through
	// ClusterSensorFinding, which had no `kind` field, and would therefore act
	// on an observation as if it were a crypto finding: route it to
	// external_connections, DNS-resolve a LAN-only hostname, or mint another
	// nameless `server`. `kind` now survives the boundary and
	// inventory-service's ingest branches on it before any of those three can
	// happen. `TestHostObservationsReachInventoryWithTheirKind` and
	// inventory-service's own resolver-ban test are what hold that open.
	//
	// Counted so an operator can still see how much of a batch was host
	// presence rather than cryptography — the number that was
	// `host_observations_held`, now saying what actually happens to them.
	ba.counts["host_observations_forwarded"] = countHostObservations(findingsWithStatus)

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
		if sourceAssetID := sourceAssetIDFromMetadata(d.Metadata); sourceAssetID != nil {
			req.SourceAssetID = sourceAssetID
		}
		if d.Hostname != nil {
			req.DestHostname = d.Hostname
			if entry.HostnameSourceKind != "" {
				kind := entry.HostnameSourceKind
				req.DestHostnameSourceKind = &kind
			}
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
			req.CertSCTSource = crypto.CertSCTSource
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

	ba.counts["internal_findings"] = len(findingsWithStatus)
	ba.counts["external_connections"] = len(externalEntries) - externalFailed
	ba.counts["external_failed"] = externalFailed

	// --- Managed asset pipeline ---
	// A batch of nothing but host observations was processed correctly — the
	// rows are stored and deliberately not imported. Returning
	// ErrNoValidFindings for it would mark a healthy batch permanently failed,
	// because that sentinel is classified as terminal.
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

		ba.counts["monitoring"] = len(monitoringFindings)
		ba.counts["pending_approval"] = len(pendingFindings)

		batchJobID := uuid.New()
		totalImported := 0

		if len(monitoringFindings) > 0 {
			imported, err := p.importInChunks(tenantID, batchJobID, monitoringFindings, monitoringDiscoveries, "monitoring")
			totalImported += imported
			ba.imported = totalImported
			if err != nil {
				// Flush what IS settled (the external connections already
				// upserted above) before bailing, so the retry does not redo
				// them.
				p.markProcessed(ctx, tenantID, now, marks)
				return fmt.Errorf("failed to import monitoring findings: %w", err)
			}
		}

		if len(pendingFindings) > 0 {
			imported, err := p.importInChunks(tenantID, batchJobID, pendingFindings, pendingDiscoveries, "pending_approval")
			totalImported += imported
			ba.imported = totalImported
			if err != nil {
				p.markProcessed(ctx, tenantID, now, marks)
				return fmt.Errorf("failed to import pending findings: %w", err)
			}
		}

		allDiscoveries := append(monitoringDiscoveries, pendingDiscoveries...)
		for _, discovery := range allDiscoveries {
			// discovery.AssetID is what adoptAssetID read off the import
			// response — the asset this row actually landed on, or nil.
			marks.addWithAsset(discovery.ID, discovery.ApprovalStatus, discovery.AutoApprovalRuleID, discovery.AssetID)
		}

		// "%d assets created/updated" is inventory-service's import counter: assets
		// created + assets refreshed/status-changed + findings routed to
		// external_connections. Pending-approval findings DO create assets — their
		// certificates/crypto configurations are deferred into asset metadata until
		// the asset is approved (Discovery → Approvals), so a batch that reports
		// pending findings here has produced work even though the certificates and
		// crypto_implementations tables stay empty.
		deferredNote := ""
		if len(pendingFindings) > 0 {
			deferredNote = " — certs/crypto deferred until approval"
		}
		fmt.Printf("Successfully processed batch %s: %d internal findings (%d monitoring, %d pending approval%s), %d assets created/updated, %d external connections (%d failed)\n",
			batchID, len(monitoringFindings)+len(pendingFindings), len(monitoringFindings), len(pendingFindings), deferredNote,
			totalImported, len(externalEntries)-externalFailed, externalFailed)
	} else {
		// This branch means the batch produced no importable internal
		// (managed-asset) findings — everything was classified third_party or
		// held back as a host observation. Say which, rather than the old "0
		// asset findings", which read as "the pipeline produced nothing" even
		// when other batches were creating pending assets.
		fmt.Printf("Successfully processed batch %s: no internal findings imported from this batch (%d external connection(s), %d failed)\n",
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

func sourceAssetIDFromMetadata(raw []byte) *uuid.UUID {
	if len(raw) == 0 {
		return nil
	}
	var metadata map[string]any
	if json.Unmarshal(raw, &metadata) != nil {
		return nil
	}
	if metadata["discovery_type"] != "host_connection" || metadata["discovery_method"] != "host_inventory" {
		return nil
	}
	value, _ := metadata["source_asset_id"].(string)
	id, err := uuid.Parse(strings.TrimSpace(value))
	if err != nil {
		return nil
	}
	return &id
}

// FindingWithStatus pairs a converted finding with the asset status
// discovery-processor already decided for it and the row it came from.
type FindingWithStatus struct {
	Finding     converter.IngestFinding
	AssetStatus string
	Discovery   *models.SensorDiscovery
}

// countHostObservations reports how many of a batch's findings are passive
// host-presence rows rather than cryptographic measurements.
//
// It replaced splitHeldHostObservations, which used to REMOVE them from the set
// handed to inventory-service. The hold existed because the boundary between
// the two services lost the one field that distinguished them:
// inventory-service re-bound every finding through ClusterSensorFinding, which
// had no `kind`, so a host observation arriving there was acted on as a crypto
// finding — classified third_party for having no RFC-1918 address and written
// into external_connections, or DNS-resolved on a hostname that exists only on
// the customer's LAN, or turned into another nameless asset typed `server`.
//
// `kind` now crosses the boundary (converter.IngestFinding.Kind →
// services.ClusterSensorFinding.Kind → services.IngestFinding.Kind) and
// inventory-service branches on it before any of those three can happen. The
// count stays because "how much of this batch was host presence" is still the
// question an operator asks of a batch log.
func countHostObservations(findings []FindingWithStatus) int {
	n := 0
	for _, fws := range findings {
		if fws.Finding.Kind == converter.KindHostObservation {
			n++
		}
	}
	return n
}

// approvalKindOf maps "is this a host observation" onto the `kind` vocabulary
// the observation target publishes (shared/query/catalog/registrycatalog).
//
// Both values are STATED rather than one being left absent. A rule writer can
// then say `kind:crypto` and mean it — where leaving the crypto path empty
// would make that predicate Unknown for the very findings it names, which is
// the "a check that cannot fire" shape. The paths that genuinely have no answer
// (manual create, spreadsheet import, CMDB pull) are the ones that leave it
// empty.
func approvalKindOf(hostObservation bool) string {
	if hostObservation {
		return converter.KindHostObservation
	}
	return approval.KindCrypto
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
	// assets is the asset each settled discovery landed on, for the rows that
	// landed on one. Per-row rather than per-mark, so it cannot ride on the
	// grouped UPDATE and gets its own statement — see markProcessed.
	assets map[string]string
}

func newProcessedMarks() *processedMarks {
	return &processedMarks{ids: make(map[processedMark][]string), assets: make(map[string]string)}
}

func (m *processedMarks) add(id uuid.UUID, approvalStatus string, ruleID *uuid.UUID) {
	m.addWithAsset(id, approvalStatus, ruleID, nil)
}

func (m *processedMarks) addWithAsset(id uuid.UUID, approvalStatus string, ruleID *uuid.UUID, assetID *uuid.UUID) {
	key := processedMark{approvalStatus: approvalStatus}
	if ruleID != nil {
		key.ruleID = ruleID.String()
	}
	if _, seen := m.ids[key]; !seen {
		m.order = append(m.order, key)
	}
	m.ids[key] = append(m.ids[key], id.String())
	if assetID != nil && *assetID != uuid.Nil {
		m.assets[id.String()] = assetID.String()
	}
}

// assetPairs returns the (discovery id, asset id) pairs to write, in a stable
// order so the two unnest arrays line up and a test can assert on them.
func (m *processedMarks) assetPairs() (discoveryIDs, assetIDs []string) {
	for _, key := range m.order {
		for _, id := range m.ids[key] {
			if assetID, ok := m.assets[id]; ok {
				discoveryIDs = append(discoveryIDs, id)
				assetIDs = append(assetIDs, assetID)
			}
		}
	}
	return discoveryIDs, assetIDs
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
// importChunkSize bounds how many findings go to inventory-service in one
// import call.
//
// The import is O(n) on the far side — per finding it resolves identity,
// scores the catalogue risk and publishes an event, measured at 100-280ms
// each on a dev cluster — while the client that calls it holds a 30s timeout
// (client.NewInventoryClient). One call per batch therefore could not survive
// a batch of any size: seeding a 4-site tenant produced batches of 338, 208
// and 156 findings, every one of which blew the deadline, exhausted the retry
// ladder and left its rows marked `rejected` — while inventory-service,
// which never saw the client leave, finished all three imports anyway and
// did each of them three times over, once per retry.
//
// 50 keeps a chunk near 10s at the slowest observed rate, which leaves room
// for a far side several times slower than measured before anything times
// out again.
const importChunkSize = 50

// importInChunks imports findings in importChunkSize-sized calls, returning
// how many were imported before any error.
//
// Chunks share the batch's job ID: inventory-service uses it only to stamp the
// audit event, so one logical import stays one job in the audit trail.
//
// A chunk that fails abandons the rest — the caller retries the whole batch,
// and the upserts on the far side are idempotent (proved in anger:'s
// three concurrent imports of the same batch still produced exactly one crypto
// implementation per endpoint). Re-importing a chunk that already landed is
// wasted work, not corruption.
// discoveries is index-aligned with findings: entry i is the row finding i was
// converted from, and it is what adoptEffectiveStatus stamps.
func (p *BatchProcessor) importInChunks(tenantID, jobID uuid.UUID, findings []converter.IngestFinding, discoveries []*models.SensorDiscovery, assetStatus string) (int, error) {
	imported := 0
	unknownOutcomes := map[string]int{}
	defer func() {
		// Loud, once per import, naming the value and how many rows carried it
		// — the thing the batch-rejecting version never managed to be.
		for outcome, n := range unknownOutcomes {
			fmt.Printf("Warning: inventory-service reported outcome %q for %d finding(s) this build has no arm for; their discovery rows were left as the rules set them. Teach applyIngestOutcome about it.\n",
				outcome, n)
		}
	}()
	for start := 0; start < len(findings); start += importChunkSize {
		end := start + importChunkSize
		if end > len(findings) {
			end = len(findings)
		}
		response, err := p.inventoryClient.ImportFindings(tenantID, jobID, findings[start:end], assetStatus)
		if err != nil {
			return imported, fmt.Errorf("chunk %d-%d of %d: %w", start, end, len(findings), err)
		}
		imported += response.Imported
		if end > len(discoveries) {
			// The two slices are built side by side by the caller, so this
			// cannot happen without a bug — and a silent no-op would leave
			// every row in the batch stamped from the rule result alone, which
			// is the failure this function exists to prevent. Say so.
			fmt.Printf("Warning: %d findings were imported against only %d discovery rows; their row state was left as the rules set it\n",
				len(findings), len(discoveries))
			continue
		}
		adoptEffectiveStatus(discoveries[start:end], response.AssetStatuses)
		if len(response.Results) != 0 {
			if len(response.Results) != end-start {
				return imported, fmt.Errorf("inventory returned %d outcomes for %d findings", len(response.Results), end-start)
			}
			for i, result := range response.Results {
				d := discoveries[start+i]
				adoptAssetID(d, result.AssetID)
				if err := applyIngestOutcome(d, result); err != nil {
					if errors.Is(err, errUnknownIngestOutcome) {
						// One row this build has no arm for must not cost the
						// other forty-nine. See errUnknownIngestOutcome.
						unknownOutcomes[result.Outcome]++
						continue
					}
					return imported, err
				}
			}
		}
	}
	return imported, nil
}

// errUnknownIngestOutcome is what [applyIngestOutcome] reports for an outcome
// this build has no arm for.
//
// It is a sentinel, and importInChunks does NOT fail the batch on it, because
// the alternative was measured: `supporting` — an identity outcome that has
// existed since and shipped in core-v1.0.0 — was never added to the
// switch below, so every batch containing one supporting row errored, was
// retried three times as if the error were transient, and then had ALL of its
// rows stamped `processed_at` + `approval_status = 'rejected'` by
// markBatchAsFailed. 5,006 rows on the dev cluster, ~500/hour, for as long as
// the rule had been on. Nobody noticed, because a rejected row reads as a
// decision somebody made rather than as evidence thrown away.
//
// So: an outcome we cannot interpret is a fact about THIS BUILD, not about the
// forty-nine other findings in the chunk. The row keeps the state the
// auto-approval rules gave it — `pending` at worst, which is visible, joined to
// its asset by adoptAssetID and settleable by inventory-service's
// settleDiscoveryQueueRows once a human decides — and every other row in the
// batch lands. Rejecting them all converts "we added a new outcome" into silent
// bulk data loss; leaving one row on the rules' answer converts it into a log
// line and, at worst, a stale queue row.
//
// The rows still get `processed_at` (markProcessed runs), so nothing loops.
var errUnknownIngestOutcome = errors.New("inventory returned an unrecognized outcome")

// applyIngestOutcome settles one discovery row from the identity outcome
// inventory-service reported for the finding that row produced.
//
// This switch is the ONLY definition of which outcomes this service
// understands; ingest_outcome_coverage_test.go drives it with every
// [identity.Outcome] constant declared in shared/identity and fails if any of
// them lands in the default arm. That guard is the real fix here — the switch
// and the Outcome set drifting apart with nothing noticing is what produced the
// data loss described on errUnknownIngestOutcome.
func applyIngestOutcome(d *models.SensorDiscovery, result identity.IngestResult) error {
	switch result.Outcome {
	case string(identity.OutcomeUnresolved), string(identity.OutcomeConflict):
		// Evidence was committed, but identity admission made no
		// monitoring approval. Do not retry retained evidence.
		if result.Outcome == string(identity.OutcomeUnresolved) && result.ObservationID == "" {
			return fmt.Errorf("unresolved ingestion omitted durable observation ID")
		}
		if result.AssetID == "" && d != nil {
			d.ApprovalStatus = "observed"
			d.AutoApprovalRuleID = nil
		}
	case "routed":
		// Not an identity.Outcome: asset_service stamps it itself for a
		// finding it classified third-party, so there is no constant to
		// name here.
		//
		// The finding landed on NO asset: inventory-service
		// classified it third-party and wrote it to
		// external_connections instead. The evidence is recorded —
		// somewhere else — and no approval decision about this row
		// will ever be made, because Discovery → Approvals lists
		// pending ASSETS and this finding produced none.
		//
		// `observed` rather than `auto_approved`: nothing approved
		// anything here, and a row claiming an approval nobody made
		// is the same dishonesty adoptEffectiveStatus's own comment
		// argues against. `observed` is the value this column
		// already carries for "recorded as evidence, no approval
		// decision will ever follow" (host observations, and the
		// unresolved branch above).
		//
		// This is what left the two CloudFront rows of's
		// audit `pending` forever: EffectiveStatus is deliberately
		// empty for a routed finding, so adoptEffectiveStatus left
		// the rule's `pending` in place and nothing ever cleared it.
		if d != nil && !isHostObservationDiscovery(d) {
			d.ApprovalStatus = "observed"
			d.AutoApprovalRuleID = nil
		}
	case string(identity.OutcomeCreated), string(identity.OutcomeMatched),
		string(identity.OutcomeProvisional), string(identity.OutcomeSupporting):
		// Nothing to correct here. All four landed the finding ON an asset,
		// so the row's fate is that asset's fate, and two mechanisms already
		// govern it honestly: adoptEffectiveStatus has just stamped the row
		// from the status the asset ACTUALLY has (`auto_approved` when it is
		// monitoring, `suppressed` when archived/denied), and adoptAssetID has
		// linked the row to the asset so inventory-service's
		// settleDiscoveryQueueRows closes it out when a human decides on a
		// still-pending one.
		//
		// The two arms are here rather than on `observed` for exactly
		// that reason. `observed` means "recorded as evidence, no approval
		// decision will EVER follow" — true for `routed` and for an
		// asset-less `unresolved`, and false for both of these:
		//
		//   provisional — the engine CREATED an asset (pending_approval,
		//     identity_status provisional). It is in Discovery → Approvals
		//     waiting for a person, exactly like `created`.
		//   supporting  — another sighting of an asset we already hold, which
		//     may itself be a provisional asset still awaiting that decision.
		//     Stamping `observed` would both deny a decision that is still
		//     coming and overwrite the accurate `auto_approved`
		//     adoptEffectiveStatus just wrote for an already-monitoring one,
		//     replacing a true statement with a vaguer one.
		//
		// Neither outcome is an approval, and neither arm claims one: no arm
		// here ever writes `auto_approved`.
	case "rejected":
		// Also not an identity.Outcome: like "routed", asset_service stamps
		// it for a finding it declined to materialize (the asset is archived
		// or denied), so there is no constant to name.
		if d != nil {
			d.ApprovalStatus = "suppressed"
			d.AutoApprovalRuleID = nil
		}
	default:
		return fmt.Errorf("%w: %q", errUnknownIngestOutcome, result.Outcome)
	}
	return nil
}

// adoptAssetID records which asset a discovery row actually landed on.
//
// `sensor_discoveries.asset_id` has existed all along, is SELECTed into every
// row this service reads, and was never written by anything — so a processed
// queue row and the asset it produced had no link between them at all. That is
// what made "no user action clears them" literally true for the six cloud rows
// in's audit: approving the asset in Discovery → Approvals cannot settle
// a queue row it has no way to find.
//
// The id is already on the wire — inventory-service returns it per finding in
// `results[].asset_id` (identity.IngestResult), which this loop was already
// reading for its Outcome. Only rows that landed on an asset get one; a routed,
// rejected or contested finding leaves the column NULL, which is the honest
// answer for a row that produced no asset.
func adoptAssetID(d *models.SensorDiscovery, assetID string) {
	if d == nil {
		return
	}
	id, err := uuid.Parse(strings.TrimSpace(assetID))
	if err != nil || id == uuid.Nil {
		// Not an answer: an older inventory-service omits the field, and a
		// routed/rejected finding has no asset. Leave whatever the row had.
		return
	}
	d.AssetID = &id
}

// adoptEffectiveStatus corrects the row state for findings inventory-service
// materialized despite this service having asked for `pending_approval`.
//
// A discovery row is stamped from the auto-approval rule that matched it, and a
// row that matched none is `pending`. That is right for a finding that created
// an asset and wrong for one that landed on an asset the tenant approved long
// ago: inventory-service writes its certificates and crypto configuration
// immediately, and the row is then pending forever — the only thing that clears
// pending is a human approving a PENDING ASSET in Discovery → Approvals, and
// there is no pending asset to approve. Eleven access points with TLS-on-8443
// rows, and eighty host observations, sat in exactly that state on a dev
// cluster.
//
// `auto_approved` rather than a new value: it is the vocabulary the rest of the
// system already reads (cluster-sensor-service's per-batch stats count
// `auto_approved` against everything else), and `auto_approval_rule_id` stays
// NULL, which says truthfully that no rule fired.
//
// It also carries the other side of the same fix: a finding that matched an
// asset the tenant has taken off the table — `archived` or `denied` —
// materializes NOTHING (asset_service.go IngestFindings skips both), and no
// approval decision will ever be made about that row either. `suppressed` says
// so as a terminal value, the same way `observed` already does for host
// observations, rather than leaving the row `pending` where nothing will ever
// clear it.
//
// Silence is the safe answer. An inventory-service older than the field sends
// nothing, and then every row keeps the state it had.
func adoptEffectiveStatus(discoveries []*models.SensorDiscovery, statuses []string) {
	if len(statuses) == 0 {
		return
	}
	if len(statuses) != len(discoveries) {
		// Two slices that should be the same length are not, so no entry can be
		// trusted to describe the row at its index. Stamping anyway would put
		// one discovery's outcome on another.
		fmt.Printf("Warning: inventory-service returned %d asset statuses for %d findings; leaving the discovery rows as they are\n",
			len(statuses), len(discoveries))
		return
	}
	for i, status := range statuses {
		d := discoveries[i]
		if d == nil {
			continue
		}
		if isHostObservationDiscovery(d) {
			// Already stamped `observed` above, unconditionally, at the point
			// the row was classified — before inventory-service was even
			// called. A host observation's discovery row never awaits an
			// approval decision regardless of which status the resulting
			// asset landed on, so nothing here may correct it back to
			// `auto_approved` (or, below, `suppressed`).
			continue
		}
		switch status {
		case "monitoring":
			d.ApprovalStatus = "auto_approved"
		case "archived", "denied":
			d.ApprovalStatus = "suppressed"
		}
	}
}

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
		// Which asset each row landed on. Per-row, so it cannot share the
		// grouped statement above; one unnest-joined UPDATE keeps it to a
		// single round trip and to the same partition-pruning tenant_id
		// predicate. Only rows that landed on an asset appear here — a routed,
		// rejected or contested finding leaves the column NULL.
		if discoveryIDs, assetIDs := marks.assetPairs(); len(discoveryIDs) > 0 {
			if _, e := tx.ExecContext(ctx, `
				UPDATE sensor_discoveries d
				SET asset_id = v.asset_id
				FROM (SELECT unnest($1::uuid[]) AS id, unnest($2::uuid[]) AS asset_id) v
				WHERE d.tenant_id = $3 AND d.id = v.id`,
				pq.Array(discoveryIDs), pq.Array(assetIDs), tenantID,
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
//   - "internal"    — IP (or, for a cloud discovery, the cloud segment) matches a known tenant segment
//   - "third_party" — IP is a public internet address not in any registered segment
//   - "unknown"     — IP is RFC 1918 private but not in any known segment
//
// cloud is non-nil only for cloud-API discoveries; see cloudResourceHint.
func (p *BatchProcessor) classifyNetwork(tenantID uuid.UUID, ipAddress string, hostname *string, cloud *client.CloudResourceHint) *models.NetworkClassification {
	classification := &models.NetworkClassification{
		Type: "public",
	}

	resp, err := p.inventoryClient.ClassifyAsset(tenantID, ipAddress, hostname, cloud)
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

// cloudResourceHint extracts the cloud account/region/VPC a discovery came
// from, or nil if it is not a cloud-API discovery (or is one that named no
// region — older rows, before the writer stamped cloud_region).
//
// This is the fix for the placeholder address. A cloud resource's ownership
// cannot be read off its IP: a KMS key, a bucket or a managed database has no
// address at all, so the writer stores an unspecified-address placeholder, and
// an unspecified address is neither RFC 1918 nor in any CIDR segment — it
// classified as third_party and was then forced to "unknown", which no segment
// rule can match. The account and region the resource lives in are what
// actually say whose it is, and they are already on the row.
func cloudResourceHint(discovery *models.SensorDiscovery) *client.CloudResourceHint {
	if discovery == nil || len(discovery.Metadata) == 0 {
		return nil
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(discovery.Metadata, &metadata); err != nil {
		return nil
	}
	if method, _ := metadata["discovery_method"].(string); method != "cloud_api" {
		return nil
	}
	provider, _ := metadata["cloud_provider"].(string)
	region, _ := metadata["cloud_region"].(string)
	if provider == "" || region == "" {
		return nil
	}
	vpcID, _ := metadata["vpc_id"].(string)
	env, _ := metadata["environment"].(string)
	return &client.CloudResourceHint{
		Provider:    provider,
		Region:      region,
		VPCID:       vpcID,
		Environment: env,
	}
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

// resolveMissingHostname fills a discovery's absent hostname, preferring the
// TLS SNI the sensor captured off the wire over a reverse-DNS guess.
//
// The SNI is what the client itself asked to connect to — a measured fact
// from the connection — while a PTR answer is hearsay about the address from
// a third party (and often absent: most cloud/CDN IPs have no PTR record at
// all, and where one exists it can name infrastructure the client never
// referenced, such as a load balancer's generic PTR instead of the vhost the
// client actually requested).
//
// The PTR lookup itself only runs for a genuinely PUBLIC destination address
// — see isPublicAddress. For a private/LAN address the cluster's own resolver
// is the wrong vantage point (usually unreachable for that address, or
// answers a different network's idea of it), and weaker evidence besides: the
// sensor's own passive mDNS/NBNS/LLDP observations are a direct measurement of
// what the LAN host calls itself, where a PTR answer is not. Sensor-side
// passive DNS capture is unaffected by this — it is a different code path
// entirely and never reaches here.
//
// siblingSNI is the SNI another row in the SAME batch used for the same
// destination — see batchSNIIndex. It is the active enricher's missing half:
// the enrichment row has no `sni` key of its own, so without it the function
// finds nothing to prefer and falls straight through to the PTR, which is
// exactly how this shipped broken the first time.
//
// The returned value carries its own provenance, because the caller needs to
// know which of the three answers it got, not just the string.
//
// lookupPTR is injected — production passes reverseDNSLookup — so callers
// that only want to exercise the ordering (SNI beats DNS) are not forced to
// perform a real network lookup.
func resolveMissingHostname(metadata []byte, destIP string, siblingSNI string, lookupPTR func(string) string) resolvedHostname {
	if sni := sniHostnameFromDiscoveryMetadata(metadata); sni != "" {
		return resolvedHostname{Name: sni, SourceKind: string(identity.SourceMeasured)}
	}
	// The SNI its own sibling captured. Same measurement, one row over — see
	// batchSNIIndex for why it is on a different row and why borrowing it is
	// sound.
	if siblingSNI != "" {
		return resolvedHostname{Name: siblingSNI, SourceKind: string(identity.SourceMeasured)}
	}
	if !isPublicAddress(destIP) {
		return resolvedHostname{}
	}
	if name := lookupPTR(destIP); name != "" {
		return resolvedHostname{Name: name, SourceKind: string(identity.SourceInferred)}
	}
	return resolvedHostname{}
}

// resolvedHostname is a hostname together with WHERE IT CAME FROM, in the
// ADR-0005 vocabulary (shared/identity.SourceKind).
//
// The provenance travels with the name for the rest of the pipeline because
// the two are one claim. A name with no provenance is exactly what let a PTR
// answer overwrite a captured SNI in external_connections: both were just
// strings by the time they reached the upsert, and the later one won.
//
// A zero value means "no name resolved" — Name == "" and SourceKind == "". Do
// not read an empty SourceKind on a non-empty Name as `inferred`; nothing
// produces that combination here, and the three states (measured, inferred,
// unstated) are kept apart all the way to the column.
type resolvedHostname struct {
	Name       string
	SourceKind string
}

// batchSNIIndex answers "what hostname did anything else in this batch ask
// this destination for?".
//
// The active TLS enricher probes a destination BECAUSE a passive capture saw a
// connection to it, and it writes its result as a second sensor_discoveries
// row — same tenant, same batch, same dest_ip/port/protocol, milliseconds
// apart. That second row carries the measured certificate and cipher but no
// `sni` key at all: the enricher knows the name it probed with and does not
// record it. So the row that reaches external_connections LAST, and therefore
// decides the stored hostname, is precisely the row that cannot see the SNI —
// even though the SNI is sitting on its sibling.
//
// That is the whole of the reason `slack.com` became
// `ec2-54-163-235-119.compute-1.amazonaws.com`. Reading SNI per-row can never
// fix it; the batch is the smallest scope where both halves are in hand.
//
// AMBIGUITY IS REFUSED, NOT GUESSED. One address can serve many vhosts — that
// is what SNI is FOR — so a destination the batch contacted under two
// different names yields nothing rather than one of them picked arbitrarily.
// A borrowed name has to be the only candidate to be a fact about this flow.
type batchSNIIndex map[string]string

// ambiguousSNI marks a destination the batch contacted under more than one
// name. Stored in-band rather than in a second map: it cannot collide with a
// real answer, because sniHostnameFromMap rejects anything with no plausible
// DNS shape, and an empty-string key is never a hostname.
const ambiguousSNI = "\x00ambiguous"

// buildBatchSNIIndex indexes every SNI observed in the batch by the
// destination endpoint it was sent to.
//
// Host observations are excluded from both halves: they carry no SNI, their
// dest_ip is routinely 0.0.0.0 ("no address observed"), and their names are a
// different measurement (what the host called ITSELF) that must not be mixed
// into what a client asked a remote endpoint for.
func buildBatchSNIIndex(discoveries []*models.SensorDiscovery) batchSNIIndex {
	index := batchSNIIndex{}
	for _, d := range discoveries {
		if d == nil || isHostObservationDiscovery(d) {
			continue
		}
		sni := sniHostnameFromDiscoveryMetadata(d.Metadata)
		if sni == "" {
			continue
		}
		key := destinationKey(d)
		switch existing := index[key]; existing {
		case "":
			index[key] = sni
		case sni, ambiguousSNI:
			// Same name again, or already known ambiguous: nothing changes.
		default:
			index[key] = ambiguousSNI
		}
	}
	return index
}

// lookup returns the single SNI this batch used for a discovery's destination,
// or "" when there was none or more than one.
func (b batchSNIIndex) lookup(d *models.SensorDiscovery) string {
	if d == nil {
		return ""
	}
	sni := b[destinationKey(d)]
	if sni == ambiguousSNI {
		return ""
	}
	return sni
}

// destinationKey identifies the endpoint a discovery describes: protocol,
// address and port together. Protocol is folded to lower case because the
// producers spell it inconsistently ("TLS", "tls"); the address is not
// normalized beyond trimming, because two spellings of one address would key
// apart and the only consequence is a borrow that does not happen.
func destinationKey(d *models.SensorDiscovery) string {
	return fmt.Sprintf("%s|%s|%d", strings.ToLower(strings.TrimSpace(d.Protocol)), strings.TrimSpace(d.DestIP), d.Port)
}

// isPublicAddress reports whether destIP is a genuinely public unicast
// address — the only case where a reverse-DNS lookup from inside the cluster
// is meaningful evidence at all.
//
// Reuses shared/autoscan's address ladder (the same one automatic active
// scanning already uses to decide what it may probe) instead of duplicating
// it: with no registered segments and no exclusions, Classify answers exactly
// "is this address public" and nothing more — private (RFC 1918 / ULA),
// loopback, link-local, multicast, unspecified and carrier-grade NAT
// (100.64.0.0/10) all come back non-public, which is every case's
// cluster-internal-PTR-name rejection cannot itself rule out (that guard
// catches a fabricated CLUSTER answer; this guard stops the lookup for a
// PRIVATE destination before any answer, real or fabricated, is asked for).
//
// An address that fails to parse is treated as not public — the safe
// direction is to skip the lookup, not to guess.
func isPublicAddress(destIP string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(destIP))
	if err != nil {
		return false
	}
	_, reason := autoscan.Classify(addr.Unmap(), nil, nil)
	return reason == autoscan.ReasonPublic
}

// reverseDNSLookup performs a PTR lookup for the given IP address with a 3s timeout.
// Returns the first resolved hostname (with trailing dot stripped), or empty string on failure/timeout.
//
// This runs from inside a pod on the RKE2/EKS cluster, using the pod's own
// resolver (kube-dns/CoreDNS). Kubernetes DNS synthesises a PTR answer for any
// IP it considers "in-cluster" rather than forwarding to the customer's real
// resolver — so a customer host at, say, 192.0.2.124 came back as
// "192-0-2-124.kubernetes.default.svc.cluster.local", a name nothing on the
// customer's network ever answers to. That fabricated name must never become
// a discovered asset's display name; isClusterInternalPTRName rejects it so
// the caller falls back to the address until a real name arrives.
// lookupPTR is the reverse-DNS lookup ProcessBatch actually calls. It is a
// package-level var so a test can drive the REAL batch path — the loop, the
// sibling-SNI index, the upsert payload — without a live resolver and without
// depending on what the public DNS happens to answer for a fixture address.
//
// The same seam as inventory-service's `lookupHost`, for the same reason: a
// hostname fix that is only ever exercised through the helper is how the first
// one passed its tests and stayed broken in production.
var lookupPTR = reverseDNSLookup

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
	if isClusterInternalPTRName(name) {
		return ""
	}
	return name
}

// isClusterInternalPTRName reports whether name is a Kubernetes-synthesised
// PTR answer rather than a name a real host answers to.
//
// Cluster DNS providers (CoreDNS/kube-dns) synthesise reverse-lookup answers
// for pod/service/node IPs in three recognisable shapes, all rejected here:
//   - anything ending in ".cluster.local" (the default cluster domain);
//   - anything with "svc" or "pod" as its own label (".svc.<anything>",
//     ".pod.<anything>") — clusters can and do run a custom cluster domain,
//     so the suffix alone is not a reliable signal;
//   - the general synthesized shape "<a>-<b>-<c>-<d>.<...>", where the first
//     label is simply the queried IP address with its dots replaced by
//     dashes. This is the part of the answer that is always fabricated,
//     whatever domain trails it, so it is checked independent of the other
//     two rules.
func isClusterInternalPTRName(name string) bool {
	lower := strings.ToLower(strings.TrimSuffix(name, "."))
	if lower == "" {
		return false
	}
	if strings.HasSuffix(lower, ".cluster.local") {
		return true
	}
	labels := strings.Split(lower, ".")
	for _, label := range labels {
		if label == "svc" || label == "pod" {
			return true
		}
	}
	// The first label, with dashes turned back into dots, is the fabricated
	// IP-shaped name Kubernetes emits for an in-cluster address — check it
	// regardless of what domain follows.
	if len(labels) > 0 {
		candidate := strings.ReplaceAll(labels[0], "-", ".")
		if ip := net.ParseIP(candidate); ip != nil {
			return true
		}
	}
	return false
}

// isHostObservationDiscovery reports whether a stored discovery is a passive
// host observation rather than a cryptographic one.
//
// The marker is read from both levels of the sensor-manager envelope for the
// same reason the converter reads both: sensor-manager promotes it to the top
// level while pcap-processor writes it flat, and checking one level would miss
// half of them.
func isHostObservationDiscovery(d *models.SensorDiscovery) bool {
	if d == nil || len(d.Metadata) == 0 {
		return false
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(d.Metadata, &metadata); err != nil {
		return false
	}
	if v, ok := metadata["discovery_type"].(string); ok && v == "host_observation" {
		return true
	}
	if nested, ok := metadata["raw_metadata"].(map[string]interface{}); ok {
		if v, ok := nested["discovery_type"].(string); ok && v == "host_observation" {
			return true
		}
	}
	return false
}

// sniHostnameFromDiscoveryMetadata returns the TLS SNI hostname captured for
// a stored discovery, or "" when none is present or usable.
//
// sensor-manager nests the sensor's own payload under "raw_metadata" and only
// promotes a fixed set of envelope keys to the top level (version,
// cipher_suite, key_size, source_ip, discovery_method, discovery_type) — SNI
// is not one of them, so it is read from the nested object.
// pcap-processor writes its metadata flat (no envelope), so the top level is
// checked too; either shape resolves through one unmarshal.
//
// "sni" is the first-class key the passive TLS assembler writes
// (sensor/internal/capture/tls_assembler.go); "sni_server_name" is the older
// spelling kept alongside it there and, for STARTTLS sessions, written alone
// (sensor/internal/capture/starttls_assembler.go never gained the "sni"
// alias). Both are checked, "sni" first.
func sniHostnameFromDiscoveryMetadata(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var metadata map[string]interface{}
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return ""
	}
	if s := sniHostnameFromMap(metadata); s != "" {
		return s
	}
	if nested, ok := metadata["raw_metadata"].(map[string]interface{}); ok {
		return sniHostnameFromMap(nested)
	}
	return ""
}

// sniHostnameFromMap reads "sni"/"sni_server_name" from one metadata level,
// rejecting anything that is not a plausible DNS name. An IP literal is not a
// hostname — RFC 6066 server_name is a DNS identity check, not an address —
// and net.ParseIP is the standard way to reject one before it reaches a
// hostname column.
func sniHostnameFromMap(m map[string]interface{}) string {
	for _, key := range []string{"sni", "sni_server_name"} {
		v, ok := m[key]
		if !ok || v == nil {
			continue
		}
		s, ok := v.(string)
		if !ok {
			continue
		}
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if net.ParseIP(s) != nil {
			continue
		}
		return s
	}
	return ""
}
