package processor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"github.com/jmoiron/sqlx"
	"github.com/nats-io/nats.go"

	"github.com/vistasecurity/vistaplatform/pcap-processor/internal/config"
	"github.com/vistasecurity/vistaplatform/pcap-processor/internal/tlsparse"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/events"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// CryptoDiscovery represents a cryptographic finding from pcap analysis.
type CryptoDiscovery struct {
	SourceIP        string                         `json:"source_ip"`
	SourcePort      int                            `json:"source_port"`
	DestIP          string                         `json:"dest_ip"`
	DestPort        int                            `json:"dest_port"`
	Protocol        string                         `json:"protocol"`
	ProtocolVersion string                         `json:"protocol_version,omitempty"`
	CipherSuite     string                         `json:"cipher_suite,omitempty"`
	CipherSuites    []string                       `json:"cipher_suites,omitempty"`
	SNI             string                         `json:"sni,omitempty"`
	Certificates    []certificates.CertificateInfo `json:"certificates,omitempty"`
	DiscoveryMethod string                         `json:"discovery_method"`
	DiscoveryType   string                         `json:"discovery_type"`
	Timestamp       time.Time                      `json:"timestamp"`
	RawMetadata     map[string]string              `json:"raw_metadata,omitempty"`
}

// PcapResult holds the aggregated results of processing a pcap file.
type PcapResult struct {
	Discoveries      []CryptoDiscovery `json:"discoveries"`
	DiscoveryCount   int               `json:"discovery_count"`
	ProtocolsFound   []string          `json:"protocols_found"`
	CaptureStartTime *time.Time        `json:"capture_start_time,omitempty"`
	CaptureEndTime   *time.Time        `json:"capture_end_time,omitempty"`
	PacketsProcessed int               `json:"packets_processed"`
	ErrorCount       int               `json:"error_count"`
}

// AuditSink records one unit of consumer work on the shared audit path.
// *auditmiddleware.Middleware satisfies it; tests substitute a recorder.
type AuditSink interface {
	LogConsumerEvent(ctx context.Context, ev auditmiddleware.ConsumerEvent) error
}

// Processor handles pcap file processing jobs.
type Processor struct {
	db         *sqlx.DB
	cfg        *config.Config
	sem        chan struct{}
	natsClient *events.NATSClient
	audit      AuditSink
}

// New creates a new Processor.
//
// auditSink may be nil (no audit-service configured); the processor then
// records nothing rather than failing the job.
func New(db *sqlx.DB, cfg *config.Config, natsClient *events.NATSClient, auditSink AuditSink) *Processor {
	return &Processor{
		db:         db,
		cfg:        cfg,
		sem:        make(chan struct{}, cfg.MaxConcurrentJobs),
		natsClient: natsClient,
		audit:      auditSink,
	}
}

// logJobAudit records the outcome of one PCAP job.
//
// pcap-processor ingests a tenant-uploaded capture into sensor_discoveries and
// on into the crypto inventory. Its only HTTP surface is /health, so the
// LogRequest middleware every other service mounts has nothing to attach to —
// every mutation it made was invisible to the audit trail. This is the
// consumer-path equivalent.
//
// Counts only: number of discoveries, packets and parse errors. Never the
// capture's contents, and never the uploaded filename — the pcap_jobs row
// already holds that, keyed by the job id recorded here, and a capture's
// payload is exactly the material CLAUDE.md says not to collect.
func (p *Processor) logJobAudit(ctx context.Context, job *events.PcapJobEvent, result *PcapResult, started time.Time, errorKind string) {
	if p.audit == nil {
		return
	}

	counts := map[string]int{}
	eventType := "discovery.pcap.failed"
	if result != nil {
		counts["discoveries"] = result.DiscoveryCount
		counts["packets_processed"] = result.PacketsProcessed
		counts["parse_errors"] = result.ErrorCount
		counts["protocols_found"] = len(result.ProtocolsFound)
		eventType = "discovery.pcap.processed"
	}

	tenantID := job.TenantID
	jobID := job.JobID
	if err := p.audit.LogConsumerEvent(ctx, auditmiddleware.ConsumerEvent{
		TenantID:      &tenantID,
		Source:        events.SubjectPcapJobsProcess,
		Stream:        "PCAP_JOBS",
		EventCategory: "discovery",
		EventType:     eventType,
		Action:        "process",
		ResourceType:  "pcap_job",
		ResourceID:    &jobID,
		Counts:        counts,
		Duration:      time.Since(started),
		Success:       errorKind == "",
		ErrorKind:     errorKind,
	}); err != nil {
		log.Printf("[PCAP] Warning: failed to record audit event for job %s: %v", job.JobID, err)
	}
}

// HandlePcapJob processes a single NATS message containing a PcapJobEvent.
func (p *Processor) HandlePcapJob(ctx context.Context, msg *nats.Msg) error {
	var job events.PcapJobEvent
	if err := events.UnmarshalMsg(msg, &job); err != nil {
		return fmt.Errorf("unmarshal pcap job event: %w", err)
	}

	log.Printf("[PCAP] Processing job %s for tenant %s (file: %s, size: %d bytes)",
		job.JobID, job.TenantID, job.OriginalFilename, job.FileSizeBytes)

	started := time.Now()

	// Acquire semaphore to respect MaxConcurrentJobs
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return fmt.Errorf("context cancelled waiting for semaphore: %w", ctx.Err())
	}

	// Update job status to processing
	if err := p.updateJobStatus(ctx, job.TenantID, job.JobID, "processing", nil); err != nil {
		log.Printf("[PCAP] Warning: failed to update job %s status to processing: %v", job.JobID, err)
	}

	// Process the pcap file
	result, err := p.processPcapFile(ctx, job.FilePath, job.TenantID.String())
	if err != nil {
		errMsg := err.Error()
		if updateErr := p.updateJobFailed(ctx, job.TenantID, job.JobID, errMsg); updateErr != nil {
			log.Printf("[PCAP] Warning: failed to update job %s status to failed: %v", job.JobID, updateErr)
		}
		p.cleanupFile(job.FilePath)
		p.logJobAudit(ctx, &job, nil, started, "process_failed")
		return fmt.Errorf("process pcap file: %w", err)
	}

	// Insert individual crypto discoveries into the sensor_discoveries pipeline
	// so they flow through discovery-processor-service into the crypto inventory.
	if len(result.Discoveries) > 0 {
		if err := p.insertDiscoveriesIntoPipeline(ctx, job.JobID, job.TenantID, result.Discoveries); err != nil {
			log.Printf("[PCAP] Warning: failed to insert discoveries into pipeline for job %s: %v", job.JobID, err)
		}
	}

	// Submit aggregate summary and mark job completed via sensor-manager
	if err := p.submitResults(ctx, job.JobID, job.TenantID, result); err != nil {
		log.Printf("[PCAP] Warning: failed to submit results for job %s: %v", job.JobID, err)
		// Fall back to direct DB update on submission failure
		if dbErr := p.updateJobCompletedDB(ctx, job.TenantID, job.JobID, result); dbErr != nil {
			log.Printf("[PCAP] Warning: fallback DB update also failed for job %s: %v", job.JobID, dbErr)
		}
	}

	// Clean up the temp file
	p.cleanupFile(job.FilePath)

	log.Printf("[PCAP] Job %s completed: %d discoveries, %d packets processed, protocols: %v",
		job.JobID, result.DiscoveryCount, result.PacketsProcessed, result.ProtocolsFound)

	p.logJobAudit(ctx, &job, result, started, "")

	return nil
}

// processPcapFile opens and analyzes a pcap file for cryptographic protocol usage.
func (p *Processor) processPcapFile(ctx context.Context, filePath string, sensorID string) (*PcapResult, error) {
	handle, err := pcap.OpenOffline(filePath)
	if err != nil {
		return nil, fmt.Errorf("open pcap file: %w", err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.NoCopy = true

	result := &PcapResult{
		Discoveries: make([]CryptoDiscovery, 0),
	}
	protocolSet := make(map[string]bool)

	// Track seen connections to avoid duplicate discoveries (SSH banners and
	// QUIC Initials are single-packet observations, so they dedup per packet).
	seen := make(map[string]bool)

	// TLS handshakes are reassembled per flow across TCP segments and emitted
	// once per session, so a Certificate message that spans several segments is
	// actually parseable. Dedup keeps repeated clients from producing identical
	// rows while preserving distinct SNI/certificate/negotiated-crypto evidence
	// behind the same IP:port.
	tlsSeen := make(map[string]bool)
	tracker := tlsparse.NewTracker(func(s *tlsparse.Session) {
		key := tlsSessionDedupeKey(s)
		if tlsSeen[key] {
			return
		}
		tlsSeen[key] = true
		d := discoveryFromTLSSession(s)
		result.Discoveries = append(result.Discoveries, d)
		protocolSet[d.Protocol] = true
	})

	for packet := range packetSource.Packets() {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("processing cancelled: %w", ctx.Err())
		default:
		}

		result.PacketsProcessed++

		// Track capture time range
		ts := packet.Metadata().Timestamp
		if !ts.IsZero() {
			if result.CaptureStartTime == nil || ts.Before(*result.CaptureStartTime) {
				t := ts
				result.CaptureStartTime = &t
			}
			if result.CaptureEndTime == nil || ts.After(*result.CaptureEndTime) {
				t := ts
				result.CaptureEndTime = &t
			}
		}

		// Extract IP layer
		var srcIP, dstIP string
		if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
			ipv4 := ipv4Layer.(*layers.IPv4)
			srcIP = ipv4.SrcIP.String()
			dstIP = ipv4.DstIP.String()
		} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
			ipv6 := ipv6Layer.(*layers.IPv6)
			srcIP = ipv6.SrcIP.String()
			dstIP = ipv6.DstIP.String()
		} else {
			continue
		}

		// Check TCP layer
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp := tcpLayer.(*layers.TCP)
			srcPort := int(tcp.SrcPort)
			dstPort := int(tcp.DstPort)
			payload := tcp.Payload

			if len(payload) == 0 {
				continue
			}

			// Feed TLS handshake bytes into the per-flow reassembler. It emits
			// a session (via the onComplete callback above) when the handshake
			// finishes, is abandoned, or at Flush.
			tracker.Feed(tlsparse.FlowKey{
				SrcIP:   srcIP,
				SrcPort: srcPort,
				DstIP:   dstIP,
				DstPort: dstPort,
			}, payload, ts)

			// Check for SSH banners
			if d := p.analyzeSSH(payload, srcIP, srcPort, dstIP, dstPort, ts); d != nil {
				key := fmt.Sprintf("%s:%d-%s:%d-ssh", d.SourceIP, d.SourcePort, d.DestIP, d.DestPort)
				if !seen[key] {
					seen[key] = true
					result.Discoveries = append(result.Discoveries, *d)
					protocolSet["SSH"] = true
				}
			}
		}

		// Check UDP layer for QUIC
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			srcPort := int(udp.SrcPort)
			dstPort := int(udp.DstPort)
			payload := udp.Payload

			if d := p.analyzeQUIC(payload, srcIP, srcPort, dstIP, dstPort, ts); d != nil {
				key := fmt.Sprintf("%s:%d-%s:%d-quic", d.SourceIP, d.SourcePort, d.DestIP, d.DestPort)
				if !seen[key] {
					seen[key] = true
					result.Discoveries = append(result.Discoveries, *d)
					protocolSet["QUIC"] = true
				}
			}
		}
	}

	// Emit handshakes that were still in flight when the capture ended.
	tracker.Flush()

	if tracker.Evicted > 0 || tracker.Truncated > 0 || tracker.Desynced > 0 {
		log.Printf("[PCAP] TLS reassembly limits hit (%s): %d flows dropped over the flow cap, %d truncated over the per-direction byte cap, %d abandoned on desynchronised record framing",
			tracker.LimitsDescription(), tracker.Evicted, tracker.Truncated, tracker.Desynced)
	}

	result.DiscoveryCount = len(result.Discoveries)
	for proto := range protocolSet {
		result.ProtocolsFound = append(result.ProtocolsFound, proto)
	}

	return result, nil
}

func tlsSessionDedupeKey(s *tlsparse.Session) string {
	leafFingerprint := ""
	if len(s.Certificates) > 0 {
		leafFingerprint = s.Certificates[0].FingerprintSHA256
		if leafFingerprint == "" {
			leafFingerprint = s.Certificates[0].SerialNumber
		}
	}
	return fmt.Sprintf("%s:%d|sni=%q|version=%q|cipher=%q|leaf=%q",
		s.ServerIP, s.ServerPort, s.SNI, s.NegotiatedVersion, s.CipherSuite, leafFingerprint)
}

// discoveryFromTLSSession converts a reassembled TLS session into the discovery
// shape the sensor pipeline consumes.
//
// The negotiated protocol version comes from the ServerHello alone. When the
// capture never carried the server's side, ProtocolVersion stays empty — the
// client's best offer is recorded as metadata, never promoted to "what this
// connection used".
func discoveryFromTLSSession(s *tlsparse.Session) CryptoDiscovery {
	meta := map[string]string{
		"reassembled":     "true",
		"handshake_types": strings.Join(s.HandshakeTypes, ","),
	}
	if s.RecordVersion != "" {
		meta["record_version"] = s.RecordVersion
	}
	if s.ClientLegacyVersion != "" {
		meta["client_legacy_version"] = s.ClientLegacyVersion
	}
	if s.ClientMaxOffered != "" {
		meta["client_max_offered_version"] = s.ClientMaxOffered
	}
	if len(s.OfferedCipherSuites) > 0 {
		meta["cipher_suite_count"] = fmt.Sprintf("%d", len(s.OfferedCipherSuites))
	}
	if s.CipherSuite != "" {
		meta["selected_cipher_suite"] = s.CipherSuite
	}
	if len(s.Certificates) > 0 {
		meta["certificate_count"] = fmt.Sprintf("%d", len(s.Certificates))
	}
	if s.Truncated {
		meta["reassembly_truncated"] = "true"
	}

	return CryptoDiscovery{
		SourceIP:        s.ClientIP,
		SourcePort:      s.ClientPort,
		DestIP:          s.ServerIP,
		DestPort:        s.ServerPort,
		Protocol:        "TLS",
		ProtocolVersion: s.NegotiatedVersion,
		CipherSuite:     s.CipherSuite,
		CipherSuites:    s.OfferedCipherSuites,
		SNI:             s.SNI,
		Certificates:    s.Certificates,
		DiscoveryMethod: "pcap_upload",
		DiscoveryType:   "tls_session",
		Timestamp:       s.FirstSeen,
		RawMetadata:     meta,
	}
}

// analyzeSSH checks if a TCP payload contains an SSH banner.
func (p *Processor) analyzeSSH(payload []byte, srcIP string, srcPort int, dstIP string, dstPort int, ts time.Time) *CryptoDiscovery {
	if len(payload) < 4 {
		return nil
	}

	payloadStr := string(payload)
	if !strings.HasPrefix(payloadStr, "SSH-") {
		return nil
	}

	// Extract version string (up to CR or LF)
	banner := payloadStr
	if idx := strings.IndexAny(banner, "\r\n"); idx != -1 {
		banner = banner[:idx]
	}

	// Parse SSH-protoversion-softwareversion
	parts := strings.SplitN(banner, "-", 3)
	var protoVersion string
	if len(parts) >= 2 {
		protoVersion = parts[1]
	}

	return &CryptoDiscovery{
		SourceIP:        srcIP,
		SourcePort:      srcPort,
		DestIP:          dstIP,
		DestPort:        dstPort,
		Protocol:        "SSH",
		ProtocolVersion: protoVersion,
		DiscoveryMethod: "pcap_upload",
		DiscoveryType:   "ssh_banner",
		Timestamp:       ts,
		RawMetadata: map[string]string{
			"banner": banner,
		},
	}
}

// analyzeQUIC checks if a UDP payload contains a QUIC Initial packet.
func (p *Processor) analyzeQUIC(payload []byte, srcIP string, srcPort int, dstIP string, dstPort int, ts time.Time) *CryptoDiscovery {
	if len(payload) < 5 {
		return nil
	}

	// QUIC long header: first bit is 1, second bit (fixed) is 1
	firstByte := payload[0]
	if firstByte&0xC0 != 0xC0 {
		return nil
	}

	// Check version field (bytes 1-4)
	// QUIC v1: 0x00000001, QUIC v2: 0x6b3343cf
	version := binary.BigEndian.Uint32(payload[1:5])

	var versionStr string
	switch version {
	case 0x00000001:
		versionStr = "1"
	case 0x6b3343cf:
		versionStr = "2"
	case 0x00000000:
		// Version negotiation
		versionStr = "negotiation"
	default:
		// Could be a draft version or not QUIC
		if version&0xff000000 == 0xff000000 {
			versionStr = fmt.Sprintf("draft-%d", version&0xff)
		} else {
			return nil
		}
	}

	// Packet type (bits 4-5 of first byte for long header)
	packetType := (firstByte & 0x30) >> 4
	if packetType != 0x00 { // 0x00 = Initial packet
		return nil
	}

	return &CryptoDiscovery{
		SourceIP:        srcIP,
		SourcePort:      srcPort,
		DestIP:          dstIP,
		DestPort:        dstPort,
		Protocol:        "QUIC",
		ProtocolVersion: versionStr,
		DiscoveryMethod: "pcap_upload",
		DiscoveryType:   "quic_initial",
		Timestamp:       ts,
		RawMetadata: map[string]string{
			"quic_version_hex": fmt.Sprintf("0x%08X", version),
		},
	}
}

// submitResults sends processing results to sensor-manager's internal endpoint.
// Maps PcapResult fields to the expected handler input format.
func (p *Processor) submitResults(ctx context.Context, jobID uuid.UUID, tenantID uuid.UUID, result *PcapResult) error {
	url := fmt.Sprintf("%s/api/v1/sensor-manager/internal/pcap/jobs/%s/results", p.cfg.SensorManagerURL, jobID)

	// Build protocols_found as map[string]int (handler expects this format)
	protocolCounts := make(map[string]int)
	for _, proto := range result.ProtocolsFound {
		protocolCounts[proto]++
	}

	// Build capture_time_range as map (handler expects this format)
	captureTimeRange := make(map[string]interface{})
	if result.CaptureStartTime != nil {
		captureTimeRange["start"] = result.CaptureStartTime.Format(time.RFC3339)
	}
	if result.CaptureEndTime != nil {
		captureTimeRange["end"] = result.CaptureEndTime.Format(time.RFC3339)
	}

	// Build payload matching the handler's input struct
	payload := map[string]interface{}{
		"status":             "completed",
		"discovery_count":    result.DiscoveryCount,
		"packet_count":       int64(result.PacketsProcessed),
		"protocols_found":    protocolCounts,
		"capture_time_range": captureTimeRange,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal results: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", tenantID.String())
	serviceauth.SignRequestFromEnv(req)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("submit discoveries: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("sensor-manager returned status %d", resp.StatusCode)
	}

	log.Printf("[PCAP] Submitted results for job %s to sensor-manager (%d discoveries)", jobID, result.DiscoveryCount)
	return nil
}

// insertDiscoveriesIntoPipeline writes each CryptoDiscovery as a sensor_discoveries row
// then publishes a discovery.jobs.submit event so discovery-processor-service picks them up.
func (p *Processor) insertDiscoveriesIntoPipeline(ctx context.Context, jobID uuid.UUID, tenantID uuid.UUID, discoveries []CryptoDiscovery) error {
	sensorID, err := p.resolvePlatformSensorID(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("resolve platform sensor id: %w", err)
	}

	batchID := jobID.String()
	insertQuery := `
		INSERT INTO sensor_discoveries
			(sensor_id, tenant_id, batch_id, protocol, dest_ip, port, confidence, metadata, timestamp, source_ip, hostname)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`

	// RLS-scoped write: sensor_discoveries (the partitioned table behind the view)
	// carries a tenant_isolation policy, so the inserts run inside WithTenantTx
	// (sets app.tenant_id). The explicit tenant_id column value is kept so the
	// policy's WITH CHECK is satisfied and a cross-tenant write would be denied.
	inserted := 0
	if err := shareddatabase.WithTenantTx(ctx, p.db.DB, tenantID, func(tx *sql.Tx) error {
		for _, d := range discoveries {
			meta := buildDiscoveryMetadata(d)
			metaJSON, mErr := json.Marshal(meta)
			if mErr != nil {
				log.Printf("[PCAP] Warning: failed to marshal metadata for discovery %s→%s:%d: %v", d.SourceIP, d.DestIP, d.DestPort, mErr)
				continue
			}

			var sourceIP *string
			if d.SourceIP != "" {
				s := d.SourceIP
				sourceIP = &s
			}

			var hostname *string
			if d.SNI != "" {
				h := d.SNI
				hostname = &h
			}

			_, iErr := tx.ExecContext(ctx, insertQuery,
				sensorID,
				tenantID,
				batchID,
				// Canonical protocol_type spelling — see cryptoparse.NormalizeProtocol.
				cryptoparse.NormalizeProtocol(d.Protocol),
				d.DestIP,
				d.DestPort,
				0.85,
				metaJSON,
				d.Timestamp,
				sourceIP,
				hostname,
			)
			if iErr != nil {
				log.Printf("[PCAP] Warning: failed to insert discovery %s→%s:%d into pipeline: %v", d.SourceIP, d.DestIP, d.DestPort, iErr)
				continue
			}
			inserted++
		}
		return nil
	}); err != nil {
		return fmt.Errorf("insert discoveries into pipeline: %w", err)
	}

	log.Printf("[PCAP] Inserted %d/%d discoveries into sensor_discoveries pipeline (batch %s)", inserted, len(discoveries), batchID)

	if inserted > 0 && p.natsClient != nil {
		event := &events.DiscoveryJobEvent{
			EventID:  uuid.New(),
			TenantID: tenantID,
			JobID:    batchID,
			JobType:  "pcap_upload",
		}
		if err := events.PublishJSON(p.natsClient, events.SubjectDiscoveryJobsSubmit, event); err != nil {
			log.Printf("[PCAP] Warning: failed to publish discovery job event for batch %s: %v", batchID, err)
		}
	}

	return nil
}

// resolvePlatformSensorID finds the best sensor to attribute PCAP discoveries to.
// It prefers the Platform Discovery Sensor, then falls back to any active sensor for the tenant.
func (p *Processor) resolvePlatformSensorID(ctx context.Context, tenantID uuid.UUID) (uuid.UUID, error) {
	// RLS-scoped read: sensors carries a tenant_isolation policy, so the lookup
	// runs inside WithTenantTx (sets app.tenant_id). The explicit
	// WHERE tenant_id = $1 is kept as the primary control (belt-and-suspenders).
	var sensorID uuid.UUID
	err := shareddatabase.WithTenantTx(ctx, p.db.DB, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT id FROM sensors
			WHERE tenant_id = $1 AND status = 'active'
			ORDER BY (name = 'Platform Discovery Sensor') DESC, created_at ASC
			LIMIT 1
		`, tenantID).Scan(&sensorID)
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("no active sensor found for tenant %s: %w", tenantID, err)
	}
	return sensorID, nil
}

// buildDiscoveryMetadata converts a CryptoDiscovery into a metadata map compatible
// with the SensorDiscoveryConverter used by discovery-processor-service.
func buildDiscoveryMetadata(d CryptoDiscovery) map[string]interface{} {
	meta := map[string]interface{}{
		"discovery_method": "pcap_upload",
		"discovery_type":   d.DiscoveryType,
		"source_port":      d.SourcePort,
	}
	if d.ProtocolVersion != "" {
		meta["version"] = d.ProtocolVersion
	}
	if d.CipherSuite != "" {
		meta["cipher_suite"] = d.CipherSuite
	}
	if len(d.CipherSuites) > 0 {
		meta["cipher_suites"] = d.CipherSuites
	}
	if d.SNI != "" {
		meta["sni"] = d.SNI
		meta["sni_server_name"] = d.SNI
	}
	// Canonical "certificates" array — the single certificate format every
	// discovery path emits (see the Discovery Pipeline Principles in
	// CLAUDE.md). discovery-processor-service reads the leaf from here.
	if len(d.Certificates) > 0 {
		certs := make([]interface{}, 0, len(d.Certificates))
		for _, c := range d.Certificates {
			certs = append(certs, map[string]interface{}{
				"serial_number":             c.SerialNumber,
				"subject_dn":                c.SubjectDN,
				"issuer_dn":                 c.IssuerDN,
				"not_before":                c.NotBefore.Format(time.RFC3339),
				"not_after":                 c.NotAfter.Format(time.RFC3339),
				"key_algorithm":             c.KeyAlgorithm,
				"signature_alg":             c.SignatureAlg,
				"is_ca":                     c.IsCA,
				"certificate_pem":           c.CertificatePEM,
				"fingerprint_sha256":        c.FingerprintSHA256,
				"fingerprint_sha1":          c.FingerprintSHA1,
				"subject_alternative_names": c.SubjectAlternativeNames,
				"key_usage":                 c.KeyUsage,
				"extended_key_usage":        c.ExtendedKeyUsage,
				"key_size":                  c.KeySize,
				"chain_order":               c.ChainOrder,
			})
		}
		meta["certificates"] = certs
	}
	for k, v := range d.RawMetadata {
		meta[k] = v
	}
	return meta
}

// updateJobStatus updates the pcap_upload_jobs table status.
func (p *Processor) updateJobStatus(ctx context.Context, tenantID, jobID uuid.UUID, status string, errorMsg *string) error {
	// RLS-scoped write: pcap_upload_jobs carries a tenant_isolation policy, so the
	// UPDATE runs inside WithTenantTx (sets app.tenant_id). The policy's USING
	// clause confines the row set to the caller's tenant; the WHERE id remains the
	// primary control.
	query := `UPDATE pcap_upload_jobs SET status = $1, error_message = $2, updated_at = NOW() WHERE id = $3`
	err := shareddatabase.WithTenantTx(ctx, p.db.DB, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, status, errorMsg, jobID)
		return e
	})
	if err != nil {
		return fmt.Errorf("update job status: %w", err)
	}
	return nil
}

// updateJobCompletedDB is a fallback that writes results directly to the DB
// when the sensor-manager HTTP endpoint is unreachable.
func (p *Processor) updateJobCompletedDB(ctx context.Context, tenantID, jobID uuid.UUID, result *PcapResult) error {
	// Build protocols_found as map[string]int for JSONB storage
	protocolCounts := make(map[string]int)
	for _, proto := range result.ProtocolsFound {
		protocolCounts[proto]++
	}
	protocolsJSON, _ := json.Marshal(protocolCounts)

	// Build capture_time_range as JSONB
	captureRange := make(map[string]interface{})
	if result.CaptureStartTime != nil {
		captureRange["start"] = result.CaptureStartTime.Format(time.RFC3339)
	}
	if result.CaptureEndTime != nil {
		captureRange["end"] = result.CaptureEndTime.Format(time.RFC3339)
	}
	captureRangeJSON, _ := json.Marshal(captureRange)

	// RLS-scoped write: pcap_upload_jobs carries a tenant_isolation policy, so the
	// UPDATE runs inside WithTenantTx (sets app.tenant_id). The WHERE id remains the
	// primary control; the policy's USING clause confines it to the caller's tenant.
	query := `UPDATE pcap_upload_jobs
		SET status = 'completed',
			discovery_count = $1,
			packet_count = $2,
			protocols_found = $3,
			capture_time_range = $4,
			completed_at = NOW(),
			updated_at = NOW()
		WHERE id = $5`
	err := shareddatabase.WithTenantTx(ctx, p.db.DB, tenantID, func(tx *sql.Tx) error {
		_, e := tx.ExecContext(ctx, query, result.DiscoveryCount, result.PacketsProcessed, string(protocolsJSON), string(captureRangeJSON), jobID)
		return e
	})
	if err != nil {
		return fmt.Errorf("update job completed: %w", err)
	}
	return nil
}

// updateJobFailed marks a job as failed with an error message.
func (p *Processor) updateJobFailed(ctx context.Context, tenantID, jobID uuid.UUID, errMsg string) error {
	return p.updateJobStatus(ctx, tenantID, jobID, "failed", &errMsg)
}

// cleanupFile removes the temporary pcap file.
func (p *Processor) cleanupFile(filePath string) {
	if err := os.Remove(filePath); err != nil && !os.IsNotExist(err) {
		log.Printf("[PCAP] Warning: failed to remove temp file %s: %v", filePath, err)
	}
}
