package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
)

// LogStorageService handles storage and retrieval of logs in S3
// with encryption (SSE-KMS) and compliance features.
//
// RLS: cross-tenant — all platform_log_metadata access here runs on the bypass
// role (Phase 4). platform_log_metadata IS RLS-policied, but this is the central
// platform/SIEM log store: store/search/retrieve/delete operate by log_id,
// service, and severity across ALL tenants (admin-facing), never scoped to a
// single app.tenant_id. None of these methods are wrapped in WithTenantTx.
type LogStorageService struct {
	s3Client     *s3.Client
	uploader     *manager.Uploader
	downloader   *manager.Downloader
	bucket       string
	region       string
	kmsKeyID     string // KMS key ID for SSE-KMS encryption
	db           *sql.DB
	bypassDB     *sql.DB               // BYPASSRLS handle for cross-tenant platform_log_metadata access
	piiDetector  *PIIDetector          // PII detection and scrubbing service
	incidentHook *IncidentResponseHook // Incident response hooks
}

// LogEntry represents a raw log entry to be stored
type LogEntry struct {
	ID             string                 `json:"id"`
	CorrelationID  string                 `json:"correlation_id,omitempty"`
	TraceID        string                 `json:"trace_id,omitempty"`
	Service        string                 `json:"service"`
	ServiceVersion string                 `json:"service_version,omitempty"`
	Environment    string                 `json:"environment"`
	Severity       string                 `json:"severity"`
	EventType      string                 `json:"event_type"`
	Category       string                 `json:"category,omitempty"`
	Message        string                 `json:"message"`
	TenantID       *uuid.UUID             `json:"tenant_id,omitempty"`
	UserID         *uuid.UUID             `json:"user_id,omitempty"`
	UserType       string                 `json:"user_type,omitempty"`
	RequestID      string                 `json:"request_id,omitempty"`
	SourceIP       string                 `json:"source_ip,omitempty"`
	UserAgent      string                 `json:"user_agent,omitempty"`
	RequestMethod  string                 `json:"request_method,omitempty"`
	RequestPath    string                 `json:"request_path,omitempty"`
	ResponseStatus int                    `json:"response_status,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	DurationMs     int                    `json:"duration_ms,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// LogMetadata represents sanitized log metadata stored in database
type LogMetadata struct {
	ID              uuid.UUID
	LogID           string
	CorrelationID   string
	TraceID         string
	ServiceName     string
	ServiceVersion  string
	Environment     string
	Severity        string
	EventType       string
	Category        string
	MessageDigest   string
	MessagePreview  string
	RedactionMask   string
	TenantID        *uuid.UUID
	UserID          *uuid.UUID
	UserType        string
	RequestID       string
	SourceIP        *string
	UserAgent       *string
	RequestMethod   string
	RequestPath     string
	ResponseStatus  *int
	Timestamp       time.Time
	DurationMs      *int
	S3Bucket        string
	S3Key           string
	S3Region        string
	S3ETag          string
	Status          string
	RetentionPolicy string
	PIIDetected     bool
	PIITypes        []string
	ComplianceTags  []string
	Metadata        map[string]interface{}
	Tags            map[string]interface{}
}

// NewLogStorageService creates a new log storage service.
//
// bypassDB is the BYPASSRLS (crypto_bypass) handle used for all
// platform_log_metadata access — that table is RLS-policied but this is the
// central platform/SIEM store operating across ALL tenants, so under crypto_app
// those queries would fail closed.
func NewLogStorageService(db, bypassDB *sql.DB, bucket, region, kmsKeyID string, hook *IncidentResponseHook) (*LogStorageService, error) {
	ctx := context.Background()

	// Load AWS config
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	s3Client := s3.NewFromConfig(cfg)
	uploader := manager.NewUploader(s3Client)
	downloader := manager.NewDownloader(s3Client)

	// Initialize PII detector
	piiDetector, err := NewPIIDetector(db)
	if err != nil {
		// If PII detector fails to initialize (e.g., table doesn't exist), continue without it
		// This allows the service to work before migrations are applied
		piiDetector = nil
	}

	return &LogStorageService{
		s3Client:     s3Client,
		uploader:     uploader,
		downloader:   downloader,
		bucket:       bucket,
		region:       region,
		kmsKeyID:     kmsKeyID,
		db:           db,
		bypassDB:     bypassDB,
		piiDetector:  piiDetector,
		incidentHook: hook,
	}, nil
}

// StoreLog stores a log entry in S3 and saves metadata in database
func (s *LogStorageService) StoreLog(ctx context.Context, entry LogEntry) (*LogMetadata, error) {
	// Generate log ID if not provided
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}

	// Serialize log entry to JSON
	logJSON, err := json.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal log entry: %w", err)
	}

	// Calculate message digest (SHA-256)
	digest := sha256.Sum256([]byte(entry.Message))
	messageDigest := hex.EncodeToString(digest[:])

	// Generate S3 key: logs/{year}/{month}/{day}/{service}/{log_id}.json
	now := entry.Timestamp
	if now.IsZero() {
		now = time.Now()
		entry.Timestamp = now
	}
	s3Key := fmt.Sprintf("logs/%d/%02d/%02d/%s/%s.json",
		now.Year(), now.Month(), now.Day(), entry.Service, entry.ID)

	// Upload to S3 with SSE-KMS encryption
	uploadResult, err := s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(s.bucket),
		Key:                  aws.String(s3Key),
		Body:                 bytes.NewReader(logJSON),
		ContentType:          aws.String("application/json"),
		ServerSideEncryption: types.ServerSideEncryptionAwsKms,
		SSEKMSKeyId:          aws.String(s.kmsKeyID),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload log to S3: %w", err)
	}

	// Detect and scrub PII from message
	piiResult := &PIIDetectionResult{
		Detected:      false,
		PIITypes:      []string{},
		ScrubbedText:  entry.Message,
		RedactionMask: []string{},
	}

	if s.piiDetector != nil {
		piiResult = s.piiDetector.DetectAndScrub(ctx, entry.Message)
	}

	// Create sanitized message preview (first 200 chars of scrubbed text)
	messagePreview := piiResult.ScrubbedText
	if len(messagePreview) > 200 {
		messagePreview = messagePreview[:200] + "..."
	}

	// Get redaction mask as JSON string
	redactionMask := piiResult.GetRedactionMaskJSON()

	// Determine compliance tags
	complianceTags := []string{}
	if piiResult.Detected {
		complianceTags = append(complianceTags, "pii", "gdpr")
	}
	if entry.Severity == "error" || entry.Severity == "critical" {
		complianceTags = append(complianceTags, "security")
	}

	// Save metadata to database
	metadata := &LogMetadata{
		ID:              uuid.New(),
		LogID:           entry.ID,
		CorrelationID:   entry.CorrelationID,
		TraceID:         entry.TraceID,
		ServiceName:     entry.Service,
		ServiceVersion:  entry.ServiceVersion,
		Environment:     entry.Environment,
		Severity:        entry.Severity,
		EventType:       entry.EventType,
		Category:        entry.Category,
		MessageDigest:   messageDigest,
		MessagePreview:  messagePreview,
		RedactionMask:   redactionMask,
		TenantID:        entry.TenantID,
		UserID:          entry.UserID,
		UserType:        entry.UserType,
		RequestID:       entry.RequestID,
		RequestMethod:   entry.RequestMethod,
		RequestPath:     entry.RequestPath,
		Timestamp:       entry.Timestamp,
		S3Bucket:        s.bucket,
		S3Key:           s3Key,
		S3Region:        s.region,
		S3ETag:          *uploadResult.ETag,
		Status:          "active",
		RetentionPolicy: "90-days-hot",
		PIIDetected:     piiResult.Detected,
		PIITypes:        piiResult.PIITypes,
		ComplianceTags:  complianceTags,
		Metadata:        entry.Metadata,
		Tags:            make(map[string]interface{}),
	}

	// Handle nullable fields
	if entry.SourceIP != "" {
		metadata.SourceIP = &entry.SourceIP
	}
	if entry.UserAgent != "" {
		metadata.UserAgent = &entry.UserAgent
	}
	if entry.ResponseStatus > 0 {
		metadata.ResponseStatus = &entry.ResponseStatus
	}
	if entry.DurationMs > 0 {
		metadata.DurationMs = &entry.DurationMs
	}

	// Insert metadata into database
	err = s.saveMetadata(ctx, metadata)
	if err != nil {
		return nil, fmt.Errorf("failed to save log metadata: %w", err)
	}

	// Trigger incident response hooks if enabled
	if s.incidentHook != nil {
		if err := s.incidentHook.CheckAndCreateIncident(ctx, metadata); err != nil {
			// Log error but don't fail log storage - incidents are important but shouldn't block logging
			// In production, this should go to an error log or monitoring system
			fmt.Printf("WARNING: Failed to trigger incident response hook: %v\n", err)
			_ = s.recordAccessAudit(ctx, uuid.Nil, "monitoring-service@system", "incident", metadata.LogID, map[string]interface{}{
				"error": err.Error(),
			}, 0, "error", err.Error(), 0)
		} else {
			s.recordIncidentAudit(ctx, metadata)
		}
	}

	return metadata, nil
}

// saveMetadata saves log metadata to the database
func (s *LogStorageService) saveMetadata(ctx context.Context, metadata *LogMetadata) error {
	query := `
		INSERT INTO platform_log_metadata (
			id, log_id, correlation_id, trace_id, service_name, service_version, environment,
			severity, event_type, category, message_digest, message_preview, redaction_mask,
			tenant_id, user_id, user_type, request_id, source_ip, user_agent,
			request_method, request_path, response_status, timestamp, duration_ms,
			s3_bucket, s3_key, s3_region, s3_etag, status, retention_policy,
			pii_detected, pii_types, compliance_tags, metadata, tags, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
			$20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34, $35, NOW(), NOW()
		)
	`

	metadataJSON, _ := json.Marshal(metadata.Metadata)
	tagsJSON, _ := json.Marshal(metadata.Tags)

	_, err := s.bypassDB.ExecContext(ctx, query,
		metadata.ID, metadata.LogID, metadata.CorrelationID, metadata.TraceID,
		metadata.ServiceName, metadata.ServiceVersion, metadata.Environment,
		metadata.Severity, metadata.EventType, metadata.Category,
		metadata.MessageDigest, metadata.MessagePreview, metadata.RedactionMask,
		metadata.TenantID, metadata.UserID, metadata.UserType, metadata.RequestID,
		metadata.SourceIP, metadata.UserAgent, metadata.RequestMethod, metadata.RequestPath,
		metadata.ResponseStatus, metadata.Timestamp, metadata.DurationMs,
		metadata.S3Bucket, metadata.S3Key, metadata.S3Region, metadata.S3ETag,
		metadata.Status, metadata.RetentionPolicy,
		metadata.PIIDetected, metadata.PIITypes, metadata.ComplianceTags,
		metadataJSON, tagsJSON,
	)

	return err
}

// GetSignedURL generates a time-limited signed URL for accessing a log from S3
// and records the access in the audit trail
func (s *LogStorageService) GetSignedURL(ctx context.Context, logID string, userID uuid.UUID, userEmail string, expiry time.Duration) (string, error) {
	startTime := time.Now()

	// Get log metadata to find S3 key
	var s3Key string
	query := `SELECT s3_key FROM platform_log_metadata WHERE log_id = $1 AND status = 'active'`
	err := s.bypassDB.QueryRowContext(ctx, query, logID).Scan(&s3Key)
	if err != nil {
		// Record failed access attempt
		_ = s.recordAccessAudit(ctx, userID, userEmail, "metadata", logID, nil, 0, "denied", fmt.Sprintf("Log not found: %v", err), time.Since(startTime))
		return "", fmt.Errorf("log not found: %w", err)
	}

	// Generate presigned URL
	presignClient := s3.NewPresignClient(s.s3Client)
	request, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = expiry
	})
	if err != nil {
		// Record failed access attempt
		_ = s.recordAccessAudit(ctx, userID, userEmail, "download", logID, nil, 0, "error", fmt.Sprintf("Failed to generate signed URL: %v", err), time.Since(startTime))
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}

	// Record successful access
	_ = s.recordAccessAudit(ctx, userID, userEmail, "download", logID, map[string]interface{}{"expiry_seconds": int(expiry.Seconds())}, 1, "success", "", time.Since(startTime))

	return request.URL, nil
}

// RetrieveLog retrieves a log entry from S3
func (s *LogStorageService) RetrieveLog(ctx context.Context, logID string) (*LogEntry, error) {
	// Get log metadata to find S3 key
	var s3Key string
	query := `SELECT s3_key FROM platform_log_metadata WHERE log_id = $1 AND status = 'active'`
	err := s.bypassDB.QueryRowContext(ctx, query, logID).Scan(&s3Key)
	if err != nil {
		return nil, fmt.Errorf("log not found: %w", err)
	}

	// Download from S3
	buf := manager.NewWriteAtBuffer([]byte{})
	_, err = s.downloader.Download(ctx, buf, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to download log from S3: %w", err)
	}

	// Deserialize log entry
	var entry LogEntry
	err = json.Unmarshal(buf.Bytes(), &entry)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal log entry: %w", err)
	}

	return &entry, nil
}

// DeleteLog marks a log as deleted (soft delete for compliance)
func (s *LogStorageService) DeleteLog(ctx context.Context, logID string, userID uuid.UUID, userEmail string) error {
	startTime := time.Now()

	query := `UPDATE platform_log_metadata SET status = 'deleted', deleted_at = NOW() WHERE log_id = $1`
	_, err := s.bypassDB.ExecContext(ctx, query, logID)

	if err != nil {
		_ = s.recordAccessAudit(ctx, userID, userEmail, "delete", logID, nil, 0, "error", err.Error(), time.Since(startTime))
		return err
	}

	_ = s.recordAccessAudit(ctx, userID, userEmail, "delete", logID, nil, 0, "success", "", time.Since(startTime))
	return nil
}

// recordAccessAudit records a log access operation in the audit trail
func (s *LogStorageService) recordAccessAudit(ctx context.Context, userID uuid.UUID, userEmail, accessType, logID string, filterCriteria map[string]interface{}, resultCount int, result, errorMessage string, duration time.Duration) error {
	query := `
		INSERT INTO platform_log_access_audit (
			accessed_by_user_id, accessed_by_email, access_type, log_id,
			filter_criteria, result_count, signed_url_generated, access_result,
			error_message, accessed_at, access_duration_ms, created_at
		) VALUES (
			$1, $2, $3, 
			CASE WHEN $4 = '' THEN NULL ELSE $4::uuid END,
			$5, $6, $7, $8, $9, NOW(), $10, NOW()
		)
	`

	var logIDUUID *uuid.UUID
	if logID != "" {
		if parsed, err := uuid.Parse(logID); err == nil {
			logIDUUID = &parsed
		}
	}

	filterJSON, _ := json.Marshal(filterCriteria)
	if filterJSON == nil {
		filterJSON = []byte("{}")
	}

	signedURLGenerated := accessType == "download"

	_, err := s.db.ExecContext(ctx, query,
		userID, userEmail, accessType, logIDUUID,
		filterJSON, resultCount, signedURLGenerated, result,
		errorMessage, int(duration.Milliseconds()),
	)

	return err
}

// recordIncidentAudit notes that an automated incident was generated for a log entry
func (s *LogStorageService) recordIncidentAudit(ctx context.Context, metadata *LogMetadata) {
	if metadata == nil {
		return
	}
	details := map[string]interface{}{
		"incident_source": "monitoring-service",
		"service":         metadata.ServiceName,
		"severity":        metadata.Severity,
		"event_type":      metadata.EventType,
		"category":        metadata.Category,
	}
	_ = s.recordAccessAudit(ctx, uuid.Nil, "monitoring-service@system", "incident", metadata.LogID, details, 1, "created", "", 0)
}

// SearchLogs searches logs by metadata and returns results with pagination
// Records the search in the access audit trail
func (s *LogStorageService) SearchLogs(ctx context.Context, userID uuid.UUID, userEmail string, filters map[string]interface{}, limit, offset int) ([]*LogMetadata, int, error) {
	startTime := time.Now()

	// Build query with filters
	query := `
		SELECT id, log_id, correlation_id, trace_id, service_name, service_version, environment,
		       severity, event_type, category, message_digest, message_preview, redaction_mask,
		       tenant_id, user_id, user_type, request_id, source_ip, user_agent,
		       request_method, request_path, response_status, timestamp, duration_ms,
		       s3_bucket, s3_key, s3_region, s3_etag, status, retention_policy,
		       pii_detected, pii_types, compliance_tags, metadata, tags
		FROM platform_log_metadata
		WHERE status = 'active'
	`
	args := []interface{}{}
	argIndex := 1

	// Apply filters
	if logID, ok := filters["log_id"].(string); ok && logID != "" {
		query += fmt.Sprintf(" AND log_id = $%d", argIndex)
		args = append(args, logID)
		argIndex++
	}
	if service, ok := filters["service"].(string); ok && service != "" {
		query += fmt.Sprintf(" AND service_name = $%d", argIndex)
		args = append(args, service)
		argIndex++
	}
	if severity, ok := filters["severity"].(string); ok && severity != "" {
		query += fmt.Sprintf(" AND severity = $%d", argIndex)
		args = append(args, severity)
		argIndex++
	}
	if startTime, ok := filters["start_time"].(time.Time); ok {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, startTime)
		argIndex++
	}
	if endTime, ok := filters["end_time"].(time.Time); ok {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, endTime)
		argIndex++
	}

	// Get total count
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM (%s) AS filtered", query)
	var totalCount int
	err := s.bypassDB.QueryRowContext(ctx, countQuery, args...).Scan(&totalCount)
	if err != nil {
		_ = s.recordAccessAudit(ctx, userID, userEmail, "search", "", filters, 0, "error", err.Error(), time.Since(startTime))
		return nil, 0, fmt.Errorf("failed to count logs: %w", err)
	}

	// Apply pagination
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT $%d OFFSET $%d", argIndex, argIndex+1) //nolint:gosec // intentional — placeholder concatenation only; values are parameterized via args slice
	args = append(args, limit, offset)

	// Execute query
	rows, err := s.bypassDB.QueryContext(ctx, query, args...)
	if err != nil {
		_ = s.recordAccessAudit(ctx, userID, userEmail, "search", "", filters, 0, "error", err.Error(), time.Since(startTime))
		return nil, 0, fmt.Errorf("failed to query logs: %w", err)
	}
	defer rows.Close()

	var results []*LogMetadata
	for rows.Next() {
		metadata := &LogMetadata{}
		var metadataJSON, tagsJSON []byte
		err := rows.Scan(
			&metadata.ID, &metadata.LogID, &metadata.CorrelationID, &metadata.TraceID,
			&metadata.ServiceName, &metadata.ServiceVersion, &metadata.Environment,
			&metadata.Severity, &metadata.EventType, &metadata.Category,
			&metadata.MessageDigest, &metadata.MessagePreview, &metadata.RedactionMask,
			&metadata.TenantID, &metadata.UserID, &metadata.UserType, &metadata.RequestID,
			&metadata.SourceIP, &metadata.UserAgent, &metadata.RequestMethod, &metadata.RequestPath,
			&metadata.ResponseStatus, &metadata.Timestamp, &metadata.DurationMs,
			&metadata.S3Bucket, &metadata.S3Key, &metadata.S3Region, &metadata.S3ETag,
			&metadata.Status, &metadata.RetentionPolicy,
			&metadata.PIIDetected, &metadata.PIITypes, &metadata.ComplianceTags,
			&metadataJSON, &tagsJSON,
		)
		if err != nil {
			continue
		}

		json.Unmarshal(metadataJSON, &metadata.Metadata)
		json.Unmarshal(tagsJSON, &metadata.Tags)
		results = append(results, metadata)
	}

	// Record access audit
	_ = s.recordAccessAudit(ctx, userID, userEmail, "search", "", filters, len(results), "success", "", time.Since(startTime))

	return results, totalCount, nil
}
