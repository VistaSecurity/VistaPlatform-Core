package services

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/google/uuid"
	auditConfig "github.com/vistasecurity/vistaplatform/audit-service/internal/config"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
)

// S3ArchivalService handles archiving audit logs to S3
type S3ArchivalService struct {
	client     *s3.Client
	bucket     string
	pathPrefix string
	kmsKeyID   string
	enabled    bool
	logger     *log.Logger
}

// NewS3ArchivalService creates a new S3 archival service
func NewS3ArchivalService(cfg *auditConfig.S3Config) (*S3ArchivalService, error) {
	service := &S3ArchivalService{
		bucket:     cfg.Bucket,
		pathPrefix: cfg.PathPrefix,
		kmsKeyID:   cfg.KMSKeyID,
		enabled:    cfg.Enabled,
		logger:     log.New(log.Writer(), "[S3Archival] ", log.LstdFlags),
	}

	if !cfg.Enabled {
		service.logger.Println("S3 archival is disabled")
		return service, nil
	}

	if cfg.Bucket == "" {
		return nil, fmt.Errorf("S3_LOG_BUCKET is required when S3 archival is enabled")
	}

	// Build AWS config options
	var optFns []func(*config.LoadOptions) error

	// Set region
	optFns = append(optFns, config.WithRegion(cfg.Region))

	// Use explicit credentials if provided
	if cfg.AccessKeyID != "" && cfg.SecretAccessKey != "" {
		optFns = append(optFns, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				cfg.AccessKeyID,
				cfg.SecretAccessKey,
				"",
			),
		))
	}

	// Load AWS config
	awsCfg, err := config.LoadDefaultConfig(context.Background(), optFns...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create S3 client with optional custom endpoint (for MinIO)
	s3Options := func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
			o.UsePathStyle = true // Required for MinIO
		}
	}

	service.client = s3.NewFromConfig(awsCfg, s3Options)
	service.logger.Printf("S3 archival initialized: bucket=%s, region=%s", cfg.Bucket, cfg.Region)

	return service, nil
}

// IsEnabled returns whether S3 archival is enabled
func (s *S3ArchivalService) IsEnabled() bool {
	return s.enabled
}

// ArchiveLogs archives a batch of activity logs to S3
func (s *S3ArchivalService) ArchiveLogs(ctx context.Context, logs []*models.ActivityLog, tenantID *uuid.UUID) (*ArchiveResult, error) {
	if !s.enabled {
		return nil, fmt.Errorf("S3 archival is not enabled")
	}

	if len(logs) == 0 {
		return &ArchiveResult{LogsArchived: 0}, nil
	}

	// Determine the time range of the logs
	var minTime, maxTime time.Time
	for _, log := range logs {
		if minTime.IsZero() || log.OccurredAt.Before(minTime) {
			minTime = log.OccurredAt
		}
		if maxTime.IsZero() || log.OccurredAt.After(maxTime) {
			maxTime = log.OccurredAt
		}
	}

	// Generate S3 key
	key := s.generateKey(tenantID, minTime, maxTime)

	// Serialize logs to JSON
	data, err := json.Marshal(logs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal logs: %w", err)
	}

	// Compress with gzip
	var compressed bytes.Buffer
	gzWriter := gzip.NewWriter(&compressed)
	if _, err := gzWriter.Write(data); err != nil {
		return nil, fmt.Errorf("failed to compress logs: %w", err)
	}
	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Upload to S3
	input := &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(compressed.Bytes()),
		ContentType: aws.String("application/gzip"),
		Metadata: map[string]string{
			"log-count":       fmt.Sprintf("%d", len(logs)),
			"min-timestamp":   minTime.Format(time.RFC3339),
			"max-timestamp":   maxTime.Format(time.RFC3339),
			"original-size":   fmt.Sprintf("%d", len(data)),
			"compressed-size": fmt.Sprintf("%d", compressed.Len()),
		},
	}

	// Add KMS encryption if configured
	if s.kmsKeyID != "" {
		input.ServerSideEncryption = types.ServerSideEncryptionAwsKms
		input.SSEKMSKeyId = aws.String(s.kmsKeyID)
	}

	if tenantID != nil {
		input.Metadata["tenant-id"] = tenantID.String()
	}

	_, err = s.client.PutObject(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to upload to S3: %w", err)
	}

	s.logger.Printf("Archived %d logs to s3://%s/%s (%.2f KB compressed)",
		len(logs), s.bucket, key, float64(compressed.Len())/1024)

	return &ArchiveResult{
		LogsArchived:   len(logs),
		S3Key:          key,
		OriginalSize:   len(data),
		CompressedSize: compressed.Len(),
		MinTimestamp:   minTime,
		MaxTimestamp:   maxTime,
	}, nil
}

// generateKey generates the S3 key for archived logs
func (s *S3ArchivalService) generateKey(tenantID *uuid.UUID, minTime, maxTime time.Time) string {
	year := minTime.Year()
	month := int(minTime.Month())
	day := minTime.Day()

	var key string
	if tenantID != nil {
		// Tenant-specific path
		key = fmt.Sprintf("%s/tenant/%s/%d/%02d/%02d/logs_%s_%s.json.gz",
			s.pathPrefix,
			tenantID.String(),
			year, month, day,
			minTime.Format("150405"),
			uuid.New().String()[:8],
		)
	} else {
		// Platform-wide path
		key = fmt.Sprintf("%s/platform/%d/%02d/%02d/logs_%s_%s.json.gz",
			s.pathPrefix,
			year, month, day,
			minTime.Format("150405"),
			uuid.New().String()[:8],
		)
	}

	return key
}

// ListArchivedLogs lists archived log files for a tenant within a date range
func (s *S3ArchivalService) ListArchivedLogs(ctx context.Context, tenantID *uuid.UUID, startDate, endDate time.Time) ([]ArchivedLogFile, error) {
	if !s.enabled {
		return nil, fmt.Errorf("S3 archival is not enabled")
	}

	var prefix string
	if tenantID != nil {
		prefix = fmt.Sprintf("%s/tenant/%s/", s.pathPrefix, tenantID.String())
	} else {
		prefix = fmt.Sprintf("%s/platform/", s.pathPrefix)
	}

	input := &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	}

	var files []ArchivedLogFile
	paginator := s3.NewListObjectsV2Paginator(s.client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list S3 objects: %w", err)
		}

		for _, obj := range page.Contents {
			// Filter by date range based on last modified
			if obj.LastModified != nil {
				if obj.LastModified.Before(startDate) || obj.LastModified.After(endDate) {
					continue
				}
			}

			files = append(files, ArchivedLogFile{
				Key:          aws.ToString(obj.Key),
				Size:         aws.ToInt64(obj.Size),
				LastModified: aws.ToTime(obj.LastModified),
			})
		}
	}

	return files, nil
}

// ArchiveResult contains the result of an archive operation
type ArchiveResult struct {
	LogsArchived   int       `json:"logs_archived"`
	S3Key          string    `json:"s3_key"`
	OriginalSize   int       `json:"original_size"`
	CompressedSize int       `json:"compressed_size"`
	MinTimestamp   time.Time `json:"min_timestamp"`
	MaxTimestamp   time.Time `json:"max_timestamp"`
}

// ArchivedLogFile represents an archived log file in S3
type ArchivedLogFile struct {
	Key          string    `json:"key"`
	Size         int64     `json:"size"`
	LastModified time.Time `json:"last_modified"`
}
