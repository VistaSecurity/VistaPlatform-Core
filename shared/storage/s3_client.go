package storage

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// S3StorageService implements ArtifactStorageService using AWS S3
type S3StorageService struct {
	config              *StorageConfig
	integrationProvider IntegrationProvider
	configProvider      ConfigProvider
	log                 *logrus.Logger
	mu                  sync.RWMutex

	// Cached S3 clients per integration
	clients   map[uuid.UUID]*s3.Client
	clientsMu sync.RWMutex
}

// NewS3StorageService creates a new S3-backed storage service
func NewS3StorageService(
	configProvider ConfigProvider,
	integrationProvider IntegrationProvider,
	log *logrus.Logger,
) *S3StorageService {
	if log == nil {
		log = logrus.New()
	}

	return &S3StorageService{
		config:              DefaultStorageConfig(),
		integrationProvider: integrationProvider,
		configProvider:      configProvider,
		log:                 log,
		clients:             make(map[uuid.UUID]*s3.Client),
	}
}

// Reload reloads the storage configuration from the database
func (s *S3StorageService) Reload(ctx context.Context) error {
	if s.configProvider == nil {
		return nil
	}

	config, err := s.configProvider.GetStorageConfig(ctx)
	if err != nil {
		return fmt.Errorf("failed to load storage config: %w", err)
	}

	s.mu.Lock()
	s.config = config
	s.mu.Unlock()

	// Clear cached clients since credentials might have changed
	s.clientsMu.Lock()
	s.clients = make(map[uuid.UUID]*s3.Client)
	s.clientsMu.Unlock()

	s.log.Info("Storage configuration reloaded")
	return nil
}

// getConfig returns the current config with read lock
func (s *S3StorageService) getConfig() *StorageConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

// IsEnabled returns whether storage is enabled for the given artifact type
func (s *S3StorageService) IsEnabled(artifactType ArtifactType) bool {
	config := s.getConfig()
	if config == nil || config.DefaultIntegrationID == nil {
		return false
	}

	artConfig, ok := config.ArtifactTypes[artifactType]
	if !ok {
		return false
	}

	return artConfig.Enabled
}

// GetArtifactConfig returns the artifact configuration for the given type
func (s *S3StorageService) GetArtifactConfig(artifactType ArtifactType) (*ArtifactConfig, error) {
	config := s.getConfig()
	if config == nil {
		return nil, ErrStorageNotConfigured
	}

	artConfig, ok := config.ArtifactTypes[artifactType]
	if !ok {
		return nil, ErrArtifactTypeNotFound
	}

	return &artConfig, nil
}

// getS3Client returns an S3 client for the given integration, creating one if needed
func (s *S3StorageService) getS3Client(ctx context.Context, integrationID uuid.UUID) (*s3.Client, error) {
	// Check cache first
	s.clientsMu.RLock()
	client, ok := s.clients[integrationID]
	s.clientsMu.RUnlock()

	if ok {
		return client, nil
	}

	// Get credentials from integration provider
	creds, err := s.integrationProvider.GetAWSCredentials(ctx, integrationID)
	if err != nil {
		return nil, fmt.Errorf("failed to get AWS credentials: %w", err)
	}

	// Create S3 client
	cfg := aws.Config{
		Region: creds.Region,
		Credentials: credentials.NewStaticCredentialsProvider(
			creds.AccessKeyID,
			creds.SecretAccessKey,
			creds.SessionToken,
		),
	}

	client = s3.NewFromConfig(cfg)

	// Cache the client
	s.clientsMu.Lock()
	s.clients[integrationID] = client
	s.clientsMu.Unlock()

	return client, nil
}

// Upload uploads a file to S3
func (s *S3StorageService) Upload(
	ctx context.Context,
	artifactType ArtifactType,
	tenantID *uuid.UUID,
	filename string,
	data io.Reader,
	contentType string,
	size int64,
) (*UploadResult, error) {
	config := s.getConfig()
	if config == nil {
		return nil, ErrStorageNotConfigured
	}

	artConfig, ok := config.ArtifactTypes[artifactType]
	if !ok {
		return nil, ErrArtifactTypeNotFound
	}

	if !artConfig.Enabled {
		return nil, ErrStorageNotConfigured
	}

	// Validate file size
	if size > artConfig.GetMaxFileSize() {
		return nil, ErrFileTooLarge
	}

	// Validate content type
	if !artConfig.IsAllowedType(contentType) {
		return nil, ErrContentTypeNotAllowed
	}

	// Get integration ID
	integrationID := artConfig.GetIntegrationID(config.DefaultIntegrationID)
	if integrationID == nil {
		return nil, ErrIntegrationNotConfigured
	}

	// Get S3 client
	client, err := s.getS3Client(ctx, *integrationID)
	if err != nil {
		return nil, err
	}

	// Determine bucket and key
	bucket := artConfig.GetBucket(config.DefaultBucket)
	key := artConfig.ResolvePath(filename, tenantID)

	// Read data to calculate checksum (we need to read it anyway for upload)
	dataBytes, err := io.ReadAll(data)
	if err != nil {
		return nil, fmt.Errorf("failed to read upload data: %w", err)
	}

	// Calculate MD5 checksum
	hash := md5.Sum(dataBytes)
	checksum := hex.EncodeToString(hash[:])

	// Upload to S3
	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        strings.NewReader(string(dataBytes)),
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upload to S3: %w", err)
	}

	// Generate URL based on strategy
	url, err := s.generateURL(ctx, client, bucket, key, &artConfig, config)
	if err != nil {
		return nil, fmt.Errorf("failed to generate URL: %w", err)
	}

	s.log.WithFields(logrus.Fields{
		"artifact_type": artifactType,
		"bucket":        bucket,
		"key":           key,
		"size":          len(dataBytes),
	}).Info("File uploaded to S3")

	return &UploadResult{
		Key:      key,
		URL:      url,
		Bucket:   bucket,
		Size:     int64(len(dataBytes)),
		Checksum: checksum,
	}, nil
}

// GetURL generates a URL for accessing an existing artifact
func (s *S3StorageService) GetURL(
	ctx context.Context,
	artifactType ArtifactType,
	key string,
	tenantID *uuid.UUID,
) (string, error) {
	config := s.getConfig()
	if config == nil {
		return "", ErrStorageNotConfigured
	}

	artConfig, ok := config.ArtifactTypes[artifactType]
	if !ok {
		return "", ErrArtifactTypeNotFound
	}

	if !artConfig.Enabled {
		return "", ErrStorageNotConfigured
	}

	// Get integration ID
	integrationID := artConfig.GetIntegrationID(config.DefaultIntegrationID)
	if integrationID == nil {
		return "", ErrIntegrationNotConfigured
	}

	// Get S3 client
	client, err := s.getS3Client(ctx, *integrationID)
	if err != nil {
		return "", err
	}

	bucket := artConfig.GetBucket(config.DefaultBucket)

	return s.generateURL(ctx, client, bucket, key, &artConfig, config)
}

// generateURL generates a URL based on the configured strategy
func (s *S3StorageService) generateURL(
	ctx context.Context,
	client *s3.Client,
	bucket, key string,
	artConfig *ArtifactConfig,
	config *StorageConfig,
) (string, error) {
	switch artConfig.URLStrategy {
	case URLStrategyCDN:
		if artConfig.BaseURL != nil && *artConfig.BaseURL != "" {
			return fmt.Sprintf("%s/%s", strings.TrimSuffix(*artConfig.BaseURL, "/"), key), nil
		}
		// Fallback to direct S3 URL
		return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, config.DefaultRegion, key), nil

	case URLStrategyDirect:
		return fmt.Sprintf("https://%s.s3.%s.amazonaws.com/%s", bucket, config.DefaultRegion, key), nil

	case URLStrategyPresigned:
		fallthrough
	default:
		// Generate presigned URL
		presignClient := s3.NewPresignClient(client)
		expiry := time.Duration(artConfig.GetPresignExpiry()) * time.Second

		presignedReq, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(key),
		}, func(opts *s3.PresignOptions) {
			opts.Expires = expiry
		})
		if err != nil {
			return "", fmt.Errorf("failed to generate presigned URL: %w", err)
		}

		return presignedReq.URL, nil
	}
}

// Delete removes a file from S3
func (s *S3StorageService) Delete(
	ctx context.Context,
	artifactType ArtifactType,
	key string,
	tenantID *uuid.UUID,
) error {
	config := s.getConfig()
	if config == nil {
		return ErrStorageNotConfigured
	}

	artConfig, ok := config.ArtifactTypes[artifactType]
	if !ok {
		return ErrArtifactTypeNotFound
	}

	if !artConfig.Enabled {
		return ErrStorageNotConfigured
	}

	// Get integration ID
	integrationID := artConfig.GetIntegrationID(config.DefaultIntegrationID)
	if integrationID == nil {
		return ErrIntegrationNotConfigured
	}

	// Get S3 client
	client, err := s.getS3Client(ctx, *integrationID)
	if err != nil {
		return err
	}

	bucket := artConfig.GetBucket(config.DefaultBucket)

	_, err = client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("failed to delete from S3: %w", err)
	}

	s.log.WithFields(logrus.Fields{
		"artifact_type": artifactType,
		"bucket":        bucket,
		"key":           key,
	}).Info("File deleted from S3")

	return nil
}

// Stream opens a read stream to an existing object's bytes via S3 GetObject.
// The caller must Close the returned reader.
func (s *S3StorageService) Stream(
	ctx context.Context,
	artifactType ArtifactType,
	key string,
	tenantID *uuid.UUID,
) (io.ReadCloser, error) {
	config := s.getConfig()
	if config == nil {
		return nil, ErrStorageNotConfigured
	}

	artConfig, ok := config.ArtifactTypes[artifactType]
	if !ok {
		return nil, ErrArtifactTypeNotFound
	}

	if !artConfig.Enabled {
		return nil, ErrStorageNotConfigured
	}

	integrationID := artConfig.GetIntegrationID(config.DefaultIntegrationID)
	if integrationID == nil {
		return nil, ErrIntegrationNotConfigured
	}

	client, err := s.getS3Client(ctx, *integrationID)
	if err != nil {
		return nil, err
	}

	bucket := artConfig.GetBucket(config.DefaultBucket)

	out, err := client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open S3 object stream: %w", err)
	}

	return out.Body, nil
}

// SetConfig sets the storage configuration directly (useful for testing or initialization)
func (s *S3StorageService) SetConfig(config *StorageConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.config = config
}
