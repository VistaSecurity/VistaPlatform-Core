package storage

import (
	"context"
	"errors"
	"io"

	"github.com/google/uuid"
)

var (
	// ErrStorageNotConfigured indicates storage is not configured for this artifact type
	ErrStorageNotConfigured = errors.New("storage not configured for this artifact type")
	// ErrArtifactTypeNotFound indicates the artifact type is not recognized
	ErrArtifactTypeNotFound = errors.New("artifact type not found in configuration")
	// ErrFileTooLarge indicates the file exceeds the maximum allowed size
	ErrFileTooLarge = errors.New("file exceeds maximum allowed size")
	// ErrContentTypeNotAllowed indicates the content type is not allowed for this artifact type
	ErrContentTypeNotAllowed = errors.New("content type not allowed for this artifact type")
	// ErrIntegrationNotConfigured indicates no AWS integration is configured
	ErrIntegrationNotConfigured = errors.New("AWS integration not configured")
)

// UploadResult contains the result of an upload operation
type UploadResult struct {
	Key      string `json:"key"`      // S3 object key (full path)
	URL      string `json:"url"`      // Public or presigned URL for accessing the file
	Bucket   string `json:"bucket"`   // S3 bucket name
	Size     int64  `json:"size"`     // File size in bytes
	Checksum string `json:"checksum"` // MD5 or SHA256 checksum
}

// ArtifactStorageService defines the interface for artifact storage operations
type ArtifactStorageService interface {
	// Upload uploads a file to storage for the given artifact type
	// Returns the upload result with the URL to access the file
	Upload(ctx context.Context, artifactType ArtifactType, tenantID *uuid.UUID,
		filename string, data io.Reader, contentType string, size int64) (*UploadResult, error)

	// GetURL generates a URL for accessing an existing artifact
	// For presigned strategy, generates a new presigned URL
	// For CDN/direct strategy, returns the public URL
	GetURL(ctx context.Context, artifactType ArtifactType, key string,
		tenantID *uuid.UUID) (string, error)

	// Stream opens a read stream to an existing artifact's bytes. The caller
	// owns the returned reader and must Close it. Used for server-side reads
	// (e.g. CBOM diff, signature verification, SPDX/PDF projection) that need
	// the content itself rather than a presigned/CDN URL handed to the client.
	Stream(ctx context.Context, artifactType ArtifactType, key string,
		tenantID *uuid.UUID) (io.ReadCloser, error)

	// Delete removes a file from storage
	Delete(ctx context.Context, artifactType ArtifactType, key string,
		tenantID *uuid.UUID) error

	// IsEnabled returns whether storage is enabled for the given artifact type
	IsEnabled(artifactType ArtifactType) bool

	// GetConfig returns the artifact configuration for validation
	GetArtifactConfig(artifactType ArtifactType) (*ArtifactConfig, error)

	// Reload reloads the storage configuration from the database
	Reload(ctx context.Context) error
}

// AWSCredentials contains decrypted AWS credentials for S3 access
type AWSCredentials struct {
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string // Optional, for temporary credentials
	Region          string
}

// IntegrationProvider defines the interface for retrieving AWS credentials
// This is implemented by the admin-service's IntegrationService
type IntegrationProvider interface {
	// GetAWSCredentials retrieves decrypted AWS credentials for the given integration ID
	GetAWSCredentials(ctx context.Context, integrationID uuid.UUID) (*AWSCredentials, error)
}

// ConfigProvider defines the interface for retrieving storage configuration
type ConfigProvider interface {
	// GetStorageConfig retrieves the current storage configuration from the database
	GetStorageConfig(ctx context.Context) (*StorageConfig, error)
}
