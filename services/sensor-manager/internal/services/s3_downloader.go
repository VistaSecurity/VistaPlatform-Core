package services

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Downloader handles downloading sensor binaries from S3
type S3Downloader struct {
	s3Client   *s3.Client
	downloader *manager.Downloader
	bucket     string
	region     string
	version    string
	enabled    bool
}

// NewS3Downloader creates a new S3 downloader
func NewS3Downloader(bucket, region, version string) (*S3Downloader, error) {
	if bucket == "" {
		// S3 not configured, return disabled downloader
		return &S3Downloader{
			enabled: false,
		}, nil
	}

	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	s3Client := s3.NewFromConfig(cfg)
	downloader := manager.NewDownloader(s3Client)

	if version == "" {
		version = "latest"
	}

	return &S3Downloader{
		s3Client:   s3Client,
		downloader: downloader,
		bucket:     bucket,
		region:     region,
		version:    version,
		enabled:    true,
	}, nil
}

// IsEnabled returns whether S3 downloading is enabled
func (s *S3Downloader) IsEnabled() bool {
	return s.enabled
}

// DownloadBinary downloads a sensor binary from S3
// Returns the binary data and content type, or an error
func (s *S3Downloader) DownloadBinary(ctx context.Context, osName, arch string) ([]byte, string, error) {
	if !s.enabled {
		return nil, "", fmt.Errorf("S3 downloader not enabled")
	}

	// Determine binary name based on OS
	binaryName := "crypto-sensor"
	if osName == "windows" {
		binaryName = "crypto-sensor.exe"
	}

	// S3 key: sensors/{version}/{os}/{arch}/crypto-sensor[.exe]
	s3Key := fmt.Sprintf("sensors/%s/%s/%s/%s", s.version, osName, arch, binaryName)

	// Create a buffer to download into
	buf := manager.NewWriteAtBuffer([]byte{})

	// Download from S3
	_, err := s.downloader.Download(ctx, buf, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to download from S3: %w", err)
	}

	return buf.Bytes(), "application/octet-stream", nil
}

// GetPresignedURL generates a presigned URL for direct S3 download
// This allows clients to download directly from S3 without going through the service
// expiresIn is the duration in seconds for the presigned URL to be valid
func (s *S3Downloader) GetPresignedURL(ctx context.Context, osName, arch string, expiresIn int) (string, error) {
	if !s.enabled {
		return "", fmt.Errorf("S3 downloader not enabled")
	}

	// Determine binary name based on OS
	binaryName := "crypto-sensor"
	if osName == "windows" {
		binaryName = "crypto-sensor.exe"
	}

	// S3 key: sensors/{version}/{os}/{arch}/crypto-sensor[.exe]
	s3Key := fmt.Sprintf("sensors/%s/%s/%s/%s", s.version, osName, arch, binaryName)

	presignClient := s3.NewPresignClient(s.s3Client)
	request, err := presignClient.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(s3Key),
	}, func(opts *s3.PresignOptions) {
		opts.Expires = time.Duration(expiresIn) * time.Second
	})
	if err != nil {
		return "", fmt.Errorf("failed to generate presigned URL: %w", err)
	}

	return request.URL, nil
}

// StreamBinary streams a binary from S3 to an HTTP response writer
func (s *S3Downloader) StreamBinary(ctx context.Context, w http.ResponseWriter, osName, arch string) error {
	if !s.enabled {
		return fmt.Errorf("S3 downloader not enabled")
	}

	data, contentType, err := s.DownloadBinary(ctx, osName, arch)
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=crypto-sensor%s", getExtension(osName)))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))

	_, err = w.Write(data)
	return err
}

func getExtension(osName string) string {
	if strings.ToLower(osName) == "windows" {
		return ".exe"
	}
	return ""
}
