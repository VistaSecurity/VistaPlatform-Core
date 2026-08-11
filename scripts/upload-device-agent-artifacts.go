// +build ignore

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

const (
	defaultBucket = "crypto-inventory-artifacts"
	defaultRegion = "us-east-1"
)

var (
	platforms = []struct {
		os   string
		arch string
		ext  string
	}{
		{"linux", "amd64", ""},
		{"linux", "arm64", ""},
		{"windows", "amd64", ".exe"},
		{"darwin", "amd64", ""},
		{"darwin", "arm64", ""},
	}
)

func main() {
	var (
		bucket       = flag.String("bucket", "", fmt.Sprintf("S3 bucket name (default: %s or S3_ARTIFACTS_BUCKET env var)", defaultBucket))
		region       = flag.String("region", "", fmt.Sprintf("AWS region (default: %s or AWS_REGION env var)", defaultRegion))
		version      = flag.String("version", "", "Version tag for artifacts (e.g., v1.0.0, latest). If empty, uses 'latest'")
		artifactsDir = flag.String("artifacts-dir", "artifacts/device-agent", "Path to artifacts directory")
		dryRun       = flag.Bool("dry-run", false, "Show what would be uploaded without actually uploading")
		help         = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	// Determine bucket
	bucketName := *bucket
	if bucketName == "" {
		bucketName = os.Getenv("S3_ARTIFACTS_BUCKET")
		if bucketName == "" {
			bucketName = defaultBucket
		}
	}

	// Determine region
	awsRegion := *region
	if awsRegion == "" {
		awsRegion = os.Getenv("AWS_REGION")
		if awsRegion == "" {
			awsRegion = defaultRegion
		}
	}

	// Determine version
	artifactVersion := *version
	if artifactVersion == "" {
		artifactVersion = os.Getenv("DEVICE_AGENT_VERSION")
		if artifactVersion == "" {
			artifactVersion = "latest"
		}
	}

	// Normalize version (remove 'v' prefix if present, but keep it for display)
	displayVersion := artifactVersion
	if strings.HasPrefix(artifactVersion, "v") {
		artifactVersion = strings.TrimPrefix(artifactVersion, "v")
	}

	fmt.Printf("🚀 Uploading device-agent artifacts to S3\n")
	fmt.Printf("   Bucket: %s\n", bucketName)
	fmt.Printf("   Region: %s\n", awsRegion)
	fmt.Printf("   Version: %s\n", displayVersion)
	fmt.Printf("   Artifacts Dir: %s\n", *artifactsDir)
	if *dryRun {
		fmt.Printf("   Mode: DRY RUN (no uploads will occur)\n")
	}
	fmt.Println()

	// Load AWS config
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(awsRegion))
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Failed to load AWS config: %v\n", err)
		os.Exit(1)
	}

	s3Client := s3.NewFromConfig(cfg)
	uploader := manager.NewUploader(s3Client)

	// Check if bucket exists (or create it if we have permissions)
	if !*dryRun {
		_, err = s3Client.HeadBucket(ctx, &s3.HeadBucketInput{
			Bucket: aws.String(bucketName),
		})
		if err != nil {
			fmt.Printf("⚠️  Bucket %s not found or not accessible. Attempting to create...\n", bucketName)
			_, createErr := s3Client.CreateBucket(ctx, &s3.CreateBucketInput{
				Bucket: aws.String(bucketName),
				CreateBucketConfiguration: &types.CreateBucketConfiguration{
					LocationConstraint: types.BucketLocationConstraint(awsRegion),
				},
			})
			if createErr != nil {
				fmt.Fprintf(os.Stderr, "❌ Failed to create bucket: %v\n", createErr)
				fmt.Fprintf(os.Stderr, "   Please create the bucket manually or check AWS permissions\n")
				os.Exit(1)
			}
			fmt.Printf("✅ Bucket created successfully\n")
		}
	}

	uploaded := 0
	skipped := 0
	failed := 0

	// Upload each platform binary
	for _, platform := range platforms {
		binaryName := "device-agent"
		if platform.ext != "" {
			binaryName += platform.ext
		}
		localPath := filepath.Join(*artifactsDir, platform.os, platform.arch, binaryName)

		// Check if file exists
		stat, err := os.Stat(localPath)
		if err != nil {
			fmt.Printf("⚠️  Skipping %s/%s: file not found at %s\n", platform.os, platform.arch, localPath)
			skipped++
			continue
		}

		// Calculate SHA256 hash
		hash, err := calculateSHA256(localPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to calculate hash for %s: %v\n", localPath, err)
			failed++
			continue
		}

		// S3 key: device-agents/{version}/{os}/{arch}/device-agent
		s3Key := fmt.Sprintf("device-agents/%s/%s/%s/%s", artifactVersion, platform.os, platform.arch, binaryName)

		// Also upload to latest if this is not already latest
		latestKey := fmt.Sprintf("device-agents/latest/%s/%s/%s", platform.os, platform.arch, binaryName)

		fmt.Printf("📦 %s/%s (%s)\n", platform.os, platform.arch, formatBytes(stat.Size()))
		fmt.Printf("   Hash: %s\n", hash)
		fmt.Printf("   S3 Key: s3://%s/%s\n", bucketName, s3Key)

		if *dryRun {
			fmt.Printf("   [DRY RUN] Would upload to S3\n")
			uploaded++
			continue
		}

		// Open file for reading
		file, err := os.Open(localPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to open %s: %v\n", localPath, err)
			failed++
			continue
		}

		// Upload to versioned path
		_, err = uploader.Upload(ctx, &s3.PutObjectInput{
			Bucket:               aws.String(bucketName),
			Key:                  aws.String(s3Key),
			Body:                 file,
			ContentType:          aws.String("application/octet-stream"),
			ServerSideEncryption: types.ServerSideEncryptionAes256,
			Metadata: map[string]string{
				"sha256":        hash,
				"platform":      fmt.Sprintf("%s/%s", platform.os, platform.arch),
				"version":       displayVersion,
				"uploaded-at":   time.Now().UTC().Format(time.RFC3339),
				"content-type":  "application/octet-stream",
				"artifact-type": "device_agent_binary",
			},
		})
		file.Close()

		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Failed to upload %s: %v\n", s3Key, err)
			failed++
			continue
		}

		// Also upload to latest if this is not already latest
		if artifactVersion != "latest" {
			file, err = os.Open(localPath)
			if err == nil {
				_, err = uploader.Upload(ctx, &s3.PutObjectInput{
					Bucket:               aws.String(bucketName),
					Key:                  aws.String(latestKey),
					Body:                 file,
					ContentType:          aws.String("application/octet-stream"),
					ServerSideEncryption: types.ServerSideEncryptionAes256,
					Metadata: map[string]string{
						"sha256":        hash,
						"platform":      fmt.Sprintf("%s/%s", platform.os, platform.arch),
						"version":       displayVersion,
						"uploaded-at":   time.Now().UTC().Format(time.RFC3339),
						"content-type":  "application/octet-stream",
						"artifact-type": "device_agent_binary",
						"points-to":     s3Key, // Track which version this latest points to
					},
				})
				file.Close()
				if err != nil {
					fmt.Fprintf(os.Stderr, "⚠️  Failed to upload latest symlink: %v\n", err)
				} else {
					fmt.Printf("   Also uploaded to: s3://%s/%s\n", bucketName, latestKey)
				}
			}
		}

		fmt.Printf("   ✅ Uploaded successfully\n")
		uploaded++
	}

	fmt.Println()
	if *dryRun {
		fmt.Printf("📊 Summary: Would upload %d, skip %d, fail %d\n", uploaded, skipped, failed)
	} else {
		fmt.Printf("📊 Summary: Uploaded %d, skipped %d, failed %d\n", uploaded, skipped, failed)
		if uploaded > 0 {
			fmt.Printf("\n💡 Download URLs:\n")
			fmt.Printf("   Base URL: https://%s.s3.%s.amazonaws.com/device-agents/%s/\n", bucketName, awsRegion, artifactVersion)
			fmt.Printf("   Example: https://%s.s3.%s.amazonaws.com/device-agents/%s/linux/amd64/device-agent\n", bucketName, awsRegion, artifactVersion)
		}
	}

	if failed > 0 {
		os.Exit(1)
	}
}

func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
