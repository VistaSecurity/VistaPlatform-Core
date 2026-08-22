package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
	"github.com/vistasecurity/vistaplatform/shared/storage"
)

var (
	platformBrandingLogger *logrus.Logger
	platformStorageService storage.ArtifactStorageService
)

// InitializePlatformBrandingService sets up the storage service for platform branding.
// The storage config is global, but the referenced platform_integrations row is
// RLS-protected and selected by id from that config, so credential lookup uses
// the bypass handle.
func InitializePlatformBrandingService(db, bypassDB *sql.DB, encryptionMasterKey string, log *logrus.Logger) error {
	platformBrandingLogger = log

	// Create encryption service
	encSvc, err := encryption.NewService(encryptionMasterKey)
	if err != nil {
		return fmt.Errorf("failed to create encryption service: %w", err)
	}

	// Create config and integration providers
	configProvider := storage.NewDatabaseConfigProvider(db)
	integrationProvider := storage.NewDatabaseIntegrationProvider(bypassDB, encSvc)

	// Create S3 storage service
	platformStorageService = storage.NewS3StorageService(configProvider, integrationProvider, log)

	// Load initial config with timeout to prevent deadlock during initialization
	// Use a short timeout and make it non-blocking - config can be reloaded later if needed
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Reload config in a goroutine to avoid blocking server startup
	// If it fails, the service will still start and can reload config later
	go func() {
		if err := platformStorageService.Reload(ctx); err != nil {
			log.WithError(err).Warn("Failed to load initial storage config, S3 storage may not be available. Config can be reloaded later.")
		} else {
			log.Info("Platform branding storage configuration loaded successfully")
		}
	}()

	return nil
}

// UploadPlatformBrandingAsset handles POST /admin/branding/upload - Upload platform logo
func UploadPlatformBrandingAsset(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get user ID from context (set by auth middleware)
		userIDStr, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found"})
			return
		}

		userID, err := uuid.Parse(userIDStr.(string))
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user ID"})
			return
		}

		// Get asset type (logo, login_logo, or favicon)
		assetType := c.PostForm("type")
		if assetType != "logo" && assetType != "login_logo" && assetType != "favicon" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset type. Must be 'logo', 'login_logo', or 'favicon'"})
			return
		}

		// Get uploaded file
		file, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "No file provided"})
			return
		}

		// Validate file size (5MB limit)
		if file.Size > 5*1024*1024 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "File too large. Maximum size is 5MB"})
			return
		}

		// Validate file type
		allowedTypes := map[string]bool{
			"image/png":  true,
			"image/jpeg": true,
			// SVG files excluded — they can contain embedded JavaScript (stored XSS)
			"image/x-icon": true,
		}
		contentType := file.Header.Get("Content-Type")
		if !allowedTypes[contentType] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Only PNG, JPEG, and ICO are allowed"})
			return
		}

		// Validate actual file content via magic bytes
		uploadedFile, err := file.Open()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read uploaded file"})
			return
		}
		headerBytes := make([]byte, 512)
		n, err := uploadedFile.Read(headerBytes)
		_ = uploadedFile.Close()
		if err != nil && err != io.EOF {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read uploaded file"})
			return
		}
		detectedType := http.DetectContentType(headerBytes[:n])
		if !allowedTypes[detectedType] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "File content does not match an allowed image type. Only PNG, JPEG, and ICO are allowed"})
			return
		}

		// Generate unique filename. The extension is server-authoritative,
		// derived from the SNIFFED type — never from file.Filename.
		//
		// The previous code took filepath.Ext(file.Filename) and only fell back
		// to the content type when the caller supplied no extension at all. The
		// magic-byte check above therefore constrained the file's CONTENT while
		// the caller still chose the name it was stored under: uploading valid
		// PNG bytes as filename="evil.svg" persisted a .svg asset under
		// /uploads/platform-branding/, and SVG is excluded from this allowlist
		// precisely because it can carry script. Anything that content-types the
		// served file by extension then hands the browser back an attacker-named
		// type. auth-service's tenant-branding upload was fixed this way in
		//this is the same handler on the platform-admin side, which was
		// missed at the time.
		ext, ok := brandingExtForType(detectedType)
		if !ok {
			// Unreachable while allowedTypes and brandingExtForType agree, but
			// a mismatch must not fall through to an extension-less file.
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Only PNG, JPEG, and ICO are allowed"})
			return
		}
		filename := fmt.Sprintf("platform-%s-%s%s", assetType, uuid.New().String(), ext)

		var assetURL string

		// Check if S3 storage is configured and enabled for platform branding
		if platformStorageService != nil && platformStorageService.IsEnabled(storage.ArtifactTypePlatformBranding) {
			// Use S3 storage
			assetURL, err = uploadToS3(c, file, filename, contentType)
			if err != nil {
				if platformBrandingLogger != nil {
					platformBrandingLogger.WithError(err).Error("Failed to upload to S3, falling back to local storage")
				}
				// Fall back to local storage
				assetURL, err = uploadToLocalStorage(c, file, filename)
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
					return
				}
			}
		} else {
			// Use local storage (fallback for when S3 is not configured)
			assetURL, err = uploadToLocalStorage(c, file, filename)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save file"})
				return
			}
		}

		// Update platform setting with the URL
		settingKey := "platform_logo_url"
		switch assetType {
		case "favicon":
			settingKey = "platform_favicon_url"
		case "login_logo":
			settingKey = "platform_login_logo_url"
		}

		valueJSON, err := json.Marshal(assetURL)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode URL"})
			return
		}

		_, err = db.Exec(`
			INSERT INTO platform_settings (setting_key, setting_value, updated_by, updated_at)
			VALUES ($1, $2, $3, NOW())
			ON CONFLICT (setting_key)
			DO UPDATE SET
				setting_value = EXCLUDED.setting_value,
				updated_by = EXCLUDED.updated_by,
				updated_at = NOW()
		`, settingKey, valueJSON, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save setting"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"url":     assetURL,
			"type":    assetType,
			"message": "Platform branding asset uploaded successfully",
		})
	}
}

// uploadToS3 uploads the file to S3 using the storage service
func uploadToS3(c *gin.Context, file *multipart.FileHeader, filename, contentType string) (string, error) {
	// Open the file
	src, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = src.Close() }()

	// Read file content
	data, err := io.ReadAll(src)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Upload to S3
	result, err := platformStorageService.Upload(
		c.Request.Context(),
		storage.ArtifactTypePlatformBranding,
		nil, // No tenant ID for platform branding
		filename,
		bytes.NewReader(data),
		contentType,
		int64(len(data)),
	)
	if err != nil {
		return "", fmt.Errorf("failed to upload to S3: %w", err)
	}

	return result.URL, nil
}

// brandingExtForType maps a SNIFFED image MIME type to the extension the asset
// is stored under. This is the only source of a branding asset's extension —
// the caller-supplied file name never contributes one.
//
// Keep in step with the allowedTypes allowlist in UploadPlatformBrandingAsset:
// a type accepted there but absent here is rejected rather than stored, which is
// the safe direction to fail.
func brandingExtForType(detectedType string) (string, bool) {
	switch detectedType {
	case "image/png":
		return ".png", true
	case "image/jpeg":
		return ".jpg", true
	case "image/x-icon":
		return ".ico", true
	default:
		return "", false
	}
}

// platformBrandingUploadDir is the on-disk root for locally-stored platform
// branding assets. It is a var, not a const, only so the handler test can point
// it at a t.TempDir() — nothing in production reassigns it.
var platformBrandingUploadDir = filepath.Join("/app", "uploads", "platform-branding")

// uploadToLocalStorage saves the file to local filesystem
func uploadToLocalStorage(c *gin.Context, file *multipart.FileHeader, filename string) (string, error) {
	// Create uploads directory for platform branding (0750: owner rwx, group rx,
	// world none — resolves gosec G301 on the public-readable default)
	uploadDir := platformBrandingUploadDir
	if err := os.MkdirAll(uploadDir, 0o750); err != nil {
		return "", fmt.Errorf("failed to create upload directory: %w", err)
	}

	// Open source file
	src, err := file.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer func() { _ = src.Close() }()

	// Create destination file
	filePath := filepath.Join(uploadDir, filename)
	dst, err := os.Create(filePath) //nolint:gosec // intentional — filename is a server-generated UUID (see line 145), uploadDir is a fixed path
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer func() { _ = dst.Close() }()

	// Copy content
	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("failed to copy file: %w", err)
	}

	// Return URL for the uploaded file
	return fmt.Sprintf("/uploads/platform-branding/%s", filename), nil
}

// DeletePlatformBrandingAsset handles DELETE /admin/branding/:type - Remove platform logo/favicon
func DeletePlatformBrandingAsset(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		assetType := c.Param("type")
		if assetType != "logo" && assetType != "login_logo" && assetType != "favicon" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset type. Must be 'logo', 'login_logo', or 'favicon'"})
			return
		}

		settingKey := "platform_logo_url"
		switch assetType {
		case "favicon":
			settingKey = "platform_favicon_url"
		case "login_logo":
			settingKey = "platform_login_logo_url"
		}

		// Get the current URL before deleting (to clean up S3 if needed)
		var currentURL string
		err := db.QueryRow(`SELECT setting_value FROM platform_settings WHERE setting_key = $1`, settingKey).Scan(&currentURL)
		if err == nil && currentURL != "" {
			// Try to delete from S3 if it's an S3 URL
			if platformStorageService != nil && platformStorageService.IsEnabled(storage.ArtifactTypePlatformBranding) {
				// Extract key from URL and delete (best effort)
				// This is a simplified implementation; in production, you'd parse the URL properly
				if platformBrandingLogger != nil {
					platformBrandingLogger.WithField("url", currentURL).Debug("Would delete from S3")
				}
			}
		}

		// Delete the setting
		_, err = db.Exec(`DELETE FROM platform_settings WHERE setting_key = $1`, settingKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete setting"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": fmt.Sprintf("Platform %s removed successfully", assetType),
		})
	}
}
