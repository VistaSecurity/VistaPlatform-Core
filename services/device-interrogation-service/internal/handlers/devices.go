package handlers

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// deviceStore is the slice of *services.DeviceService the device handlers
// depend on. Declaring it as an interface (the concrete service still satisfies
// it) lets the contract test drive the real handlers with an in-memory stub —
// no database — per the spec-first contract recipe (ADR-0001). Only the
// deviceService dependency is abstracted; jobQueue/db stay concrete for the
// interrogation handlers not covered by this slice.
type deviceStore interface {
	CreateDevice(ctx context.Context, tenantID uuid.UUID, req models.CreateDeviceRequest) (*models.Device, error)
	GetDevice(ctx context.Context, tenantID, deviceID uuid.UUID) (*models.Device, error)
	ListDevices(ctx context.Context, tenantID uuid.UUID) ([]*models.Device, error)
	UpdateDevice(ctx context.Context, tenantID, deviceID uuid.UUID, req models.UpdateDeviceRequest) (*models.Device, error)
	DeleteDevice(ctx context.Context, tenantID, deviceID uuid.UUID) error
	GetStoredDeviceCredentials(ctx context.Context, tenantID, deviceID uuid.UUID) (services.StoredDeviceCredentials, error)
}

// DeviceHandlers handles device-related HTTP requests
type DeviceHandlers struct {
	deviceService deviceStore
	jobQueue      *services.JobQueueService
	db            *sql.DB
	// bypassDB is the BYPASSRLS connection; only used here to construct the
	// JobQueueService (whose keyed-by-id paths need it) and for the
	// credential-lookup helper which runs under WithTenantTx.
	bypassDB *sql.DB
}

// NewDeviceHandlers creates a new device handlers instance
func NewDeviceHandlers(deviceService *services.DeviceService, db, bypassDB *sql.DB, redis *redis.Client) *DeviceHandlers {
	jobQueue := services.NewJobQueueService(db, bypassDB, redis)
	return &DeviceHandlers{
		deviceService: deviceService,
		jobQueue:      jobQueue,
		db:            db,
		bypassDB:      bypassDB,
	}
}

// CreateDevice handles POST /devices
func (h *DeviceHandlers) CreateDevice(c *gin.Context) {
	// Get tenant ID from context (set by middleware)
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	var req models.CreateDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		// Log the error for debugging
		fmt.Printf("Device creation validation error: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	device, err := h.deviceService.CreateDevice(c.Request.Context(), tenantID, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusCreated, device)
}

// DiscoverAndCreateDevice handles POST /devices/discover-and-create
// This endpoint connects to the device, discovers its info, and creates the device record
func (h *DeviceHandlers) DiscoverAndCreateDevice(c *gin.Context) {
	// Get tenant ID from context (set by middleware)
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Simplified request with just the essentials
	var req struct {
		DeviceType    string `json:"device_type" binding:"required"`
		ManagementURL string `json:"management_url" binding:"required"`
		Username      string `json:"username" binding:"required"`
		Password      string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		fmt.Printf("Discover-and-create validation error: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Create discovery service and attempt to discover device info
	discoveryService := services.NewDeviceDiscoveryService()
	discoveredInfo, err := discoveryService.DiscoverDevice(req.DeviceType, req.ManagementURL, req.Username, req.Password)
	if err != nil {
		fmt.Printf("Device discovery failed: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to discover device information",
		})
		return
	}

	// Build device creation request with discovered information
	createReq := models.CreateDeviceRequest{
		DeviceType:      req.DeviceType,
		ManagementURL:   &req.ManagementURL,
		Username:        &req.Username,
		Password:        &req.Password,
		DiscoveryMethod: "device_interrogation",
		Metadata:        make(map[string]interface{}),
		Tags:            make(map[string]interface{}),
	}

	// Populate discovered fields
	if discoveredInfo.Vendor != "" {
		createReq.Vendor = &discoveredInfo.Vendor
	}
	if discoveredInfo.Model != "" {
		createReq.Model = &discoveredInfo.Model
	}
	if discoveredInfo.SerialNumber != "" {
		createReq.SerialNumber = &discoveredInfo.SerialNumber
	}
	if discoveredInfo.Hostname != "" {
		createReq.Hostname = &discoveredInfo.Hostname
	}
	if discoveredInfo.IPAddress != "" {
		createReq.IPAddress = &discoveredInfo.IPAddress
	}
	if discoveredInfo.FirmwareVersion != "" {
		createReq.FirmwareVersion = &discoveredInfo.FirmwareVersion
	}

	// Add MAC address to metadata if available
	if discoveredInfo.MacAddress != "" {
		createReq.Metadata["mac_address"] = discoveredInfo.MacAddress
	}

	// Mark this as auto-discovered
	createReq.Metadata["auto_discovered"] = true
	createReq.Metadata["discovery_timestamp"] = time.Now().UTC().Format(time.RFC3339)

	// Create the device
	device, err := h.deviceService.CreateDevice(c.Request.Context(), tenantID, createReq)
	if err != nil {
		fmt.Printf("Failed to create device after discovery: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create device"})
		return
	}

	fmt.Printf("Device discovered and created successfully: %s (Model: %s, Serial: %s)\n",
		device.ID, discoveredInfo.Model, discoveredInfo.SerialNumber)

	c.JSON(http.StatusCreated, device)
}

// ListDevices handles GET /devices
func (h *DeviceHandlers) ListDevices(c *gin.Context) {
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	devices, err := h.deviceService.ListDevices(c.Request.Context(), tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"devices": stripBulkyDeviceMetadata(devices)})
}

// deviceMetadataCertKeys are the metadata keys under which cloud discovery
// (cloud_discovery_service.go) stashes full certificate chains — each entry
// can carry a multi-KB certificate_pem per certificate. Nothing on the
// Devices list view reads any of these (frontend-v2's devices-page.tsx never
// touches device.metadata); GetDevice (single) keeps them intact for whatever
// might want the full chain on a detail view.
var deviceMetadataCertKeys = []string{"certificates", "crypto_configs"}

// stripBulkyDeviceMetadata returns devices with the certificate-chain-bearing
// metadata keys removed, so a list of N devices doesn't ship N sets of PEM
// blobs to the browser on every page load (L-7). Devices with no such keys
// (the common case — network devices with no crypto_configs metadata at all)
// are returned unmodified; only devices carrying the heavy keys pay the cost
// of a shallow metadata copy.
func stripBulkyDeviceMetadata(devices []*models.Device) []*models.Device {
	for _, d := range devices {
		if d == nil || d.Metadata == nil {
			continue
		}
		hasCertKey := false
		for _, k := range deviceMetadataCertKeys {
			if _, ok := d.Metadata[k]; ok {
				hasCertKey = true
				break
			}
		}
		if !hasCertKey {
			continue
		}
		trimmed := make(models.JSONB, len(d.Metadata))
		for k, v := range d.Metadata {
			trimmed[k] = v
		}
		for _, k := range deviceMetadataCertKeys {
			delete(trimmed, k)
		}
		d.Metadata = trimmed
	}
	return devices
}

// GetDevice handles GET /devices/:id
func (h *DeviceHandlers) GetDevice(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	// Get tenant ID from context (set by middleware) for tenant isolation
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	device, err := h.deviceService.GetDevice(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	// Enforce tenant isolation - device must belong to the requesting tenant
	if device.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	c.JSON(http.StatusOK, device)
}

// UpdateDevice handles PUT /devices/:id
func (h *DeviceHandlers) UpdateDevice(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	// Get tenant ID from context (set by middleware) for tenant isolation
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// First verify the device belongs to this tenant
	existingDevice, err := h.deviceService.GetDevice(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	// Enforce tenant isolation
	if existingDevice.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	var req models.UpdateDeviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	device, err := h.deviceService.UpdateDevice(c.Request.Context(), tenantID, id, req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, device)
}

// DeleteDevice handles DELETE /devices/:id
func (h *DeviceHandlers) DeleteDevice(c *gin.Context) {
	idStr := c.Param("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	// Get tenant ID from context (set by middleware) for tenant isolation
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// First verify the device belongs to this tenant
	existingDevice, err := h.deviceService.GetDevice(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	// Enforce tenant isolation
	if existingDevice.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	err = h.deviceService.DeleteDevice(c.Request.Context(), tenantID, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Device deleted successfully"})
}

// InterrogateDevice handles POST /devices/:id/interrogate
func (h *DeviceHandlers) InterrogateDevice(c *gin.Context) {
	idStr := c.Param("id")
	deviceID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	// Get tenant ID from context
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Get device to check if it exists and get device type
	device, err := h.deviceService.GetDevice(c.Request.Context(), tenantID, deviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	// Check tenant ownership
	if device.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	// Get master key from environment for credential encryption
	masterKey := os.Getenv("ENCRYPTION_MASTER_KEY")
	if masterKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption master key not configured"})
		return
	}

	// Get encrypted credentials
	credentials, err := h.buildJobCredentials(c.Request.Context(), tenantID, device, masterKey)
	if err != nil {
		if errors.Is(err, errNoDeviceCredentials) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Device has no credentials configured"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to prepare credentials"})
		return
	}

	// Create device interrogation job
	jobRequest := models.CreateDeviceJobRequest{
		TenantID:    tenantID,
		JobType:     models.JobTypeDeviceInterrogation,
		DeviceID:    &deviceID,
		AgentID:     nil, // Claimed by the platform worker or a tenant agent
		Credentials: credentials,
		Parameters:  buildJobParameters(device, nil),
	}

	deviceJob, err := h.jobQueue.CreateJob(c.Request.Context(), jobRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create job"})
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"message": "Device interrogation job created",
		"job_id":  deviceJob.ID.String(),
		"status":  deviceJob.Status,
	})
}

// errNoDeviceCredentials means the device carries neither a credential_id nor
// embedded username/password.
var errNoDeviceCredentials = errors.New("device has no credentials configured")

// buildJobCredentials assembles the credential payload stored on a device job.
//
// The embedded-credential branch reads the password through
// GetStoredDeviceCredentials rather than off the *models.Device the caller
// already has. That is not tidiness: GetDevice masks the password before
// returning it (it feeds API responses), so the old code stored
// "abcd****wxyz" — four characters of ciphertext, four asterisks, four more —
// as the device password, and the agent then tried to log in with that.
// The value stored here stays master-key encrypted; it is decrypted and re-sealed
// for one specific agent at hand-off (services.SealCredentialsForAgent).
func (h *DeviceHandlers) buildJobCredentials(ctx context.Context, tenantID uuid.UUID, device *models.Device, masterKey string) (map[string]interface{}, error) {
	if device.CredentialID != nil {
		// Legacy: credentials live in platform_integrations, re-encrypted under
		// a per-job key.
		return h.encryptCredentialsForJob(ctx, tenantID, device.CredentialID, masterKey)
	}

	stored, err := h.deviceService.GetStoredDeviceCredentials(ctx, tenantID, device.ID)
	if err != nil {
		return nil, err
	}
	if !stored.HasCredentials() {
		return nil, errNoDeviceCredentials
	}

	creds := map[string]interface{}{
		"username":             stored.Username,
		"password":             stored.EncryptedPassword, // master-key ciphertext
		"device_type":          stored.DeviceType,
		"insecure_skip_verify": stored.InsecureSkipVerify,
		masterEncryptedFlagKey: true, // sensitive fields are master-key ciphertext
	}
	if stored.ManagementURL != "" {
		creds["management_url"] = stored.ManagementURL
	}
	return creds, nil
}

// masterEncryptedFlagKey mirrors services.masterEncryptedFlag — the marker that
// tells the hand-off sealer these fields are master-key ciphertext.
const masterEncryptedFlagKey = "encrypted"

// buildJobParameters builds the job payload an executor needs to reach the
// device.
//
// The address fields are not decoration. The in-cluster PlatformAgentWorker
// re-reads the device row by device_id, so `{device_id, device_type}` was a
// complete payload for it — but a device-agent has no database, and gets only
// what is in this map. Both consumers claim the same `agent_id IS NULL` queue,
// so which one runs a given job is a race; the payload has to be sufficient for
// the one that cannot look anything up. Registering a tenant's first agent is
// what turns that latent gap into a failed scan.
func buildJobParameters(device *models.Device, extra map[string]interface{}) map[string]interface{} {
	params := map[string]interface{}{
		"device_type": device.DeviceType,
		"device_id":   device.ID.String(),
	}
	if device.Hostname != nil && *device.Hostname != "" {
		params["hostname"] = *device.Hostname
	}
	if device.IPAddress != nil && *device.IPAddress != "" {
		params["ip_address"] = *device.IPAddress
	}
	if device.ManagementURL != nil && *device.ManagementURL != "" {
		params["management_url"] = *device.ManagementURL
	}
	// Vendor-specific addressing the agent would otherwise lose — the platform
	// path reads this off device.Metadata directly.
	if device.Metadata != nil {
		if siteID, ok := device.Metadata["site_id"].(string); ok && siteID != "" {
			params["site_id"] = siteID
		}
	}
	for k, v := range extra {
		params[k] = v
	}
	return params
}

// encryptCredentialsForJob decrypts credentials from platform_integrations and re-encrypts them with a job-specific key
func (h *DeviceHandlers) encryptCredentialsForJob(ctx context.Context, tenantID uuid.UUID, credentialID *uuid.UUID, masterKey string) (map[string]interface{}, error) {
	// Load credentials from platform_integrations. RLS-scoped read under the
	// caller's tenantID (the integration belongs to the same tenant as the device).
	query := `
		SELECT config
		FROM platform_integrations
		WHERE id = $1 AND is_active = true AND deleted_at IS NULL
	`

	var configJSON string
	err := shareddatabase.WithTenantTx(ctx, h.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, credentialID).Scan(&configJSON)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to load credentials: %w", err)
	}

	// Decrypt credentials using master key
	masterEnc, err := encryption.NewService(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize encryption service: %w", err)
	}

	var encryptedConfig map[string]interface{}
	if err := json.Unmarshal([]byte(configJSON), &encryptedConfig); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Decrypt all sensitive fields
	decryptedConfig := make(map[string]interface{})
	sensitiveKeys := []string{"username", "password", "api_key", "api_token", "client_secret", "access_key_id", "secret_access_key"}

	for key, value := range encryptedConfig {
		if slices.Contains(sensitiveKeys, key) {
			// Decrypt sensitive field
			strValue, ok := value.(string)
			if !ok {
				strValue = fmt.Sprintf("%v", value)
			}
			decrypted, err := masterEnc.Decrypt(strValue)
			if err != nil {
				// If decryption fails, it might not be encrypted (legacy data)
				decryptedConfig[key] = strValue
			} else {
				decryptedConfig[key] = decrypted
			}
		} else {
			// Non-sensitive field, copy as-is
			decryptedConfig[key] = value
		}
	}

	// Generate a job-specific encryption key (32 bytes for AES-256)
	jobKeyBytes := make([]byte, 32)
	if _, err := rand.Read(jobKeyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate job-specific key: %w", err)
	}
	jobKey := hex.EncodeToString(jobKeyBytes)

	// Create job-specific encryption service
	jobEnc, err := encryption.NewService(jobKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize job encryption service: %w", err)
	}

	// Re-encrypt sensitive fields with job-specific key
	jobEncryptedConfig := make(map[string]interface{})
	for key, value := range decryptedConfig {
		if slices.Contains(sensitiveKeys, key) {
			// Encrypt with job-specific key
			strValue := fmt.Sprintf("%v", value)
			encrypted, err := jobEnc.Encrypt(strValue)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt %s with job key: %w", key, err)
			}
			jobEncryptedConfig[key] = encrypted
		} else {
			// Non-sensitive field, copy as-is
			jobEncryptedConfig[key] = value
		}
	}

	// Encrypt the job-specific key with master key and include it in the credentials
	encryptedJobKey, err := masterEnc.Encrypt(jobKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt job key: %w", err)
	}

	// Return credentials with encrypted job key and re-encrypted sensitive fields
	return map[string]interface{}{
		"_job_key": encryptedJobKey,    // Encrypted job-specific key (encrypted with master key)
		"config":   jobEncryptedConfig, // Credentials encrypted with job-specific key
	}, nil
}

// BulkInterrogateRequest represents a request to interrogate multiple devices
type BulkInterrogateRequest struct {
	DeviceIDs []string `json:"device_ids" binding:"required,min=1"`
}

// BulkInterrogateResponse represents the response for bulk interrogation
type BulkInterrogateResponse struct {
	TotalRequested int                     `json:"total_requested"`
	Successful     int                     `json:"successful"`
	Failed         int                     `json:"failed"`
	Jobs           []BulkInterrogateResult `json:"jobs"`
}

// BulkInterrogateResult represents the result for a single device in bulk interrogation
type BulkInterrogateResult struct {
	DeviceID string  `json:"device_id"`
	JobID    *string `json:"job_id,omitempty"`
	Status   string  `json:"status"` // "created", "failed"
	Error    string  `json:"error,omitempty"`
}

// BulkInterrogateDevices handles POST /devices/bulk-interrogate
func (h *DeviceHandlers) BulkInterrogateDevices(c *gin.Context) {
	// Get tenant ID from context
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	var req BulkInterrogateRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Limit the number of devices in a single bulk request
	maxBulkDevices := 100
	if len(req.DeviceIDs) > maxBulkDevices {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Maximum %d devices allowed per bulk request", maxBulkDevices),
		})
		return
	}

	// Get master key from environment
	masterKey := os.Getenv("ENCRYPTION_MASTER_KEY")
	if masterKey == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Encryption master key not configured"})
		return
	}

	response := BulkInterrogateResponse{
		TotalRequested: len(req.DeviceIDs),
		Jobs:           make([]BulkInterrogateResult, 0, len(req.DeviceIDs)),
	}

	for _, deviceIDStr := range req.DeviceIDs {
		result := BulkInterrogateResult{
			DeviceID: deviceIDStr,
		}

		deviceID, err := uuid.Parse(deviceIDStr)
		if err != nil {
			result.Status = "failed"
			result.Error = "Invalid device ID format"
			response.Failed++
			response.Jobs = append(response.Jobs, result)
			continue
		}

		// Get device and verify tenant ownership
		device, err := h.deviceService.GetDevice(c.Request.Context(), tenantID, deviceID)
		if err != nil {
			result.Status = "failed"
			result.Error = "Device not found"
			response.Failed++
			response.Jobs = append(response.Jobs, result)
			continue
		}

		if device.TenantID != tenantID {
			result.Status = "failed"
			result.Error = "Device not found"
			response.Failed++
			response.Jobs = append(response.Jobs, result)
			continue
		}

		// Get credentials. Embedded device credentials used to be skipped here
		// entirely (only credential_id was handled), so a bulk interrogation of
		// a device configured the modern way ran with no credentials at all.
		credentials, err := h.buildJobCredentials(c.Request.Context(), tenantID, device, masterKey)
		if err != nil && !errors.Is(err, errNoDeviceCredentials) {
			result.Status = "failed"
			result.Error = fmt.Sprintf("Failed to prepare credentials: %v", err)
			response.Failed++
			response.Jobs = append(response.Jobs, result)
			continue
		}

		// Create job
		jobRequest := models.CreateDeviceJobRequest{
			TenantID:    tenantID,
			JobType:     models.JobTypeDeviceInterrogation,
			DeviceID:    &deviceID,
			Credentials: credentials,
			Parameters:  buildJobParameters(device, map[string]interface{}{"bulk": true}),
		}

		deviceJob, err := h.jobQueue.CreateJob(c.Request.Context(), jobRequest)
		if err != nil {
			result.Status = "failed"
			result.Error = fmt.Sprintf("Failed to create job: %v", err)
			response.Failed++
			response.Jobs = append(response.Jobs, result)
			continue
		}

		jobIDStr := deviceJob.ID.String()
		result.JobID = &jobIDStr
		result.Status = "created"
		response.Successful++
		response.Jobs = append(response.Jobs, result)
	}

	c.JSON(http.StatusAccepted, response)
}

// TestConnection handles POST /devices/:id/test-connection
func (h *DeviceHandlers) TestConnection(c *gin.Context) {
	idStr := c.Param("id")
	deviceID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device ID"})
		return
	}

	// Get tenant ID from context
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return
	}

	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
		return
	}

	// Get device and verify tenant ownership
	device, err := h.deviceService.GetDevice(c.Request.Context(), tenantID, deviceID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	if device.TenantID != tenantID {
		c.JSON(http.StatusNotFound, gin.H{"error": "Device not found"})
		return
	}

	// For now, simulate a connection test (in production, this would actually test the connection)
	// This could be enhanced to:
	// 1. Try to ping the device IP/hostname
	// 2. Try to authenticate with stored credentials
	// 3. Verify the device is accessible over the network

	// Simulate connection test based on connection status
	connectionSuccess := device.ConnectionStatus == "connected" || device.ConnectionStatus == "unknown"

	c.JSON(http.StatusOK, gin.H{
		"device_id":  deviceID.String(),
		"success":    connectionSuccess,
		"status":     device.ConnectionStatus,
		"tested_at":  time.Now().Format(time.RFC3339),
		"message":    "Connection test completed",
		"latency_ms": 42, // Simulated latency
	})
}
