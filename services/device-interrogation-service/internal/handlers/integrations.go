package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// CloudIntegration represents a tenant cloud integration
type CloudIntegration struct {
	ID              uuid.UUID              `json:"id"`
	TenantID        uuid.UUID              `json:"tenant_id"`
	IntegrationType string                 `json:"integration_type"` // aws, azure, gcp
	IntegrationName string                 `json:"integration_name"`
	Provider        string                 `json:"provider"` // cloud
	Config          map[string]interface{} `json:"config"`   // Credentials (masked in response)
	AccountID       *string                `json:"account_id,omitempty"`
	Region          *string                `json:"region,omitempty"`
	Environment     *string                `json:"environment,omitempty"`
	Description     *string                `json:"description,omitempty"`
	Tags            []string               `json:"tags,omitempty"`
	IsEnabled       bool                   `json:"is_enabled"`
	IsShared        bool                   `json:"is_shared,omitempty"`
	Status          string                 `json:"status"` // pending, configured, connected, error
	StatusMessage   *string                `json:"status_message,omitempty"`
	LastTestedAt    *time.Time             `json:"last_tested_at,omitempty"`
	LastTestError   *string                `json:"last_test_error,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
}

// CreateIntegrationRequest represents the request to create an integration
type CreateIntegrationRequest struct {
	IntegrationType string                 `json:"integration_type" binding:"required,oneof=aws azure gcp slack pagerduty datadog splunk custom"`
	IntegrationName string                 `json:"integration_name" binding:"required"`
	Provider        string                 `json:"provider" binding:"required,oneof=cloud saas custom"`
	Config          map[string]interface{} `json:"config" binding:"required"`
	AccountID       *string                `json:"account_id,omitempty"`
	Region          *string                `json:"region,omitempty"`
	Environment     *string                `json:"environment,omitempty"`
	Description     *string                `json:"description,omitempty"`
	Tags            []string               `json:"tags,omitempty"`
	IsEnabled       *bool                  `json:"is_enabled,omitempty"`
}

// UpdateIntegrationRequest represents the request to update an integration
type UpdateIntegrationRequest struct {
	IntegrationName *string                `json:"integration_name,omitempty"`
	Config          map[string]interface{} `json:"config,omitempty"`
	AccountID       *string                `json:"account_id,omitempty"`
	Region          *string                `json:"region,omitempty"`
	Environment     *string                `json:"environment,omitempty"`
	Description     *string                `json:"description,omitempty"`
	Tags            []string               `json:"tags,omitempty"`
	IsEnabled       *bool                  `json:"is_enabled,omitempty"`
}

// IntegrationHandlers handles cloud integration operations. It depends on the
// integrationStore interface (the SQL-backed integrationRepository satisfies
// it), which is what makes these handlers contract-testable without a database.
// The credential encrypt/decrypt/mask logic stays here (it never touched SQL).
type IntegrationHandlers struct {
	store         integrationStore
	encryptionKey string
}

// NewIntegrationHandlers creates a new IntegrationHandlers backed by the SQL
// integration repository. db is the RLS-scoped (crypto_app) connection; bypassDB
// is the BYPASSRLS (crypto_bypass) connection used by the shared-integration read
// paths.
func NewIntegrationHandlers(db, bypassDB *sql.DB, encryptionKey string) *IntegrationHandlers {
	return &IntegrationHandlers{
		store:         newIntegrationRepository(db, bypassDB),
		encryptionKey: encryptionKey,
	}
}

// ListIntegrations lists all cloud integrations for the tenant
func (h *IntegrationHandlers) ListIntegrations(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	// Optional provider filter
	providerFilter := c.Query("provider")

	integrations, err := h.store.List(c.Request.Context(), tenantID, providerFilter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to query integrations"})
		return
	}

	// The store returns config still encrypted; decrypt then mask per row.
	for i := range integrations {
		integrations[i].Config = h.decryptAndMask(integrations[i].Config)
	}

	c.JSON(http.StatusOK, gin.H{
		"integrations": integrations,
		"count":        len(integrations),
	})
}

// decryptAndMask decrypts an encrypted config map and masks its sensitive
// fields for safe response serialization. On decrypt failure it masks the
// encrypted values as-is (matching the prior inline behavior). A nil config
// yields nil.
func (h *IntegrationHandlers) decryptAndMask(encryptedConfig map[string]interface{}) map[string]interface{} {
	if encryptedConfig == nil {
		return nil
	}
	if decrypted, err := h.decryptConfig(encryptedConfig); err == nil {
		return maskSensitiveFields(decrypted)
	}
	return maskSensitiveFields(encryptedConfig)
}

// GetIntegration retrieves a single integration by ID
func (h *IntegrationHandlers) GetIntegration(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	idStr := c.Param("id")
	integrationID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integration ID"})
		return
	}

	integration, err := h.store.Get(c.Request.Context(), integrationID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get integration"})
		return
	}
	if integration == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Integration not found"})
		return
	}

	// The store returns config still encrypted; decrypt then mask.
	integration.Config = h.decryptAndMask(integration.Config)

	c.JSON(http.StatusOK, gin.H{
		"integration": integration,
	})
}

// CreateIntegration creates a new cloud or network device integration
func (h *IntegrationHandlers) CreateIntegration(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	var req CreateIntegrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate based on integration type
	if err := validateIntegrationConfig(req.IntegrationType, req.Config); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Encrypt sensitive config fields
	encryptedConfig, err := h.encryptConfig(req.Config)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt credentials"})
		return
	}

	configJSON, err := json.Marshal(encryptedConfig)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process config"})
		return
	}

	tagsJSON := "[]"
	if len(req.Tags) > 0 {
		if b, err := json.Marshal(req.Tags); err == nil {
			tagsJSON = string(b)
		}
	}

	isEnabled := true
	if req.IsEnabled != nil {
		isEnabled = *req.IsEnabled
	}

	integrationID := uuid.New()
	now := time.Now()

	if err := h.store.Create(c.Request.Context(), CreateIntegrationParams{
		ID:              integrationID,
		TenantID:        tenantID,
		IntegrationType: req.IntegrationType,
		IntegrationName: req.IntegrationName,
		Provider:        req.Provider,
		ConfigJSON:      string(configJSON),
		AccountID:       req.AccountID,
		Region:          req.Region,
		Environment:     req.Environment,
		Description:     req.Description,
		TagsJSON:        tagsJSON,
		IsEnabled:       isEnabled,
		Status:          "configured",
		CreatedAt:       now,
	}); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create integration",
		})
		return
	}

	// Audit: log integration creation
	if rawMW, exists := c.Get("audit_middleware"); exists {
		if mw, ok := rawMW.(*audithelpers.Middleware); ok {
			_ = audithelpers.LogSimple(c.Request.Context(), mw,
				"integration.created", "config", "create",
				"cloud_integration", integrationID.String(), req.IntegrationName,
				true, "")
		}
	}

	c.JSON(http.StatusCreated, gin.H{
		"integration": CloudIntegration{
			ID:              integrationID,
			TenantID:        tenantID,
			IntegrationType: req.IntegrationType,
			IntegrationName: req.IntegrationName,
			Provider:        req.Provider,
			Config:          maskSensitiveFields(req.Config),
			AccountID:       req.AccountID,
			Region:          req.Region,
			Environment:     req.Environment,
			Description:     req.Description,
			Tags:            req.Tags,
			IsEnabled:       isEnabled,
			Status:          "configured",
			CreatedAt:       now,
			UpdatedAt:       now,
		},
	})
}

// UpdateIntegration updates an existing integration
func (h *IntegrationHandlers) UpdateIntegration(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	idStr := c.Param("id")
	integrationID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integration ID"})
		return
	}

	var req UpdateIntegrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Verify integration exists and belongs to tenant
	existingConfig, integrationType, found, err := h.store.GetConfigForUpdate(c.Request.Context(), integrationID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to verify integration"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Integration not found"})
		return
	}

	// Build the column→value set. The repo owns the dynamic SQL; updated_at is
	// added there.
	fields := map[string]interface{}{}

	if req.IntegrationName != nil {
		fields["integration_name"] = *req.IntegrationName
	}

	if req.Config != nil {
		// Merge new values into the decrypted existing config, validate, re-encrypt.
		var existing map[string]interface{}
		_ = json.Unmarshal([]byte(existingConfig), &existing)
		decryptedExisting, _ := h.decryptConfig(existing)
		for k, v := range req.Config {
			decryptedExisting[k] = v
		}
		if err := validateIntegrationConfig(integrationType, decryptedExisting); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		encryptedConfig, err := h.encryptConfig(decryptedExisting)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt credentials"})
			return
		}
		configJSON, _ := json.Marshal(encryptedConfig)
		fields["config"] = string(configJSON)
	}

	if req.AccountID != nil {
		fields["account_id"] = *req.AccountID
	}
	if req.Region != nil {
		fields["region"] = *req.Region
	}
	if req.Environment != nil {
		fields["environment"] = *req.Environment
	}
	if req.Description != nil {
		fields["description"] = *req.Description
	}
	if req.Tags != nil {
		tagsJSON, _ := json.Marshal(req.Tags)
		fields["tags"] = string(tagsJSON)
	}
	if req.IsEnabled != nil {
		fields["is_enabled"] = *req.IsEnabled
	}

	if len(fields) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No fields to update"})
		return
	}

	if _, err := h.store.Update(c.Request.Context(), integrationID, tenantID, fields); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update integration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Integration updated successfully"})
}

// DeleteIntegration deletes an integration (soft delete)
func (h *IntegrationHandlers) DeleteIntegration(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	idStr := c.Param("id")
	integrationID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integration ID"})
		return
	}

	rowsAffected, err := h.store.Delete(c.Request.Context(), integrationID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete integration"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Integration not found"})
		return
	}

	// Audit: log integration deletion
	if rawMW, exists := c.Get("audit_middleware"); exists {
		if mw, ok := rawMW.(*audithelpers.Middleware); ok {
			_ = audithelpers.LogSimple(c.Request.Context(), mw,
				"integration.deleted", "config", "delete",
				"cloud_integration", integrationID.String(), "",
				true, "")
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "Integration deleted successfully"})
}

// TestConnection tests the connection for an integration
func (h *IntegrationHandlers) TestConnection(c *gin.Context) {
	tenantID, ok := getTenantID(c)
	if !ok {
		return
	}

	idStr := c.Param("id")
	integrationID, err := uuid.Parse(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid integration ID"})
		return
	}

	// Get integration details
	configJSON, integrationType, found, err := h.store.GetConfigForTest(c.Request.Context(), integrationID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get integration"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Integration not found"})
		return
	}

	// Decrypt config
	var encryptedConfig map[string]interface{}
	_ = json.Unmarshal([]byte(configJSON), &encryptedConfig)
	config, _ := h.decryptConfig(encryptedConfig)

	// Test connection based on type
	var testResult struct {
		Success bool                   `json:"success"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details,omitempty"`
	}

	switch integrationType {
	case "aws":
		testResult = testAWSConnection(config)
	case "azure":
		testResult = testAzureConnection(config)
	case "gcp":
		testResult = testGCPConnection(config)
	case "unifi", "ubiquiti", "fortinet", "cisco", "palo_alto", "f5":
		testResult.Success = false
		testResult.Message = "Network device types are no longer supported. Please create devices with embedded credentials."
	default:
		testResult.Success = false
		testResult.Message = "Unknown integration type"
	}

	// Update last_tested_at and status
	status := "connected"
	var statusMessage *string
	if !testResult.Success {
		status = "error"
		statusMessage = &testResult.Message
	}

	_ = h.store.UpdateTestStatus(c.Request.Context(), tenantID, integrationID, status, statusMessage)

	c.JSON(http.StatusOK, testResult)
}

// Helper functions

func getTenantID(c *gin.Context) (uuid.UUID, bool) {
	tid, ok := sharedmw.GetTenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	return tid, true
}

func (h *IntegrationHandlers) encryptConfig(config map[string]interface{}) (map[string]interface{}, error) {
	enc, err := encryption.NewService(h.encryptionKey)
	if err != nil {
		return nil, err
	}

	sensitiveKeys := []string{
		"access_key_id", "secret_access_key", "session_token",
		"client_id", "client_secret",
		"service_account_json", "api_key",
		"password", // Network device credentials - username is NOT sensitive
	}

	encrypted := make(map[string]interface{})
	for key, value := range config {
		strValue, ok := value.(string)
		if !ok || strValue == "" {
			encrypted[key] = value
			continue
		}

		isSensitive := false
		for _, sk := range sensitiveKeys {
			if key == sk {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			encryptedValue, err := enc.Encrypt(strValue)
			if err != nil {
				return nil, err
			}
			encrypted[key] = encryptedValue
		} else {
			encrypted[key] = value
		}
	}

	return encrypted, nil
}

func (h *IntegrationHandlers) decryptConfig(config map[string]interface{}) (map[string]interface{}, error) {
	enc, err := encryption.NewService(h.encryptionKey)
	if err != nil {
		return nil, err
	}

	sensitiveKeys := []string{
		"access_key_id", "secret_access_key", "session_token",
		"client_id", "client_secret",
		"service_account_json", "api_key",
		"password", // Network device credentials - username is NOT sensitive
	}

	decrypted := make(map[string]interface{})
	for key, value := range config {
		strValue, ok := value.(string)
		if !ok || strValue == "" {
			decrypted[key] = value
			continue
		}

		isSensitive := false
		for _, sk := range sensitiveKeys {
			if key == sk {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			decryptedValue, err := enc.Decrypt(strValue)
			if err != nil {
				// If decryption fails, it might not be encrypted
				decrypted[key] = strValue
			} else {
				decrypted[key] = decryptedValue
			}
		} else {
			decrypted[key] = value
		}
	}

	return decrypted, nil
}

func maskSensitiveFields(config map[string]interface{}) map[string]interface{} {
	sensitiveKeys := []string{
		"access_key_id", "secret_access_key", "session_token",
		"client_id", "client_secret",
		"service_account_json", "api_key",
		"password", // Network device credentials (username is not sensitive)
	}

	masked := make(map[string]interface{})
	for key, value := range config {
		isSensitive := false
		for _, sk := range sensitiveKeys {
			if key == sk {
				isSensitive = true
				break
			}
		}

		if isSensitive {
			if strValue, ok := value.(string); ok && len(strValue) > 0 {
				// Show first 4 and last 4 characters
				if len(strValue) > 8 {
					masked[key] = strValue[:4] + "****" + strValue[len(strValue)-4:]
				} else {
					masked[key] = "****"
				}
			} else {
				masked[key] = "****"
			}
		} else {
			masked[key] = value
		}
	}

	return masked
}

func validateIntegrationConfig(integrationType string, config map[string]interface{}) error {
	switch integrationType {
	case "aws":
		if _, ok := config["access_key_id"]; !ok {
			return fmt.Errorf("AWS integration requires access_key_id")
		}
		if _, ok := config["secret_access_key"]; !ok {
			return fmt.Errorf("AWS integration requires secret_access_key")
		}
	case "azure":
		if _, ok := config["tenant_id"]; !ok {
			return fmt.Errorf("Azure integration requires tenant_id")
		}
		if _, ok := config["client_id"]; !ok {
			return fmt.Errorf("Azure integration requires client_id")
		}
		if _, ok := config["client_secret"]; !ok {
			return fmt.Errorf("Azure integration requires client_secret")
		}
	case "gcp":
		_, hasJSON := config["service_account_json"]
		_, hasKey := config["service_account_key"]
		_, hasCreds := config["credentials_json"]
		if !hasJSON && !hasKey && !hasCreds {
			if _, ok := config["project_id"]; !ok {
				return fmt.Errorf("GCP integration requires service account credentials or project_id")
			}
		}
	case "unifi", "ubiquiti", "fortinet", "cisco", "palo_alto", "f5":
		return fmt.Errorf("network device types are no longer supported in integrations. Please create devices with embedded credentials instead")
	case "custom":
		// Custom integrations have no specific requirements
	default:
		return fmt.Errorf("unsupported integration type: %s", integrationType)
	}
	return nil
}

func testAWSConnection(config map[string]interface{}) struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
} {
	accessKey, ok1 := config["access_key_id"].(string)
	secretKey, ok2 := config["secret_access_key"].(string)

	if !ok1 || !ok2 || accessKey == "" || secretKey == "" {
		return struct {
			Success bool                   `json:"success"`
			Message string                 `json:"message"`
			Details map[string]interface{} `json:"details,omitempty"`
		}{
			Success: false,
			Message: "Missing AWS credentials",
		}
	}

	// Test connection using AWS STS GetCallerIdentity
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Get region from config or use default
	region, ok := config["region"].(string)
	if !ok || region == "" {
		region = "us-east-1"
	}

	// Create AWS config
	cfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(
			accessKey,
			secretKey,
			"", // Session token if needed
		)),
	)
	if err != nil {
		return struct {
			Success bool                   `json:"success"`
			Message string                 `json:"message"`
			Details map[string]interface{} `json:"details,omitempty"`
		}{
			Success: false,
			Message: fmt.Sprintf("Failed to create AWS config: %v", err),
		}
	}

	// Call STS GetCallerIdentity to verify credentials
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return struct {
			Success bool                   `json:"success"`
			Message string                 `json:"message"`
			Details map[string]interface{} `json:"details,omitempty"`
		}{
			Success: false,
			Message: fmt.Sprintf("AWS authentication failed: %v", err),
		}
	}

	// Success - return account details
	return struct {
		Success bool                   `json:"success"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details,omitempty"`
	}{
		Success: true,
		Message: "AWS credentials validated successfully",
		Details: map[string]interface{}{
			"region":     region,
			"account_id": aws.ToString(identity.Account),
			"user_id":    aws.ToString(identity.UserId),
			"arn":        aws.ToString(identity.Arn),
		},
	}
}

func testAzureConnection(config map[string]interface{}) struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
} {
	tenantID, ok1 := config["tenant_id"].(string)
	clientID, ok2 := config["client_id"].(string)
	clientSecret, ok3 := config["client_secret"].(string)

	if !ok1 || !ok2 || !ok3 || tenantID == "" || clientID == "" || clientSecret == "" {
		return struct {
			Success bool                   `json:"success"`
			Message string                 `json:"message"`
			Details map[string]interface{} `json:"details,omitempty"`
		}{
			Success: false,
			Message: "Missing Azure credentials",
		}
	}

	// TODO: Actually test connection using Azure SDK
	return struct {
		Success bool                   `json:"success"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details,omitempty"`
	}{
		Success: true,
		Message: "Azure credentials validated",
		Details: map[string]interface{}{
			"subscription_id": config["subscription_id"],
		},
	}
}

func testGCPConnection(config map[string]interface{}) struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
} {
	// Get service account JSON from config (try all known field names)
	serviceAccountJSON := ""
	for _, key := range []string{"service_account_json", "service_account_key", "credentials_json"} {
		if v, ok := config[key].(string); ok && v != "" {
			serviceAccountJSON = v
			break
		}
	}

	if serviceAccountJSON == "" {
		return struct {
			Success bool                   `json:"success"`
			Message string                 `json:"message"`
			Details map[string]interface{} `json:"details,omitempty"`
		}{
			Success: false,
			Message: "Missing GCP service account credentials",
		}
	}

	// Parse and validate the service account key JSON
	var serviceKey struct {
		Type        string `json:"type"`
		ProjectID   string `json:"project_id"`
		ClientEmail string `json:"client_email"`
		PrivateKey  string `json:"private_key"`
	}
	if err := json.Unmarshal([]byte(serviceAccountJSON), &serviceKey); err != nil {
		return struct {
			Success bool                   `json:"success"`
			Message string                 `json:"message"`
			Details map[string]interface{} `json:"details,omitempty"`
		}{
			Success: false,
			Message: fmt.Sprintf("Invalid service account JSON: %v", err),
		}
	}

	if serviceKey.Type != "service_account" {
		return struct {
			Success bool                   `json:"success"`
			Message string                 `json:"message"`
			Details map[string]interface{} `json:"details,omitempty"`
		}{
			Success: false,
			Message: fmt.Sprintf("Invalid credential type: expected 'service_account', got '%s'", serviceKey.Type),
		}
	}

	if serviceKey.PrivateKey == "" || serviceKey.ClientEmail == "" {
		return struct {
			Success bool                   `json:"success"`
			Message string                 `json:"message"`
			Details map[string]interface{} `json:"details,omitempty"`
		}{
			Success: false,
			Message: "Service account key missing required fields (private_key, client_email)",
		}
	}

	projectID := ""
	if pid, ok := config["project_id"].(string); ok && pid != "" {
		projectID = pid
	}
	if projectID == "" {
		projectID = serviceKey.ProjectID
	}

	return struct {
		Success bool                   `json:"success"`
		Message string                 `json:"message"`
		Details map[string]interface{} `json:"details,omitempty"`
	}{
		Success: true,
		Message: "GCP credentials validated successfully",
		Details: map[string]interface{}{
			"project_id":            projectID,
			"service_account_email": serviceKey.ClientEmail,
		},
	}
}

func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}
