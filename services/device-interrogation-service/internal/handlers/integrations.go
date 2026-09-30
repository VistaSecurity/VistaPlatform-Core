package handlers

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
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
	// azureOptions / gcpOptions are empty in production. A test sets them to
	// point Test Connection's (real) provider clients at a local server.
	azureOptions []azureclient.Option
	gcpOptions   []gcpclient.Option
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
		if errors.Is(err, errIntegrationNameTaken) {
			c.JSON(http.StatusConflict, gin.H{"error": integrationNameTakenMessage(req.IntegrationName)})
			return
		}
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
		var existing map[string]interface{}
		_ = json.Unmarshal([]byte(existingConfig), &existing)
		merged, stored, err := h.mergeConfigUpdate(existing, req.Config)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encrypt credentials"})
			return
		}
		if err := validateIntegrationConfig(integrationType, merged); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		configJSON, _ := json.Marshal(stored)
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
		if errors.Is(err, errIntegrationNameTaken) && req.IntegrationName != nil {
			c.JSON(http.StatusConflict, gin.H{"error": integrationNameTakenMessage(*req.IntegrationName)})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update integration"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Integration updated successfully"})
}

// integrationNameTakenMessage is the 409 body for a create/rename that collides
// with another of the caller's own integrations.
func integrationNameTakenMessage(name string) string {
	return fmt.Sprintf("An integration named %q already exists", name)
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
	target, found, err := h.store.GetConfigForTest(c.Request.Context(), integrationID, tenantID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get integration"})
		return
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "Integration not found"})
		return
	}

	// Every cloud provider is tested from the STORED row, through the same
	// decryption and client construction its discovery uses. The handler used
	// to decrypt leniently here — a credential that failed to decrypt was
	// passed on as its own ciphertext — so a credential saved under a retired
	// key reached AWS as a base64 blob and came back as an unexplained
	// authentication failure, where discovery says "re-enter the credential".
	ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
	defer cancel()

	var testResult connectionTestResult
	switch target.IntegrationType {
	case "aws":
		testResult = h.testStoredAWSConnection(target)
	case "azure":
		testResult = h.testStoredAzureConnection(ctx, integrationID, target)
	case "gcp":
		testResult = h.testStoredGCPConnection(ctx, integrationID, target)
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

// sensitiveKeys is the single list of integration-config keys stored encrypted
// and masked in responses. Every cloud provider's half comes from that
// provider's client package (awsclient/azureclient/gcpclient.SensitiveConfigKeys)
// so client construction and the handler cannot disagree about what is a
// secret. They used to keep independent copies, which is how external_id came
// to be encrypted in one place and plaintext in the other, and how Azure's
// client came to demand ciphertext for tenant_id/subscription_id that this
// handler had always stored in plaintext (Azure discovery never ran).
//
// NOTE: assume_role_arn, tenant_id and subscription_id are intentionally absent
// — they are identifiers, not secrets, and the UI displays them.
var sensitiveKeys = func() []string {
	keys := []string{
		"api_key",
		"password", // Network device credentials - username is NOT sensitive
	}
	keys = append(keys, awsclient.SensitiveConfigKeys...)
	keys = append(keys, azureclient.SensitiveConfigKeys...)
	keys = append(keys, gcpclient.SensitiveConfigKeys...)
	return keys
}()

func (h *IntegrationHandlers) encryptConfig(config map[string]interface{}) (map[string]interface{}, error) {
	enc, err := encryption.NewService(h.encryptionKey)
	if err != nil {
		return nil, err
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

// mergeConfigUpdate applies a partial config edit to a stored config. It
// returns the merged config in the clear (for validation only) and the config
// to store.
//
// A stored credential the edit does not touch is written back EXACTLY as it
// was stored. The merge used to decrypt everything leniently — a value that
// failed to decrypt was kept as its own ciphertext — and then encrypt
// everything again, so an edit that only flipped "Enabled" turned a credential
// saved under a retired key into a fresh, perfectly decryptable ciphertext OF
// THE OLD CIPHERTEXT. From then on the platform handed the provider a base64
// blob as the secret, and the honest "re-enter the credential" error became an
// unexplained authentication failure.
//
// The one stored value that IS re-encrypted is legacy plaintext — a value in a
// sensitive key that is not even base64, from before the key was classified
// sensitive. Encrypting it on the next edit is the migration that has always
// happened here; a base64 value that will not decrypt is ciphertext this key
// cannot read, and re-encrypting it would be the bug above.
func (h *IntegrationHandlers) mergeConfigUpdate(existing, changes map[string]interface{}) (merged, stored map[string]interface{}, err error) {
	enc, err := encryption.NewService(h.encryptionKey)
	if err != nil {
		return nil, nil, err
	}
	merged = make(map[string]interface{}, len(existing)+len(changes))
	stored = make(map[string]interface{}, len(existing)+len(changes))
	for key, value := range existing {
		merged[key] = value
		stored[key] = value
		raw, ok := value.(string)
		if !ok || raw == "" || !isSensitiveKey(key) {
			continue
		}
		if plain, derr := enc.Decrypt(raw); derr == nil {
			merged[key] = plain
			continue
		}
		if _, b64err := base64.StdEncoding.DecodeString(raw); b64err != nil {
			// Legacy plaintext: store it encrypted from now on.
			ct, eerr := enc.Encrypt(raw)
			if eerr != nil {
				return nil, nil, eerr
			}
			stored[key] = ct
		}
		// Otherwise: ciphertext this key cannot read. Kept verbatim.
	}
	for key, value := range changes {
		merged[key] = value
		raw, ok := value.(string)
		if !ok || raw == "" || !isSensitiveKey(key) {
			stored[key] = value
			continue
		}
		ct, eerr := enc.Encrypt(raw)
		if eerr != nil {
			return nil, nil, eerr
		}
		stored[key] = ct
	}
	return merged, stored, nil
}

func isSensitiveKey(key string) bool {
	for _, sk := range sensitiveKeys {
		if key == sk {
			return true
		}
	}
	return false
}

func (h *IntegrationHandlers) decryptConfig(config map[string]interface{}) (map[string]interface{}, error) {
	enc, err := encryption.NewService(h.encryptionKey)
	if err != nil {
		return nil, err
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
		// Delegated so the handler and the discovery client cannot disagree on
		// what an AWS integration must carry. access_key mode still requires
		// both keys; assume_role mode requires assume_role_arn and neither key.
		return awsclient.ValidateConfigMap(config)
	case "azure":
		if _, ok := config["tenant_id"]; !ok {
			return fmt.Errorf("missing tenant_id: Azure integration requires it")
		}
		if _, ok := config["client_id"]; !ok {
			return fmt.Errorf("missing client_id: Azure integration requires it")
		}
		if _, ok := config["client_secret"]; !ok {
			return fmt.Errorf("missing client_secret: Azure integration requires it")
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

type awsTestResult = connectionTestResult

// testAWSConnection validates an AWS integration's credentials by calling STS
// GetCallerIdentity.
//
// It builds its aws.Config through awsclient.BuildAWSConfig — the SAME function
// the discovery path uses — so a green "Test Connection" actually proves
// discovery will authenticate, in access_key AND assume_role mode. It used to
// assemble its own static-credentials config, which meant the test could pass
// while discovery failed (and, for assume_role integrations, tested credentials
// discovery would never use).
func testAWSConnection(config map[string]interface{}) awsTestResult {
	credCfg := awsclient.CredentialConfigFromMap(config)

	if err := credCfg.Validate(); err != nil {
		return awsTestResult{
			Success: false,
			Message: fmt.Sprintf("Missing AWS credentials: %v", err),
		}
	}

	region := credCfg.Region
	if region == "" {
		region = awsclient.DefaultRegion
		credCfg.Region = region
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := awsclient.BuildAWSConfig(ctx, credCfg)
	if err != nil {
		return awsTestResult{
			Success: false,
			Message: fmt.Sprintf("Failed to create AWS config: %v", err),
		}
	}

	// Call STS GetCallerIdentity to verify credentials. In assume_role mode this
	// resolves through the AssumeRole provider first, so the identity reported
	// back is the assumed role session — exactly what discovery will act as.
	stsClient := sts.NewFromConfig(cfg)
	identity, err := stsClient.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return awsTestResult{
			Success: false,
			Message: "AWS authentication failed: " + providerFailureText(services.SanitizeCloudFailure("", err)),
		}
	}

	return awsTestResult{
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
