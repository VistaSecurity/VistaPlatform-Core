package handlers

// Test Connection for the cloud providers (integrations review M4).
//
// Azure's test was a TODO that answered "validated" for any three non-empty
// strings, and GCP's only parsed the key JSON — so a wrong secret, a revoked
// key, a subscription the principal cannot read or a project the account has
// no role on all tested green, and the first sign was a discovery job failing
// later. Each provider now authenticates for real and makes one cheap read,
// through the SAME client constructor its discovery uses
// (NewClientFromStoredConfig, fed the stored row), so a passing test proves
// discovery can authenticate. AWS already worked this way (STS
// GetCallerIdentity through awsclient.BuildAWSConfig).
//
// What reaches the user is the provider's own error code and message,
// projected and sanitised — never a raw response body.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/google/uuid"
	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/security/encryption"
)

// connectionTestResult is the Test Connection response body.
type connectionTestResult struct {
	Success bool                   `json:"success"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// integrationTestTarget is the part of an integration row a connection test
// reads: exactly the columns the discovery clients are constructed from.
type integrationTestTarget struct {
	ConfigJSON      string
	IntegrationType string
	AccountID       string
	Region          string
}

func failed(format string, args ...interface{}) connectionTestResult {
	return connectionTestResult{Success: false, Message: fmt.Sprintf(format, args...)}
}

// credentialUnusable is the answer for a stored credential the platform
// cannot read or a row the client refuses to build from. A credential saved
// under a retired key gets the same instruction discovery gives: re-enter it.
func credentialUnusable(provider string, err error) connectionTestResult {
	if errors.Is(err, encryption.ErrRetiredKeyVersion) {
		return failed("A stored %s credential was saved under a retired encryption key and can no longer be read. "+
			"Re-enter the credential in this integration and save it, then test again.", provider)
	}
	if strings.Contains(err.Error(), "failed to decrypt") {
		return failed("A stored %s credential could not be decrypted (%s). Re-enter the credential in this integration and save it.",
			provider, services.SanitizeCloudErrorMessage(err.Error()))
	}
	return failed("The %s integration is incomplete: %s", provider, services.SanitizeCloudErrorMessage(err.Error()))
}

// providerFailureText renders a projected provider failure: its own code, then
// its message.
func providerFailureText(f services.CloudCollectorFailure) string {
	switch {
	case f.Code != "" && f.Message != "":
		return f.Code + ": " + f.Message
	case f.Code != "":
		return f.Code
	default:
		return f.Message
	}
}

// testStoredAWSConnection decrypts the stored row exactly as
// awsclient.NewClientFromStoredConfig does (strictly, so a retired ciphertext
// is reported rather than sent to AWS), applies the row's region as it does,
// and runs STS GetCallerIdentity through the shared config builder.
func (h *IntegrationHandlers) testStoredAWSConnection(t integrationTestTarget) connectionTestResult {
	enc, err := encryption.NewService(h.encryptionKey)
	if err != nil {
		return failed("Credential encryption is not configured on this platform")
	}
	var stored map[string]interface{}
	if err := json.Unmarshal([]byte(t.ConfigJSON), &stored); err != nil {
		return failed("The AWS integration's stored configuration is unreadable")
	}
	decrypted, err := awsclient.DecryptConfigMap(enc, stored)
	if err != nil {
		return credentialUnusable("AWS", err)
	}
	config := make(map[string]interface{}, len(decrypted)+1)
	for k, v := range decrypted {
		config[k] = v
	}
	if t.Region != "" {
		config["region"] = t.Region
	}
	return testAWSConnection(config)
}

// testStoredAzureConnection builds the discovery client from the stored row
// and reads the configured subscription through Azure Resource Manager.
func (h *IntegrationHandlers) testStoredAzureConnection(ctx context.Context, integrationID uuid.UUID, t integrationTestTarget) connectionTestResult {
	client, err := azureclient.NewClientFromStoredConfig(integrationID, t.ConfigJSON, t.AccountID, h.encryptionKey, h.azureOptions...)
	if err != nil {
		return credentialUnusable("Azure", err)
	}
	sub, err := client.CheckSubscription(ctx)
	if err != nil {
		return connectionTestResult{Success: false, Message: azureFailureMessage(err), Details: map[string]interface{}{"subscription_id": client.GetSubscriptionID()}}
	}
	details := map[string]interface{}{"subscription_id": sub.SubscriptionID}
	if sub.DisplayName != "" {
		details["subscription_name"] = sub.DisplayName
	}
	if sub.State != "" {
		details["subscription_state"] = sub.State
	}
	// A subscription that is not Enabled answers reads but has nothing
	// discovery can usefully collect, and may stop answering at any moment.
	if sub.State != "" && !strings.EqualFold(sub.State, "Enabled") {
		return connectionTestResult{Success: false, Details: details,
			Message: fmt.Sprintf("Authenticated, but subscription %s is %s. Discovery needs an enabled subscription.", sub.SubscriptionID, sub.State)}
	}
	return connectionTestResult{Success: true, Details: details,
		Message: fmt.Sprintf("Azure credentials validated: the service principal can read subscription %s", sub.SubscriptionID)}
}

// testStoredGCPConnection builds the discovery client from the stored row,
// exchanges the key for a token and reads the project.
func (h *IntegrationHandlers) testStoredGCPConnection(ctx context.Context, integrationID uuid.UUID, t integrationTestTarget) connectionTestResult {
	client, err := gcpclient.NewClientFromStoredConfig(integrationID, t.ConfigJSON, t.AccountID, h.encryptionKey, h.gcpOptions...)
	if err != nil {
		return credentialUnusable("GCP", err)
	}
	check, err := client.CheckProject(ctx)
	details := map[string]interface{}{"project_id": check.ProjectID, "service_account_email": check.ServiceAccount}
	if err != nil {
		return connectionTestResult{Success: false, Message: gcpFailureMessage(check, err), Details: details}
	}
	return connectionTestResult{Success: true, Details: details,
		Message: fmt.Sprintf("GCP credentials validated: %s can read project %s", check.ServiceAccount, check.ProjectID)}
}

func gcpFailureMessage(check gcpclient.ProjectCheck, err error) string {
	var checkErr *gcpclient.CheckError
	stage := ""
	if errors.As(err, &checkErr) {
		stage = checkErr.Stage
	}
	code, msg, status, ok := gcpclient.ErrorDetail(err)
	switch {
	case ok && stage == gcpclient.CheckStageToken:
		return "Google rejected the service account key: " + services.SanitizeCloudErrorMessage(strings.Join(nonEmpty(code, msg), ": "))
	case ok:
		hint := ""
		switch status {
		case http.StatusForbidden:
			hint = " Load-balancer and SSL-proxy discovery need roles/compute.viewer on the project."
		case http.StatusNotFound:
			hint = " Check the project ID, and that the Compute Engine API is enabled on it."
		}
		return fmt.Sprintf("Authenticated as %s, but reading project %s failed (%d): %s.%s",
			check.ServiceAccount, check.ProjectID, status, services.SanitizeCloudErrorMessage(strings.Join(nonEmpty(code, msg), ": ")), hint)
	case stage == gcpclient.CheckStageToken:
		return "Could not obtain a Google access token: " + services.SanitizeCloudErrorMessage(checkErr.Err.Error())
	default:
		return "Could not reach Google Cloud: " + services.SanitizeCloudErrorMessage(err.Error())
	}
}

// azureFailureMessage projects a failed Azure check onto what the user can act
// on: Microsoft Entra ID's own AADSTS error for a refused token, ARM's error
// code and message for a refused read.
func azureFailureMessage(err error) string {
	var authErr *azidentity.AuthenticationFailedError
	code, msg, status, ok := azureclient.ErrorDetail(err)
	switch {
	case ok && errors.As(err, &authErr):
		return "Microsoft Entra ID rejected the integration's credentials: " + services.SanitizeCloudErrorMessage(strings.Join(nonEmpty(code, msg), ": "))
	case ok:
		return fmt.Sprintf("Authenticated, but Azure Resource Manager refused to read the subscription (%d): %s",
			status, services.SanitizeCloudErrorMessage(strings.Join(nonEmpty(code, msg), ": ")))
	default:
		return "Could not reach Azure: " + services.SanitizeCloudErrorMessage(err.Error())
	}
}

func nonEmpty(parts ...string) []string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, strings.TrimSpace(p))
		}
	}
	return out
}
