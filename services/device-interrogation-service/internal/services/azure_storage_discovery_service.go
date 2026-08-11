package services

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
	"github.com/google/uuid"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// DiscoverAzureStorageAccounts discovers at-rest encryption configuration for
// Storage accounts, mirroring the AWS S3 / GCP Cloud Storage paths. Azure Storage
// always encrypts at rest with AES-256; we surface Microsoft-managed vs
// customer-managed (CMK, KeySource = Microsoft.Keyvault).
func (s *StorageEncryptionService) DiscoverAzureStorageAccounts(ctx context.Context, tenantID uuid.UUID, azClient *azureclient.Client) ([]models.Device, error) {
	client, err := azClient.GetStorageAccountsClient()
	if err != nil {
		return nil, err
	}

	var devices []models.Device
	pager := client.NewListPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return devices, err
		}
		for _, acct := range page.Value {
			if acct == nil {
				continue
			}
			finding := azureStorageAccountToFinding(acct)

			vendor := "Microsoft"
			hostname := azStr(acct.Name)
			devices = append(devices, models.Device{
				ID:               uuid.New(),
				TenantID:         tenantID,
				DeviceType:       "azure_storage_account",
				Vendor:           &vendor,
				Hostname:         &hostname,
				DiscoveryMethod:  "cloud_api",
				ConnectionStatus: "discovered",
				Metadata: models.JSONB{
					"arn":               finding.ResourceARN,
					"region":            finding.Region,
					"encrypted":         finding.Encrypted,
					"encryption_type":   finding.EncryptionType,
					"algorithm":         finding.Algorithm,
					"kms_key_id":        finding.KMSKeyID,
					"resource_type":     "storage_account",
					"additional_detail": finding.AdditionalDetail,
					"discovery_method":  "cloud_api",
					"discovered_at":     time.Now().Format(time.RFC3339),
				},
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			})
		}
	}
	return devices, nil
}

// azureStorageAccountToFinding maps a Storage account to a provider-neutral
// storage encryption finding. Azure Storage always encrypts at rest with AES-256;
// KeySource = Microsoft.Keyvault marks a customer-managed key.
func azureStorageAccountToFinding(acct *armstorage.Account) StorageEncryptionFinding {
	finding := StorageEncryptionFinding{
		ResourceType:   "storage_account",
		ResourceName:   azStr(acct.Name),
		ResourceARN:    azStr(acct.ID),
		Region:         azStr(acct.Location),
		Encrypted:      true,
		Algorithm:      "AES-256",
		EncryptionType: "microsoft-managed",
	}
	detail := map[string]interface{}{}
	if acct.Properties != nil && acct.Properties.Encryption != nil {
		enc := acct.Properties.Encryption
		if enc.KeySource != nil && *enc.KeySource == armstorage.KeySourceMicrosoftKeyvault {
			finding.EncryptionType = "cmk"
			if enc.KeyVaultProperties != nil {
				finding.KMSKeyID = azStr(enc.KeyVaultProperties.KeyVaultURI) + azStr(enc.KeyVaultProperties.KeyName)
			}
		}
		if enc.RequireInfrastructureEncryption != nil {
			detail["require_infrastructure_encryption"] = *enc.RequireInfrastructureEncryption
		}
	}
	if acct.Kind != nil {
		detail["kind"] = string(*acct.Kind)
	}
	finding.AdditionalDetail = detail
	return finding
}
