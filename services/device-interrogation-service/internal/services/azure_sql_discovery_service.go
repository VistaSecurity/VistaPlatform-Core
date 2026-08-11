package services

import (
	"context"
	"log"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
	"github.com/google/uuid"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// DiscoverAzureSQLDatabases discovers at-rest encryption (TDE) configuration for
// Azure SQL databases, mirroring the AWS RDS / GCP Cloud SQL paths. Azure SQL
// enables TDE by default; the server's encryption protector determines whether
// TDE uses a service-managed key or an Azure Key Vault CMK. Emits one device per
// user database (system 'master' is skipped).
func (s *StorageEncryptionService) DiscoverAzureSQLDatabases(ctx context.Context, tenantID uuid.UUID, azClient *azureclient.Client) ([]models.Device, error) {
	serversClient, err := azClient.GetSQLServersClient()
	if err != nil {
		return nil, err
	}
	dbClient, err := azClient.GetSQLDatabasesClient()
	if err != nil {
		return nil, err
	}
	protectorClient, err := azClient.GetSQLEncryptionProtectorsClient()
	if err != nil {
		return nil, err
	}

	var devices []models.Device
	serverPager := serversClient.NewListPager(nil)
	for serverPager.More() {
		page, err := serverPager.NextPage(ctx)
		if err != nil {
			return devices, err
		}
		for _, server := range page.Value {
			if server == nil || server.ID == nil || server.Name == nil {
				continue
			}
			rg := extractResourceGroupFromID(*server.ID)
			serverName := *server.Name

			// Server-level encryption protector → TDE key management.
			keyType, keyURI := "ServiceManaged", ""
			if prot, err := protectorClient.Get(ctx, rg, serverName, armsql.EncryptionProtectorNameCurrent, nil); err == nil && prot.Properties != nil {
				if prot.Properties.ServerKeyType != nil {
					keyType = string(*prot.Properties.ServerKeyType)
				}
				keyURI = azStr(prot.Properties.URI)
			}

			dbPager := dbClient.NewListByServerPager(rg, serverName, nil)
			for dbPager.More() {
				dbPage, err := dbPager.NextPage(ctx)
				if err != nil {
					log.Printf("Warning: failed to list databases on SQL server %s: %v", serverName, err)
					break
				}
				for _, db := range dbPage.Value {
					if db == nil || db.Name == nil || strings.EqualFold(*db.Name, "master") {
						continue
					}
					finding := azureSQLDatabaseToFinding(db, serverName, azStr(server.Location), keyType, keyURI)

					vendor := "Microsoft"
					hostname := *db.Name
					devices = append(devices, models.Device{
						ID:               uuid.New(),
						TenantID:         tenantID,
						DeviceType:       "azure_sql_database",
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
							"resource_type":     "sql_database",
							"additional_detail": finding.AdditionalDetail,
							"discovery_method":  "cloud_api",
						},
					})
				}
			}
		}
	}
	return devices, nil
}

// azureSQLDatabaseToFinding maps an Azure SQL database (plus its server's
// encryption-protector key management) to a provider-neutral storage encryption
// finding. TDE is on by default (AES-256); the server key type distinguishes a
// service-managed key from an Azure Key Vault CMK.
func azureSQLDatabaseToFinding(db *armsql.Database, serverName, serverLocation, serverKeyType, keyURI string) StorageEncryptionFinding {
	region := serverLocation
	if db.Location != nil && *db.Location != "" {
		region = *db.Location
	}
	finding := StorageEncryptionFinding{
		ResourceType: "sql_database",
		ResourceName: azStr(db.Name),
		ResourceARN:  azStr(db.ID),
		Region:       region,
		Encrypted:    true,
		Algorithm:    "AES-256",
	}
	if strings.EqualFold(serverKeyType, "AzureKeyVault") {
		finding.EncryptionType = "tde-cmk"
		finding.KMSKeyID = keyURI
	} else {
		finding.EncryptionType = "tde-service-managed"
	}
	finding.AdditionalDetail = map[string]interface{}{
		"server":          serverName,
		"server_key_type": serverKeyType,
	}
	return finding
}
