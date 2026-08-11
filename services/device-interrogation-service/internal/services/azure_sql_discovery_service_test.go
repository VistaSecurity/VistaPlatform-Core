package services

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql"
)

func TestAzureSQLDatabaseToFinding(t *testing.T) {
	strptr := func(s string) *string { return &s }
	db := &armsql.Database{
		ID:       strptr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Sql/servers/srv/databases/appdb"),
		Name:     strptr("appdb"),
		Location: strptr("eastus"),
	}

	// Service-managed TDE.
	sm := azureSQLDatabaseToFinding(db, "srv", "eastus", "ServiceManaged", "")
	if !sm.Encrypted || sm.Algorithm != "AES-256" || sm.EncryptionType != "tde-service-managed" {
		t.Errorf("service-managed finding = %+v", sm)
	}
	if sm.KMSKeyID != "" {
		t.Errorf("KMSKeyID = %q, want empty for service-managed", sm.KMSKeyID)
	}
	if sm.AdditionalDetail["server"] != "srv" {
		t.Errorf("server detail = %v", sm.AdditionalDetail["server"])
	}

	// CMK (Azure Key Vault).
	uri := "https://v.vault.azure.net/keys/tde-key/abc"
	cmk := azureSQLDatabaseToFinding(db, "srv", "eastus", "AzureKeyVault", uri)
	if cmk.EncryptionType != "tde-cmk" || cmk.KMSKeyID != uri {
		t.Errorf("cmk finding = %+v", cmk)
	}
}
