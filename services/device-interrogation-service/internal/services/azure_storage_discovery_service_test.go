package services

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

func TestAzureStorageAccountToFinding(t *testing.T) {
	strptr := func(s string) *string { return &s }

	// Microsoft-managed.
	msSource := armstorage.KeySourceMicrosoftStorage
	mm := azureStorageAccountToFinding(&armstorage.Account{
		ID:       strptr("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct1"),
		Name:     strptr("acct1"),
		Location: strptr("eastus"),
		Properties: &armstorage.AccountProperties{
			Encryption: &armstorage.Encryption{KeySource: &msSource},
		},
	})
	if !mm.Encrypted || mm.Algorithm != "AES-256" || mm.EncryptionType != "microsoft-managed" {
		t.Errorf("microsoft-managed finding = %+v", mm)
	}
	if mm.KMSKeyID != "" {
		t.Errorf("KMSKeyID = %q, want empty for Microsoft-managed", mm.KMSKeyID)
	}

	// Customer-managed (CMK via Key Vault).
	kvSource := armstorage.KeySourceMicrosoftKeyvault
	cmk := azureStorageAccountToFinding(&armstorage.Account{
		Name:     strptr("secure"),
		Location: strptr("westus"),
		Properties: &armstorage.AccountProperties{
			Encryption: &armstorage.Encryption{
				KeySource: &kvSource,
				KeyVaultProperties: &armstorage.KeyVaultProperties{
					KeyVaultURI: strptr("https://v.vault.azure.net/"),
					KeyName:     strptr("storage-key"),
				},
			},
		},
	})
	if cmk.EncryptionType != "cmk" {
		t.Errorf("EncryptionType = %q, want cmk", cmk.EncryptionType)
	}
	if cmk.KMSKeyID != "https://v.vault.azure.net/storage-key" {
		t.Errorf("KMSKeyID = %q", cmk.KMSKeyID)
	}
}
