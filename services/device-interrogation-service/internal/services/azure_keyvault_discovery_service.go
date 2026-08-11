package services

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault"
	"github.com/google/uuid"
	azureclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/azure"
)

// DiscoverAzureKeyVaultKeys enumerates keys across every Key Vault in the
// subscription and returns them as provider-neutral KMSKeyFinding records (the
// AWS KMS shape), ready for StoreKMSKeyFindings with provider "azure".
func (s *KMSDiscoveryService) DiscoverAzureKeyVaultKeys(
	ctx context.Context,
	tenantID uuid.UUID,
	integrationID uuid.UUID,
	azClient *azureclient.Client,
) ([]KMSKeyFinding, error) {
	vaultsClient, err := azClient.GetKeyVaultVaultsClient()
	if err != nil {
		return nil, err
	}
	keysClient, err := azClient.GetKeyVaultKeysClient()
	if err != nil {
		return nil, err
	}
	subID := azClient.GetSubscriptionID()

	var findings []KMSKeyFinding
	vaultPager := vaultsClient.NewListBySubscriptionPager(nil)
	for vaultPager.More() {
		page, err := vaultPager.NextPage(ctx)
		if err != nil {
			return findings, fmt.Errorf("failed to list Key Vaults: %w", err)
		}
		for _, vault := range page.Value {
			if vault == nil || vault.ID == nil || vault.Name == nil {
				continue
			}
			rg := extractResourceGroupFromID(*vault.ID)
			location := azStr(vault.Location)

			keyPager := keysClient.NewListPager(rg, *vault.Name, nil)
			for keyPager.More() {
				kp, err := keyPager.NextPage(ctx)
				if err != nil {
					log.Printf("Warning: failed to list keys in vault %s: %v", *vault.Name, err)
					break
				}
				for _, key := range kp.Value {
					findings = append(findings, azureKeyToFinding(key, location, subID))
				}
			}
		}
	}

	log.Printf("Discovered %d Azure Key Vault keys", len(findings))
	return findings, nil
}

// azureKeyToFinding maps a Key Vault key onto the provider-neutral KMSKeyFinding,
// normalising the key type/size/curve to the canonical key-spec vocabulary.
func azureKeyToFinding(key *armkeyvault.Key, location, subscriptionID string) KMSKeyFinding {
	f := KMSKeyFinding{
		KeyManager: "CUSTOMER",
		Region:     location,
		AccountID:  subscriptionID,
		KeyState:   "ENABLED",
	}
	if key == nil {
		return f
	}
	f.KeyID = azStr(key.ID)
	f.KeyARN = azStr(key.ID)

	p := key.Properties
	if p == nil {
		return f
	}

	kty := ""
	if p.Kty != nil {
		kty = string(*p.Kty)
	}
	var curve string
	if p.CurveName != nil {
		curve = string(*p.CurveName)
	}
	f.KeySpec = mapAzureKeyToKeySpec(kty, p.KeySize, curve)
	if strings.Contains(strings.ToUpper(kty), "HSM") {
		f.Origin = "HSM"
	} else {
		f.Origin = "SOFTWARE"
	}
	if kty != "" {
		f.EncryptionAlgorithms = []string{kty}
	}
	f.RotationEnabled = p.RotationPolicy != nil

	for _, op := range p.KeyOps {
		if op != nil {
			f.KeyUsage = string(*op)
			break
		}
	}

	if p.Attributes != nil {
		if p.Attributes.Enabled != nil && !*p.Attributes.Enabled {
			f.KeyState = "DISABLED"
		}
		f.Enabled = p.Attributes.Enabled == nil || *p.Attributes.Enabled
		if p.Attributes.Created != nil {
			f.CreationDate = time.Unix(*p.Attributes.Created, 0).UTC()
		}
	}
	return f
}

// mapAzureKeyToKeySpec normalises an Azure key type/size/curve to the canonical
// key-spec vocabulary understood by keySpecToSize and the algorithms table.
func mapAzureKeyToKeySpec(kty string, keySize *int32, curve string) string {
	upper := strings.ToUpper(kty)
	switch {
	case strings.HasPrefix(upper, "RSA"):
		if keySize != nil {
			return fmt.Sprintf("RSA_%d", *keySize)
		}
		return "RSA_2048"
	case strings.HasPrefix(upper, "EC"):
		switch curve {
		case "P-256":
			return "ECC_NIST_P256"
		case "P-384":
			return "ECC_NIST_P384"
		case "P-521":
			return "ECC_NIST_P521"
		case "P-256K":
			return "ECC_SECG_P256K1"
		}
		return "ECC_NIST_P256"
	default:
		if kty == "" {
			return ""
		}
		return kty
	}
}

// azStr safely dereferences a *string.
func azStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
