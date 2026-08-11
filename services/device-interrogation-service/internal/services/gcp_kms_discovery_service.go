package services

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
)

// DiscoverGCPKMSKeys enumerates customer-managed Cloud KMS keys across every KMS
// location in the project and returns them as provider-neutral KMSKeyFinding
// records (the same shape the AWS path produces), ready for StoreKMSKeyFindings.
func (s *KMSDiscoveryService) DiscoverGCPKMSKeys(
	ctx context.Context,
	tenantID uuid.UUID,
	integrationID uuid.UUID,
	gcpCli *gcpclient.Client,
) ([]KMSKeyFinding, error) {
	locations, err := gcpCli.ListKMSLocations(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list Cloud KMS locations: %w", err)
	}

	projectID := gcpCli.GetProjectID()
	var findings []KMSKeyFinding

	for _, loc := range locations {
		rings, err := gcpCli.ListKeyRings(ctx, loc.LocationID)
		if err != nil {
			log.Printf("Warning: failed to list key rings in %s: %v", loc.LocationID, err)
			continue
		}
		for _, ring := range rings {
			keys, err := gcpCli.ListCryptoKeys(ctx, ring.Name)
			if err != nil {
				log.Printf("Warning: failed to list crypto keys in %s: %v", ring.Name, err)
				continue
			}
			for _, key := range keys {
				findings = append(findings, gcpCryptoKeyToFinding(key, loc.LocationID, projectID))
			}
		}
	}

	log.Printf("Discovered %d GCP Cloud KMS keys across %d locations", len(findings), len(locations))
	return findings, nil
}

// gcpCryptoKeyToFinding maps a Cloud KMS crypto key onto the provider-neutral
// KMSKeyFinding, normalising the GCP algorithm enum to a canonical key spec so
// the shared key_size derivation and algorithms-table join behave identically
// across providers.
func gcpCryptoKeyToFinding(key gcpclient.KMSCryptoKey, location, projectID string) KMSKeyFinding {
	// versionTemplate carries the algorithm/protection level even for asymmetric
	// keys that have no primary version; fall back to the primary version.
	algorithm, protection := "", ""
	if key.VersionTemplate != nil {
		algorithm = key.VersionTemplate.Algorithm
		protection = key.VersionTemplate.ProtectionLevel
	}
	state := "ENABLED"
	if key.Primary != nil {
		if key.Primary.Algorithm != "" && algorithm == "" {
			algorithm = key.Primary.Algorithm
		}
		if key.Primary.ProtectionLevel != "" && protection == "" {
			protection = key.Primary.ProtectionLevel
		}
		if key.Primary.State != "" {
			state = key.Primary.State
		}
	}

	rotationEnabled, rotationDays := parseGCPRotationPeriod(key.RotationPeriod)

	f := KMSKeyFinding{
		KeyID:       key.Name, // full resource name — globally unique per project
		KeyARN:      key.Name,
		KeyState:    state,
		KeyUsage:    key.Purpose,
		KeySpec:     mapGCPKMSAlgorithmToKeySpec(algorithm),
		KeyManager:  "CUSTOMER",
		Origin:      protection,
		Enabled:     state == "ENABLED",
		MultiRegion: location == "global",
		Region:      location,
		AccountID:   projectID,

		RotationEnabled:    rotationEnabled,
		RotationPeriodDays: rotationDays,
	}
	if algorithm != "" {
		// Preserve the raw GCP algorithm for the metadata blob.
		if strings.Contains(key.Purpose, "SIGN") {
			f.SigningAlgorithms = []string{algorithm}
		} else {
			f.EncryptionAlgorithms = []string{algorithm}
		}
	}
	if t, err := time.Parse(time.RFC3339, key.CreateTime); err == nil {
		f.CreationDate = t
	}
	return f
}

// mapGCPKMSAlgorithmToKeySpec normalises a Cloud KMS algorithm enum to the
// canonical key spec vocabulary used by the AWS path (and understood by
// keySpecToSize / the algorithms table). Returns the raw algorithm when no
// mapping applies.
func mapGCPKMSAlgorithmToKeySpec(alg string) string {
	a := strings.ToUpper(alg)
	switch {
	case a == "":
		return ""
	case strings.Contains(a, "GOOGLE_SYMMETRIC_ENCRYPTION"), strings.Contains(a, "EXTERNAL_SYMMETRIC_ENCRYPTION"):
		return "SYMMETRIC_DEFAULT"
	case strings.HasPrefix(a, "RSA") && strings.Contains(a, "2048"):
		return "RSA_2048"
	case strings.HasPrefix(a, "RSA") && strings.Contains(a, "3072"):
		return "RSA_3072"
	case strings.HasPrefix(a, "RSA") && strings.Contains(a, "4096"):
		return "RSA_4096"
	case strings.Contains(a, "SECP256K1"):
		return "ECC_SECG_P256K1"
	case strings.Contains(a, "P256"):
		return "ECC_NIST_P256"
	case strings.Contains(a, "P384"):
		return "ECC_NIST_P384"
	case strings.Contains(a, "HMAC_SHA224"):
		return "HMAC_224"
	case strings.Contains(a, "HMAC_SHA256"):
		return "HMAC_256"
	case strings.Contains(a, "HMAC_SHA384"):
		return "HMAC_384"
	case strings.Contains(a, "HMAC_SHA512"):
		return "HMAC_512"
	default:
		return alg
	}
}

// parseGCPRotationPeriod parses a Cloud KMS rotation period (e.g. "7776000s")
// into an enabled flag and a whole-day count.
func parseGCPRotationPeriod(period string) (enabled bool, days int) {
	if period == "" {
		return false, 0
	}
	secsStr := strings.TrimSuffix(period, "s")
	secs, err := strconv.ParseFloat(secsStr, 64)
	if err != nil || secs <= 0 {
		return false, 0
	}
	return true, int(secs / 86400)
}
