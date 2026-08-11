package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// RegistrationKey represents a sensor registration key
type RegistrationKey struct {
	Key         string    `json:"key"`
	TenantID    string    `json:"tenant_id"`
	Description string    `json:"description"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
	MaxSensors  int       `json:"max_sensors"`
	UsedCount   int       `json:"used_count"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run generate-registration-key.go <tenant-id> [description] [max-sensors]")
		fmt.Println("Example: go run generate-registration-key.go tenant-123 'Datacenter Sensors' 10")
		os.Exit(1)
	}

	tenantID := os.Args[1]
	description := "Sensor Registration Key"
	maxSensors := 1

	if len(os.Args) > 2 {
		description = os.Args[2]
	}
	if len(os.Args) > 3 {
		if _, err := fmt.Sscanf(os.Args[3], "%d", &maxSensors); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing max sensors: %v\n", err)
			os.Exit(1)
		}
	}

	// Generate random key components
	keyBytes := make([]byte, 8)
	if _, err := rand.Read(keyBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating random key: %v\n", err)
		os.Exit(1)
	}
	keySuffix := hex.EncodeToString(keyBytes)[:6]

	// Create registration key
	now := time.Now()
	key := fmt.Sprintf("REG-%s-%s-%s",
		tenantID[:8],
		now.Format("20060102"),
		keySuffix)

	regKey := RegistrationKey{
		Key:         key,
		TenantID:    tenantID,
		Description: description,
		ExpiresAt:   now.Add(30 * 24 * time.Hour), // 30 days
		CreatedAt:   now,
		MaxSensors:  maxSensors,
		UsedCount:   0,
	}

	// Output registration key
	fmt.Printf("🔑 Sensor Registration Key Generated\n")
	fmt.Printf("=====================================\n")
	fmt.Printf("Key: %s\n", regKey.Key)
	fmt.Printf("Tenant ID: %s\n", regKey.TenantID)
	fmt.Printf("Description: %s\n", regKey.Description)
	fmt.Printf("Expires: %s\n", regKey.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Max Sensors: %d\n", regKey.MaxSensors)
	fmt.Printf("\n")
	fmt.Printf("📋 Installation Command:\n")
	fmt.Printf("curl -X POST http://localhost:8085/api/v1/sensors/register \\\n")
	fmt.Printf("  -H \"Content-Type: application/json\" \\\n")
	fmt.Printf("  -d '{\n")
	fmt.Printf("    \"registration_key\": \"%s\",\n", regKey.Key)
	fmt.Printf("    \"name\": \"sensor-<hostname>\",\n")
	fmt.Printf("    \"platform\": \"linux\",\n")
	fmt.Printf("    \"version\": \"1.0.0\",\n")
	fmt.Printf("    \"profile\": \"datacenter_host\",\n")
	fmt.Printf("    \"network_interfaces\": [\"eth0\", \"eth1\"]\n")
	fmt.Printf("  }'\n")
}
