package handlers

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
)

// credentialDeviceStore returns a device whose password is MASKED (as GetDevice
// really does, because *models.Device feeds API responses) alongside the true
// stored ciphertext behind GetStoredDeviceCredentials.
type credentialDeviceStore struct {
	stubDeviceStore
	realCiphertext string
	storedErr      error
	storedCalls    int
}

func (s *credentialDeviceStore) GetStoredDeviceCredentials(context.Context, uuid.UUID, uuid.UUID) (services.StoredDeviceCredentials, error) {
	s.storedCalls++
	if s.storedErr != nil {
		return services.StoredDeviceCredentials{}, s.storedErr
	}
	return services.StoredDeviceCredentials{
		Username:           "admin",
		EncryptedPassword:  s.realCiphertext,
		ManagementURL:      "https://bigip.example.test",
		DeviceType:         "f5",
		InsecureSkipVerify: true,
	}, nil
}

func maskedDevice(realCiphertext string) *models.Device {
	username := "admin"
	// maskPassword's output: first 4 + "****" + last 4 of the ciphertext.
	masked := realCiphertext[:4] + "****" + realCiphertext[len(realCiphertext)-4:]
	mgmt := "https://bigip.example.test"
	return &models.Device{
		ID:            uuid.New(),
		TenantID:      deviceTestTenant,
		DeviceType:    "f5",
		Username:      &username,
		Password:      &masked,
		ManagementURL: &mgmt,
	}
}

// TestBuildJobCredentials_UsesUnmaskedStoredPassword is the producer-side
// regression for.
//
// The interrogation handler used to take device.Password straight off the
// *models.Device returned by GetDevice — which masks it. The value that
// travelled to the remote agent as the device password was therefore literally
// "abcd****wxyz": four characters of ciphertext, four asterisks, four more. The
// credential had to come from the unmasked reader instead.
func TestBuildJobCredentials_UsesUnmaskedStoredPassword(t *testing.T) {
	const realCiphertext = "AuzVHm4PZMOanEjrDkrTRjmy9V1N1V0e6rfC8Upr58I29PEbUtQRPg=="
	store := &credentialDeviceStore{realCiphertext: realCiphertext}
	h := &DeviceHandlers{deviceService: store}
	device := maskedDevice(realCiphertext)

	creds, err := h.buildJobCredentials(context.Background(), deviceTestTenant, device, "unused-master-key")
	if err != nil {
		t.Fatalf("buildJobCredentials = %v, want nil", err)
	}

	got, _ := creds["password"].(string)
	if strings.Contains(got, "****") {
		t.Fatalf("password = %q — a MASKED value is being shipped as the device credential", got)
	}
	if got != realCiphertext {
		t.Fatalf("password = %q, want the full stored ciphertext %q", got, realCiphertext)
	}
	if store.storedCalls != 1 {
		t.Fatalf("GetStoredDeviceCredentials called %d times, want 1 — the masked *models.Device must not be the credential source", store.storedCalls)
	}

	if creds["username"] != "admin" {
		t.Fatalf("username = %v, want admin", creds["username"])
	}
	if creds[masterEncryptedFlagKey] != true {
		t.Fatalf("%q = %v, want true so the hand-off sealer knows to decrypt", masterEncryptedFlagKey, creds[masterEncryptedFlagKey])
	}
	if creds["insecure_skip_verify"] != true {
		t.Fatalf("insecure_skip_verify = %v, want it carried through from the device row", creds["insecure_skip_verify"])
	}
}

// TestBuildJobCredentials_NoCredentialsIsDistinguishable — callers branch on
// this to return 400 rather than 500, and the bulk path uses it to keep going.
func TestBuildJobCredentials_NoCredentialsIsDistinguishable(t *testing.T) {
	store := &credentialDeviceStore{realCiphertext: ""}
	h := &DeviceHandlers{deviceService: store}

	_, err := h.buildJobCredentials(context.Background(), deviceTestTenant, &models.Device{ID: uuid.New()}, "k")
	if !errors.Is(err, errNoDeviceCredentials) {
		t.Fatalf("buildJobCredentials = %v, want errNoDeviceCredentials", err)
	}
}
