package services

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

func TestCredentialsFromIntegration_ReadsSharedIntegrationsViaBypass(t *testing.T) {
	appDB, appMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock app db: %v", err)
	}
	defer appDB.Close()
	bypassDB, bypassMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock bypass db: %v", err)
	}
	defer bypassDB.Close()

	tenantID := uuid.New()
	credentialID := uuid.New()
	configJSON := encryptedIntegrationConfig(t, map[string]string{
		"username": "shared-admin",
		"password": "shared-pass",
	})

	bypassMock.ExpectQuery(`(?s)SELECT config\s+FROM platform_integrations.*tenant_id = \$2.*tenant_id IS NULL AND is_shared = true`).
		WithArgs(credentialID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"config"}).AddRow(configJSON))

	svc := &AgentService{
		db:            appDB,
		bypassDB:      bypassDB,
		encryptionKey: testMasterKey,
	}
	got, err := svc.credentialsFromIntegration(context.Background(), tenantID, credentialID)
	if err != nil {
		t.Fatalf("credentialsFromIntegration: %v", err)
	}
	if got["username"] != "shared-admin" {
		t.Fatalf("username = %v, want shared-admin", got["username"])
	}
	if got["password"] != "shared-pass" {
		t.Fatalf("password = %v, want shared-pass", got["password"])
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
	if err := appMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("app expectations: %v", err)
	}
}

func TestGetDeviceCredentials_ReadsSharedIntegrationsViaBypass(t *testing.T) {
	appDB, appMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock app db: %v", err)
	}
	defer appDB.Close()
	bypassDB, bypassMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock bypass db: %v", err)
	}
	defer bypassDB.Close()

	tenantID := uuid.New()
	credentialID := uuid.New()
	configJSON := encryptedIntegrationConfig(t, map[string]string{
		"username": "worker-admin",
		"password": "worker-pass",
	})

	bypassMock.ExpectQuery(`(?s)SELECT config, integration_type\s+FROM platform_integrations.*tenant_id = \$2.*tenant_id IS NULL AND is_shared = true`).
		WithArgs(credentialID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"config", "integration_type"}).AddRow(configJSON, "unifi"))

	svc := NewDeviceInterrogationService(appDB, bypassDB, testMasterKey)
	username, password, _, _, err := svc.getDeviceCredentials(context.Background(), tenantID, &models.Device{CredentialID: &credentialID})
	if err != nil {
		t.Fatalf("getDeviceCredentials: %v", err)
	}
	if username != "worker-admin" {
		t.Fatalf("username = %q, want worker-admin", username)
	}
	if password != "worker-pass" {
		t.Fatalf("password = %q, want worker-pass", password)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
	if err := appMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("app expectations: %v", err)
	}
}

func encryptedIntegrationConfig(t *testing.T, values map[string]string) string {
	t.Helper()
	encrypted := make(map[string]string, len(values))
	for key, value := range values {
		encrypted[key] = mustEncrypt(t, testMasterKey, value)
	}
	data, err := json.Marshal(encrypted)
	if err != nil {
		t.Fatalf("marshal integration config: %v", err)
	}
	return string(data)
}
