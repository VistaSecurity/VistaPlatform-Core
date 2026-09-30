package services

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
)

// The integration's "Enabled" switch used to be read by nothing: a disabled
// integration's schedules and Discover runs went on collecting.
//
// MUTATION-VERIFIED: drop the `if !enabled` refusal and this goes red.
func TestAuthorizeCloudIntegration_DisabledIntegrationIsRefused(t *testing.T) {
	bypassDB, bypassMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock bypass db: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()
	tenantID, integrationID := uuid.New(), uuid.New()
	bypassMock.ExpectQuery(authorizeCloudIntegrationQuery+`.*integration_type = \$3`).
		WithArgs(integrationID, tenantID, "aws").
		WillReturnRows(sqlmock.NewRows([]string{"integration_type", "enabled"}).AddRow("aws", false))

	svc := NewCloudDiscoveryService(nil, bypassDB, testMasterKey)
	_, err = svc.DiscoverAWSResources(context.Background(), tenantID, integrationID, []string{"s3"}, nil)
	if !errors.Is(err, ErrCloudIntegrationDisabled) {
		t.Fatalf("a disabled integration ran: err = %v", err)
	}
}

const authorizeCloudIntegrationQuery = `(?s)SELECT integration_type, COALESCE\(is_enabled, true\)\s+FROM platform_integrations.*tenant_id = \$2.*tenant_id IS NULL AND is_shared = true.*is_active = true.*deleted_at IS NULL`

func TestGetIntegrationCloudProviderAuthorizesSharedIntegration(t *testing.T) {
	bypassDB, bypassMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock bypass db: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	tenantID := uuid.New()
	integrationID := uuid.New()

	bypassMock.ExpectQuery(authorizeCloudIntegrationQuery).
		WithArgs(integrationID, tenantID).
		WillReturnRows(sqlmock.NewRows([]string{"integration_type", "enabled"}).AddRow("aws", true))

	svc := NewCloudDiscoveryService(nil, bypassDB, testMasterKey)
	got, err := svc.GetIntegrationCloudProvider(context.Background(), tenantID, integrationID)
	if err != nil {
		t.Fatalf("GetIntegrationCloudProvider: %v", err)
	}
	if got != "aws" {
		t.Fatalf("provider = %q, want aws", got)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

func TestDiscoverAWSResourcesRejectsUnauthorizedIntegrationBeforeCredentialLookup(t *testing.T) {
	bypassDB, bypassMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock bypass db: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	tenantID := uuid.New()
	integrationID := uuid.New()

	bypassMock.ExpectQuery(authorizeCloudIntegrationQuery+`.*integration_type = \$3`).
		WithArgs(integrationID, tenantID, "aws").
		WillReturnRows(sqlmock.NewRows([]string{"integration_type", "enabled"}))

	svc := NewCloudDiscoveryService(nil, bypassDB, testMasterKey)
	_, err = svc.DiscoverAWSResources(context.Background(), tenantID, integrationID, []string{"s3"}, nil)
	if err == nil {
		t.Fatal("DiscoverAWSResources unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("error = %q, want authorization failure", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}

func TestDiscoverAWSKMSKeysRejectsUnauthorizedIntegrationBeforeCredentialLookup(t *testing.T) {
	bypassDB, bypassMock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock bypass db: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	tenantID := uuid.New()
	integrationID := uuid.New()

	bypassMock.ExpectQuery(authorizeCloudIntegrationQuery+`.*integration_type = \$3`).
		WithArgs(integrationID, tenantID, "aws").
		WillReturnRows(sqlmock.NewRows([]string{"integration_type", "enabled"}))

	svc := NewKMSDiscoveryService(nil, bypassDB, testMasterKey)
	_, err = svc.DiscoverAWSKMSKeys(context.Background(), tenantID, integrationID, nil, nil)
	if err == nil {
		t.Fatal("DiscoverAWSKMSKeys unexpectedly succeeded")
	}
	if !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("error = %q, want authorization failure", err)
	}
	if err := bypassMock.ExpectationsWereMet(); err != nil {
		t.Fatalf("bypass expectations: %v", err)
	}
}
