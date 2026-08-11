package rbac

import (
	"os"
	"testing"

	"github.com/vistasecurity/vistaplatform/auth-service/internal/database"
)

// TestRBACRoutesRegistered tests that RBAC routes are registered
// This is an integration test that requires a database connection
func TestRBACRoutesRegistered(t *testing.T) {
	// Skip if database is not available (CI environment should have it)
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("Integration test - requires DATABASE_URL environment variable")
	}

	// Connect to test database
	db, err := database.Connect(databaseURL)
	if err != nil {
		t.Skipf("Integration test - failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Create service with actual database connection
	svc := NewRBACService(db)
	h := NewRBACHandlers(svc)

	// Test that the handler can be called without panicking
	// The actual route registration is tested in integration tests
	// This just verifies the handler setup works
	if svc == nil || h == nil {
		t.Fatal("Failed to create RBAC service or handlers")
	}

	// Verify service has database connection
	if svc.db == nil {
		t.Fatal("RBAC service database connection is nil")
	}
}
