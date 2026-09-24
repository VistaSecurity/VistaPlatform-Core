// Package main provides the entry point for the SaaS Admin Service.
// This service handles platform-level administration including tenant management,
// platform user management, and system-wide statistics and monitoring.
//
// Architecture:
// - RESTful API with JWT authentication
// - Platform-level RBAC (Role-Based Access Control)
// - Multi-tenant data access with proper isolation
// - Comprehensive tenant and user management
//
// Key Features:
// - Tenant CRUD operations (create, read, update, delete, suspend, activate)
// - Platform user management (create, update, delete platform administrators)
// - Platform statistics and monitoring
// - System health checks and logging
//
// Security:
// - JWT-based authentication with platform admin roles
// - Permission-based authorization (platform_user_has_permission over platform_role_permissions)
// - Input validation and sanitization
// - CORS protection and rate limiting
package main

import (
	"log"
	"os"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/api"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/database"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
)

// main initializes and starts the SaaS Admin Service.
// It loads configuration, establishes database connection, and starts the HTTP server.
func main() {
	// Load configuration from environment variables with sensible defaults
	cfg := config.Load()

	// Initialize database connection with connection pooling
	// This connects to the shared PostgreSQL database used by all services
	db, err := database.NewConnection(cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() { _ = db.Close() }()

	bypassDB, err := shareddatabase.ConnectBypass()
	if err != nil {
		log.Fatalf("Failed to open bypass database connection: %v", err)
	}
	defer func() { _ = bypassDB.Close() }()

	// Enterprise builds verify the entitlement token and record the install's
	// licence here, once the pool is up and before serving. Nil in Core — an
	// open-source build has no token concept, so there is nothing to check and
	// nothing to fail, and with no platform_license row every service resolves
	// the install as Core. Never fatal: see ee/edition.Apply. A Core build
	// that finds a token configured logs that it is ignoring it
	// (edition_token.go).
	applyEdition(hooks, bypassDB, os.Getenv, os.ReadFile, log.Printf)

	// Initialize the HTTP server with all routes and middleware.
	// `hooks` is the edition seam (see edition.go): zero in a Core build,
	// populated by cmd/edition_ee.go under `-tags ee`.
	server := api.NewServerWithConnections(cfg, db, bypassDB, hooks)

	// Start the server and listen for incoming requests
	log.Printf("🚀 SaaS Admin Service (%s edition) starting on port %s", edition(), cfg.Port)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
