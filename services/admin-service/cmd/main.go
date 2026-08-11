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
// - Role-based authorization (super_admin, platform_admin, support_admin)
// - Input validation and sanitization
// - CORS protection and rate limiting
package main

import (
	"log"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/api"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/admin-service/internal/database"
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

	// Enterprise builds verify the entitlement token and seed its grants here,
	// once the pool is up and before serving. Nil in Core — an open-source
	// build has no token concept, so there is nothing to check and nothing to
	// fail. Never fatal: see ee/edition.Apply.
	if hooks.ApplyEditionToken != nil {
		hooks.ApplyEditionToken(db)
	}

	// Initialize the HTTP server with all routes and middleware.
	// `hooks` is the edition seam (see edition.go): zero in a Core build,
	// populated by cmd/edition_ee.go under `-tags ee`.
	server := api.NewServerWithEdition(cfg, db, hooks)

	// Start the server and listen for incoming requests
	log.Printf("🚀 SaaS Admin Service (%s edition) starting on port %s", edition(), cfg.Port)
	if err := server.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
