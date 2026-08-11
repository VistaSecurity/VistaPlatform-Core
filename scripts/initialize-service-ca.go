package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

func main() {
	var (
		dbURL        = flag.String("db-url", "", "Database connection URL")
		encryptionKey = flag.String("encryption-key", "", "Encryption master key")
		action       = flag.String("action", "create-ca", "Action: create-ca, create-cert, validate-cert")
		serviceName  = flag.String("service-name", "", "Service name for certificate generation")
	)
	flag.Parse()

	if *dbURL == "" {
		fmt.Fprintf(os.Stderr, "Error: -db-url is required\n")
		os.Exit(1)
	}

	if *encryptionKey == "" {
		fmt.Fprintf(os.Stderr, "Error: -encryption-key is required\n")
		os.Exit(1)
	}

	// Connect to database
	db, err := sql.Open("postgres", *dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to connect to database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	// Ping with retry — Postgres can be momentarily busy after heavy schema
	// application (autovacuum, checkpoints) even though the healthcheck passed.
	// Retry up to 6 times with a 5-second wait between attempts (30s total).
	const maxPingAttempts = 6
	const pingRetryDelay = 5 * time.Second
	var pingErr error
	for attempt := 1; attempt <= maxPingAttempts; attempt++ {
		pingErr = db.Ping()
		if pingErr == nil {
			break
		}
		if attempt < maxPingAttempts {
			fmt.Fprintf(os.Stderr, "Warning: Database ping attempt %d/%d failed (%v) — retrying in %v...\n",
				attempt, maxPingAttempts, pingErr, pingRetryDelay)
			time.Sleep(pingRetryDelay)
		}
	}
	if pingErr != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to ping database after %d attempts: %v\n", maxPingAttempts, pingErr)
		os.Exit(1)
	}

	switch *action {
	case "create-ca":
		caManager := certificates.NewServiceCAManager(db)
		ca, err := caManager.GetOrCreateActiveCA(*encryptionKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to create/get service CA: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Service CA created/retrieved successfully\n")
		fmt.Printf("CA ID: %s\n", ca.ID)
		fmt.Printf("CA expires at: %s\n", ca.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("CA Certificate:\n%s\n", ca.CACertPEM)

	case "create-cert":
		if *serviceName == "" {
			fmt.Fprintf(os.Stderr, "Error: -service-name is required for create-cert action\n")
			os.Exit(1)
		}
		certService := certificates.NewServiceCertificateService(db, *encryptionKey)
		certs, err := certService.IssueServiceCertificates(*serviceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to create service certificates: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Service certificates created successfully for %s\n", *serviceName)
		fmt.Printf("Serial Number: %s\n", certs.SerialNumber)
		fmt.Printf("Expires at: %s\n", certs.ExpiresAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("Server Certificate:\n%s\n", certs.ServerCertPEM)
		fmt.Printf("Server Key:\n%s\n", certs.ServerKeyPEM)
		fmt.Printf("Client Certificate:\n%s\n", certs.ClientCertPEM)
		fmt.Printf("Client Key:\n%s\n", certs.ClientKeyPEM)

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown action: %s\n", *action)
		os.Exit(1)
	}
}
