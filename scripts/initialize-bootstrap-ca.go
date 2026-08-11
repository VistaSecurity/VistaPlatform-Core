package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"

	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

func main() {
	var (
		dbURL        = flag.String("db-url", "", "Database connection URL")
		encryptionKey = flag.String("encryption-key", "", "Encryption master key")
		action       = flag.String("action", "create-ca", "Action: create-ca, create-cert, validate-cert")
		serviceName  = flag.String("service-name", "", "Service name for certificate generation")
		certPEM      = flag.String("cert-pem", "", "Certificate PEM for validation")
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

	if err := db.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to ping database: %v\n", err)
		os.Exit(1)
	}

	switch *action {
	case "create-ca":
		caManager := certificates.NewBootstrapCAManager(db)
		ca, err := caManager.GetOrCreateActiveCA(*encryptionKey)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to create/bootstrap CA: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Bootstrap CA created/retrieved successfully\n")
		fmt.Printf("CA ID: %s\n", ca.ID.String())
		fmt.Printf("CA Cert (first 100 chars): %s...\n", ca.CACertPEM[:100])

	case "create-cert":
		if *serviceName == "" {
			fmt.Fprintf(os.Stderr, "Error: -service-name is required for create-cert\n")
			os.Exit(1)
		}
		certService := certificates.NewBootstrapCertificateService(db, *encryptionKey)
		certPEM, keyPEM, err := certService.IssueBootstrapCertificate(*serviceName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to create certificate: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Bootstrap certificate created successfully for %s\n", *serviceName)
		fmt.Printf("Certificate PEM:\n%s\n", certPEM)
		fmt.Printf("Private Key PEM:\n%s\n", keyPEM)

	case "validate-cert":
		if *certPEM == "" {
			fmt.Fprintf(os.Stderr, "Error: -cert-pem is required for validate-cert\n")
			os.Exit(1)
		}
		certService := certificates.NewBootstrapCertificateService(db, *encryptionKey)
		err := certService.ValidateBootstrapCertificate(*certPEM)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Certificate validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Certificate validation successful\n")

	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown action: %s\n", *action)
		fmt.Fprintf(os.Stderr, "Valid actions: create-ca, create-cert, validate-cert\n")
		os.Exit(1)
	}
}
