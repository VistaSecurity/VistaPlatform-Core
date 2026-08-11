package services

import (
	"testing"

	gcpclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/gcp"
)

func TestEngineFromDatabaseVersion(t *testing.T) {
	cases := map[string]string{
		"POSTGRES_14":             "postgres",
		"MYSQL_8_0":               "mysql",
		"SQLSERVER_2019_STANDARD": "sqlserver",
		"":                        "",
	}
	for in, want := range cases {
		if got := engineFromDatabaseVersion(in); got != want {
			t.Errorf("engineFromDatabaseVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGCPSQLInstanceToFinding(t *testing.T) {
	// Google-managed.
	gm := gcpSQLInstanceToFinding(gcpclient.SQLInstance{
		Name:            "pg-prod",
		DatabaseVersion: "POSTGRES_14",
		Region:          "us-east1",
	})
	if !gm.Encrypted || gm.Algorithm != "AES-256" || gm.EncryptionType != "google-managed" {
		t.Errorf("google-managed finding = %+v", gm)
	}
	if gm.AdditionalDetail["engine"] != "postgres" {
		t.Errorf("engine = %v, want postgres", gm.AdditionalDetail["engine"])
	}

	// CMEK.
	kek := "projects/p/locations/us-east1/keyRings/kr/cryptoKeys/sql-key"
	cmek := gcpSQLInstanceToFinding(gcpclient.SQLInstance{
		Name:                        "sql-secure",
		DatabaseVersion:             "MYSQL_8_0",
		DiskEncryptionConfiguration: &gcpclient.SQLDiskEncryptionConfig{KmsKeyName: kek},
	})
	if cmek.EncryptionType != "cmek" || cmek.KMSKeyID != kek {
		t.Errorf("cmek finding = %+v", cmek)
	}
}
