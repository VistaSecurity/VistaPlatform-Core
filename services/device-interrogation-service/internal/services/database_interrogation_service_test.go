package services

import (
	"testing"
)

func TestCalculateRiskScore_SSLDisabled(t *testing.T) {
	svc := &DatabaseInterrogationService{}

	finding := &DatabaseEncryptionFinding{
		Engine:     "postgresql",
		SSLEnabled: false,
	}

	score := svc.calculateRiskScore(finding)
	// Baseline 50 + SSLDisabled 30 + NoAtRest 10 = 90
	if score < 80 {
		t.Errorf("expected high risk score for SSL disabled, got %d", score)
	}
}

func TestCalculateRiskScore_WeakPassword(t *testing.T) {
	svc := &DatabaseInterrogationService{}

	finding := &DatabaseEncryptionFinding{
		Engine:                   "postgresql",
		SSLEnabled:               true,
		SSLEnforced:              true,
		EncryptionAtRestEnabled:  true,
		PasswordEncryptionMethod: "md5",
	}

	score := svc.calculateRiskScore(finding)
	// Baseline 50 + md5 password 20 = 70
	if score < 60 {
		t.Errorf("expected elevated risk for MD5 passwords, got %d", score)
	}
}

func TestCalculateRiskScore_FullySecure(t *testing.T) {
	svc := &DatabaseInterrogationService{}

	finding := &DatabaseEncryptionFinding{
		Engine:                   "postgresql",
		SSLEnabled:               true,
		SSLEnforced:              true,
		SSLVersion:               "TLSv1.3",
		EncryptionAtRestEnabled:  true,
		PasswordEncryptionMethod: "scram-sha-256",
	}

	score := svc.calculateRiskScore(finding)
	// Baseline 50, nothing adds to it
	if score != 50 {
		t.Errorf("expected baseline risk for fully secure DB, got %d", score)
	}
}

func TestCalculateRiskScore_WeakTLS(t *testing.T) {
	svc := &DatabaseInterrogationService{}

	finding := &DatabaseEncryptionFinding{
		Engine:                  "mysql",
		SSLEnabled:              true,
		SSLEnforced:             false,
		SSLVersion:              "TLSv1.0,TLSv1.1,TLSv1.2",
		EncryptionAtRestEnabled: true,
	}

	score := svc.calculateRiskScore(finding)
	// Baseline 50 + not enforced 10 + weak TLS 15 = 75
	if score < 70 {
		t.Errorf("expected elevated risk for weak TLS, got %d", score)
	}
}

func TestCalculateRiskScore_CappedAt100(t *testing.T) {
	svc := &DatabaseInterrogationService{}

	finding := &DatabaseEncryptionFinding{
		Engine:                   "postgresql",
		SSLEnabled:               false,
		SSLVersion:               "TLSv1.0",
		PasswordEncryptionMethod: "md5",
	}

	score := svc.calculateRiskScore(finding)
	if score > 100 {
		t.Errorf("risk score should be capped at 100, got %d", score)
	}
}
