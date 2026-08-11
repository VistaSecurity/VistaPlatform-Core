package main

import (
	"errors"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
)

type fakeCertificateRotator struct {
	expiresAt    time.Time
	expiringSoon bool
	checkErr     error
	rotateErr    error
	checks       int
	rotations    int
}

func (f *fakeCertificateRotator) CheckCertificateExpiration() (time.Time, bool, error) {
	f.checks++
	return f.expiresAt, f.expiringSoon, f.checkErr
}

func (f *fakeCertificateRotator) RotateCertificate() error {
	f.rotations++
	return f.rotateErr
}

func TestCheckAndRotateAgentCertificate_RotatesAndPersistsExpiringCert(t *testing.T) {
	rotator := &fakeCertificateRotator{
		expiresAt:    time.Now().Add(7 * 24 * time.Hour),
		expiringSoon: true,
	}
	cfg := &config.Config{}
	var savedCerts, savedConfig int

	rotated := checkAndRotateAgentCertificate(
		rotator,
		cfg,
		func(got *config.Config) error {
			savedCerts++
			if got != cfg {
				t.Fatalf("saveCerts received unexpected config pointer")
			}
			return nil
		},
		func() error {
			savedConfig++
			return nil
		},
	)

	if !rotated {
		t.Fatal("expected expiring certificate to rotate")
	}
	if rotator.checks != 1 || rotator.rotations != 1 {
		t.Fatalf("checks=%d rotations=%d, want 1/1", rotator.checks, rotator.rotations)
	}
	if savedCerts != 1 || savedConfig != 1 {
		t.Fatalf("savedCerts=%d savedConfig=%d, want 1/1", savedCerts, savedConfig)
	}
}

func TestCheckAndRotateAgentCertificate_SkipsValidCert(t *testing.T) {
	rotator := &fakeCertificateRotator{
		expiresAt: time.Now().Add(90 * 24 * time.Hour),
	}
	var savedCerts, savedConfig int

	rotated := checkAndRotateAgentCertificate(
		rotator,
		&config.Config{},
		func(*config.Config) error {
			savedCerts++
			return nil
		},
		func() error {
			savedConfig++
			return nil
		},
	)

	if rotated {
		t.Fatal("did not expect valid certificate to rotate")
	}
	if rotator.rotations != 0 {
		t.Fatalf("rotations=%d, want 0", rotator.rotations)
	}
	if savedCerts != 0 || savedConfig != 0 {
		t.Fatalf("savedCerts=%d savedConfig=%d, want 0/0", savedCerts, savedConfig)
	}
}

func TestCheckAndRotateAgentCertificate_DoesNotPersistFailedRotation(t *testing.T) {
	rotator := &fakeCertificateRotator{
		expiresAt:    time.Now().Add(7 * 24 * time.Hour),
		expiringSoon: true,
		rotateErr:    errors.New("rotation failed"),
	}
	var savedCerts, savedConfig int

	rotated := checkAndRotateAgentCertificate(
		rotator,
		&config.Config{},
		func(*config.Config) error {
			savedCerts++
			return nil
		},
		func() error {
			savedConfig++
			return nil
		},
	)

	if rotated {
		t.Fatal("did not expect failed rotation to report success")
	}
	if rotator.rotations != 1 {
		t.Fatalf("rotations=%d, want 1", rotator.rotations)
	}
	if savedCerts != 0 || savedConfig != 0 {
		t.Fatalf("savedCerts=%d savedConfig=%d, want 0/0", savedCerts, savedConfig)
	}
}
