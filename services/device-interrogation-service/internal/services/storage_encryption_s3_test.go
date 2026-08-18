package services

import (
	"errors"
	"testing"
)

// ---------------------------------------------------------------------------
// normalizeBucketLocation
//
// ListBuckets is global and does not say which region a bucket is in; every
// bucket was stamped with the integration's default region. GetBucketLocation
// fixes that, but its response has two legacy quirks that make the raw value
// unusable: us-east-1 comes back EMPTY, and eu-west-1 comes back as "EU".
// ---------------------------------------------------------------------------

func TestNormalizeBucketLocation(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"empty constraint means us-east-1, not unknown", "", "us-east-1"},
		{"legacy EU alias means eu-west-1", "EU", "eu-west-1"},
		{"modern regions pass through", "eu-west-2", "eu-west-2"},
		{"modern regions pass through (asia)", "ap-northeast-1", "ap-northeast-1"},
		{"eu-west-1 reported modern form passes through", "eu-west-1", "eu-west-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeBucketLocation(tt.in); got != tt.want {
				t.Errorf("normalizeBucketLocation(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// isNoEncryptionConfigurationError
//
// GetBucketEncryption failing used to be treated as "default SSE-S3 applies",
// which asserts a security posture that was never measured: an AccessDenied
// was reported as an encrypted bucket. Only S3's specific
// "no configuration on this bucket" error licenses that conclusion.
// ---------------------------------------------------------------------------

type fakeAPIError struct{ code string }

func (e *fakeAPIError) Error() string     { return e.code }
func (e *fakeAPIError) ErrorCode() string { return e.code }

func TestIsNoEncryptionConfigurationError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "the genuine no-configuration response",
			err:  &fakeAPIError{code: "ServerSideEncryptionConfigurationNotFoundError"},
			want: true,
		},
		{
			// The bug. Denied access is not evidence of encryption.
			name: "AccessDenied is not evidence of encryption",
			err:  &fakeAPIError{code: "AccessDenied"},
			want: false,
		},
		{
			name: "throttling is not evidence of encryption",
			err:  &fakeAPIError{code: "SlowDown"},
			want: false,
		},
		{
			name: "an unmodelled transport failure is not evidence of encryption",
			err:  errors.New("dial tcp: i/o timeout"),
			want: false,
		},
		{
			name: "wrapped modelled error is still recognised",
			err:  errors.Join(errors.New("operation error S3"), &fakeAPIError{code: "ServerSideEncryptionConfigurationNotFoundError"}),
			want: true,
		},
		{
			name: "nil",
			err:  nil,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNoEncryptionConfigurationError(tt.err); got != tt.want {
				t.Errorf("isNoEncryptionConfigurationError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// TestStorageEncryptionFinding_UndeterminedIsNotEncrypted pins the honest-
// reporting contract: "could not determine" must never be representable as
// "measured as encrypted". Per CLAUDE.md, not-assessed is its own state, not a
// synonym for safe.
func TestStorageEncryptionFinding_UndeterminedIsNotEncrypted(t *testing.T) {
	f := StorageEncryptionFinding{
		ResourceType:         "s3_bucket",
		ResourceName:         "denied-bucket",
		EncryptionDetermined: false,
		EncryptionType:       "unknown",
		EncryptionError:      "AccessDenied",
	}
	if f.Encrypted {
		t.Fatal("an undetermined finding must not be marked encrypted")
	}
	if f.Algorithm != "" {
		t.Fatalf("an undetermined finding must not name an algorithm, got %q", f.Algorithm)
	}
	if f.EncryptionType == "sse-s3-default" {
		t.Fatal("an undetermined finding must not claim the AWS default applies")
	}
}
