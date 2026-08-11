package discovery

import (
	"errors"
	"testing"
)

func TestSSHProbeShouldFallbackToBanner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		hasSSHConn bool
		want       bool
	}{
		{name: "no error", err: nil, hasSSHConn: false, want: false},
		{
			name:       "handshake failed due to algorithm mismatch",
			err:        errors.New("ssh: handshake failed: ssh: no common algorithm for key exchange"),
			hasSSHConn: false,
			want:       true,
		},
		{
			name:       "auth failure is expected",
			err:        errors.New("ssh: handshake failed: unable to authenticate, attempted methods [none], no supported methods remain"),
			hasSSHConn: false,
			want:       false,
		},
		{
			name:       "auth failure alternate message is expected",
			err:        errors.New("ssh: handshake failed: no supported methods remain"),
			hasSSHConn: false,
			want:       false,
		},
		{
			name:       "connection already established",
			err:        errors.New("ssh: handshake failed: ssh: no common algorithm for key exchange"),
			hasSSHConn: true,
			want:       false,
		},
		{
			name:       "non handshake error does not fallback",
			err:        errors.New("unexpected EOF"),
			hasSSHConn: false,
			want:       false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := sshprobeShouldFallbackToBanner(tt.err, tt.hasSSHConn); got != tt.want {
				t.Fatalf("sshprobeShouldFallbackToBanner() = %v, want %v", got, tt.want)
			}
		})
	}
}
