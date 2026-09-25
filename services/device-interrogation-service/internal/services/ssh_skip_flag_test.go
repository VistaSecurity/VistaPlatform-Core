package services

import (
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/agentcreds"
)

// The TLS skip flag must never reach an SSH-managed device's credentials,
// whichever runtime interrogates it ( review B1/NB-7). The shared Cisco
// collector passes that flag to sshtrust, where it disables known_hosts
// verification; a Cisco device stored with it set — before the form stopped
// offering it, or carried over from another device type — would otherwise keep
// skipping host-key checks on every interrogation.

func TestEffectiveInsecureSkipVerify(t *testing.T) {
	for _, tc := range []struct {
		deviceType string
		stored     bool
		want       bool
	}{
		{"cisco", true, false},
		{"cisco_router", true, false},
		{"cisco_switch", true, false},
		{"cisco_asa", true, false},
		{"f5", true, true},
		{"fortinet", true, true},
		{"unifi", false, false},
	} {
		if got := EffectiveInsecureSkipVerify(tc.deviceType, tc.stored); got != tc.want {
			t.Errorf("EffectiveInsecureSkipVerify(%q, %v) = %v, want %v", tc.deviceType, tc.stored, got, tc.want)
		}
	}
}

// In-cluster path: the credentials the platform worker hands the collector.
func TestInterrogationCredentials_SSHDeviceNeverSkips(t *testing.T) {
	if interrogationCredentials("cisco", "admin", "pw", true).InsecureSkipVerify {
		t.Fatal("a Cisco device's stored skip flag reached the collector")
	}
	if !interrogationCredentials("f5", "admin", "pw", true).InsecureSkipVerify {
		t.Fatal("an F5 device's explicit TLS opt-in was dropped")
	}
}

// Agent path: what the agent opens from the sealed envelope.
func TestSealCredentialsForAgent_SSHDeviceNeverSkips(t *testing.T) {
	v := agentcreds.ContractVector
	for deviceType, want := range map[string]bool{"cisco": false, "f5": true} {
		stored := map[string]interface{}{
			"username":             "admin",
			"password":             mustEncrypt(t, testMasterKey, "pw"),
			"device_type":          deviceType,
			"insecure_skip_verify": true,
			"encrypted":            true,
		}
		sealed, err := SealCredentialsForAgent(stored, v.JobID, v.Secret, testMasterKey)
		if err != nil {
			t.Fatalf("%s: seal: %v", deviceType, err)
		}
		got, err := agentcreds.Open(sealed, v.JobID, v.Secret)
		if err != nil {
			t.Fatalf("%s: open: %v", deviceType, err)
		}
		if got["insecure_skip_verify"] != want {
			t.Errorf("%s: agent receives insecure_skip_verify = %v, want %v", deviceType, got["insecure_skip_verify"], want)
		}
	}
}

// Storage: create and edit store an explicit false for an SSH type, including
// when an edit did not mention the flag (that is what clears a stored true).
func TestSSHSafeSkipFlag(t *testing.T) {
	on := true
	if got := sshSafeSkipFlag("cisco", &on); got == nil || *got {
		t.Fatalf("cisco with true -> %v, want false", got)
	}
	if got := sshSafeSkipFlag("cisco_asa", nil); got == nil || *got {
		t.Fatalf("cisco_asa with nil -> %v, want an explicit false", got)
	}
	if got := sshSafeSkipFlag("f5", &on); got != &on {
		t.Fatalf("f5 -> %v, want the request's own value", got)
	}
	if got := sshSafeSkipFlag("f5", nil); got != nil {
		t.Fatalf("f5 with nil -> %v, want nil (unchanged)", got)
	}
}
