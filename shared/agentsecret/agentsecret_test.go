package agentsecret

import (
	"errors"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

const masterKey = "0123456789abcdef0123456789abcdef"

func cipher(t *testing.T, key string) *credentials.Cipher {
	t.Helper()
	c, err := credentials.NewCipher("agent secret test", key, credentials.Policy{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestIssueUnwrapRoundTrip(t *testing.T) {
	c := cipher(t, masterKey)
	secret, wrapped, err := Issue(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(wrapped, secret) {
		t.Fatal("the at-rest form contains the plaintext secret")
	}
	got, err := Unwrap(c, wrapped)
	if err != nil || got != secret {
		t.Fatalf("Unwrap = %q, %v; want %q", got, err, secret)
	}
	if _, err := Unwrap(cipher(t, "another-master-key-another-master"), wrapped); err == nil {
		t.Fatal("unwrapped under the wrong master key")
	}
}

func TestDisabledCipherIssuesNothing(t *testing.T) {
	t.Setenv("ENV", "development")
	c := cipher(t, "")
	if _, _, err := Issue(c); !errors.Is(err, ErrNoMasterKey) {
		t.Fatalf("Issue without a key = %v, want ErrNoMasterKey", err)
	}
	if _, err := Unwrap(c, "x"); !errors.Is(err, ErrNoMasterKey) {
		t.Fatalf("Unwrap without a key = %v, want ErrNoMasterKey", err)
	}
}

// A stored value that is not in wrapped form must not be taken as the secret.
func TestUnwrapRefusesAnUnwrappedValue(t *testing.T) {
	if _, err := Unwrap(cipher(t, masterKey), "plain-looking-secret"); !errors.Is(err, ErrNotWrapped) {
		t.Fatalf("Unwrap(unwrapped) = %v, want ErrNotWrapped", err)
	}
}
