package integrations

import (
	"errors"
	"strings"
	"testing"
)

// The four retired types are refused, each with a message that names where the
// job is done now. The cloud types (and the other live keys) are not touched.
func TestValidateIntegrationType(t *testing.T) {
	retired := map[string]string{
		"slack":     "Settings → Integrations (tenant console) or Settings → Notification Delivery (admin console)",
		"pagerduty": "Settings → Integrations (tenant console) or Settings → Notification Delivery (admin console)",
		"datadog":   "SIEM Export",
		"splunk":    "SIEM Export",
	}
	for typ, pointer := range retired {
		err := ValidateIntegrationType(typ)
		var unsupported *UnsupportedTypeError
		if !errors.As(err, &unsupported) {
			t.Fatalf("%s: want *UnsupportedTypeError, got %v", typ, err)
		}
		if unsupported.Type != typ {
			t.Errorf("%s: error carries type %q", typ, unsupported.Type)
		}
		if !strings.Contains(err.Error(), pointer) {
			t.Errorf("%s: message %q does not point at %q", typ, err.Error(), pointer)
		}
	}

	for _, typ := range []string{"aws", "azure", "gcp", "custom", "github", "gitlab", "bitbucket", "hashicorp_vault", ""} {
		if err := ValidateIntegrationType(typ); err != nil {
			t.Errorf("%q must stay accepted, got %v", typ, err)
		}
	}
}
