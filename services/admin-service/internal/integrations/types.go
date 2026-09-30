package integrations

import "fmt"

// UnsupportedTypeError reports that an integration_type is one the platform
// accepts in the database but never acts on.
//
// slack, pagerduty, datadog and splunk rows in platform_integrations were
// dispatched by nothing: alerts are delivered by notification-service from the
// tenant/platform notification channels, and SIEM forwarding is configured on
// the SIEM export page (Security & Trust → SIEM Export, an Enterprise
// capability). The old "test" only checked that a credential field was
// non-empty and reported success, so a row of one of these types looked healthy
// while doing nothing. They are rejected here instead.
//
// The platform_integrations CHECK constraint still lists the keys — that is the
// connector registry's contract, not this package's.
type UnsupportedTypeError struct {
	Type    string
	Message string
}

func (e *UnsupportedTypeError) Error() string { return e.Message }

// retiredTypes maps each retired integration_type to the place its job is done.
var retiredTypes = map[string]string{
	"slack":     "Slack alerts are delivered through notification channels: configure one under Settings → Integrations (tenant console) or Settings → Notification Delivery (admin console)",
	"pagerduty": "PagerDuty alerts are delivered through notification channels: configure one under Settings → Integrations (tenant console) or Settings → Notification Delivery (admin console)",
	"datadog":   "Datadog audit forwarding is configured on the SIEM export page (Security & Trust → SIEM Export)",
	"splunk":    "Splunk audit forwarding is configured on the SIEM export page (Security & Trust → SIEM Export)",
}

// ValidateIntegrationType returns an *UnsupportedTypeError for a type that no
// code acts on, and nil for everything else.
func ValidateIntegrationType(t string) error {
	if where, retired := retiredTypes[t]; retired {
		return &UnsupportedTypeError{
			Type:    t,
			Message: fmt.Sprintf("integration type %q is not supported by platform integrations. %s.", t, where),
		}
	}
	return nil
}
