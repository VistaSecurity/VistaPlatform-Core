package services

// Failure classification for channel delivery.
//
// A retry loop that hammers a permanently-broken channel four more times is
// noise; one that gives up on a transient blip loses the notification. The two
// need distinguishing, and the honest answer is that we can only distinguish
// them SOMETIMES:
//
//   - Provably permanent, because retrying the identical request against the
//     identical config cannot succeed: the channel type is unsupported, a
//     required config key (webhook_url / url / integration_key / recipients) is
//     missing or malformed, the URL fails SSRF/format validation, or the remote
//     answered with a 4xx that is not a rate-limit/timeout.
//   - Everything else is treated as transient and retried. That includes SMTP
//     auth failures and DNS resolution errors, which are *often* permanent but
//     are indistinguishable at this layer from a broker restart or a DNS blip.
//     Retrying a genuinely permanent failure a bounded number of times is the
//     cheaper mistake; both outcomes end in the same durable terminal record.
//
// Classification is carried by a typed error rather than by string-matching the
// message, so a reworded fmt.Errorf cannot silently reclassify a failure.

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/vistasecurity/vistaplatform/shared/network"
)

// PermanentDeliveryError marks a channel send failure that retrying cannot fix.
type PermanentDeliveryError struct {
	Err error
}

func (e *PermanentDeliveryError) Error() string { return e.Err.Error() }
func (e *PermanentDeliveryError) Unwrap() error { return e.Err }

// permanentf builds a permanent (do-not-retry) delivery failure.
func permanentf(format string, a ...interface{}) error {
	return &PermanentDeliveryError{Err: fmt.Errorf(format, a...)}
}

// IsPermanentDeliveryFailure reports whether err is a failure that retrying
// cannot fix. Anything unrecognized is transient — the safe default is to retry
// a bounded number of times, not to drop.
func IsPermanentDeliveryFailure(err error) bool {
	if err == nil {
		return false
	}
	var perm *PermanentDeliveryError
	return errors.As(err, &perm)
}

// statusIsPermanent classifies an HTTP response status from a remote channel
// endpoint. 4xx means the request itself is wrong and will stay wrong —
// EXCEPT the three that explicitly mean "ask again later". 5xx is the remote's
// problem and is retried.
func statusIsPermanent(status int) bool {
	switch status {
	case http.StatusRequestTimeout, // 408
		http.StatusTooEarly,        // 425
		http.StatusTooManyRequests: // 429
		return false
	}
	return status >= 400 && status < 500
}

// classifyURLRejection classifies a network.ValidateWebhookURL failure. The
// validator returns both policy verdicts (bad scheme, private/internal address —
// properties of the URL, permanently true) and resolution failures (a DNS blip,
// which is not). Collapsing the two would let a transient resolver outage
// permanently discard a tenant's webhook deliveries.
func classifyURLRejection(format string, err error) error {
	if errors.Is(err, network.ErrUnresolvableHost) {
		return fmt.Errorf(format, err)
	}
	return permanentf(format, err)
}

// classifyHTTPStatus wraps a remote-endpoint error as permanent or transient
// according to the response status.
func classifyHTTPStatus(status int, format string, a ...interface{}) error {
	if statusIsPermanent(status) {
		return permanentf(format, a...)
	}
	return fmt.Errorf(format, a...)
}
