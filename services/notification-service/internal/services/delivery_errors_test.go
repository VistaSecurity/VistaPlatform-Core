package services

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/network"
)

func TestIsPermanentDeliveryFailure_Classification(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not a failure", nil, false},
		{"plain error defaults to transient", errors.New("connection reset"), false},
		{"permanent marker", permanentf("webhook url not configured"), true},
		{"permanent survives wrapping", fmt.Errorf("send: %w", permanentf("unsupported channel type: carrier-pigeon")), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsPermanentDeliveryFailure(tc.err); got != tc.want {
				t.Errorf("IsPermanentDeliveryFailure(%v) = %t, want %t", tc.err, got, tc.want)
			}
		})
	}
}

// The unknown-error default must be TRANSIENT. A default of "permanent" would
// silently discard every failure mode nobody enumerated — the drop-by-default
// shape this whole change exists to remove.
func TestIsPermanentDeliveryFailure_DefaultsToTransient(t *testing.T) {
	if IsPermanentDeliveryFailure(errors.New("i/o timeout")) {
		t.Fatal("an unrecognized error was classified permanent; unknown failures must be retried, not dropped")
	}
}

func TestStatusIsPermanent(t *testing.T) {
	cases := map[int]bool{
		200: false, // not a failure at all
		400: true, 401: true, 403: true, 404: true, 422: true,
		408: false, // request timeout — ask again
		425: false, // too early
		429: false, // rate limited — the canonical retryable 4xx
		500: false, 502: false, 503: false, 504: false,
	}
	for status, want := range cases {
		if got := statusIsPermanent(status); got != want {
			t.Errorf("statusIsPermanent(%d) = %t, want %t", status, got, want)
		}
	}
}

// A DNS resolution failure must NOT be treated the same as an SSRF policy
// rejection: the first may clear on its own, the second never will.
func TestClassifyURLRejection_SeparatesDNSFromPolicy(t *testing.T) {
	dns := fmt.Errorf("%w: no such host", network.ErrUnresolvableHost)
	if IsPermanentDeliveryFailure(classifyURLRejection("webhook URL rejected: %w", dns)) {
		t.Error("an unresolvable host was classified permanent — a DNS blip would permanently discard the tenant's webhook deliveries")
	}

	policy := errors.New("URL resolves to a private/internal IP address")
	if !IsPermanentDeliveryFailure(classifyURLRejection("webhook URL rejected: %w", policy)) {
		t.Error("an SSRF policy rejection was classified transient — retrying it can never succeed")
	}
}

func TestRetryBackoff_ExponentialAndCapped(t *testing.T) {
	want := []time.Duration{
		1 * time.Minute,  // attempt 1
		2 * time.Minute,  // attempt 2
		4 * time.Minute,  // attempt 3
		8 * time.Minute,  // attempt 4
		16 * time.Minute, // attempt 5
	}
	for i, w := range want {
		if got := retryBackoff(i + 1); got != w {
			t.Errorf("retryBackoff(%d) = %v, want %v", i+1, got, w)
		}
	}
	// Monotonic, and capped rather than overflowing into a negative or absurd
	// delay for a large configured attempt count.
	prev := time.Duration(0)
	for n := 1; n <= 64; n++ {
		d := retryBackoff(n)
		if d < prev {
			t.Fatalf("retryBackoff(%d) = %v went backwards from %v", n, d, prev)
		}
		if d > retryMaxDelay {
			t.Fatalf("retryBackoff(%d) = %v exceeds the %v cap", n, d, retryMaxDelay)
		}
		prev = d
	}
	if retryBackoff(64) != retryMaxDelay {
		t.Errorf("retryBackoff saturates at %v, want the %v cap", retryBackoff(64), retryMaxDelay)
	}
}

func TestDeliveryRetryEnabled_KillSwitch(t *testing.T) {
	t.Setenv("NOTIFICATION_DELIVERY_RETRY_ENABLED", "")
	if !DeliveryRetryEnabled() {
		t.Error("retry must default ON when the variable is unset")
	}
	t.Setenv("NOTIFICATION_DELIVERY_RETRY_ENABLED", "true")
	if !DeliveryRetryEnabled() {
		t.Error(`"true" must enable retry`)
	}
	t.Setenv("NOTIFICATION_DELIVERY_RETRY_ENABLED", "false")
	if DeliveryRetryEnabled() {
		t.Error(`"false" must disable retry — the operator kill-switch`)
	}
}

func TestMaxDeliveryAttempts_RejectsUnusableValues(t *testing.T) {
	t.Setenv("NOTIFICATION_DELIVERY_MAX_ATTEMPTS", "")
	if got := MaxDeliveryAttempts(); got != defaultMaxDeliveryAttempts {
		t.Errorf("unset → %d, want the %d default", got, defaultMaxDeliveryAttempts)
	}
	t.Setenv("NOTIFICATION_DELIVERY_MAX_ATTEMPTS", "3")
	if got := MaxDeliveryAttempts(); got != 3 {
		t.Errorf("explicit 3 → %d", got)
	}
	// A bound of 0 would mean "enqueue, then give up before trying" — strictly
	// worse than not enqueueing. Reject it rather than honoring it.
	for _, bad := range []string{"0", "-1", "banana"} {
		t.Setenv("NOTIFICATION_DELIVERY_MAX_ATTEMPTS", bad)
		if got := MaxDeliveryAttempts(); got != defaultMaxDeliveryAttempts {
			t.Errorf("%q → %d, want the %d default", bad, got, defaultMaxDeliveryAttempts)
		}
	}
}
