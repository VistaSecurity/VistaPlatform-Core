package processor

import (
	"errors"
	"fmt"
	"testing"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
)

// isPermanentError decides whether a batch-processing failure should be retried
// or treated as terminal. Getting "no valid findings to import" wrong is what
// wedged discovery-processor into an infinite poll loop in production (a
// cloud-API discovery with no source IP produced an empty, never-importable
// batch). Getting the OTHER direction wrong is worse: the classifier used to
// substring-match "400"/"invalid"/"validation" in the error text, so retryable
// failures whose message merely contained those substrings were terminally
// rejected and their discoveries permanently discarded. These cases pin both
// directions.
func TestIsPermanentError(t *testing.T) {
	status := func(code int) error {
		return &client.HTTPStatusError{StatusCode: code, Op: "inventory-service import-findings", Body: "body"}
	}

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not permanent", nil, false},
		{
			"empty/unimportable batch is permanent",
			fmt.Errorf("%w for batch 1a29f66d-bb44-436f-9d2a-5989e45264f4", ErrNoValidFindings),
			true,
		},

		// Typed status errors — classified on the code, at any wrap depth.
		{"400 client error is permanent", status(400), true},
		{"401 client error is permanent", status(401), true},
		{"403 client error is permanent", status(403), true},
		{"404 client error is permanent", status(404), true},
		{"422 client error is permanent", status(422), true},
		{"wrapped 400 is permanent", fmt.Errorf("failed to import monitoring findings: %w", status(400)), true},
		{"408 request timeout is transient", status(408), false},
		{"425 too early is transient", status(425), false},
		{"429 rate limited is transient", status(429), false},
		{"500 is transient", status(500), false},
		{"503 is transient", status(503), false},
		{"wrapped 503 is transient", fmt.Errorf("failed to import pending findings: %w", status(503)), false},

		// Statusless errors are transient. The retry budget bounds them; a wrong
		// "permanent" verdict would throw the batch away.
		{"network timeout is transient", errors.New("dial tcp 10.0.0.1:8082: i/o timeout"), false},
		{
			"mTLS rotation failure is transient despite the word 'valid'",
			errors.New("x509: certificate is not valid for any names, but wanted to match inventory-service"),
			false,
		},
		{
			"peer URL containing 400 is transient",
			errors.New("dial tcp 10.0.0.1:8400: connect: connection refused"),
			false,
		},
		{
			"free-text 'invalid' is transient",
			errors.New("failed to send request: invalid connection state, retrying"),
			false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPermanentError(tc.err); got != tc.want {
				t.Fatalf("isPermanentError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
