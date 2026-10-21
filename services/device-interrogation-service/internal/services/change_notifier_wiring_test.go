package services

import (
	"os"
	"strings"
	"testing"
)

// The three entry points that write sites, locations and clusters each open a
// change-notification unit; a refactor that drops one leaves that path's
// changes raising nothing, with every test of the writes still green. The
// unit's behaviour is tested in change_notifier_integration_test.go.
func TestCloudRunEntryPointsOpenAChangeUnit(t *testing.T) {
	for file, entries := range map[string][]string{
		"cloud_enumeration.go": {
			"out, err = s.discoverResourceEvidence(ctx,",
			"out, err = s.discoverResources(ctx,",
		},
		"retained_cloud.go": {
			"return s.replayRetainedCloudContext(ctx, tenant) })",
		},
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		src := string(raw)
		for _, e := range entries {
			at := strings.Index(src, e)
			if at < 0 {
				t.Errorf("%s: %q is gone", file, e)
				continue
			}
			// The call must sit inside a ChangeUnit closure opened just above it.
			if open := strings.LastIndex(src[:at], "ChangeUnit(ctx, func(ctx context.Context) error {"); open < 0 || at-open > 200 {
				t.Errorf("%s: %q is not inside a ChangeUnit", file, e)
			}
		}
	}
}
