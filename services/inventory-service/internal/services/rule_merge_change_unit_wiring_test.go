package services

import (
	"os"
	"strings"
	"testing"
)

// The same-device merge executor moves interfaces and addresses through the
// identity repository; each tenant's batch runs inside a changenotify.Unit so
// those changes raise object_changed. Pinned here: the executor's own
// integration tests need a stamped verdict pipeline, not a notifier.
func TestRuleMergeExecutorOpensAChangeUnitPerTenant(t *testing.T) {
	raw, err := os.ReadFile("rule_merge_executor.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	at := strings.Index(src, "n, seen, err = x.ExecuteTenant(ctx, tenant, limit)")
	open := strings.LastIndex(src[:max(at, 0)], "changenotify.Unit(ctx, func(ctx context.Context) error {")
	if at < 0 || open < 0 || at-open > 120 {
		t.Fatal("RunOnce no longer executes each tenant's batch inside a changenotify.Unit")
	}
}
