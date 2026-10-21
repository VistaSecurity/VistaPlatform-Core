package main

import (
	"os"
	"strings"
	"testing"
)

// The intake route is contract-tested through RegisterInternalAlertIntake
// (internal/handlers); this pins the line in main that mounts it with the
// real engine and the service secret, on the /api/v1 group (its own group, so
// the JWT gate on the compliance group never applies to it). Without it the change notifier's HTTP fallback
// posts to a 404 and every notification raised while NATS is down is lost.
func TestMainMountsTheInternalAlertIntake(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if !strings.Contains(src, `handlers.RegisterInternalAlertIntake(api, os.Getenv("INTERNAL_AUTH_SECRET"), alertEngine)`) {
		t.Fatal("main.go no longer mounts the internal alert intake")
	}
}
