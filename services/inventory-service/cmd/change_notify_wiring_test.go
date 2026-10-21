package main

import (
	"os"
	"strings"
	"testing"
)

// The change notifier is tested through the real service path in
// internal/services (change_notify_integration_test.go) and the job path in
// internal/jobs (change_notify_unit_integration_test.go); this pins the lines
// in main that make both run in production. gin applies r.Use only to
// routes registered AFTER it, so the middleware must come before the first
// route group — mounted later it would silently cover nothing.
func TestMainMountsTheChangeNotifierBeforeAnyRoute(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	use := strings.Index(src, "r.Use(changeNotifier.Middleware())")
	if use < 0 {
		t.Fatal("main.go no longer mounts changeNotifier.Middleware() on the router")
	}
	for _, route := range []string{`r.GET("/health"`, `r.Group("/api/v1")`, `r.Group("/api/v2")`} {
		if at := strings.Index(src, route); at >= 0 && at < use {
			t.Errorf("%s is registered before the change notifier is mounted — it would not be covered", route)
		}
	}
	if !strings.Contains(src, "changeNotifier.SetPublisher(changenotify.FallbackPublisherFromEnv(natsClient))") {
		t.Error("main.go no longer hands the change notifier its NATS + HTTP publisher — it would raise nothing")
	}
	// The background workers open their units under the job context; without
	// this line changenotify.Unit finds no notifier and every change a job
	// records raises nothing.
	jobs := strings.Index(src, "ctx = changenotify.WithNotifier(ctx, changeNotifier)")
	if jobs < 0 {
		t.Fatal("main.go no longer puts the change notifier on the background workers' context")
	}
	for _, worker := range []string{"go jobs.StartCableResolverWorker(ctx,", "go jobs.StartIdentityEvidenceWorker(ctx,",
		"go jobs.StartIdentityEnrichmentWorker(ctx,", "services.StartRuleMergeExecutor(ctx,"} {
		if at := strings.Index(src, worker); at < 0 || at < jobs {
			t.Errorf("%s is not started under the notifier-carrying context", worker)
		}
	}
}
