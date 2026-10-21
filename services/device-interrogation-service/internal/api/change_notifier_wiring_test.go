package api

import (
	"os"
	"strings"
	"testing"
)

// gin applies router.Use only to routes registered after it: the change
// notifier's middleware must come before the first route, or the
// integration writes that sync cloud accounts (sites, locations) raise
// nothing.
func TestSetupRouterMountsTheChangeNotifierBeforeAnyRoute(t *testing.T) {
	raw, err := os.ReadFile("router.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	use := strings.Index(src, "router.Use(services.ChangeNotifier().Middleware())")
	if use < 0 {
		t.Fatal("SetupRouter no longer mounts the change notifier's middleware")
	}
	if at := strings.Index(src, `router.GET("/health"`); at >= 0 && at < use {
		t.Error("a route is registered before the change notifier is mounted — it would not be covered")
	}
	if at := strings.Index(src, `router.Group("/api")`); at >= 0 && at < use {
		t.Error("the /api group is created before the change notifier is mounted")
	}
}
