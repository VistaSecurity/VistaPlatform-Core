package main

import (
	"os"
	"strings"
	"testing"
)

// This service writes sites, locations and clusters itself (cloud
// enumeration), so it raises object_changed for them itself
// (internal/services/change_notifier.go). The unit and the middleware are
// tested where they live; this pins the lines in main that give them a
// notifier with a publisher, installed before SetupRouter mounts the
// middleware (a later install would leave every request uncovered).
func TestMainInstallsTheChangeNotifier(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	for _, line := range []string{
		"changeNotifier := changenotify.New(db)",
		"changeNotifier.SetPublisher(changenotify.FallbackPublisherFromEnv(queueNATS))",
	} {
		if !strings.Contains(src, line) {
			t.Errorf("main.go no longer has %q", line)
		}
	}
	install := strings.Index(src, "services.SetChangeNotifier(changeNotifier)")
	if install < 0 {
		t.Fatal("main.go no longer installs the change notifier")
	}
	for _, after := range []string{"api.SetupRouter(", "go platformWorker.Start()", "go cloudService.RunRetainedCloudContext("} {
		if at := strings.Index(src, after); at >= 0 && at < install {
			t.Errorf("%s runs before the change notifier is installed", after)
		}
	}
}
