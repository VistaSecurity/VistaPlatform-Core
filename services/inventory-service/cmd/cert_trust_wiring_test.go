package main

import (
	"os"
	"strings"
	"testing"
)

// The reconcile publish is tested against a fake publisher in certtrust; this
// pins that main hands the store the real one. Without the line every trust
// decision is recorded and compliance-engine never hears of it until the
// nightly reconcile.
func TestMainWiresTheTrustReconcilePublisher(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if want := "trustStore.SetReconcilePublisher(eventPublisher)"; !strings.Contains(string(src), want) {
		t.Errorf("main.go no longer contains %q", want)
	}
}
