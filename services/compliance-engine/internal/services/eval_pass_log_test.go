package services

//: an asset-change evaluation that wrote nothing logs ONE line.
//
// A converged tenant re-evaluates assets whose inputs did not move; each such
// pass used to print six lines. These tests drive the REAL handler and read what
// it actually prints. The DB-backed test below it drives the real evaluation.
//
// Mutation that proves them: in handleAssetChanged send the lines straight to
// log.Printf again (or make notePassOutcome a no-op) - the single-line
// assertions go red.

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// capturePassLog returns what the standard logger prints until the test ends.
func capturePassLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return &buf
}

func logLines(buf *bytes.Buffer) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func TestHandleAssetChanged_NoOpEvaluationLogsOneLine(t *testing.T) {
	s, _ := countingSubscriber(t, nil)
	tenant, asset := uuid.New(), uuid.New()

	t.Run("a pass that wrote nothing prints one summary line", func(t *testing.T) {
		s.evaluate = func(ctx context.Context, ev events.AssetChangedEvent) error {
			passLogf(ctx, "[FindingsService] Processing asset changed event: asset=%s", ev.AssetID)
			passLogf(ctx, "[EvalEngine] per-asset tenant=%s", ev.TenantID)
			passLogf(ctx, "[FindingsService] INFO: Completed asset change reconcile: asset_id=%s", ev.AssetID)
			notePassOutcome(ctx, true, "controls=7")
			return nil
		}
		buf := capturePassLog(t)
		if err := s.handleAssetChanged(withTimeout(t), assetChangedMsg(t, tenant, asset)); err != nil {
			t.Fatal(err)
		}
		lines := logLines(buf)
		if len(lines) != 1 {
			t.Fatalf("a no-op evaluation printed %d lines, want 1:\n%s", len(lines), buf.String())
		}
		for _, want := range []string{"nothing written", asset.String(), tenant.String(), "controls=7"} {
			if !strings.Contains(lines[0], want) {
				t.Errorf("the summary line lacks %q: %s", want, lines[0])
			}
		}
	})

	t.Run("a pass that changed something keeps every line", func(t *testing.T) {
		s.evaluate = func(ctx context.Context, ev events.AssetChangedEvent) error {
			passLogf(ctx, "[FindingsService] Processing asset changed event: asset=%s", ev.AssetID)
			passLogf(ctx, "[EvalEngine] per-asset finding writes created=1")
			passLogf(ctx, "[FindingsService] INFO: Completed asset change reconcile: asset_id=%s", ev.AssetID)
			notePassOutcome(ctx, false, "controls=7")
			return nil
		}
		buf := capturePassLog(t)
		if err := s.handleAssetChanged(withTimeout(t), assetChangedMsg(t, tenant, asset)); err != nil {
			t.Fatal(err)
		}
		out := buf.String()
		for _, want := range []string{"Received asset changed", "Processing asset changed", "finding writes created=1", "Completed asset change reconcile", "Processed asset changed"} {
			if !strings.Contains(out, want) {
				t.Errorf("a pass that wrote something must keep %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "nothing written") {
			t.Errorf("a pass that wrote something must not claim it wrote nothing:\n%s", out)
		}
	})

	t.Run("a pass that cannot say stays verbose", func(t *testing.T) {
		s.evaluate = func(ctx context.Context, ev events.AssetChangedEvent) error {
			passLogf(ctx, "[FindingsService] Processing asset changed event: asset=%s", ev.AssetID)
			return nil
		}
		buf := capturePassLog(t)
		if err := s.handleAssetChanged(withTimeout(t), assetChangedMsg(t, tenant, asset)); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(buf.String(), "Received asset changed") || strings.Contains(buf.String(), "nothing written") {
			t.Errorf("an unmeasured pass must keep its detail:\n%s", buf.String())
		}
	})

	t.Run("a failed pass keeps every line even if it claimed no-op", func(t *testing.T) {
		s.evaluate = func(ctx context.Context, ev events.AssetChangedEvent) error {
			notePassOutcome(ctx, true, "")
			return context.DeadlineExceeded
		}
		buf := capturePassLog(t)
		_ = s.handleAssetChanged(withTimeout(t), assetChangedMsg(t, tenant, asset))
		if !strings.Contains(buf.String(), "ERROR: Failed to process asset changed") {
			t.Errorf("a failure must be logged in full:\n%s", buf.String())
		}
	})
}

// TestIntegration_RealEvaluation_SecondIdenticalPassLogsOneLine drives the real
// handler into the real evaluation: the first pass creates the cert-expiry
// finding (full detail), the second finds nothing to write (one line).
func TestIntegration_RealEvaluation_SecondIdenticalPassLogsOneLine(t *testing.T) {
	f := newCertExpiryFixture(t, 56)
	s := NewEventSubscriberService(nil, f.findings, nil)
	t.Cleanup(s.cancel)
	s.assetEvals.window = testEvalWindow

	msg := func() []byte { return assetChangedMsg(t, f.tenant, f.asset).Data }
	deliver := func() string {
		buf := capturePassLog(t)
		testdb.RetryTransient(t, func() error {
			buf.Reset()
			m := assetChangedMsg(t, f.tenant, f.asset)
			m.Data = msg()
			return s.handleAssetChanged(withTimeout(t), m)
		})
		return buf.String()
	}

	first := deliver()
	if !strings.Contains(first, "Completed asset change reconcile") || !strings.Contains(first, "finding writes") {
		t.Fatalf("the first pass writes the finding and must keep its detail:\n%s", first)
	}

	second := deliver()
	lines := strings.Split(strings.TrimSpace(second), "\n")
	if len(lines) != 1 || !strings.Contains(lines[0], "nothing written") {
		t.Fatalf("the identical second pass printed %d lines, want ONE 'nothing written' summary:\n%s", len(lines), second)
	}
}
