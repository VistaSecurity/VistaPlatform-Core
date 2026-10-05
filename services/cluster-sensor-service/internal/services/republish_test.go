package services

import (
	"testing"
	"time"
)

// republishDue's three answers, without a database: a job this replica
// republished and nobody has touched waits out republishInterval; a job whose
// row changed since (handed back, paused, retried) is a new episode and is due
// at once; and a job that left the queue is forgotten.
func TestRepublishDue_SkipsOnlyUntouchedRecentRepublishes(t *testing.T) {
	now := time.Date(2026, 10, 3, 14, 41, 17, 0, time.UTC)
	jp := &JobProcessor{clock: func() time.Time { return now }}
	queuedAt := now.Add(-time.Minute)
	waiting := queuedJob{ID: "waiting", UpdatedAt: queuedAt}
	touched := queuedJob{ID: "touched", UpdatedAt: queuedAt}

	ids := func(jobs []queuedJob) map[string]bool {
		out := map[string]bool{}
		for _, j := range jobs {
			out[j.ID] = true
		}
		return out
	}

	due := ids(jp.republishDue([]queuedJob{waiting, touched}))
	if !due["waiting"] || !due["touched"] {
		t.Fatalf("first sight = %v, want both due", due)
	}
	jp.markRepublished(waiting)
	jp.markRepublished(touched)

	now = now.Add(30 * time.Second)
	touched.UpdatedAt = now.Add(-2 * time.Minute) // handed back since: a new episode
	due = ids(jp.republishDue([]queuedJob{waiting, touched}))
	if due["waiting"] {
		t.Error("an untouched job republished 30s ago was republished again")
	}
	if !due["touched"] {
		t.Error("a job whose row changed since its republish was held back")
	}

	now = now.Add(republishInterval)
	if due = ids(jp.republishDue([]queuedJob{waiting})); !due["waiting"] {
		t.Errorf("after %s an untouched job was still held back — a lost message would never be replaced", republishInterval)
	}
	if _, kept := jp.republished["touched"]; kept {
		t.Error("a job that left the queue is still remembered")
	}
}
