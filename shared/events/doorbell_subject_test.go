package events

import (
	"strings"
	"testing"
)

// subjectMatches reports whether a NATS subject is matched by a (possibly
// wildcarded) stream subject filter: `*` matches one token, a trailing `>`
// matches one or more.
func subjectMatches(filter, subject string) bool {
	f := strings.Split(filter, ".")
	s := strings.Split(subject, ".")
	for i, tok := range f {
		if tok == ">" {
			return len(s) > i
		}
		if i >= len(s) {
			return false
		}
		if tok != "*" && tok != s[i] {
			return false
		}
	}
	return len(f) == len(s)
}

// A doorbell is a core-NATS hint that is fine to lose. Published on a subject a
// JetStream stream captures, every ring would be persisted — and the AUDIT
// stream's `audit.>` would have taken an audit-namespaced doorbell into the
// very stream the audit ingestion subscriber consumes.
func TestDoorbellSubjectsAreOutsideEveryStream(t *testing.T) {
	for _, subject := range []string{SubjectDoorbellAuditStored} {
		for _, sc := range DefaultStreams {
			for _, filter := range sc.Subjects {
				if subjectMatches(filter, subject) {
					t.Errorf("doorbell subject %q is captured by stream %s (%q); doorbells must never be persisted",
						subject, sc.Name, filter)
				}
			}
		}
	}
	// The matcher must be able to say yes, or the loop above proves nothing.
	if !subjectMatches("audit.>", "audit.events.stored") || !subjectMatches("a.*.c", "a.b.c") || subjectMatches("a.b", "a.b.c") {
		t.Fatal("subjectMatches is broken; the stream check above would be inert")
	}
}

// A platform-owned durable's deliver subject must sit outside every stream,
// or the server would capture the deliveries back into a stream (a cycle it
// refuses on create, with a confusing error).
func TestDeliverSubjectsAreOutsideEveryStream(t *testing.T) {
	for _, st := range DefaultStreams {
		subj := deliverSubject(st.Name, "any-durable")
		for _, other := range DefaultStreams {
			for _, pattern := range other.Subjects {
				if subjectMatches(pattern, subj) {
					t.Fatalf("deliver subject %q is inside stream %s (%q)", subj, other.Name, pattern)
				}
			}
		}
	}
}
