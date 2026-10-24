// Package agentlogs carries a discovery agent's recent log lines to the
// console, so an operator can read them without logging into the agent's host.
//
// It is the agent's half of what the sensor already does with its export_logs
// command, shaped to fit the agent's channel. The agent has no command queue;
// it has a heartbeat, and the platform's answer to that heartbeat is how it
// learns everything else (desired settings, a restart request). A log request
// rides the same answer:
//
//	console  → POST /agents/{id}/logs/request   (records a Request)
//	agent    → heartbeat; the answer carries the pending Request
//	agent    → POST /agents/{id}/logs           (the lines, as an Upload)
//	console  ← GET  /agents/{id}/logs           (the latest Export)
//
// Both ends are short-lived on purpose. A request nobody's agent collects
// expires; an export is kept long enough to read and then expires too. Log
// lines are diagnostic material, not inventory, and the platform keeps none of
// them for long.
//
// # Redaction
//
// Log lines are free text built from whatever a device, a vendor API or a
// transport said, so a credential can turn up in one. Every line goes through
// redact.Text on the agent BEFORE it leaves the host, and again on the platform
// before it is stored: the second pass is the backstop for an agent built
// before a redaction rule existed.
package agentlogs

import (
	"strings"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

const (
	// DefaultLines is how many lines a request asks for when it names none.
	DefaultLines = 200
	// MaxLines bounds one export, and is also the size of the agent's buffer.
	MaxLines = 1000
	// MaxLineBytes bounds one line. A longer line is cut and marked, so a
	// runaway log statement cannot make an export megabytes long.
	MaxLineBytes = 2000

	// RequestTTL is how long a request waits for the agent to collect it. Long
	// enough to cover an agent on a slow heartbeat, short enough that a request
	// to an agent that is gone does not hang about.
	RequestTTL = time.Hour
	// ExportTTL is how long the platform keeps what an agent sent.
	ExportTTL = 24 * time.Hour
	// CapabilityTTL is how long an agent's "I can export logs" claim stands
	// after its last heartbeat said so.
	CapabilityTTL = 15 * time.Minute
)

// truncatedMark ends a line that was cut at MaxLineBytes.
const truncatedMark = " …[truncated]"

// Request is an operator's ask for an agent's recent log lines.
type Request struct {
	// ID ties the agent's upload to this request, so an upload for a request
	// that was replaced (or never made) is refused rather than stored.
	ID          string    `json:"id"`
	Lines       int       `json:"lines"`
	RequestedAt time.Time `json:"requested_at"`
}

// Upload is what the agent sends in reply.
type Upload struct {
	RequestID string   `json:"request_id"`
	Lines     []string `json:"lines"`
}

// Export is what the platform keeps and shows: the lines one agent sent in
// reply to one request.
type Export struct {
	RequestID  string    `json:"request_id"`
	Lines      []string  `json:"lines"`
	LineCount  int       `json:"line_count"`
	ReceivedAt time.Time `json:"received_at"`
}

// ClampLines turns a requested line count into one inside [1, MaxLines], with
// zero or less meaning DefaultLines.
func ClampLines(n int) int {
	if n <= 0 {
		return DefaultLines
	}
	if n > MaxLines {
		return MaxLines
	}
	return n
}

// Clean prepares lines for the wire or for storage: at most `limit` of them
// (the LAST ones, since the newest lines are the ones being asked about), each
// cut to MaxLineBytes and redacted.
func Clean(lines []string, limit int) []string {
	limit = ClampLines(limit)
	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, cleanLine(l))
	}
	return out
}

func cleanLine(l string) string {
	// Redact BEFORE cutting: a cut can split a `password=…` pair so the name
	// survives and the rule no longer sees a value to mask.
	l = redact.Text(l)
	if len(l) > MaxLineBytes {
		cut := MaxLineBytes
		// Back off to a rune boundary so the cut cannot leave half a UTF-8
		// sequence, which a JSON encoder would turn into a replacement rune.
		for cut > 0 && !isRuneStart(l[cut]) {
			cut--
		}
		l = l[:cut] + truncatedMark
	}
	return l
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// Ring keeps the most recent log lines in memory. It is an io.Writer, so it can
// be tee'd onto the standard logger beside stderr.
type Ring struct {
	mu    sync.Mutex
	lines []string
	max   int
}

// NewRing returns a buffer holding at most max lines.
func NewRing(max int) *Ring {
	if max <= 0 {
		max = MaxLines
	}
	return &Ring{max: max}
}

// Write appends each line in p, evicting the oldest beyond the cap.
func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line == "" {
			continue
		}
		r.lines = append(r.lines, line)
	}
	if len(r.lines) > r.max {
		// Copy rather than reslice, so the evicted lines' backing array can be
		// collected instead of growing for the life of the process.
		r.lines = append([]string(nil), r.lines[len(r.lines)-r.max:]...)
	}
	return len(p), nil
}

// Tail returns a copy of the last n lines (all of them when n <= 0 or exceeds
// what is held).
func (r *Ring) Tail(n int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if n <= 0 || n > len(r.lines) {
		n = len(r.lines)
	}
	out := make([]string, n)
	copy(out, r.lines[len(r.lines)-n:])
	return out
}
