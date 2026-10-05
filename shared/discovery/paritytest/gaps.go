package paritytest

// Gap is a difference the harness EXPECTS today, named so it is a decision
// rather than an accident. CheckGaps fails on any difference no gap names, and
// on any gap that no longer occurs — so closing a gap turns the test red until
// its entry is removed here.
type Gap struct {
	ID string
	// Comparison is "golden/<path>": a path against the fixture's ground
	// truth. Since WP5 the only path is "engine".
	Comparison string
	// Cases limits the gap to these fixture cases; it must then occur on each
	// of them that ran. Empty means any case, at least once.
	Cases []string
	// Field is a Normalize field name or "finding" (one side has no finding of
	// that protocol on that case); "*" matches any run of characters.
	Field string
	// Verdict: "real loss", "naming", "improvement" or "harmless".
	Verdict string
	Note    string
}

// Verdicts.
const (
	RealLoss    = "real loss"
	Naming      = "naming"
	Improvement = "improvement"
	Harmless    = "harmless"
)

// KnownGaps is the difference list between the engine and the fixture's
// ground truth.
//
// History (one-scan-path): this list began as the difference list
// between the engine and the two legacy protocols × ports executors, and
// decided what had to be fixed before they were deleted. Closed along the way
// because the harness said so: the engine's missing TLS version enumeration
// and client-certificate-request flag (WP1), its missing metadata job_id
// (WP3), its missing key-exchange support handshakes (WP1b), and the
// sensor-only leaf key size on TLS rows and protocol version on SSH rows
// (WP4). The final comparison before WP5 deleted the legacy executors showed
// no difference that was not named here; every remaining legacy-vs-engine
// entry was a naming or harmless envelope difference, or an improvement on
// the engine's side, and went with the executors.
//
// The last entry — a TLS 1.2 server that REQUIRES a client certificate, which
// no path recorded as TLS — closed when the handshake began keeping what the
// server sent before it refused the empty certificate. The list is empty: any
// difference from the fixture's ground truth is now a failure.
var KnownGaps = []Gap{}
