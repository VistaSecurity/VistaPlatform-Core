package deviceinterrogation

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"unicode/utf8"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// Collection warnings: the sub-failures a collector survived.
//
// Every collector here is best-effort per endpoint — a FortiGate admin profile
// that may read `system/status` but not `system/interface` still yields a
// device, its identity and its tunnels. That is the right call, and it used to
// be made silently: each refused endpoint became one `fmt.Printf("Warning: …")`
// line on the stdout of whichever process ran the collector, and the job
// reported success. A read-only account refused half the API produced a
// "successful" job with half the data missing, and nothing an operator could
// see said so (finding P-17).
//
// A warning is the missing half of "best-effort": the partial result is still
// returned, AND the result says which endpoint was not read, why, and what is
// therefore absent. Both runtimes carry the list to the job's processing block,
// where the job detail shows it.
//
// Nothing in this package writes to stdout or stderr any more.
// TestCollectors_NeverWriteWarningsToStdout keeps it that way.

// WarningReason is the closed set of reasons a collection warning can carry.
// It is closed so the UI can say something specific about each one, and so a
// value arriving from an agent build we have not seen cannot invent a new one:
// [SanitizeWarnings] maps anything outside the set to [WarningError].
type WarningReason string

const (
	// WarningPermissionDenied — the device refused the account (HTTP 401/403,
	// a vendor "permission denied" code, a Cisco command-authorization
	// failure). The usual cause is a read-only profile without that scope.
	WarningPermissionDenied WarningReason = "permission_denied"
	// WarningNotSupported — the endpoint or command does not exist on this
	// model or software version (HTTP 404/405/501, an invalid-command code).
	WarningNotSupported WarningReason = "not_supported"
	// WarningTruncated — the collector read up to its bound and stopped; the
	// table it built is partial.
	WarningTruncated WarningReason = "truncated"
	// WarningTimeout — the device did not answer in time.
	WarningTimeout WarningReason = "timeout"
	// WarningUnreachable — the connection could not be made.
	WarningUnreachable WarningReason = "unreachable"
	// WarningParseError — the device answered and the answer could not be read.
	WarningParseError WarningReason = "parse_error"
	// WarningError — anything else.
	WarningError WarningReason = "error"
)

// warningReasons is the closed set, for validation.
var warningReasons = map[WarningReason]bool{
	WarningPermissionDenied: true,
	WarningNotSupported:     true,
	WarningTruncated:        true,
	WarningTimeout:          true,
	WarningUnreachable:      true,
	WarningParseError:       true,
	WarningError:            true,
}

// WarningReasons returns the closed reason set, for callers that must mirror
// it (the API contract, the UI labels). The order is stable.
func WarningReasons() []WarningReason {
	return []WarningReason{
		WarningPermissionDenied, WarningNotSupported, WarningTruncated,
		WarningTimeout, WarningUnreachable, WarningParseError, WarningError,
	}
}

// CollectionWarning is one thing a collector could not read, and what is
// therefore missing from the result.
type CollectionWarning struct {
	// Collector is the interrogator that raised it (fortinet, cisco, …).
	Collector string `json:"collector"`
	// Endpoint is the API path or CLI command that failed. Never a query
	// string and never a host: [SanitizeWarnings] strips both, because a
	// query string is where a vendor API key travels.
	Endpoint string `json:"endpoint"`
	// Reason is one of the closed [WarningReason] values.
	Reason WarningReason `json:"reason"`
	// Effect is what the result lacks because of it, in a short sentence
	// ("VLANs not collected").
	Effect string `json:"effect"`
	// Detail is the underlying error, bounded and redacted. Diagnostic only.
	Detail string `json:"detail,omitempty"`
}

// The collector names stamped on warnings. One per interrogator, spelled as the
// vendor rather than as any one of the device types that dispatch to it, so a
// FortiGate registered as "fortigate" and one registered as "fortinet" report
// the same collector.
const (
	ciscoCollector    = "cisco"
	fortinetCollector = "fortinet"
	panCollector      = "paloalto"
	f5Collector       = "f5"
	unifiCollector    = "unifi"
	snmpCollector     = "snmp"
)

// Bounds. A warning list is diagnostic, not data: a device that refuses every
// endpoint must not be able to grow a job row without limit, and one line of
// vendor error text is plenty to diagnose from.
const (
	// MaxCollectionWarnings caps the list on one result.
	MaxCollectionWarnings = 50
	maxWarningCollector   = 64
	maxWarningEndpoint    = 200
	maxWarningEffect      = 200
	maxWarningDetail      = 300
)

// warn records a sub-failure the collector survived, classifying err into a
// reason. The partial result is kept; the caller carries on.
func (r *InterrogateResult) warn(endpoint string, err error, effect string) {
	detail := ""
	if err != nil {
		detail = err.Error()
	}
	r.warnAs(ClassifyWarningReason(err), endpoint, effect, detail)
}

// warnAs records a warning whose reason the collector already knows — a
// truncation it applied itself, a response it could not parse.
func (r *InterrogateResult) warnAs(reason WarningReason, endpoint, effect, detail string) {
	if r == nil {
		return
	}
	r.Warnings = appendWarning(r.Warnings, sanitizeWarning(CollectionWarning{
		Collector: r.collector,
		Endpoint:  endpoint,
		Reason:    reason,
		Effect:    effect,
		Detail:    detail,
	}))
}

// warnTruncated records that a table was cut at bound rows.
func (r *InterrogateResult) warnTruncated(endpoint, table string, bound int) {
	r.warnAs(WarningTruncated, endpoint,
		fmt.Sprintf("%s truncated at %d rows; the rest were not collected", table, bound), "")
}

// overflowEndpoint marks the synthetic last warning that says how many more
// were raised past MaxCollectionWarnings.
const overflowEndpoint = "(further warnings)"

// appendWarning adds w unless an identical warning (same collector, endpoint,
// reason and effect) is already present. Order is insertion order, so both
// runtimes report the same list for the same run.
//
// Past MaxCollectionWarnings, warnings are counted rather than kept, into one
// synthetic final entry ("N more warnings not shown"). A cap that dropped them
// silently would be the partial-answer-presented-as-whole this whole type
// exists to end. Re-applying it to an already-capped list (the platform
// re-sanitizes what an agent sends) adds the counts instead of re-counting.
func appendWarning(list []CollectionWarning, w CollectionWarning) []CollectionWarning {
	if w.Endpoint == overflowEndpoint {
		return addOverflow(list, overflowCount(w))
	}
	for _, existing := range list {
		if existing.Collector == w.Collector && existing.Endpoint == w.Endpoint &&
			existing.Reason == w.Reason && existing.Effect == w.Effect {
			return list
		}
	}
	shown, overflowed := 0, false
	for _, existing := range list {
		if existing.Endpoint == overflowEndpoint {
			overflowed = true
			continue
		}
		shown++
	}
	if shown >= MaxCollectionWarnings {
		return addOverflow(list, 1)
	}
	list = append(list, w)
	if overflowed {
		list = addOverflow(list, 0) // keep the overflow entry last
	}
	return list
}

// addOverflow adds n to the synthetic overflow entry, creating it if needed.
func addOverflow(list []CollectionWarning, n int) []CollectionWarning {
	// Fold in any existing overflow entry, wherever it sits (a list from an
	// agent is input, not a list this code built), so there is only ever one,
	// and it is last.
	kept := list[:0:0]
	for _, w := range list {
		if w.Endpoint == overflowEndpoint {
			n += overflowCount(w)
			continue
		}
		kept = append(kept, w)
	}
	list = kept
	if n <= 0 {
		return list
	}
	noun := "warnings"
	if n == 1 {
		noun = "warning"
	}
	collector := ""
	if len(list) > 0 {
		collector = list[0].Collector
	}
	return append(list, CollectionWarning{
		Collector: collector,
		Endpoint:  overflowEndpoint,
		Reason:    WarningTruncated,
		Effect:    fmt.Sprintf("%d more %s not shown", n, noun),
	})
}

// overflowCount reads the count back out of an overflow entry.
func overflowCount(w CollectionWarning) int {
	var n int
	if _, err := fmt.Sscanf(w.Effect, "%d more", &n); err != nil || n < 1 {
		return 1
	}
	return n
}

// SanitizeWarnings returns a scrubbed, bounded, de-duplicated copy of ws.
//
// It is what [Sanitize] applies to every result, and what the platform applies
// AGAIN to a list that arrived from an agent: a warning is free text built from
// whatever a device said, and an agent binary is not a trust boundary we own.
// An unknown reason becomes [WarningError]; a nil or empty input returns nil,
// so "no warnings" has one representation.
func SanitizeWarnings(ws []CollectionWarning) []CollectionWarning {
	var out []CollectionWarning
	for _, w := range ws {
		out = appendWarning(out, sanitizeWarning(w))
	}
	return out
}

func sanitizeWarning(w CollectionWarning) CollectionWarning {
	reason := w.Reason
	if !warningReasons[reason] {
		reason = WarningError
	}
	return CollectionWarning{
		Collector: boundText(sanitizeWarningText(w.Collector), maxWarningCollector),
		Endpoint:  sanitizeEndpoint(w.Endpoint),
		Reason:    reason,
		Effect:    boundText(sanitizeWarningText(w.Effect), maxWarningEffect),
		Detail:    boundText(sanitizeWarningText(w.Detail), maxWarningDetail),
	}
}

// sanitizeWarningText is the redaction every free-text warning field gets:
// [redact.Text] (credentials still wearing their name — URL userinfo, headers,
// JSON members, Cisco secret lines, secret query parameters — and PEM private
// keys), run BEFORE control characters are folded to spaces so its line-based
// rules still see the lines, then the fold, so a device cannot lay out a row
// of its own.
func sanitizeWarningText(s string) string {
	s = redact.Text(s)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	return strings.Join(strings.Fields(s), " ")
}

// sanitizeEndpoint reduces an endpoint to its path or command. A full URL loses
// its scheme, host and userinfo; anything after `?` or `#` is dropped outright
// rather than redacted parameter by parameter, because the endpoint names WHAT
// was asked, and the query string is where a credential rides.
func sanitizeEndpoint(s string) string {
	s = strings.TrimSpace(s)
	if u, err := url.Parse(s); err == nil && u.Scheme != "" && u.Host != "" {
		s = u.Path
		if s == "" {
			s = "/"
		}
	}
	if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	return boundText(sanitizeWarningText(s), maxWarningEndpoint)
}

// boundText cuts s to at most n runes, marking the cut.
func boundText(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	runes := []rune(s)
	return string(runes[:n-1]) + "…"
}

// --- classification ---------------------------------------------------------

// deviceStatusError is a non-2xx answer from an appliance's management API. The
// status is kept so a warning can say "permission denied" rather than guess at
// it from the message; the message is the one the collector always produced.
type deviceStatusError struct {
	status int
	msg    string
}

func (e *deviceStatusError) Error() string { return e.msg }

// statusErrorf builds a [deviceStatusError] with a formatted message.
func statusErrorf(status int, format string, args ...any) error {
	return &deviceStatusError{status: status, msg: fmt.Sprintf(format, args...)}
}

// vendorAPIError is a refusal a vendor reported inside a successful HTTP
// response — a PAN-OS `<response status="error" code="403">`, a UniFi
// `api.err.NoPermission`. The collector knows the reason; the error carries it.
type vendorAPIError struct {
	reason WarningReason
	msg    string
}

func (e *vendorAPIError) Error() string { return e.msg }

// reasonErrorf builds an error whose warning reason the collector already knows.
func reasonErrorf(reason WarningReason, format string, args ...any) error {
	return &vendorAPIError{reason: reason, msg: fmt.Sprintf(format, args...)}
}

// --- vendor error bodies ----------------------------------------------------
//
// A collector error becomes a warning's Detail, and Detail is persisted and
// served to the tenant. An appliance's error BODY is therefore never put into
// one: it is the device's free text, and it has been seen to carry exactly what
// must not be stored — an F5 401 echoing the X-F5-Auth-Token and password, a
// FortiOS 500 quoting a `psksecret`. The value-shaped redactor is the backstop
// (shared/redact.Text); this is the real fix, per "collect posture, never key
// material": the body is not read into the error at all. What is kept is the
// vendor's NUMERIC error code, extracted from a named field of a bounded read.

// maxErrorBodyBytes bounds the read of an error body we only look a code up in.
const maxErrorBodyBytes = 4096

// vendorErrorCode reads a bounded JSON error body and returns the first of
// fields that holds an integer. Anything else in the body is discarded
// unread; a body that is not JSON yields nothing.
func vendorErrorCode(body io.Reader, fields ...string) (int64, bool) {
	raw, err := io.ReadAll(io.LimitReader(body, maxErrorBodyBytes))
	if err != nil {
		return 0, false
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(raw, &envelope) != nil {
		return 0, false
	}
	for _, field := range fields {
		var n json.Number
		if json.Unmarshal(envelope[field], &n) != nil {
			continue
		}
		if code, err := n.Int64(); err == nil {
			return code, true
		}
	}
	return 0, false
}

// f5ErrorCode is the " (F5 code N)" suffix for an iControl REST error body,
// or "" when it carries none.
func f5ErrorCode(body io.Reader) string {
	if code, ok := vendorErrorCode(body, "code"); ok {
		return fmt.Sprintf(" (F5 code %d)", code)
	}
	return ""
}

// fortinetErrorCode is the " (FortiOS error N)" suffix for a FortiOS error
// body, or "" when it carries none.
func fortinetErrorCode(body io.Reader) string {
	if code, ok := vendorErrorCode(body, "error"); ok {
		return fmt.Sprintf(" (FortiOS error %d)", code)
	}
	return ""
}

// isShortNumber reports whether s is a plausible vendor error code: an
// optionally signed integer of at most eight digits.
func isShortNumber(s string) bool {
	s = strings.TrimPrefix(s, "-")
	if s == "" || len(s) > 8 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// ClassifyWarningReason maps a collector error onto the closed reason set.
func ClassifyWarningReason(err error) WarningReason {
	if err == nil {
		return WarningError
	}

	var vendorErr *vendorAPIError
	if errors.As(err, &vendorErr) {
		return vendorErr.reason
	}
	var statusErr *deviceStatusError
	if errors.As(err, &statusErr) {
		return reasonForHTTPStatus(statusErr.status)
	}

	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return WarningTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return WarningTimeout
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return WarningUnreachable
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return WarningUnreachable
	}
	if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return WarningUnreachable
	}

	var syntaxErr *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	var xmlErr *xml.SyntaxError
	if errors.As(err, &syntaxErr) || errors.As(err, &typeErr) || errors.As(err, &xmlErr) {
		return WarningParseError
	}
	return WarningError
}

// reasonForHTTPStatus is the HTTP half of the classifier.
func reasonForHTTPStatus(status int) WarningReason {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return WarningPermissionDenied
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return WarningNotSupported
	case http.StatusRequestTimeout, http.StatusGatewayTimeout:
		return WarningTimeout
	default:
		return WarningError
	}
}
