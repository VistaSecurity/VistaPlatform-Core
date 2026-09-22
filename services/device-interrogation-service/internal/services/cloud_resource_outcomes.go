package services

import (
	"context"
	"errors"
	"log"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/smithy-go"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
)

// cloudScopeGlobal is the scope name for a provider API that is not regional
// (CloudFront, S3 ListBuckets). Named rather than "" so a global failure reads
// as "global" in the UI instead of as a missing region.
const cloudScopeGlobal = "global"

// Per-resource-type outcomes for one cloud discovery run ( slice E).
//
// Before this, a cloud job's stored result was `{"success": true, ...}` and a
// count. The dispatch switch swallowed kms/s3/rds failures into a log line and
// aborted the whole run on a load-balancer failure, so "the account has no KMS
// keys", "the credentials are not allowed to list KMS keys" and "KMS was never
// asked for" all produced the same result: nothing, and success. That is the
// "a check that cannot fail" pattern CLAUDE.md names.
//
// The recorder travels on the context rather than on CloudDiscoveryResult so
// the outcome of a collector deep in the call tree is recorded where it
// happens, and so an unrecorded run (a caller that did not opt in) is a no-op
// rather than a lie: every method is nil-receiver safe.

// Status of one requested resource type.
const (
	// CloudTypeSucceeded — every scope attempted answered. Found may be 0,
	// and a 0 here MEANS there was nothing there.
	CloudTypeSucceeded = "succeeded"
	// CloudTypePartial — at least one scope answered and at least one failed.
	CloudTypePartial = "partial"
	// CloudTypeFailed — every scope attempted failed. Nothing is known about
	// this resource type.
	CloudTypeFailed = "failed"
	// CloudTypeNotAttempted — the type was requested but this provider's
	// dispatch has no collector for it, so nothing was even tried. Distinct
	// from "found nothing": we did not look.
	CloudTypeNotAttempted = "not_attempted"
)

// Run-level verdict, stored alongside the per-type outcomes.
const (
	CloudRunComplete = "complete"
	CloudRunPartial  = "partial"
	CloudRunFailed   = "failed"
)

// Failure reasons. A classification of what the provider said, so the UI can
// say what the user should DO — an AccessDenied needs an IAM change, a throttle
// needs a re-run.
const (
	CloudFailureAccessDenied = "access_denied"
	CloudFailureCredentials  = "credentials"
	CloudFailureThrottled    = "throttled"
	CloudFailureRegion       = "region_unavailable"
	CloudFailureTimeout      = "timeout"
	CloudFailureNetwork      = "network"
	CloudFailureUnknown      = "unknown"
)

// CloudCollectorFailure is one scope's failure, projected onto the fields a
// human can act on.
//
// Projected, never the raw error object: an AWS SDK error can echo request
// context back, and CLAUDE.md is explicit that nothing credential-shaped may be
// persisted into device_jobs.results. Code comes from the SDK verbatim (it is a
// fixed vocabulary); Message is the service's own message with secret-shaped
// runs redacted and a length cap.
type CloudCollectorFailure struct {
	// Scope is the region this failed in, or "global" for a global API.
	Scope string `json:"scope,omitempty"`
	// Reason is our classification — see the CloudFailure* constants.
	Reason string `json:"reason"`
	// Code is the provider's own error code, e.g. "AccessDeniedException".
	Code string `json:"code,omitempty"`
	// Message is the provider's message, sanitized and bounded.
	Message string `json:"message,omitempty"`
}

// CloudResourceTypeOutcome is one requested resource type's result.
type CloudResourceTypeOutcome struct {
	ResourceType string `json:"resource_type"`
	Status       string `json:"status"`
	// Found is how many resources this type produced. Meaningful only when
	// Status is succeeded or partial — on a failure nothing was counted.
	Found int `json:"found"`
	// ScopesSucceeded / ScopesAttempted are regions (or "global"). They carry
	// the partial case honestly instead of rounding it to success or failure.
	ScopesSucceeded int                     `json:"scopes_succeeded"`
	ScopesAttempted int                     `json:"scopes_attempted"`
	Failures        []CloudCollectorFailure `json:"failures,omitempty"`
}

// CloudOutcomeRecorder accumulates per-type outcomes for one run.
type CloudOutcomeRecorder struct {
	mu     sync.Mutex
	order  []string
	byType map[string]*CloudResourceTypeOutcome
}

type cloudOutcomeKey struct{}

// NewCloudOutcomeRecorder seeds one entry per requested resource type, each
// not_attempted until a collector actually runs. Seeding up front is what makes
// "requested but this provider has no collector for it" visible: the switch's
// default case is silent, so an unseeded recorder would report nothing at all
// for a type nobody handled.
func NewCloudOutcomeRecorder(resourceTypes []string) *CloudOutcomeRecorder {
	r := &CloudOutcomeRecorder{byType: make(map[string]*CloudResourceTypeOutcome)}
	for _, t := range resourceTypes {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		r.ensure(t)
	}
	return r
}

// WithCloudOutcomes attaches a recorder to ctx. Collectors deeper in the tree
// find it with cloudOutcomesFrom.
func WithCloudOutcomes(ctx context.Context, r *CloudOutcomeRecorder) context.Context {
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, cloudOutcomeKey{}, r)
}

func cloudOutcomesFrom(ctx context.Context) *CloudOutcomeRecorder {
	r, _ := ctx.Value(cloudOutcomeKey{}).(*CloudOutcomeRecorder)
	return r
}

// ensure must be called with the lock held, or before the recorder is shared.
func (r *CloudOutcomeRecorder) ensure(resourceType string) *CloudResourceTypeOutcome {
	if o, ok := r.byType[resourceType]; ok {
		return o
	}
	o := &CloudResourceTypeOutcome{ResourceType: resourceType, Status: CloudTypeNotAttempted}
	r.byType[resourceType] = o
	r.order = append(r.order, resourceType)
	return o
}

// Attempt records one collector call: `found` resources from `scope`, or a
// failure when err is non-nil. Both may be meaningful at once — a collector
// that listed two regions and failed on the third returns what it got AND the
// error, and neither half is discarded.
//
// Nil-receiver safe: a run with no recorder records nothing.
func (r *CloudOutcomeRecorder) Attempt(resourceType, scope string, found int, err error) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	o := r.ensure(resourceType)
	o.ScopesAttempted++
	o.Found += found
	if err != nil {
		o.Failures = append(o.Failures, SanitizeCloudFailure(scope, err))
	} else {
		o.ScopesSucceeded++
	}

	switch {
	case len(o.Failures) == 0:
		o.Status = CloudTypeSucceeded
	case o.ScopesSucceeded > 0:
		o.Status = CloudTypePartial
	default:
		o.Status = CloudTypeFailed
	}
}

// Outcomes returns the per-type outcomes in the order the types were requested.
func (r *CloudOutcomeRecorder) Outcomes() []CloudResourceTypeOutcome {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]CloudResourceTypeOutcome, 0, len(r.order))
	for _, t := range r.order {
		out = append(out, *r.byType[t])
	}
	return out
}

// Verdict is the run-level answer to "did we see everything we were asked to
// look at".
//
//   - complete — nothing that was attempted failed. This is the ONLY verdict
//     that sets the stored result's `success` flag true.
//   - failed   — every type that was attempted failed outright.
//   - partial  — anything in between.
//
// not_attempted types do not make a run partial: nothing failed, the provider
// simply has no collector for that type. They are still reported per-type so
// they cannot be read as "found nothing".
func (r *CloudOutcomeRecorder) Verdict() string {
	if r == nil {
		return CloudRunComplete
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	attempted, failed, degraded := 0, 0, 0
	for _, t := range r.order {
		o := r.byType[t]
		if o.ScopesAttempted == 0 {
			continue
		}
		attempted++
		switch o.Status {
		case CloudTypeFailed:
			failed++
			degraded++
		case CloudTypePartial:
			degraded++
		}
	}
	switch {
	case degraded == 0:
		return CloudRunComplete
	case attempted > 0 && failed == attempted:
		return CloudRunFailed
	default:
		return CloudRunPartial
	}
}

// Succeeded reports whether every attempted resource type was collected
// without error. It is what the stored JobResult.Success now means.
func (r *CloudOutcomeRecorder) Succeeded() bool {
	return r.Verdict() == CloudRunComplete
}

// ApplyToJobResult writes the per-type outcomes and the run verdict onto a job
// result's metadata map, and answers what that result's `success` flag should
// be. One definition for both writers — the interactive handler and the
// scheduled worker — so the two cannot drift into disagreeing about what
// success means.
//
// A nil recorder writes nothing and answers true: absent metadata means "this
// run did not report outcomes", which the reader must not confuse with
// "everything succeeded".
func (r *CloudOutcomeRecorder) ApplyToJobResult(metadata map[string]interface{}) bool {
	if types := r.Outcomes(); len(types) > 0 && metadata != nil {
		metadata["resource_types"] = types
		metadata["outcome"] = r.Verdict()
	}
	return r.Succeeded()
}

// cloudCollector is one resource type's collection call.
type cloudCollector struct {
	// regional is true when the collector must be invoked once per region. A
	// non-regional API (CloudFront, S3 ListBuckets) runs once, under the scope
	// name "global".
	regional bool
	collect  func(ctx context.Context, scope string) ([]models.Device, error)
}

// runCloudCollectors dispatches the requested resource types and records what
// happened to each ( slice E).
//
// Three rules, each of which was broken before:
//
//  1. A failing type never aborts the run. The types that worked keep their
//     results.
//  2. A failing type is never swallowed. Its failure is recorded against the
//     type and the scope, with the provider's own error code.
//  3. Whatever a collector returned is kept even when it ALSO returned an
//     error — a collector that listed two regions and was denied the third
//     hands back both halves, and discarding either one is a lie.
//
// Regional collectors are invoked one region at a time so a type that worked
// in us-east-1 and was denied in eu-west-1 is reported partial rather than
// rounded to either answer.
func runCloudCollectors(ctx context.Context, resourceTypes, regions []string, collectors map[string]cloudCollector) []models.Device {
	outcomes := cloudOutcomesFrom(ctx)
	var devices []models.Device

	for _, resourceType := range resourceTypes {
		c, ok := collectors[resourceType]
		if !ok {
			// Requested, but nothing collects it. Left at not_attempted: the
			// old switch fell through silently, which is why "we do not
			// collect that" looked exactly like "there is none".
			continue
		}
		scopes := []string{cloudScopeGlobal}
		if c.regional {
			scopes = regions
		}
		for _, scope := range scopes {
			found, err := c.collect(ctx, scope)
			devices = append(devices, found...)
			outcomes.Attempt(resourceType, scope, len(found), err)
			logCloudCollectorFailure(resourceType, scope, err)
		}
	}

	return devices
}

// logCloudCollectorFailure keeps the operator-facing log line the swallowed
// warnings used to be — now in ADDITION to the recorded outcome rather than
// instead of it. A log line is not a result.
func logCloudCollectorFailure(resourceType, scope string, err error) {
	if err == nil {
		return
	}
	log.Printf("[cloud discovery] %s collection failed in %s: %v", resourceType, scope, err)
}

// --- provider error projection -------------------------------------------

const cloudFailureMessageMax = 240

var (
	// AWS access-key-shaped identifiers (AKIA/ASIA/... + body).
	reAWSKeyID = regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA|AGPA|AIPA|ANPA|ANVA|APKA|ABIA|ACCA)[A-Z0-9]{8,}\b`)
	// Long unbroken base64/hex runs — session tokens, signatures, secrets.
	// ARN segments are short, so this does not eat useful context.
	reLongBlob = regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`)
	// name=value / name: value where the name says secret.
	reNamedSecret = regexp.MustCompile(`(?i)\b(pass(?:word|wd)?|secret[a-z_]*|token|credentials?|signature|sig|api[_-]?key|auth(?:orization)?)\b\s*[=:]\s*\S+`)
	reWhitespace  = regexp.MustCompile(`\s+`)
)

// SanitizeCloudErrorMessage projects a provider error message onto something
// safe to persist: secret-shaped runs redacted, whitespace collapsed, length
// capped. A vendor message is free text we have never seen the whole space of,
// so it is filtered by shape rather than trusted.
func SanitizeCloudErrorMessage(msg string) string {
	msg = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || r == '\r' {
			return ' '
		}
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, msg)
	msg = reNamedSecret.ReplaceAllString(msg, "$1=[redacted]")
	msg = reAWSKeyID.ReplaceAllString(msg, "[redacted]")
	msg = reLongBlob.ReplaceAllString(msg, "[redacted]")
	msg = strings.TrimSpace(reWhitespace.ReplaceAllString(msg, " "))
	if len(msg) > cloudFailureMessageMax {
		msg = strings.TrimSpace(msg[:cloudFailureMessageMax]) + "…"
	}
	return msg
}

// classifyCloudFailure maps a provider error code + message onto an actionable
// reason. Code first: it is the provider's own fixed vocabulary, where the
// message is prose that changes between SDK versions.
func classifyCloudFailure(code, msg string) string {
	h := strings.ToLower(code + " " + msg)
	switch {
	case containsAny(h, "accessdenied", "unauthorizedoperation", "authorizationerror", "not authorized", "forbidden"):
		return CloudFailureAccessDenied
	case containsAny(h, "expiredtoken", "invalidclienttokenid", "signaturedoesnotmatch", "unrecognizedclient", "invalidaccesskeyid", "authfailure", "incompletesignature", "credential", "invalidsecurity"):
		return CloudFailureCredentials
	case containsAny(h, "throttl", "toomanyrequests", "requestlimitexceeded", "slowdown", "limitexceeded", "provisionedthroughput"):
		return CloudFailureThrottled
	case containsAny(h, "optinrequired", "invalidregion", "unsupportedregion", "endpointunreachable", "no such host"):
		return CloudFailureRegion
	case containsAny(h, "timeout", "timed out", "deadline exceeded", "context canceled"):
		return CloudFailureTimeout
	case containsAny(h, "connection refused", "dial tcp", "network is unreachable", "connection reset", "tls handshake"):
		return CloudFailureNetwork
	default:
		return CloudFailureUnknown
	}
}

func containsAny(haystack string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(haystack, n) {
			return true
		}
	}
	return false
}

// SanitizeCloudFailure projects a collector error onto the stored shape.
//
// The provider's own error code survives verbatim — "AccessDeniedException" is
// a different user action from "ThrottlingException" and flattening them to
// "failed" is what made the original bug invisible. Everything else is
// filtered.
func SanitizeCloudFailure(scope string, err error) CloudCollectorFailure {
	f := CloudCollectorFailure{Scope: scope}
	if err == nil {
		return f
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		f.Code = SanitizeCloudErrorMessage(apiErr.ErrorCode())
		f.Message = SanitizeCloudErrorMessage(apiErr.ErrorMessage())
	} else {
		f.Message = SanitizeCloudErrorMessage(err.Error())
	}
	f.Reason = classifyCloudFailure(f.Code, f.Message)
	if f.Message == "" {
		f.Message = "the provider returned an error with no message"
	}
	return f
}
