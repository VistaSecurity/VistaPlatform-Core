// Package sensordispatch is the vocabulary the platform and a tenant-deployed
// sensor share when a discovery job is handed to the sensor to run.
//
// It is pure Go with no database, NATS or multi-tenant dependency, because the
// sensor binary imports it: the standalone sensor and the in-cluster dispatcher
// must agree on the command payload, on what "this sensor is alive" means, and
// on how long a command may wait unclaimed before the job is declared dead. A
// second copy of any of those in either runtime is how a job ends up dispatched
// to a sensor that will never pick it up, or refused by a sensor that could.
package sensordispatch

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CommandType is the sensor_commands.command_type the dispatcher writes and the
// sensor's command switch dispatches on.
const CommandType = "discovery_job"

// StatusAwaitingSensor is the discovery_jobs.status of a job that has been
// handed to a tenant sensor and has not reported back. It is distinct from
// `queued` (nothing has looked at it) and `running` (the platform sensor is
// scanning it) so the stuck-job sweep and the UI can each tell the three apart.
const StatusAwaitingSensor = "awaiting_sensor"

// DiscoveryMethodActive is the discovery_method the sensor stamps on every
// result of a dispatched job. It maps onto the `active` member of the
// crypto_implementations discovery_method enum, which is what "the asset's
// configuration carries active provenance" means downstream.
const DiscoveryMethodActive = "active"

// DiscoverySourceActiveScan is the discovery_source stamp the mirrored rows of
// an in-cluster Active Scan carry (cluster-sensor's mirrorMetadata). The sensor
// stamps the same value so the two executors' results are indistinguishable to
// every reader that filters on it.
const DiscoverySourceActiveScan = "active_scan"

// MetadataJobIDKey is where the originating job id rides in a result's
// raw_metadata, so a discovery row can be traced back to the job that produced
// it without a new column.
const MetadataJobIDKey = "job_id"

// Payload is what a discovery_job command carries. It is everything the sensor
// needs to run the job without asking the platform anything else.
type Payload struct {
	JobID     string                 `json:"job_id"`
	TenantID  string                 `json:"tenant_id"`
	Targets   []string               `json:"targets"`
	Protocols []string               `json:"protocols"`
	Ports     []int                  `json:"ports"`
	Options   map[string]interface{} `json:"options,omitempty"`
}

// ToMap renders the payload as the generic map sensor_commands.payload stores
// and the sensor's Command.Payload decodes into.
func (p Payload) ToMap() map[string]interface{} {
	out := map[string]interface{}{
		"job_id":    p.JobID,
		"tenant_id": p.TenantID,
		"targets":   append([]string(nil), p.Targets...),
		"protocols": append([]string(nil), p.Protocols...),
		"ports":     append([]int(nil), p.Ports...),
	}
	if len(p.Options) > 0 {
		opts := make(map[string]interface{}, len(p.Options))
		for k, v := range p.Options {
			opts[k] = v
		}
		out["options"] = opts
	}
	return out
}

// ErrMalformedPayload is wrapped by every ParsePayload failure so the sensor
// can tell "the platform sent something I cannot run" from "I ran it and it
// failed", and answer the first with a failed acknowledgement rather than
// silence.
var ErrMalformedPayload = errors.New("malformed discovery_job payload")

// ParsePayload validates a command payload as it arrives at the sensor.
//
// Strict on purpose. A job with no targets, a port outside 1–65535 or an
// unparseable job id cannot be run, and the honest answer is to refuse it in
// a way the platform records — not to scan nothing and report success. Any
// caller that accepts the map shape (JSON numbers arrive as float64, Go
// callers hand over ints) is served.
func ParsePayload(m map[string]interface{}) (Payload, error) {
	var p Payload
	if m == nil {
		return p, fmt.Errorf("%w: payload is empty", ErrMalformedPayload)
	}

	jobID, _ := m["job_id"].(string)
	if _, err := uuid.Parse(strings.TrimSpace(jobID)); err != nil {
		return p, fmt.Errorf("%w: job_id %q is not a UUID", ErrMalformedPayload, jobID)
	}
	p.JobID = strings.TrimSpace(jobID)

	if tenantID, ok := m["tenant_id"].(string); ok {
		p.TenantID = strings.TrimSpace(tenantID)
	}

	targets, err := stringList(m["targets"])
	if err != nil {
		return p, fmt.Errorf("%w: targets: %v", ErrMalformedPayload, err)
	}
	if len(targets) == 0 {
		return p, fmt.Errorf("%w: targets is empty", ErrMalformedPayload)
	}
	p.Targets = targets

	if protocols, err := stringList(m["protocols"]); err != nil {
		return p, fmt.Errorf("%w: protocols: %v", ErrMalformedPayload, err)
	} else {
		p.Protocols = protocols
	}

	ports, err := intList(m["ports"])
	if err != nil {
		return p, fmt.Errorf("%w: ports: %v", ErrMalformedPayload, err)
	}
	for _, port := range ports {
		if port < 1 || port > 65535 {
			return p, fmt.Errorf("%w: port %d is out of range", ErrMalformedPayload, port)
		}
	}
	p.Ports = ports

	if opts, ok := m["options"].(map[string]interface{}); ok {
		p.Options = opts
	}
	return p, nil
}

func stringList(v interface{}) ([]string, error) {
	switch list := v.(type) {
	case nil:
		return nil, nil
	case []string:
		out := make([]string, 0, len(list))
		for _, s := range list {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	case []interface{}:
		out := make([]string, 0, len(list))
		for _, item := range list {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("entry %v is not a string", item)
			}
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected a list, got %T", v)
	}
}

func intList(v interface{}) ([]int, error) {
	switch list := v.(type) {
	case nil:
		return nil, nil
	case []int:
		return append([]int(nil), list...), nil
	case []interface{}:
		out := make([]int, 0, len(list))
		for _, item := range list {
			switch n := item.(type) {
			case int:
				out = append(out, n)
			case int64:
				out = append(out, int(n))
			case float64:
				if n != float64(int(n)) {
					return nil, fmt.Errorf("entry %v is not an integer", item)
				}
				out = append(out, int(n))
			default:
				return nil, fmt.Errorf("entry %v is not a number", item)
			}
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected a list, got %T", v)
	}
}

// Liveness.
//
// A sensor is live when it says it is (`status = active`) AND it has proved it
// recently — a heartbeat inside its liveness window. The window is derived from
// the sensor's own reporting cadence so a sensor configured to report every
// five minutes is not declared dead for being quiet for four, while one that
// reports every ten seconds is not carried as alive for a quarter of an hour
// after it stopped.
const (
	// DefaultLivenessWindow applies when the sensor never reported a cadence.
	// It matches sensor-manager's offline reaper, so "live" here and "offline"
	// there cannot disagree about a sensor with no reporting_interval.
	DefaultLivenessWindow = 5 * time.Minute
	// livenessMultiple is how many reporting intervals a sensor may miss.
	livenessMultiple  = 5
	minLivenessWindow = 3 * time.Minute
	maxLivenessWindow = 15 * time.Minute
)

// LivenessWindow is how long since its last heartbeat a sensor is still
// considered reachable, given its reporting interval in seconds (0 = unknown).
func LivenessWindow(reportingIntervalSeconds int) time.Duration {
	if reportingIntervalSeconds <= 0 {
		return DefaultLivenessWindow
	}
	window := time.Duration(reportingIntervalSeconds) * time.Second * livenessMultiple
	if window < minLivenessWindow {
		return minLivenessWindow
	}
	if window > maxLivenessWindow {
		return maxLivenessWindow
	}
	return window
}

// IsLive is the one liveness rule. Both the dispatcher (may this job be handed
// to this sensor?) and the router (may this target be assigned to this sensor?)
// call it, so a sensor cannot be "live enough to route to" and "too dead to
// dispatch to" at the same instant.
func IsLive(status string, lastHeartbeat *time.Time, reportingIntervalSeconds int, now time.Time) bool {
	if !strings.EqualFold(strings.TrimSpace(status), "active") {
		return false
	}
	if lastHeartbeat == nil || lastHeartbeat.IsZero() {
		return false
	}
	age := now.Sub(*lastHeartbeat)
	return age >= 0 && age < LivenessWindow(reportingIntervalSeconds)
}

// DispatchTimeout is how long a discovery_job command may sit unclaimed before
// the job is failed as "sensor offline". It is the liveness window: a sensor
// that was live at dispatch and does not collect the command within the time
// its own cadence promises has, by this package's definition, gone offline.
func DispatchTimeout(reportingIntervalSeconds int) time.Duration {
	return LivenessWindow(reportingIntervalSeconds)
}

// ExecutionTimeout bounds how long a sensor that DID collect a command may run
// it before the platform stops waiting. Generous: a thousand-target sweep on a
// slow link is legitimate work. It exists so a sensor that dies mid-job leaves
// a failed job with a reason, not one that says "awaiting sensor" forever.
const ExecutionTimeout = 2 * time.Hour

// Completion is what the sensor reports when a dispatched job finishes, through
// the sensor-authenticated completion callback.
type Completion struct {
	// Status is "completed" or "failed".
	Status string `json:"status"`
	// ErrorMessage says why, when Status is "failed".
	ErrorMessage string `json:"error_message,omitempty"`

	TotalTargets      int `json:"total_targets"`
	SuccessfulTargets int `json:"successful_targets"`
	FailedTargets     int `json:"failed_targets"`
	// DiscoveriesSubmitted is how many result rows the sensor pushed through
	// the discovery submission route for this job. Zero with Status
	// "completed" is a legitimate answer: every target was reachable and none
	// of them spoke a protocol the probe recognises.
	DiscoveriesSubmitted int `json:"discoveries_submitted"`
}

// Validate rejects a completion the platform must not record.
func (c Completion) Validate() error {
	switch c.Status {
	case "completed", "failed":
	default:
		return fmt.Errorf("status must be completed or failed, got %q", c.Status)
	}
	if c.TotalTargets < 0 || c.SuccessfulTargets < 0 || c.FailedTargets < 0 || c.DiscoveriesSubmitted < 0 {
		return errors.New("counts cannot be negative")
	}
	return nil
}

// SensorOfflineMessage is the error_message a job carries when its command
// expired before the sensor collected it. The wording is the product promise:
// nothing ran anywhere else.
func SensorOfflineMessage(sensorName string, lastHeartbeat *time.Time) string {
	msg := "sensor offline; nothing was scanned"
	if strings.TrimSpace(sensorName) != "" {
		msg = fmt.Sprintf("sensor %s offline; nothing was scanned", strings.TrimSpace(sensorName))
	}
	if lastHeartbeat != nil && !lastHeartbeat.IsZero() {
		msg += fmt.Sprintf(" (last heartbeat %s)", lastHeartbeat.UTC().Format(time.RFC3339))
	}
	return msg
}
