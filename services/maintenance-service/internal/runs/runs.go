// Package runs is maintenance-service's run machinery: a run row in
// platform_maintenance_runs is what the admin console shows, a Kubernetes Job
// is what executes it, and the Runner keeps the two in step.
//
// The Runner creates the row, launches the Job, follows it (per-step status
// and a bounded log tail read from the Job pod's log), runs the service-side
// steps that come after the Job (a Finalizer per run kind), and settles the
// row. On boot it reconciles: every row still `running` is matched to its Job
// by name and either resumed or settled from the Job's status. That is how a
// run survives the service restarting under it — which the update run (WP4)
// does by design, since it upgrades the service itself.
//
// One run at a time: the database refuses a second `running` row
// (platform_maintenance_runs_one_running), and Begin returns ErrRunInProgress.
package runs

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Kind is platform_maintenance_runs.kind.
type Kind string

const (
	KindBackup   Kind = "backup"
	KindUpdate   Kind = "update"
	KindRollback Kind = "rollback"
)

// Status is platform_maintenance_runs.status.
type Status string

const (
	StatusRunning   Status = "running"
	StatusSucceeded Status = "succeeded"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// Step statuses.
const (
	StepPending   = "pending"
	StepRunning   = "running"
	StepSucceeded = "succeeded"
	StepFailed    = "failed"
	StepSkipped   = "skipped"
)

// Who executes a step.
const (
	ExecutorJob     = "job"     // the Kubernetes Job, reported through VISTA_STEP log markers
	ExecutorService = "service" // maintenance-service, after the Job ended (the Finalizer)
)

// Step is one entry of platform_maintenance_runs.steps.
type Step struct {
	Name       string     `json:"name"`
	Executor   string     `json:"executor"`
	Status     string     `json:"status"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	// LogTail is the last lines of what the step printed, bounded by the
	// Runner (MaxLogTailBytes). Never more than a tail: the full log stays in
	// the cluster for as long as the Job's pod does.
	LogTail string `json:"log_tail,omitempty"`
	Error   string `json:"error,omitempty"`
	// Detail is a machine-readable note on HOW a step ended when the status
	// alone does not say it — e.g. "skipped_by_operator" on an update's backup
	// step when the operator ticked "I have my own backup" (D4).
	Detail string `json:"detail,omitempty"`
}

// StepDef declares a step when a run begins.
type StepDef struct {
	Name     string
	Executor string
}

// Run is one row of platform_maintenance_runs.
type Run struct {
	ID          uuid.UUID  `json:"id"`
	Kind        Kind       `json:"kind"`
	Status      Status     `json:"status"`
	StartedBy   *uuid.UUID `json:"started_by"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  *time.Time `json:"finished_at"`
	FromVersion string     `json:"from_version,omitempty"`
	ToVersion   string     `json:"to_version,omitempty"`
	JobName     string     `json:"k8s_job_name,omitempty"`
	Steps       []Step     `json:"steps"`
	Error       string     `json:"error,omitempty"`
}

// FailedStep names the first failed step, or "" when none failed.
func (r Run) FailedStep() string {
	for _, s := range r.Steps {
		if s.Status == StepFailed {
			return s.Name
		}
	}
	return ""
}

var (
	// ErrRunInProgress: a run is already `running`; only one at a time.
	ErrRunInProgress = errors.New("runs: a maintenance run is already in progress")
	// ErrNotFound: no run with that id.
	ErrNotFound = errors.New("runs: run not found")
)

// LabelRunID labels every Job (and so its pod) the Runner launches with the
// run it executes.
const LabelRunID = "vistasecurity.io/maintenance-run"
