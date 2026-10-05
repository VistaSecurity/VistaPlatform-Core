package main

// Planned discovery jobs on this sensor ( WP2b; holes H10, H31).
//
// A discovery_job command whose payload carries a plan (scan depth, ports,
// pace) is run on the shared engine by shared/sensordispatch/planrun — the
// same per-host pipeline the Platform Sensor runs — and every host is reported
// to the platform as it finishes, so nothing is held past the host that
// produced it, the platform shows real progress, and a sensor that dies
// mid-scan loses only the hosts in flight. This sensor says it can do this by
// reporting sensordispatch.ScanPlanCapability on its heartbeat; the platform
// hands a plan to no sensor that does not.
//
// The scan touches only addresses this sensor's own rules allow
// (planrun.SensorRule over the owned-network scope the platform delivers on
// every heartbeat): never reserved ranges, never an excluded prefix, only the
// tenant's own networks — checked before any packet, liveness included.
//
// Cancel reaches the run two ways: the answer to its next report (the run
// stops at once and discards what it has not reported), and a
// cancel_discovery_job command on a heartbeat, which also drops a job still
// waiting in the queue.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch/planrun"
)

// planJobClient is what a planned job needs of the control plane.
type planJobClient interface {
	ReportDiscoveryJobUnits(jobID string, batch sensordispatch.UnitBatch) (sensordispatch.UnitBatchResponse, error)
	CompleteDiscoveryJob(jobID string, completion sensordispatch.Completion) error
	AcknowledgeCommand(commandID string, response *models.CommandResponse) error
}

// errCancelledByCommand is the cause a run is stopped with when a
// cancel_discovery_job command names it.
var errCancelledByCommand = errors.New("cancelled by the platform")

// maxRememberedCancels bounds the queued-job cancels held for the worker.
// The queue holds at most discoveryJobQueueDepth jobs; anything beyond that
// names a job this sensor will never see.
const maxRememberedCancels = 64

// planJobState is the running planned job's cancel and the queued jobs a
// cancel arrived for.
type planJobState struct {
	running   string
	cancel    context.CancelCauseFunc
	cancelled map[string]bool
}

// startPlanJob registers jobID as running, or reports false when a cancel for
// it arrived while it waited in the queue.
func (s *Sensor) startPlanJob(jobID string, cancel context.CancelCauseFunc) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.planJobs.cancelled[jobID] {
		delete(s.planJobs.cancelled, jobID)
		return false
	}
	s.planJobs.running, s.planJobs.cancel = jobID, cancel
	return true
}

func (s *Sensor) finishPlanJob(jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.planJobs.running == jobID {
		s.planJobs.running, s.planJobs.cancel = "", nil
	}
}

// cancelPlanJob stops jobID if it is running, else remembers it so the worker
// drops it when its turn comes. It reports what it did.
func (s *Sensor) cancelPlanJob(jobID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.planJobs.running == jobID && s.planJobs.cancel != nil {
		s.planJobs.cancel(errCancelledByCommand)
		return "stopped the running job"
	}
	if s.planJobs.cancelled == nil {
		s.planJobs.cancelled = map[string]bool{}
	}
	if len(s.planJobs.cancelled) >= maxRememberedCancels {
		for k := range s.planJobs.cancelled {
			delete(s.planJobs.cancelled, k)
			break
		}
	}
	s.planJobs.cancelled[jobID] = true
	return "the job will not be started"
}

// handleCancelDiscoveryJob answers a cancel_discovery_job command.
func (s *Sensor) handleCancelDiscoveryJob(command models.Command) *models.CommandResponse {
	jobID, _ := command.Payload["job_id"].(string)
	resp := &models.CommandResponse{ID: uuid.New(), CommandID: command.ID, SensorID: s.config.SensorID, Timestamp: time.Now()}
	if _, err := uuid.Parse(jobID); err != nil {
		resp.Status, resp.Message = "error", fmt.Sprintf("cancel_discovery_job: job_id %q is not a UUID", jobID)
		return resp
	}
	what := s.cancelPlanJob(jobID)
	log.Printf("🛑 Discovery job %s cancelled by the platform: %s", jobID, what)
	resp.Status, resp.Message = "success", "Discovery job cancelled: "+what
	resp.ResponseData = map[string]interface{}{"job_id": jobID}
	return resp
}

// planClientFor is the control-plane client a planned job reports through.
func (s *Sensor) planClientFor() planJobClient {
	if s.planClient != nil {
		return s.planClient
	}
	if s.apiClient != nil && !s.config.TestMode {
		return s.apiClient
	}
	return nil
}

// planReporter delivers a planned job's reports through the client.
type planReporter struct {
	client planJobClient
	jobID  string
}

func (r planReporter) Report(_ context.Context, units []sensordispatch.UnitResult) error {
	_, err := r.client.ReportDiscoveryJobUnits(r.jobID, sensordispatch.UnitBatch{Units: units})
	return err
}

// executePlanJob runs one planned job end to end. Reports went out host by
// host; this reports completion and acknowledges the command, unless the
// platform stopped the job, which needs neither.
func (s *Sensor) executePlanJob(command models.Command, payload sensordispatch.Payload) {
	jobID := payload.JobID
	client := s.planClientFor()
	ack := func(status, message string, data map[string]interface{}) {
		if client == nil {
			return
		}
		if err := client.AcknowledgeCommand(command.ID, &models.CommandResponse{
			ID: uuid.New(), CommandID: command.ID, SensorID: s.config.SensorID,
			Status: status, Message: message, ResponseData: data, Timestamp: time.Now(),
		}); err != nil {
			log.Printf("❌ Failed to acknowledge discovery job command %s: %v", command.ID, err)
		}
	}
	if client == nil {
		log.Printf("❌ Planned discovery job %s refused: no control-plane client to report its hosts to", jobID)
		return
	}

	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	if !s.startPlanJob(jobID, cancel) {
		log.Printf("🛑 Planned discovery job %s was cancelled before it started; dropped", jobID)
		ack("error", "Discovery job cancelled before it started", map[string]interface{}{"job_id": jobID, "cancelled": true})
		return
	}
	defer s.finishPlanJob(jobID)

	started := time.Now()
	log.Printf("🔍 Running planned discovery job %s (command %s): %d target(s), attempt %d, pace %s",
		jobID, command.ID, len(payload.Plan.Targets), payload.Plan.Attempt, payload.Plan.Pace)
	sum, err := planrun.Run(ctx, *payload.Plan, planrun.Config{
		Allow:    planrun.SensorRule(func() probeconsent.Scope { return s.owned().Scope() }),
		Reporter: planReporter{client: client, jobID: jobID},
		Dialer:   s.planDialer,
	})
	if errors.Is(err, planrun.ErrJobStopped) || errors.Is(context.Cause(ctx), errCancelledByCommand) {
		// Cancelled or ended on the platform: it already says so, and
		// nothing more is reported for it.
		log.Printf("🛑 Planned discovery job %s stopped after %s: %d host(s) reported done, %d failed", jobID, time.Since(started).Round(time.Second), sum.Done, sum.Failed)
		ack("error", "Discovery job stopped: the platform cancelled or ended it", map[string]interface{}{"job_id": jobID, "stopped": true})
		return
	}

	completion := sensordispatch.Completion{
		Status: "completed", TotalTargets: sum.Units, SuccessfulTargets: sum.Done, FailedTargets: sum.Failed + sum.Unreported,
	}
	if err != nil {
		completion.Status, completion.ErrorMessage = "failed", err.Error()
	} else if sum.Unreported > 0 {
		completion.ErrorMessage = fmt.Sprintf("%d host result(s) could not be reported", sum.Unreported)
	}
	log.Printf("📤 Planned discovery job %s %s in %s: %d host(s) done, %d failed, %d unreported",
		jobID, completion.Status, time.Since(started).Round(time.Second), sum.Done, sum.Failed, sum.Unreported)
	if err := client.CompleteDiscoveryJob(jobID, completion); err != nil {
		// The platform's lease fails the job on its own; the hosts already
		// reported are stored either way.
		log.Printf("❌ Failed to report completion of discovery job %s: %v", jobID, err)
		s.recordError()
	}
	status := "success"
	if completion.Status == "failed" {
		status = "error"
	} else if completion.ErrorMessage != "" {
		status = "partial"
	}
	ack(status, completionMessage(completion), map[string]interface{}{
		"job_id": jobID, "status": completion.Status, "total_targets": completion.TotalTargets,
		"successful_targets": completion.SuccessfulTargets, "failed_targets": completion.FailedTargets,
	})
}
