package main

// Dispatched discovery jobs: the sensor's side of "run this scan from
// the sensor that can actually see the host".
//
// The command arrives on a heartbeat like every other command. It is validated
// on the spot — a payload nothing can run is acknowledged as FAILED right away,
// so the platform records the refusal instead of waiting for a completion
// that never comes — and then queued for the job worker, which runs one job at
// a time. Results go out through the ordinary discovery batch route (the same
// one passive observations use), completion through the sensor-authenticated
// callback, and only then is the command acknowledged, with the counts.

import (
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor/internal/discovery"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// discoveryJobQueueDepth bounds how many dispatched jobs may wait behind the
// one running. Small on purpose: the platform dispatches a job per sweep per
// sensor, and a backlog deeper than this means something upstream is wrong.
const discoveryJobQueueDepth = 8

// discoverySubmitBatch is how many result rows go in one discovery submission.
// Matches StoreDiscoveries' own multi-value insert batch, so one request never
// carries more than the server would split anyway.
const discoverySubmitBatch = 100

// startDiscoveryJobWorker creates the queue and starts the single worker.
// Idempotent, so a restart-in-place cannot start two.
func (s *Sensor) startDiscoveryJobWorker() {
	s.mu.Lock()
	if s.jobQueue != nil {
		s.mu.Unlock()
		return
	}
	s.jobQueue = make(chan models.Command, discoveryJobQueueDepth)
	queue := s.jobQueue
	s.mu.Unlock()
	go s.runDiscoveryJobs(queue)
}

// handleDiscoveryJob validates and queues a discovery_job command.
//
// Returns a FAILED acknowledgement for a command that cannot be run (malformed
// payload, no executor, queue full) and nil for one that was accepted — the
// worker acknowledges that one when the job finishes.
func (s *Sensor) handleDiscoveryJob(command models.Command) *models.CommandResponse {
	if _, err := discovery.ParseDiscoveryJobCommand(&command); err != nil {
		log.Printf("❌ Discovery job command %s refused: %v", command.ID, err)
		return s.discoveryJobRefusal(command, err.Error())
	}
	if s.jobExecutor == nil {
		return s.discoveryJobRefusal(command, "sensor has no discovery job executor")
	}
	s.mu.RLock()
	queue := s.jobQueue
	s.mu.RUnlock()
	if queue == nil {
		return s.discoveryJobRefusal(command, "sensor job worker is not running")
	}
	select {
	case queue <- command:
		log.Printf("📥 Discovery job command %s queued (%d waiting)", command.ID, len(queue))
		return nil
	default:
		return s.discoveryJobRefusal(command, fmt.Sprintf("sensor busy: %d discovery jobs already queued", cap(queue)))
	}
}

func (s *Sensor) discoveryJobRefusal(command models.Command, reason string) *models.CommandResponse {
	return &models.CommandResponse{
		ID:           uuid.New(),
		CommandID:    command.ID,
		SensorID:     s.config.SensorID,
		Status:       "error",
		Message:      reason,
		ResponseData: map[string]interface{}{"refused": true, "reason": reason},
		Timestamp:    time.Now(),
	}
}

// runDiscoveryJobs is the worker: one job at a time, for the life of the
// process.
func (s *Sensor) runDiscoveryJobs(queue <-chan models.Command) {
	for command := range queue {
		s.executeDiscoveryJob(command)
	}
}

// executeDiscoveryJob runs one dispatched job end to end: probe, submit the
// results as ordinary discoveries, report completion, acknowledge the command.
func (s *Sensor) executeDiscoveryJob(command models.Command) {
	started := time.Now()
	jobID, _ := command.Payload["job_id"].(string)
	log.Printf("🔍 Running dispatched discovery job %s (command %s)", jobID, command.ID)

	response, err := s.jobExecutor.ProcessDiscoveryJobCommand(&command)
	if err != nil {
		// Parse errors were caught at queue time; this is "could not run".
		s.finishDiscoveryJob(command, jobID, nil, 0, 0, err)
		return
	}
	if jobID == "" {
		jobID = response.JobID
	}

	discoveries := discovery.DiscoveriesForJob(response, s.config.SensorID, time.Now())
	submitted, submitErr := s.submitJobDiscoveries(discoveries)
	log.Printf("📤 Discovery job %s: %d/%d target(s) answered, %d result(s), %d submitted in %s",
		jobID, response.SuccessfulTargets, response.TotalTargets, len(discoveries), submitted, time.Since(started).Round(time.Millisecond))
	s.finishDiscoveryJob(command, jobID, response, len(discoveries), submitted, submitErr)
}

// submitJobDiscoveries pushes the results through the ordinary discovery
// route in batches, returning how many rows were accepted. In test mode the
// rows go to the test log like every other discovery.
func (s *Sensor) submitJobDiscoveries(discoveries []*models.CryptoDiscovery) (int, error) {
	if len(discoveries) == 0 {
		return 0, nil
	}
	if s.config.TestMode && s.testLogger != nil {
		logged := 0
		for _, d := range discoveries {
			if err := s.testLogger.LogDiscovery(d); err != nil {
				return logged, err
			}
			logged++
		}
		return logged, nil
	}
	if s.apiClient == nil {
		return 0, fmt.Errorf("no control-plane client")
	}
	submitted := 0
	var firstErr error
	for start := 0; start < len(discoveries); start += discoverySubmitBatch {
		end := start + discoverySubmitBatch
		if end > len(discoveries) {
			end = len(discoveries)
		}
		if err := s.apiClient.SubmitDiscoveries(discoveries[start:end]); err != nil {
			log.Printf("❌ Discovery job results batch %d-%d failed to submit: %v", start, end, err)
			s.recordError()
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		submitted += end - start
	}
	return submitted, firstErr
}

// finishDiscoveryJob reports completion to the platform and acknowledges the
// command with the same counts.
func (s *Sensor) finishDiscoveryJob(command models.Command, jobID string, response *models.DiscoveryJobResponse, discoveries, submitted int, runErr error) {
	completion := discovery.SummarizeJob(response, discoveries, submitted, runErr)
	if response == nil && runErr != nil {
		completion.ErrorMessage = runErr.Error()
	}

	if s.apiClient != nil && !s.config.TestMode {
		if err := s.apiClient.CompleteDiscoveryJob(jobID, completion); err != nil {
			// The platform's stale-dispatch sweep fails the job on its own
			// after the execution timeout, naming this sensor; the results
			// already went through the discovery route, so nothing is lost
			// but the tidy status.
			log.Printf("❌ Failed to report completion of discovery job %s: %v", jobID, err)
			s.recordError()
		}
	}

	status := "success"
	if completion.Status == "failed" {
		status = "error"
	} else if completion.ErrorMessage != "" {
		status = "partial"
	}
	ack := &models.CommandResponse{
		ID:        uuid.New(),
		CommandID: command.ID,
		SensorID:  s.config.SensorID,
		Status:    status,
		Message:   completionMessage(completion),
		ResponseData: map[string]interface{}{
			"job_id":                jobID,
			"status":                completion.Status,
			"total_targets":         completion.TotalTargets,
			"successful_targets":    completion.SuccessfulTargets,
			"failed_targets":        completion.FailedTargets,
			"discoveries_submitted": completion.DiscoveriesSubmitted,
		},
		Timestamp: time.Now(),
	}
	if s.apiClient != nil && !s.config.TestMode {
		if err := s.apiClient.AcknowledgeCommand(command.ID, ack); err != nil {
			log.Printf("❌ Failed to acknowledge discovery job command %s: %v", command.ID, err)
		}
	}
}

func completionMessage(c sensordispatch.Completion) string {
	if c.Status == "failed" {
		return "Discovery job failed: " + c.ErrorMessage
	}
	msg := fmt.Sprintf("Discovery job completed: %d/%d target(s) answered, %d result(s) submitted",
		c.SuccessfulTargets, c.TotalTargets, c.DiscoveriesSubmitted)
	if c.ErrorMessage != "" {
		msg += " (" + c.ErrorMessage + ")"
	}
	return msg
}
