package discovery

import (
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// JobExecutor handles discovery job execution
type JobExecutor struct {
	prober   *ActiveProber
	sensorID string
}

// NewJobExecutor creates a new job executor.
// sensorID is included in all job responses so the platform can attribute results.
func NewJobExecutor(timeout time.Duration, sensorID string) *JobExecutor {
	return &JobExecutor{
		prober:   NewActiveProber(timeout),
		sensorID: sensorID,
	}
}

// SetSensorID updates the sensor ID (called after registration completes)
func (e *JobExecutor) SetSensorID(id string) {
	e.sensorID = id
}

// ExecuteJob executes a discovery job
func (e *JobExecutor) ExecuteJob(job *models.DiscoveryJobRequest) *models.DiscoveryJobResponse {
	response := &models.DiscoveryJobResponse{
		JobID:        job.JobID,
		SensorID:     e.sensorID,
		Status:       "completed",
		TotalTargets: len(job.Targets),
		CreatedAt:    time.Now(),
	}

	// If active scanning is explicitly disabled, return immediately with no results
	if job.Options.ActiveScanning != nil && !*job.Options.ActiveScanning {
		log.Printf("Active scanning disabled for job %s, skipping probes", job.JobID)
		response.Status = "completed"
		response.CompletedAt = time.Now()
		response.ExecutionTime = 0
		return response
	}

	// Set concurrency limit
	concurrency := job.Options.Concurrency
	if concurrency <= 0 {
		concurrency = 10 // Default
	}

	// Create semaphore for concurrency control
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Build the scan task list. CIDR/range targets expand into per-host sweeps
	// ("find listeners + identify crypto"); a single host with explicit
	// protocols+ports uses the targeted (lite) probe; a bare host with no
	// protocols/ports is swept on the default crypto port set.
	sweepPorts := job.Ports
	if len(sweepPorts) == 0 {
		sweepPorts = shareddisc.DefaultCryptoPorts()
	}
	liteMode := len(job.Protocols) > 0 && len(job.Ports) > 0

	type scanTask struct {
		host  string
		sweep bool
	}
	var tasks []scanTask
	for _, target := range job.Targets {
		if shareddisc.IsNetworkRange(target) {
			for _, host := range shareddisc.ExpandTargets([]string{target}) {
				tasks = append(tasks, scanTask{host: host, sweep: true})
			}
		} else if liteMode {
			tasks = append(tasks, scanTask{host: target, sweep: false})
		} else {
			tasks = append(tasks, scanTask{host: target, sweep: true})
		}
	}
	response.TotalTargets = len(tasks)

	// Process tasks concurrently
	for _, task := range tasks {
		wg.Add(1)
		go func(t scanTask) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			var result *models.DiscoveryJobResult
			if t.sweep {
				findings := e.prober.SweepHost(t.host, sweepPorts, job.Options)
				status, errCode := "success", ""
				if len(findings) == 0 {
					status, errCode = "failed", "no_findings"
				}
				result = &models.DiscoveryJobResult{
					Target:      t.host,
					Status:      status,
					ExecutedVia: "sensor",
					Findings:    findings,
					ErrorCode:   errCode,
					CreatedAt:   time.Now(),
				}
			} else {
				var err error
				result, err = e.prober.ProbeTarget(t.host, job.Protocols, job.Ports, job.Options)
				if err != nil {
					log.Printf("Failed to probe target %s: %v", t.host, err)
					result = &models.DiscoveryJobResult{
						Target:       t.host,
						Status:       "failed",
						ExecutedVia:  "sensor",
						ErrorCode:    "probe_error",
						ErrorMessage: err.Error(),
						CreatedAt:    time.Now(),
					}
				}
			}

			// Add result to response
			mu.Lock()
			response.Results = append(response.Results, *result)
			if result.Status == "success" {
				response.SuccessfulTargets++
			} else {
				response.FailedTargets++
			}
			mu.Unlock()
		}(task)
	}

	// Wait for all probes to complete
	wg.Wait()

	// Set final status
	if response.SuccessfulTargets == 0 {
		response.Status = "failed"
	} else if response.FailedTargets > 0 {
		response.Status = "partial"
	}

	response.CompletedAt = time.Now()
	response.ExecutionTime = response.CompletedAt.Sub(response.CreatedAt).Milliseconds()

	return response
}

// ProcessDiscoveryJobCommand processes a discovery job command
func (e *JobExecutor) ProcessDiscoveryJobCommand(command *models.Command) (*models.DiscoveryJobResponse, error) {
	// Extract job details from command payload
	jobID, ok := command.Payload["job_id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing job_id in command payload")
	}

	tenantID, ok := command.Payload["tenant_id"].(string)
	if !ok {
		return nil, fmt.Errorf("missing tenant_id in command payload")
	}

	targets, ok := command.Payload["targets"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("missing targets in command payload")
	}

	protocols, ok := command.Payload["protocols"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("missing protocols in command payload")
	}

	ports, ok := command.Payload["ports"].([]interface{})
	if !ok {
		return nil, fmt.Errorf("missing ports in command payload")
	}

	// Convert targets
	var targetStrings []string
	for _, t := range targets {
		if ts, ok := t.(string); ok {
			targetStrings = append(targetStrings, ts)
		}
	}

	// Convert protocols
	var protocolStrings []string
	for _, p := range protocols {
		if ps, ok := p.(string); ok {
			protocolStrings = append(protocolStrings, ps)
		}
	}

	// Convert ports
	var portInts []int
	for _, p := range ports {
		switch v := p.(type) {
		case int:
			portInts = append(portInts, v)
		case float64:
			portInts = append(portInts, int(v))
		}
	}

	// Extract options
	options := models.DiscoveryOptions{
		Concurrency:    10,
		TimeoutSeconds: 30,
		RetryCount:     2,
		RespectRobots:  false,
		BannerGrabbing: true,
		FollowDNS:      true,
	}

	if opts, ok := command.Payload["options"].(map[string]interface{}); ok {
		if c, ok := opts["concurrency"].(float64); ok {
			options.Concurrency = int(c)
		}
		if t, ok := opts["timeout_seconds"].(float64); ok {
			options.TimeoutSeconds = int(t)
		}
		if r, ok := opts["retry_count"].(float64); ok {
			options.RetryCount = int(r)
		}
		if rb, ok := opts["respect_robots"].(bool); ok {
			options.RespectRobots = rb
		}
		if bg, ok := opts["banner_grabbing"].(bool); ok {
			options.BannerGrabbing = bg
		}
		if fd, ok := opts["follow_dns"].(bool); ok {
			options.FollowDNS = fd
		}
		if as, ok := opts["active_scanning"].(bool); ok {
			options.ActiveScanning = &as
		}
	}

	// Create job request
	job := &models.DiscoveryJobRequest{
		JobID:             jobID,
		TenantID:          tenantID,
		Targets:           targetStrings,
		Protocols:         protocolStrings,
		Ports:             portInts,
		Options:           options,
		RetentionCapMB:    25,
		RetentionTTLHours: 24,
		CreatedAt:         time.Now(),
	}

	// Execute job
	response := e.ExecuteJob(job)
	return response, nil
}
