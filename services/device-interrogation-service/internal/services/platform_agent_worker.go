package services

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/redis/go-redis/v9"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	auditlog "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// PlatformAgentWorker is a background worker that processes device jobs for the platform.
// It listens for jobs via NATS JetStream (preferred) and falls back to DB polling.
type PlatformAgentWorker struct {
	db                  *sql.DB
	bypassDB            *sql.DB
	redis               *redis.Client
	jobQueue            *JobQueueService
	cloudService        *CloudDiscoveryService
	deviceService       *DeviceService
	deviceInterrogation *DeviceInterrogationService
	resultProcessor     *ResultProcessor
	natsClient          *events.NATSClient
	subscriber          *events.Subscriber
	ctx                 context.Context
	cancel              context.CancelFunc
	pollInterval        time.Duration
}

// NewPlatformAgentWorker creates a new platform agent worker. db is the
// RLS-scoped (crypto_app) connection; bypassDB is the BYPASSRLS (crypto_bypass)
// connection used by the cross-tenant job sweep (GetNextJobForPlatform) and the
// keyed-by-job-id status updates. Per-item work resolves job.TenantID and runs
// under WithTenantTx.
func NewPlatformAgentWorker(
	db *sql.DB,
	bypassDB *sql.DB,
	redis *redis.Client,
	cloudService *CloudDiscoveryService,
	deviceService *DeviceService,
	deviceInterrogation *DeviceInterrogationService,
) *PlatformAgentWorker {
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize NATS client for event-driven job processing
	var natsClient *events.NATSClient
	var subscriber *events.Subscriber
	nc, natsErr := events.NewNATSClient("")
	if natsErr != nil {
		log.Printf("[PlatformAgentWorker] Warning: NATS unavailable, using DB polling only: %v", natsErr)
	} else {
		natsClient = nc
		subscriber = events.NewSubscriber(nc)
	}

	return &PlatformAgentWorker{
		db:                  db,
		bypassDB:            bypassDB,
		redis:               redis,
		jobQueue:            NewJobQueueService(db, bypassDB, redis),
		cloudService:        cloudService,
		deviceService:       deviceService,
		deviceInterrogation: deviceInterrogation,
		resultProcessor:     NewResultProcessor(db, bypassDB),
		natsClient:          natsClient,
		subscriber:          subscriber,
		ctx:                 ctx,
		cancel:              cancel,
		pollInterval:        30 * time.Second, // Reduced polling frequency since NATS handles primary delivery
	}
}

// Start starts the platform agent worker with NATS subscription and DB polling fallback
func (w *PlatformAgentWorker) Start() {
	// Subscribe to NATS for instant job delivery
	if w.subscriber != nil {
		err := w.subscriber.Subscribe(events.SubscriptionConfig{
			Stream:            "DEVICE_JOBS",
			Subject:           events.SubjectDeviceJobsSubmit,
			Durable:           "device-job-processor",
			QueueGroup:        "device-interrogation",
			MaxDeliver:        3,
			AckWait:           6 * time.Minute,
			ProcessingTimeout: 5 * time.Minute,
		}, func(ctx context.Context, msg *nats.Msg) error {
			var jobEvent events.DeviceJobEvent
			if err := events.UnmarshalMsg(msg, &jobEvent); err != nil {
				log.Printf("[PlatformAgentWorker] Failed to unmarshal device job event: %v", err)
				return nil // Don't redeliver bad data
			}
			log.Printf("[PlatformAgentWorker] Received job %s via NATS", jobEvent.JobID)
			w.processNextJob() // Process the next available job from the DB
			return nil
		})
		if err != nil {
			log.Printf("[PlatformAgentWorker] Failed to subscribe to NATS: %v. Using DB polling only.", err)
		} else {
			log.Println("Platform agent worker started with NATS subscription + DB polling fallback")
		}
	} else {
		log.Println("Platform agent worker started with DB polling only")
	}

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	// Process immediately on start
	w.processNextJob()

	// DB polling fallback for missed events
	for {
		select {
		case <-w.ctx.Done():
			log.Println("Platform agent worker stopping...")
			return
		case <-ticker.C:
			w.processNextJob()
		}
	}
}

// Stop stops the platform agent worker
func (w *PlatformAgentWorker) Stop() {
	w.cancel()
	if w.subscriber != nil {
		w.subscriber.Drain()
	}
	if w.natsClient != nil {
		w.natsClient.Close()
	}
}

// processNextJob processes the next available job for the platform
func (w *PlatformAgentWorker) processNextJob() {
	// Use a longer timeout for cloud discovery jobs (5 minutes)
	// Cloud discovery can take time when scanning multiple resources across regions
	ctx, cancel := context.WithTimeout(w.ctx, 5*time.Minute)
	defer cancel()

	// Get next job for platform
	deviceJob, err := w.jobQueue.GetNextJobForPlatform(ctx)
	if err != nil {
		log.Printf("Error getting next job: %v", err)
		return
	}
	if deviceJob == nil {
		return // No job available
	}

	log.Printf("Processing job %s (type: %s)", deviceJob.ID, deviceJob.JobType)

	// Mark job as in progress
	err = w.jobQueue.UpdateJobStatus(ctx, deviceJob.ID, models.JobStatusInProgress, nil, nil)
	if err != nil {
		log.Printf("Error updating job status to in_progress: %v", err)
		return
	}

	// Start audit job-execution log so the Operations > Job Logs tab shows this job.
	auditURL := os.Getenv("AUDIT_SERVICE_URL")
	if auditURL == "" {
		auditURL = sharedconfig.PeerURL("audit-service", sharedconfig.MTLSEnabled())
	}
	tenantPtr := &deviceJob.TenantID
	jobLogger := auditlog.NewJobLogger(
		auditURL,
		deviceJob.ID,
		string(deviceJob.JobType),
		string(deviceJob.JobType),
		tenantPtr,
		nil, // no user context available at worker level
	)
	if _, logErr := jobLogger.LogStart(ctx, map[string]interface{}{
		"device_id":      deviceJob.DeviceID,
		"integration_id": deviceJob.IntegrationID,
	}); logErr != nil {
		log.Printf("[PlatformAgentWorker] Warning: failed to log job start for %s: %v", deviceJob.ID, logErr)
	}

	// Execute job based on type
	var result *models.JobResult
	switch deviceJob.JobType {
	case models.JobTypeCloudDiscovery:
		result, err = w.executeCloudDiscovery(ctx, deviceJob)
	case models.JobTypeDeviceInterrogation:
		result, err = w.executeDeviceInterrogation(ctx, deviceJob)
	default:
		err = fmt.Errorf("unknown job type: %s", deviceJob.JobType)
	}

	// Update job status and store results.
	// Use background context for status updates to avoid context deadline issues.
	updateCtx := context.Background()
	if err != nil {
		errorMsg := err.Error()
		log.Printf("Job %s failed: %v", deviceJob.ID, err)
		if updateErr := w.jobQueue.UpdateJobStatus(updateCtx, deviceJob.ID, models.JobStatusFailed, nil, &errorMsg); updateErr != nil {
			log.Printf("ERROR: Failed to update job status to failed for job %s: %v", deviceJob.ID, updateErr)
		}
		if logErr := jobLogger.LogCompletion(updateCtx, "failed", 0, 0, 1, &errorMsg, nil); logErr != nil {
			log.Printf("[PlatformAgentWorker] Warning: failed to log job failure for %s: %v", deviceJob.ID, logErr)
		}
	} else {
		log.Printf("Job %s completed successfully", deviceJob.ID)
		if updateErr := w.jobQueue.UpdateJobStatus(updateCtx, deviceJob.ID, models.JobStatusCompleted, result, nil); updateErr != nil {
			log.Printf("ERROR: Failed to update job status to completed for job %s: %v", deviceJob.ID, updateErr)
		}
		assetsCount := 0
		if result != nil {
			assetsCount = len(result.Assets)
		}
		if logErr := jobLogger.LogCompletion(updateCtx, "completed", assetsCount, assetsCount, 0, nil, nil); logErr != nil {
			log.Printf("[PlatformAgentWorker] Warning: failed to log job completion for %s: %v", deviceJob.ID, logErr)
		}

		// Process results to create discovery findings
		if result != nil && result.Success {
			err = w.resultProcessor.ProcessJobResults(updateCtx, deviceJob.ID, result)
			if err != nil {
				log.Printf("Warning: failed to process job results: %v", err)
			}
		}
	}
}

// executeCloudDiscovery executes a cloud discovery job
func (w *PlatformAgentWorker) executeCloudDiscovery(ctx context.Context, job *models.DeviceJob) (*models.JobResult, error) {
	// Extract integration_id from job (top-level field, not parameters)
	if job.IntegrationID == nil {
		return nil, fmt.Errorf("missing integration_id in job")
	}
	integrationID := *job.IntegrationID

	resourceTypes := []string{}
	if rt, ok := job.Parameters["resource_types"].([]interface{}); ok {
		for _, r := range rt {
			if str, ok := r.(string); ok {
				resourceTypes = append(resourceTypes, str)
			}
		}
	}

	regions := []string{}
	if r, ok := job.Parameters["regions"].([]interface{}); ok {
		for _, reg := range r {
			if str, ok := reg.(string); ok {
				regions = append(regions, str)
			}
		}
	}

	// Get master key from environment
	masterKey := os.Getenv("ENCRYPTION_MASTER_KEY")
	if masterKey == "" {
		return nil, fmt.Errorf("ENCRYPTION_MASTER_KEY not configured")
	}

	// Discover AWS resources
	devices, err := w.cloudService.DiscoverAWSResources(ctx, job.TenantID, integrationID, resourceTypes, regions)
	if err != nil {
		return nil, fmt.Errorf("failed to discover AWS resources: %w", err)
	}

	// Convert devices to discovered assets
	assets := []models.DiscoveredAsset{}
	for i := range devices {
		device := &devices[i]
		// Extract crypto configs from metadata
		if device.Metadata != nil {
			if configs, ok := device.Metadata["crypto_configs"].([]interface{}); ok {
				for _, cfgInterface := range configs {
					if cfg, ok := cfgInterface.(map[string]interface{}); ok {
						asset := w.convertCryptoConfigToAsset(device, cfg)
						if asset != nil {
							assets = append(assets, *asset)
						}
					}
				}
			}
		}
	}

	result := &models.JobResult{
		JobID:       job.ID,
		Success:     true,
		Assets:      assets,
		CompletedAt: time.Now(),
		Metadata: map[string]interface{}{
			"devices_count": len(devices),
			"assets_count":  len(assets),
		},
	}

	return result, nil
}

// executeDeviceInterrogation executes a device interrogation job
func (w *PlatformAgentWorker) executeDeviceInterrogation(ctx context.Context, job *models.DeviceJob) (*models.JobResult, error) {
	if job.DeviceID == nil {
		return nil, fmt.Errorf("device_id is required for device interrogation")
	}

	// Get device (scoped to the job's resolved tenant).
	device, err := w.deviceService.GetDevice(ctx, job.TenantID, *job.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to get device: %w", err)
	}

	// Get master key from environment
	masterKey := os.Getenv("ENCRYPTION_MASTER_KEY")
	if masterKey == "" {
		return nil, fmt.Errorf("ENCRYPTION_MASTER_KEY not configured")
	}

	// Use system user ID for device-initiated jobs
	systemUserID := uuid.MustParse("00000000-0000-0000-0000-000000000000")

	// Interrogate device using device interrogation service
	// This will create a discovery job and return findings
	_, err = w.deviceInterrogation.InterrogateDevice(ctx, job.TenantID, systemUserID, *job.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("failed to interrogate device: %w", err)
	}

	// For now, return success result
	// The actual assets will be created through the discovery integration
	result := &models.JobResult{
		JobID:       job.ID,
		Success:     true,
		Assets:      []models.DiscoveredAsset{}, // Assets created via discovery integration
		CompletedAt: time.Now(),
		Metadata: map[string]interface{}{
			"device_id":   device.ID.String(),
			"device_type": device.DeviceType,
		},
	}

	return result, nil
}

// convertCryptoConfigToAsset converts a crypto config from device metadata to a DiscoveredAsset
func (w *PlatformAgentWorker) convertCryptoConfigToAsset(device *models.Device, cfg map[string]interface{}) *models.DiscoveredAsset {
	asset := &models.DiscoveredAsset{
		Metadata: make(map[string]interface{}),
	}

	// Extract hostname
	if hostname, ok := cfg["hostname"].(string); ok {
		asset.Hostname = hostname
	} else if device.Hostname != nil {
		asset.Hostname = *device.Hostname
	}

	// Extract IP address
	if ip, ok := cfg["ip_address"].(string); ok {
		asset.IPAddress = ip
	} else if device.IPAddress != nil {
		asset.IPAddress = *device.IPAddress
	}

	// Extract port
	if port, ok := cfg["port"].(float64); ok {
		asset.Port = int(port)
	} else {
		asset.Port = 443 // Default
	}

	// Extract protocol
	if protocol, ok := cfg["protocol"].(string); ok {
		asset.Protocol = protocol
	} else {
		asset.Protocol = "TLS"
	}

	// Extract protocol version
	if version, ok := cfg["protocol_version"].(string); ok {
		asset.ProtocolVersion = version
	}

	// Extract cipher suite
	if cipher, ok := cfg["cipher_suite"].(string); ok {
		asset.CipherSuite = cipher
	}

	// Extract key size
	if keySize, ok := cfg["key_size"].(float64); ok {
		asset.KeySize = int(keySize)
	}

	// Extract certificate info
	if cert, ok := cfg["certificate"].(map[string]interface{}); ok {
		certInfo := &models.CertificateInfo{}
		if subject, ok := cert["subject_dn"].(string); ok {
			certInfo.SubjectDN = subject
		}
		if issuer, ok := cert["issuer_dn"].(string); ok {
			certInfo.IssuerDN = issuer
		}
		if serial, ok := cert["serial_number"].(string); ok {
			certInfo.SerialNumber = serial
		}
		if fingerprint, ok := cert["fingerprint"].(string); ok {
			certInfo.Fingerprint = fingerprint
		}
		asset.Certificate = certInfo
	}

	// Store device metadata
	asset.Metadata["device_id"] = device.ID.String()
	asset.Metadata["device_type"] = device.DeviceType
	if device.Vendor != nil {
		asset.Metadata["vendor"] = *device.Vendor
	}

	return asset
}
