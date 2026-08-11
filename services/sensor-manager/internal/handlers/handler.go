package handlers

import (
	"database/sql"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/version"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
)

// legacySensorService is the slice of *services.SensorService the handlers
// depend on. Declaring it as an interface (the concrete service still satisfies
// it) lets the contract test drive the real handlers with an in-memory stub —
// no database — per the spec-first contract recipe (ADR-0001).
//
// GetDB() leaks the raw *sql.DB because several legacy handlers (health-history,
// discoveries) still run inline SQL rather than going through a service method;
// it is here only so those (un-specced) handlers compile against the interface.
type legacySensorService interface {
	AcknowledgeCommand(sensorID, commandID string, response *models.CommandResponse) error
	CountPendingSensors(tenantID uuid.UUID) (int, error)
	CreatePendingSensor(registration *models.PendingSensorRegistration) error
	DeletePendingSensor(registrationKey string) error
	GetDB() *sql.DB
	GetBypassDB() *sql.DB
	GetPendingCommands(sensorID string) ([]models.Command, error)
	GetPendingSensorByKey(registrationKey string) (*models.PendingSensorRegistration, error)
	GetPendingSensors(tenantID uuid.UUID) ([]models.PendingSensorRegistration, error)
	GetSensor(sensorID uuid.UUID) (*models.Sensor, error)
	GetSensorConfig(sensorID string) (*models.SensorConfig, error)
	GetWebhookConfig(sensorID string) (*models.WebhookConfig, error)
	MarkCommandsAsDelivered(sensorID string, commandIDs []string) error
	RegisterSensor(registration *models.SensorRegistration) (*models.Sensor, error)
	StoreAirGappedExport(export *models.AirGappedExport) error
	StoreDiscoveries(batch *models.DiscoveryBatch) error
	UpdateSensor(sensor *models.Sensor) error
	UpdateSensorHealth(sensorID string, health *models.SensorHealth) error
	UpdateSensorHealthWithIP(sensorID string, health *models.SensorHealth, ipAddress *string) error
}

// pcapStore is the slice of *services.PcapService the pcap handlers depend on.
// Declaring it as an interface (the concrete service still satisfies it) lets
// the contract test drive the real handlers with an in-memory stub — no
// database — per the spec-first contract recipe (ADR-0001).
type pcapStore interface {
	GetMaxUploadSize() (int, error)
	CreateJob(tenantID, uploadedBy uuid.UUID, filename string, fileSize int64, filePath string) (*models.PcapUploadJob, error)
	ListJobs(tenantID uuid.UUID, page, limit int, status string) ([]models.PcapUploadJob, int, error)
	GetJob(tenantID, jobID uuid.UUID) (*models.PcapUploadJob, error)
	DeleteJob(tenantID, jobID uuid.UUID) error
	UpdateJobStatus(jobID uuid.UUID, status string, updates map[string]interface{}) error
}

// Handler contains all the handler functions
type Handler struct {
	sensorService       legacySensorService
	sensorServiceV2     *services.SensorServiceV2
	repo                database.SensorRepository
	db                  *sql.DB // Added for platform-level queries
	s3Downloader        *services.S3Downloader
	discoveryJobService *services.DiscoveryJobService
	pcapService         pcapStore
	natsClient          *events.NATSClient
	encryptionKey       string // Encryption master key for CA certificate encryption
	log                 *logrus.Logger
}

// NewHandler creates a new handler instance with old service (for fallback)
func NewHandler(sensorService *services.SensorService) *Handler {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	return &Handler{
		sensorService: sensorService,
		log:           logger,
	}
}

// NewHandlerWithService creates a new handler instance with new service and repository
func NewHandlerWithService(sensorServiceV2 *services.SensorServiceV2, repo database.SensorRepository) *Handler {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	return &Handler{
		sensorServiceV2: sensorServiceV2,
		repo:            repo,
		log:             logger,
	}
}

// NewHandlerWithBoth creates a new handler instance with both legacy and v2 services
func NewHandlerWithBoth(sensorService *services.SensorService, sensorServiceV2 *services.SensorServiceV2, repo database.SensorRepository, db *sql.DB) *Handler {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	return &Handler{
		sensorService:       sensorService,
		sensorServiceV2:     sensorServiceV2,
		repo:                repo,
		db:                  db,
		s3Downloader:        nil, // Will be set via SetS3Downloader
		discoveryJobService: nil, // Will be set via SetDiscoveryJobService
		encryptionKey:       "",  // Will be set via SetEncryptionKey
		log:                 logger,
	}
}

// SetEncryptionKey sets the encryption master key for the handler
func (h *Handler) SetEncryptionKey(key string) {
	h.encryptionKey = key
}

// SetDiscoveryJobService sets the discovery job service for the handler
func (h *Handler) SetDiscoveryJobService(service *services.DiscoveryJobService) {
	h.discoveryJobService = service
}

// SetS3Downloader sets the S3 downloader for the handler
func (h *Handler) SetS3Downloader(downloader *services.S3Downloader) {
	h.s3Downloader = downloader
}

// SetPcapService sets the PCAP service for the handler
func (h *Handler) SetPcapService(service *services.PcapService) {
	h.pcapService = service
}

// SetNATSClient sets the NATS client for the handler
func (h *Handler) SetNATSClient(client *events.NATSClient) {
	h.natsClient = client
}

// SetLogger sets the logger for the handler
func (h *Handler) SetLogger(logger *logrus.Logger) {
	h.log = logger
}

// Health handles health check requests
func (h *Handler) Health(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  "healthy",
		"service": "sensor-manager",
		"version": version.Get(),
	})
}
