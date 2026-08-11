package models

import (
	"time"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
)

// DiscoveryJob represents a discovery job in the cluster
type DiscoveryJob struct {
	ID                 string                 `json:"id" db:"id"`
	TenantID           string                 `json:"tenant_id" db:"tenant_id"`
	CreatedBy          string                 `json:"created_by" db:"created_by"`
	ExecutionMode      string                 `json:"execution_mode" db:"execution_mode"`
	Targets            []string               `json:"targets" db:"targets"`
	RequestedSensorIDs []string               `json:"requested_sensor_ids" db:"requested_sensor_ids"`
	AssignedSensorID   *string                `json:"assigned_sensor_id" db:"assigned_sensor_id"`
	Fanout             bool                   `json:"fanout" db:"fanout"`
	Status             string                 `json:"status" db:"status"` // "queued", "running", "completed", "failed"
	Progress           int                    `json:"progress" db:"progress"`
	ResultsSummary     map[string]interface{} `json:"results_summary" db:"results_summary"`
	RetentionCapMB     int                    `json:"retention_cap_mb" db:"retention_cap_mb"`
	RetentionTTLHours  int                    `json:"retention_ttl_hours" db:"retention_ttl_hours"`
	StartedAt          *time.Time             `json:"started_at" db:"started_at"`
	CompletedAt        *time.Time             `json:"completed_at" db:"completed_at"`
	CreatedAt          time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt          time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt          *time.Time             `json:"deleted_at" db:"deleted_at"`
}

// CreateDiscoveryJobRequest represents a request to create a discovery job
type CreateDiscoveryJobRequest struct {
	Targets            []string               `json:"targets" binding:"required"`
	ExecutionMode      string                 `json:"execution_mode"`
	PreferredSensorIDs []string               `json:"preferred_sensor_ids"`
	RetentionCapMB     *int                   `json:"retention_cap_mb"`
	RetentionTTLHours  *int                   `json:"retention_ttl_hours"`
	Ports              []int                  `json:"ports"`
	Protocols          []string               `json:"protocols"`
	Options            map[string]interface{} `json:"options,omitempty"`
	// OTProbeProtocols lists which OT/ICS active probes the operator opted
	// into for this job (Modbus, OPC_UA, EtherNet_IP, BACnet). Gated by the
	// ot_active_probing tier feature flag at the API layer; values from
	// tenants without the flag are dropped server-side. Empty / omitted =
	// no OT active probing for this job.
	OTProbeProtocols []string `json:"ot_probe_protocols,omitempty"`
}

// DiscoveryResultsResponse represents the response for discovery results
type DiscoveryResultsResponse struct {
	JobID      string                   `json:"job_id"`
	Status     string                   `json:"status"`
	Progress   int                      `json:"progress"`
	Results    []map[string]interface{} `json:"results"`
	Findings   []DiscoveryFinding       `json:"findings"`
	Summary    map[string]interface{}   `json:"summary"`
	TotalFound int                      `json:"total_found"`
	Total      int                      `json:"total"`
	Processed  int                      `json:"processed"`
	Page       int                      `json:"page"`
	PageSize   int                      `json:"page_size"`
	Errors     []string                 `json:"errors"`
}

// AlertConfigRequest represents a request to configure alerts
type AlertConfigRequest struct {
	TenantID             string                 `json:"tenant_id" binding:"required"`
	AlertType            string                 `json:"alert_type" binding:"required"`
	Threshold            float64                `json:"threshold"`
	Enabled              bool                   `json:"enabled"`
	EmailEnabled         bool                   `json:"email_enabled"`
	SlackEnabled         bool                   `json:"slack_enabled"`
	SlackChannel         string                 `json:"slack_channel"`
	SlackWebhookURL      string                 `json:"slack_webhook_url"`
	InAppEnabled         bool                   `json:"in_app_enabled"`
	NotificationChannels []string               `json:"notification_channels"`
	Conditions           map[string]interface{} `json:"conditions"`
	Schedule             *string                `json:"schedule"`
	CreatedAt            time.Time              `json:"created_at"`
	UpdatedAt            time.Time              `json:"updated_at"`
}

// ClusterSensor represents a sensor in the cluster
type ClusterSensor struct {
	ID           string                 `json:"id" db:"id"`
	TenantID     string                 `json:"tenant_id" db:"tenant_id"`
	Name         string                 `json:"name" db:"name"`
	Type         string                 `json:"type" db:"type"`
	Status       string                 `json:"status" db:"status"`
	Version      string                 `json:"version" db:"version"`
	LastSeen     *time.Time             `json:"last_seen" db:"last_seen"`
	Capabilities []string               `json:"capabilities" db:"capabilities"`
	Location     *string                `json:"location" db:"location"`
	Tags         map[string]interface{} `json:"tags" db:"tags"`
	Metadata     map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt    *time.Time             `json:"deleted_at" db:"deleted_at"`
}

// JobAssignment represents a job assignment to a sensor
type JobAssignment struct {
	ID          string     `json:"id" db:"id"`
	JobID       string     `json:"job_id" db:"job_id"`
	SensorID    string     `json:"sensor_id" db:"sensor_id"`
	TenantID    string     `json:"tenant_id" db:"tenant_id"`
	Status      string     `json:"status" db:"status"` // "assigned", "accepted", "running", "completed", "failed"
	AssignedAt  time.Time  `json:"assigned_at" db:"assigned_at"`
	AcceptedAt  *time.Time `json:"accepted_at" db:"accepted_at"`
	StartedAt   *time.Time `json:"started_at" db:"started_at"`
	CompletedAt *time.Time `json:"completed_at" db:"completed_at"`
	CreatedAt   time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at" db:"updated_at"`
}

// DiscoveryResult represents a single discovery result
type DiscoveryResult struct {
	ID           string                 `json:"id" db:"id"`
	JobID        string                 `json:"job_id" db:"job_id"`
	SensorID     string                 `json:"sensor_id" db:"sensor_id"`
	TenantID     string                 `json:"tenant_id" db:"tenant_id"`
	AssetType    string                 `json:"asset_type" db:"asset_type"`
	AssetData    map[string]interface{} `json:"asset_data" db:"asset_data"`
	Confidence   float64                `json:"confidence" db:"confidence"`
	RiskScore    int                    `json:"risk_score" db:"risk_score"`
	DiscoveredAt time.Time              `json:"discovered_at" db:"discovered_at"`
	CreatedAt    time.Time              `json:"created_at" db:"created_at"`
}

// DiscoveryTarget represents a target for discovery
type DiscoveryTarget struct {
	ID          string                 `json:"id" db:"id"`
	JobID       string                 `json:"job_id" db:"job_id"`
	TenantID    string                 `json:"tenant_id" db:"tenant_id"`
	Target      string                 `json:"target" db:"target"`
	Input       string                 `json:"input" db:"input"`
	Type        string                 `json:"type" db:"type"`     // "ip", "hostname", "cidr", "url"
	Status      string                 `json:"status" db:"status"` // "pending", "scanning", "completed", "failed"
	Priority    int                    `json:"priority" db:"priority"`
	Ports       []int32                `json:"ports" db:"ports"`
	Protocols   []string               `json:"protocols" db:"protocols"`
	Metadata    map[string]interface{} `json:"metadata" db:"metadata"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at" db:"updated_at"`
	CompletedAt *time.Time             `json:"completed_at" db:"completed_at"`
}

// DiscoveryFinding represents a specific finding during discovery
type DiscoveryFinding struct {
	ID              string                 `json:"id" db:"id"`
	JobID           string                 `json:"job_id" db:"job_id"`
	TargetID        string                 `json:"target_id" db:"target_id"`
	SensorID        string                 `json:"sensor_id" db:"sensor_id"`
	TenantID        string                 `json:"tenant_id" db:"tenant_id"`
	FindingType     string                 `json:"finding_type" db:"finding_type"`
	Title           string                 `json:"title" db:"title"`
	Description     string                 `json:"description" db:"description"`
	Severity        string                 `json:"severity" db:"severity"`
	Confidence      float64                `json:"confidence" db:"confidence"`
	ConfidenceScore float64                `json:"confidence_score" db:"confidence_score"`
	RiskScore       int                    `json:"risk_score" db:"risk_score"`
	Data            map[string]interface{} `json:"data" db:"data"`
	Tags            []string               `json:"tags" db:"tags"`
	ExecutedVia     string                 `json:"executed_via" db:"executed_via"`
	Protocol        string                 `json:"protocol" db:"protocol"`
	Port            int                    `json:"port" db:"port"`
	ResolvedIP      string                 `json:"resolved_ip" db:"resolved_ip"`
	Hostname        string                 `json:"hostname" db:"hostname"`
	DiscoveredAt    time.Time              `json:"discovered_at" db:"discovered_at"`
	CreatedAt       time.Time              `json:"created_at" db:"created_at"`
}

// SensorHealth represents sensor health in the cluster
type SensorHealth struct {
	ID          string                 `json:"id" db:"id"`
	SensorID    string                 `json:"sensor_id" db:"sensor_id"`
	TenantID    string                 `json:"tenant_id" db:"tenant_id"`
	Status      string                 `json:"status" db:"status"`
	Message     string                 `json:"message" db:"message"`
	LastSeen    time.Time              `json:"last_seen" db:"last_seen"`
	Uptime      int64                  `json:"uptime" db:"uptime"`
	CPUUsage    float64                `json:"cpu_usage" db:"cpu_usage"`
	MemoryUsage float64                `json:"memory_usage" db:"memory_usage"`
	DiskUsage   float64                `json:"disk_usage" db:"disk_usage"`
	NetworkIO   int64                  `json:"network_io" db:"network_io"`
	Metrics     map[string]interface{} `json:"metrics" db:"metrics"`
	CreatedAt   time.Time              `json:"created_at" db:"created_at"`
}

// ClusterMetrics represents cluster-wide metrics
type ClusterMetrics struct {
	ID             string    `json:"id" db:"id"`
	TenantID       string    `json:"tenant_id" db:"tenant_id"`
	TotalSensors   int       `json:"total_sensors" db:"total_sensors"`
	ActiveSensors  int       `json:"active_sensors" db:"active_sensors"`
	TotalJobs      int       `json:"total_jobs" db:"total_jobs"`
	RunningJobs    int       `json:"running_jobs" db:"running_jobs"`
	CompletedJobs  int       `json:"completed_jobs" db:"completed_jobs"`
	FailedJobs     int       `json:"failed_jobs" db:"failed_jobs"`
	TotalAssets    int       `json:"total_assets" db:"total_assets"`
	AverageJobTime float64   `json:"average_job_time" db:"average_job_time"`
	Throughput     float64   `json:"throughput" db:"throughput"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
}

// Alert represents an alert in the cluster
type Alert struct {
	ID         string                 `json:"id" db:"id"`
	TenantID   string                 `json:"tenant_id" db:"tenant_id"`
	Type       string                 `json:"type" db:"type"`
	Severity   string                 `json:"severity" db:"severity"`
	Title      string                 `json:"title" db:"title"`
	Message    string                 `json:"message" db:"message"`
	Data       map[string]interface{} `json:"data" db:"data"`
	Status     string                 `json:"status" db:"status"` // "active", "acknowledged", "resolved"
	CreatedAt  time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time              `json:"updated_at" db:"updated_at"`
	ResolvedAt *time.Time             `json:"resolved_at" db:"resolved_at"`
}

// DiscoveryAlertConfig represents alert configuration for discovery
type DiscoveryAlertConfig struct {
	ID              string           `json:"id" db:"id"`
	TenantID        string           `json:"tenant_id" db:"tenant_id"`
	AlertType       string           `json:"alert_type" db:"alert_type"`
	Threshold       float64          `json:"threshold" db:"threshold"`
	Enabled         bool             `json:"enabled" db:"enabled"`
	EmailEnabled    bool             `json:"email_enabled" db:"email_enabled"`
	SlackEnabled    bool             `json:"slack_enabled" db:"slack_enabled"`
	SlackChannel    string           `json:"slack_channel" db:"slack_channel"`
	SlackWebhookURL string           `json:"slack_webhook_url" db:"slack_webhook_url"`
	InAppEnabled    bool             `json:"in_app_enabled" db:"in_app_enabled"`
	Conditions      shareddb.JSONMap `json:"conditions" db:"conditions"`
	Schedule        *string          `json:"schedule" db:"schedule"`
	CreatedAt       time.Time        `json:"created_at" db:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at" db:"updated_at"`
}

// DiscoveryRateLimit represents rate limiting for discovery
type DiscoveryRateLimit struct {
	ID               string    `json:"id" db:"id"`
	TenantID         string    `json:"tenant_id" db:"tenant_id"`
	SensorID         string    `json:"sensor_id" db:"sensor_id"`
	LimitType        string    `json:"limit_type" db:"limit_type"` // "per_second", "per_minute", "per_hour"
	LimitValue       int       `json:"limit_value" db:"limit_value"`
	CurrentCount     int       `json:"current_count" db:"current_count"`
	ScansPerHour     int       `json:"scans_per_hour" db:"scans_per_hour"`
	ConcurrentJobs   int       `json:"concurrent_jobs" db:"concurrent_jobs"`
	MaxTargetsPerJob int       `json:"max_targets_per_job" db:"max_targets_per_job"`
	IsActive         bool      `json:"is_active" db:"is_active"`
	WindowStart      time.Time `json:"window_start" db:"window_start"`
	WindowEnd        time.Time `json:"window_end" db:"window_end"`
	CreatedAt        time.Time `json:"created_at" db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at" db:"updated_at"`
}

// RateLimitConfigRequest represents a request to configure rate limits
type RateLimitConfigRequest struct {
	TenantID         string `json:"tenant_id" binding:"required"`
	SensorID         string `json:"sensor_id" binding:"required"`
	LimitType        string `json:"limit_type" binding:"required"`
	LimitValue       int    `json:"limit_value" binding:"required"`
	ScansPerHour     int    `json:"scans_per_hour"`
	ConcurrentJobs   int    `json:"concurrent_jobs"`
	MaxTargetsPerJob int    `json:"max_targets_per_job"`
	IsActive         bool   `json:"is_active"`
}

// DiscoveryJobsResponse represents a response containing multiple discovery jobs
type DiscoveryJobsResponse struct {
	Jobs       []DiscoveryJob `json:"jobs"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
	TotalPages int            `json:"total_pages"`
}

// DiscoveryJobResponse represents a response containing a single discovery job
type DiscoveryJobResponse struct {
	Job DiscoveryJob `json:"job"`
}

// DiscoveryJobStatusResponse represents a response containing job status
type DiscoveryJobStatusResponse struct {
	JobID       string     `json:"job_id"`
	Status      string     `json:"status"`
	Message     string     `json:"message"`
	Progress    int        `json:"progress"`
	StartedAt   *time.Time `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at"`
}
