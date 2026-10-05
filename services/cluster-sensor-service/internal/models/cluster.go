package models

import (
	"time"

	"github.com/lib/pq"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// DiscoveryJob represents a discovery job in the cluster
type DiscoveryJob struct {
	ID       string `json:"id" db:"id"`
	TenantID string `json:"tenant_id" db:"tenant_id"`
	// CreatedBy is empty for a job the platform created on its own initiative
	// (the automatic active-scan sweep, any HMAC service-auth caller): the
	// column is NULL for those and the reads COALESCE it.
	CreatedBy     string   `json:"created_by" db:"created_by"`
	ExecutionMode string   `json:"execution_mode" db:"execution_mode"`
	Targets       []string `json:"targets" db:"targets"`
	// RequestedSensorIDs is a pq.StringArray (a []string that knows how to
	// scan a Postgres text[]) so sqlx can read it straight off a row; it
	// marshals to JSON as an ordinary string array.
	RequestedSensorIDs pq.StringArray `json:"requested_sensor_ids" db:"requested_sensor_ids"`
	// Tenant-sensor dispatch. AssignedSensorID is the tenant sensor a
	// `sensors` job was handed to; DispatchedAt is when its command was
	// written; PickedUpAt is when the sensor collected that command on a
	// heartbeat (sensor_commands.delivered_at). Executor is derived —
	// "platform" or "sensor" — so a reader does not have to infer it from
	// which of the other fields are set. AssignedSensorLastHeartbeat is what a
	// "sensor offline" failure shows beside the error.
	AssignedSensorID            *string    `json:"assigned_sensor_id" db:"assigned_sensor_id"`
	AssignedSensorName          *string    `json:"assigned_sensor_name,omitempty" db:"assigned_sensor_name"`
	AssignedSensorLastHeartbeat *time.Time `json:"assigned_sensor_last_heartbeat,omitempty" db:"assigned_sensor_last_heartbeat"`
	Executor                    string     `json:"executor" db:"-"`
	DispatchedAt                *time.Time `json:"dispatched_at" db:"dispatched_at"`
	PickedUpAt                  *time.Time `json:"picked_up_at" db:"picked_up_at"`
	Fanout                      bool       `json:"fanout" db:"fanout"`
	// Status is one of queued, awaiting_sensor, running, completed, failed,
	// cancelled. awaiting_sensor is the interval between a `sensors` job being
	// dispatched and the sensor's completion callback.
	Status       string  `json:"status" db:"status"`
	ErrorMessage *string `json:"error_message" db:"error_message"`
	// Progress is the integer percent of the job's targets the scanner is
	// finished with, and TargetCounts the counts it is computed from. Filled
	// on the single-job reads (GET /jobs/:id and /jobs/:id/status), and on a
	// listing for a scan-plan job that has not ended; any other listed job
	// carries Progress 0 and TargetCounts nil. Per TARGET, not per host: a /24
	// is one target, so one long CIDR moves the number once — except a
	// scan-plan job run in work units, whose Progress is per host.
	Progress          int                    `json:"progress" db:"progress"`
	TargetCounts      *JobTargetCounts       `json:"target_counts,omitempty" db:"-"`
	ResultsSummary    map[string]interface{} `json:"results_summary" db:"results_summary"`
	RetentionCapMB    int                    `json:"retention_cap_mb" db:"retention_cap_mb"`
	RetentionTTLHours int                    `json:"retention_ttl_hours" db:"retention_ttl_hours"`
	StartedAt         *time.Time             `json:"started_at" db:"started_at"`
	CompletedAt       *time.Time             `json:"completed_at" db:"completed_at"`
	CreatedAt         time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt         time.Time              `json:"updated_at" db:"updated_at"`
	DeletedAt         *time.Time             `json:"deleted_at" db:"deleted_at"`
	// ExternalTargets is set on the create response only: the confirmed
	// targets outside the tenant's registered networks, for the UI and the
	// audit record. Not a column.
	ExternalTargets []ExternalScanTarget `json:"external_targets,omitempty" db:"-"`
	// Origin is the auto-scan marker (autoscan.Origin = "auto_scan" in
	// inventory-service) an automatic-scan job carries in
	// `metadata.options.origin`, surfaced here read-only so a listing can tell
	// an automatic sweep's job from an operator-started one (Discover wizard,
	// Active Scan) without parsing raw metadata itself. Empty for both — the
	// distinction between those two is ExecutionMode/CreatedBy, not Origin.
	Origin string `json:"origin,omitempty" db:"origin"`
	// Plan is what the server decided a scan-plan job does ( WP3):
	// metadata.scan_plan, surfaced on the create response, the single-job
	// read and the listing. Nil for a legacy protocols × ports job.
	Plan *shareddisc.ScanPlan `json:"plan,omitempty" db:"-"`
	// Coverage is what a scan-plan job's work units have learned so far:
	// hosts that responded, gave no answer or could not be scanned, port
	// verdicts, and warnings a person should read. Filled on the single-job
	// reads for a scan-plan job, and on a listing for one that has not ended;
	// nil for a legacy job.
	Coverage *JobCoverage `json:"coverage,omitempty" db:"-"`
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
	// into for this job (Modbus, OPC_UA, EtherNet_IP, BACnet). This explicit
	// per-job opt-in is the only way an OT probe is requested; automatic
	// scans may not carry it. Values are dropped server-side when the
	// tenant's ot_active_probing switch is off (Core, on by default).
	// Empty / omitted = no OT active probing for this job.
	OTProbeProtocols []string `json:"ot_probe_protocols,omitempty"`
	// ExternalTargetsConfirmed is a person's explicit consent to scan targets
	// outside the tenant's registered networks ( W5.13b). Without it a
	// request naming such a target is refused with the list of them, so a
	// stray or scripted call never scans a third party silently. It is
	// meaningless — and ignored — on the automatic and service paths.
	ExternalTargetsConfirmed bool `json:"external_targets_confirmed,omitempty"`
	// SNICandidates maps a SINGLE-ADDRESS target to names it is known by. A
	// scan presents them as SNI only to a TLS port that answers the nameless
	// attempt with an alert. Optional, bounded and validated server-side
	// (shared/discovery.SanitizeSNICandidates): an invalid name is dropped, never
	// the request. Names for a hostname or a range are ignored.
	SNICandidates map[string][]string `json:"sni_candidates,omitempty"`

	// The scan-plan fields ( WP3). Present ⇒ the job is planned by depth
	// rather than by protocols × ports, which must then be absent; see
	// shared/discovery.ResolveJobRequest for the rules and ScanPlan for what
	// the server decides from them.
	ScanDepth string `json:"scan_depth,omitempty"`
	TCPPorts  string `json:"tcp_ports,omitempty"`
	UDPPorts  string `json:"udp_ports,omitempty"`
	Pace      string `json:"pace,omitempty"`
	RunFrom   string `json:"run_from,omitempty"`
	SensorID  string `json:"sensor_id,omitempty"`

	// DryRun asks for the plan and a time estimate without creating anything
	// ( WP3b): the request is validated, authorized, classified, capped,
	// routed and budget-checked exactly as a real create would be, and the
	// answer is a shared/discovery.ScanPreview. Scan-plan shape only.
	DryRun bool `json:"dry_run,omitempty"`
}

// ExternalScanTarget is a confirmed target outside the tenant's registered
// networks and the addresses it named when the job was created: what the
// create response and the audit event carry.
type ExternalScanTarget struct {
	Target    string   `json:"target"`
	Addresses []string `json:"addresses"`
}

// DiscoveryMaterialization reports what became of a job's findings AFTER they
// left the job record — i.e. how many reached the ingestion queue
// (sensor_discoveries) and how the tenant's segment auto-approval rules
// dispositioned them.
//
// It exists because "findings" and "assets" are two different questions and one
// number cannot honestly answer both (F7): a job can record N findings and add
// zero assets — third-party endpoints route to external_connections, findings
// with no resolved IP cannot be anchored, and processing is asynchronous, so
// immediately after a job completes the queue may not have been drained yet.
// AwaitingProcessing is that last case, reported explicitly rather than folded
// into a zero.
type DiscoveryMaterialization struct {
	// Findings recorded by the job itself (rows in discovery_findings).
	Findings int `json:"findings"`
	// Findings mirrored into the ingestion queue (rows in sensor_discoveries).
	// Lower than Findings when a finding had no resolved IP to anchor on.
	Queued int `json:"queued"`
	// Queue rows an auto-approval rule matched — assets went straight to monitoring.
	AutoApproved int `json:"auto_approved"`
	// Queue rows genuinely awaiting a human — no rule matched, and the row is
	// in Discovery → Approvals. Counted by `approval_status = 'pending'`, not
	// merely "not auto_approved": `observed` (host observations) and
	// `suppressed` (the matched asset is archived or denied) are also not
	// auto_approved, and neither is awaiting anything.
	PendingApproval int `json:"pending_approval"`
	// Queue rows the pipeline has not dispositioned yet.
	AwaitingProcessing int `json:"awaiting_processing"`
	// Queue rows that matched an asset the tenant has taken off the table —
	// archived or denied. Nothing was materialized and no approval decision
	// will ever be made; these are neither pending nor processed in the sense
	// the other counts mean.
	Suppressed int `json:"suppressed"`
	// Observed counts queue rows kept as evidence with no asset and no
	// approval decision to come (`approval_status = 'observed'`): a finding
	// identity could not tie to an asset yet — e.g. an address on a DHCP
	// network, with nothing else to identify the device — and is now an
	// unresolved observation in Discovery → Observations; a host observation;
	// or a third-party endpoint recorded as a connection. ObservedHosts is how
	// many distinct addresses those rows are on.
	Observed      int `json:"observed"`
	ObservedHosts int `json:"observed_hosts"`
	// FindingHosts is how many distinct hosts the job's findings are on, so a
	// finding count is never read as a count of hosts or assets.
	FindingHosts int `json:"finding_hosts"`
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
	// Materialization is omitted (not zeroed) when the counts could not be read,
	// so a consumer can tell "nothing materialized" from "we don't know".
	Materialization *DiscoveryMaterialization `json:"materialization,omitempty"`
}

// DiscoveryResultsByHostResponse is a job's findings grouped by host (
// H21): GET /discovery/jobs/{id}/results?group=host. It pages by HOST, not by
// finding, so a host with many open ports is never split across pages and a
// busy network does not cost one call per twenty ports. For a scan-plan job
// the hosts are every host that responded — those with findings and those
// that answered with nothing open — so TotalHosts matches the coverage's
// hosts_responded.
type DiscoveryResultsByHostResponse struct {
	JobID      string          `json:"job_id"`
	Group      string          `json:"group"`
	Hosts      []DiscoveryHost `json:"hosts"`
	TotalHosts int             `json:"total_hosts"`
	Page       int             `json:"page"`
	PageSize   int             `json:"page_size"`
}

// DiscoveryHost is one host of a job and what it was seen listening on.
type DiscoveryHost struct {
	// Address is the host's IP address, or — for a finding that could not be
	// resolved — the name it was scanned by.
	Address  string `json:"address"`
	Hostname string `json:"hostname,omitempty"`
	// Ports are the host's findings in port order: identified services with
	// their protocol, and open ports nothing could name as protocol "tcp"
	// with Identified false. A tarpit host has one entry, with the sample.
	Ports []DiscoveryHostPort `json:"ports"`
	// NothingOpen marks a host listed only because it responded: it answered
	// (refused ports, or a liveness reply) but nothing was open on the ports
	// scanned, so Ports is empty. Unit carries the refused/filtered counts.
	NothingOpen bool `json:"nothing_open,omitempty"`
	// Unit is the host's work unit for a scan-plan job — how the scan of this
	// address went; nil for a legacy job.
	Unit *DiscoveryHostUnit `json:"unit,omitempty"`
}

// DiscoveryHostPort is one finding on a host.
type DiscoveryHostPort struct {
	FindingID       string                 `json:"finding_id"`
	Port            int                    `json:"port"`
	Protocol        string                 `json:"protocol"`
	Transport       string                 `json:"transport,omitempty"`
	Identified      bool                   `json:"identified"`
	ServiceHint     string                 `json:"service_hint,omitempty"`
	ConfidenceScore float64                `json:"confidence_score"`
	Data            map[string]interface{} `json:"data"`
}

// DiscoveryHostUnit is a host's work-unit outcome.
type DiscoveryHostUnit struct {
	Status        string `json:"status"`
	LivenessState string `json:"liveness_state,omitempty"`
	// LivenessEvidence is what decided the liveness verdict, e.g. "tcp-refused:22".
	LivenessEvidence   string `json:"liveness_evidence,omitempty"`
	PortsRequested     int    `json:"ports_requested"`
	OpenCount          int    `json:"open_count"`
	ClosedCount        int    `json:"closed_count"`
	FilteredCount      int    `json:"filtered_count"`
	NotProbedCount     int    `json:"not_probed_count"`
	UDPAnsweredCount   int    `json:"udp_answered_count,omitempty"`
	RespondsOnAllPorts bool   `json:"responds_on_all_ports"`
	OTSuspect          bool   `json:"ot_suspect"`
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
	JobID        string           `json:"job_id"`
	Status       string           `json:"status"`
	Message      string           `json:"message"`
	Progress     int              `json:"progress"`
	TargetCounts *JobTargetCounts `json:"target_counts,omitempty"`
	Coverage     *JobCoverage     `json:"coverage,omitempty"`
	StartedAt    *time.Time       `json:"started_at"`
	CompletedAt  *time.Time       `json:"completed_at"`
}

// JobCoverage is a scan-plan job's work units summed ( H10/H21): one unit
// per address, so every host count is a count of addresses.
//
// Hosts are conserved: HostsTotal = HostsResponded + HostsNoAnswer +
// HostsUndetermined + HostsFailed + HostsPending + HostsCancelled. Ports are
// conserved over the units that have run: PortsRequested = PortsOpen +
// PortsClosed + PortsFiltered + PortsLocalErrors + PortsNotProbed.
//
// "No answer" is NOT "down": a firewall that drops everything looks exactly
// like an empty address, which is why it is never called down.
type JobCoverage struct {
	HostsTotal int `json:"hosts_total"`
	// HostsResponded answered at all: a TCP port open or refused, or a UDP
	// service reply.
	HostsResponded int `json:"hosts_responded"`
	// HostsNoAnswer were probed and nothing answered.
	HostsNoAnswer int `json:"hosts_no_answer"`
	// HostsUndetermined were scanned but got no verdict (every probe failed on
	// the scanner's own side).
	HostsUndetermined int `json:"hosts_undetermined"`
	// HostsFailed could not be scanned — refused by the target-authorization
	// guard, or an error — each with a reason on its unit.
	HostsFailed int `json:"hosts_failed"`
	// HostsPending are not finished yet (queued or in progress).
	HostsPending int `json:"hosts_pending"`
	// HostsCancelled were never reached because the job was cancelled.
	HostsCancelled int `json:"hosts_cancelled"`

	PortsRequested   int64 `json:"ports_requested"`
	PortsOpen        int64 `json:"ports_open"`
	PortsClosed      int64 `json:"ports_closed"`
	PortsFiltered    int64 `json:"ports_filtered"`
	PortsLocalErrors int64 `json:"ports_local_errors"`
	PortsNotProbed   int64 `json:"ports_not_probed"`

	// TarpitHosts accepted connections on so many ports that the scan stopped
	// early; their open ports are a sample.
	TarpitHosts    int `json:"tarpit_hosts"`
	OTSuspectHosts int `json:"ot_suspect_hosts"`
	// UDPAnswered counts UDP services that replied (a silent UDP port is not
	// counted: silence is not an answer).
	UDPAnswered int `json:"udp_answered"`

	// Warnings are sentences a person should read beside the numbers, e.g.
	// that nothing responded and the platform sensor may not reach the
	// network. Never nil.
	Warnings []string `json:"warnings"`
}

// JobTargetCounts is a job's discovery_targets rows by status.
//
// It counts TARGETS — the rows a job was created with, one per input — not the
// hosts a target expands to. A /24 is one target from start to finish, so a
// job of one CIDR reads 0% until the whole range is done. A scan-plan job run
// in work units reports per-host progress and Coverage from its units instead;
// its target counts are still filled, for the same rows.
//
// Cancelled is a target the job never reached because it was cancelled first.
type JobTargetCounts struct {
	Total     int `json:"total" db:"total"`
	Pending   int `json:"pending" db:"pending"`
	Running   int `json:"running" db:"running"`
	Completed int `json:"completed" db:"completed"`
	Failed    int `json:"failed" db:"failed"`
	Cancelled int `json:"cancelled" db:"cancelled"`
}
