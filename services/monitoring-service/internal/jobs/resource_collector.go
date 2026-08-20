package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// ResourceCollector collects host-level metrics and sends them to the resource
// tracker.
//
// Two properties of this collector are load-bearing and easy to undo by
// accident:
//
//  1. It measures the HOST, not a tenant. The platform runs shared service
//     pods, so nothing here is attributable to a tenant unless an operator
//     asserts that this host serves exactly one — via RESOURCE_METRICS_TENANT_ID.
//     Unset, the collector measures and publishes nothing. It used to fall back
//     to `ORDER BY created_at DESC LIMIT 1`, which billed the most recently
//     created tenant for the whole platform's usage.
//
//  2. It publishes DELTAS, not counters. /proc/net/dev reports bytes since
//     boot. Publishing that figure as period usage charges a tenant for the
//     pod's entire uptime, and does so again, larger, on every tick.
type ResourceCollector struct {
	trackerURL string
	httpClient *http.Client
	natsClient *events.NATSClient
	logger     *logrus.Logger
	interval   time.Duration

	// mu guards the counter baseline below. Collection is driven by a single
	// ticker today, but the baseline is state and must not be racy if that
	// changes.
	mu sync.Mutex
	// prevNetworkBytes is the previous total of the since-boot receive and
	// transmit counters; hasPrevNetwork says whether a baseline exists yet.
	// Without a baseline there is no delta to report, and no delta means the
	// key is omitted — never published as zero.
	prevNetworkBytes int64
	hasPrevNetwork   bool
}

// SystemMetrics represents host-level resource metrics.
//
// Every measurement is a pointer and nil means NOT MEASURED. This is not
// defensive style: the fields that are nil here used to carry invented values
// — CPU derived from the Go runtime's own MemStats, disk usage returned as a
// hardcoded "100MB used, 1GB total" — that were indistinguishable downstream
// from real measurements and were priced as though real.
type SystemMetrics struct {
	Timestamp   time.Time `json:"timestamp"`
	ServiceName string    `json:"service_name"`

	// NetworkBytesIn and NetworkBytesOut are since-boot counters straight from
	// /proc/net/dev. They are published for observability only.
	NetworkBytesIn  *int64 `json:"network_bytes_in,omitempty"`
	NetworkBytesOut *int64 `json:"network_bytes_out,omitempty"`
	// NetworkBytesDelta is the bytes transferred since the previous collection
	// — the only network figure that may be costed. Nil on the first tick
	// (no baseline) and after a counter reset.
	NetworkBytesDelta *int64 `json:"network_bytes,omitempty"`

	ContainerID string `json:"container_id"`
	Hostname    string `json:"hostname"`
}

// NewResourceCollector creates a new resource collector.
func NewResourceCollector(logger *logrus.Logger) *ResourceCollector {
	if logger == nil {
		logger = logrus.New()
	}

	trackerURL := os.Getenv("RESOURCE_TRACKER_URL")
	if trackerURL == "" {
		trackerURL = sharedconfig.PeerURL("resource-tracker-service", sharedconfig.MTLSEnabled())
	}

	interval := 5 * time.Minute
	if intervalStr := os.Getenv("RESOURCE_COLLECTION_INTERVAL"); intervalStr != "" {
		if parsed, err := time.ParseDuration(intervalStr); err == nil {
			interval = parsed
		}
	}

	// Initialize NATS client for metrics publishing
	var natsClient *events.NATSClient
	nc, natsErr := events.NewNATSClient("")
	if natsErr != nil {
		log.Printf("[ResourceCollector] Warning: NATS unavailable, falling back to HTTP: %v", natsErr)
	} else {
		natsClient = nc
	}

	return &ResourceCollector{
		trackerURL: trackerURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		natsClient: natsClient,
		logger:     logger,
		interval:   interval,
	}
}

// resolveMetricsTenantID returns the tenant to attribute host metrics to, or
// uuid.Nil when no operator has declared one.
//
// There is deliberately no fallback. RESOURCE_METRICS_TENANT_ID is an
// operator's assertion that this host serves exactly one tenant — a configured
// fact about a dedicated deployment. Guessing a tenant instead (the previous
// behaviour selected the newest row in `tenants`) does not make the platform's
// host metrics per-tenant; it just picks someone to blame for them.
func (rc *ResourceCollector) resolveMetricsTenantID() (uuid.UUID, error) {
	s := strings.TrimSpace(os.Getenv("RESOURCE_METRICS_TENANT_ID"))
	if s == "" {
		return uuid.Nil, nil
	}
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("invalid RESOURCE_METRICS_TENANT_ID: %w", err)
	}
	return id, nil
}

// Start begins the resource collection process
func (rc *ResourceCollector) Start(ctx context.Context) {
	rc.logger.Info("Starting resource collector")

	ticker := time.NewTicker(rc.interval)
	defer ticker.Stop()

	// Collect immediately on start
	rc.collectAndSend()

	for {
		select {
		case <-ctx.Done():
			rc.logger.Info("Resource collector stopping")
			return
		case <-ticker.C:
			rc.collectAndSend()
		}
	}
}

// collectAndSend collects host metrics and sends them to the resource tracker
func (rc *ResourceCollector) collectAndSend() {
	metrics := rc.collectSystemMetrics()

	if err := rc.sendMetrics(metrics); err != nil {
		rc.logger.WithError(err).Error("Failed to send metrics to resource tracker")
		return
	}

	fields := logrus.Fields{"hostname": metrics.Hostname}
	if metrics.NetworkBytesDelta != nil {
		fields["network_bytes_delta"] = *metrics.NetworkBytesDelta
	} else {
		fields["network_bytes_delta"] = "not measured"
	}
	rc.logger.WithFields(fields).Debug("Host metrics collected and sent")
}

// collectSystemMetrics collects the host metrics that can actually be measured.
//
// CPU, memory and disk are absent by design. The values previously reported
// for them were fabrications: CPU was a formula over runtime.MemStats' GC
// counter, and disk was a constant returned regardless of what /proc/diskstats
// said. Reporting nothing is worse than reporting a real number and better
// than reporting an invented one.
func (rc *ResourceCollector) collectSystemMetrics() *SystemMetrics {
	hostname, _ := os.Hostname()
	containerID := os.Getenv("HOSTNAME") // Docker sets this

	metrics := &SystemMetrics{
		Timestamp:   time.Now(),
		ServiceName: "monitoring-service",
		ContainerID: containerID,
		Hostname:    hostname,
	}

	if in, out, ok := rc.getNetworkStats(); ok {
		metrics.NetworkBytesIn = &in
		metrics.NetworkBytesOut = &out
		metrics.NetworkBytesDelta = rc.networkDelta(in + out)
	}

	return metrics
}

// networkDelta converts a since-boot byte counter into bytes transferred since
// the previous collection.
//
// It returns nil — not zero — when there is no usable delta: on the first
// observation, and when the counter has gone backwards (a reboot, an interface
// reset, or a container restart). In the reset case the baseline is moved to
// the new value so the following interval is measured correctly; reporting the
// post-reset total as a delta would attribute a fresh boot's worth of traffic
// to one interval.
func (rc *ResourceCollector) networkDelta(total int64) *int64 {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	prev, hadPrev := rc.prevNetworkBytes, rc.hasPrevNetwork
	rc.prevNetworkBytes = total
	rc.hasPrevNetwork = true

	if !hadPrev || total < prev {
		return nil
	}
	delta := total - prev
	return &delta
}

// getNetworkStats reads the host's since-boot network counters. The bool
// reports whether a measurement was obtained at all.
func (rc *ResourceCollector) getNetworkStats() (int64, int64, bool) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, false
	}
	return parseNetworkStats(string(data))
}

// parseNetworkStats parses network statistics from /proc/net/dev. The bool
// reports whether any matching interface was found — distinguishing "no
// traffic" from "no interface to read", which must not both become zero.
func parseNetworkStats(data string) (int64, int64, bool) {
	var totalIn, totalOut int64
	found := false

	for _, line := range strings.Split(data, "\n") {
		if !strings.Contains(line, "eth0") && !strings.Contains(line, "ens") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		in, inErr := strconv.ParseInt(fields[1], 10, 64)
		out, outErr := strconv.ParseInt(fields[9], 10, 64)
		if inErr != nil || outErr != nil {
			continue
		}
		totalIn += in
		totalOut += out
		found = true
	}

	return totalIn, totalOut, found
}

// sendMetrics sends metrics via NATS (preferred) or HTTP (fallback).
//
// Sending is skipped entirely unless an operator has declared this host's
// tenant. See resolveMetricsTenantID.
func (rc *ResourceCollector) sendMetrics(metrics *SystemMetrics) error {
	tenantUUID, err := rc.resolveMetricsTenantID()
	if err != nil {
		rc.logger.WithError(err).Warn("Could not resolve metrics tenant; skipping host metrics to resource tracker")
		return nil
	}
	if tenantUUID == uuid.Nil {
		rc.logger.Debug("RESOURCE_METRICS_TENANT_ID is unset; host metrics are not attributed to any tenant")
		return nil
	}
	tenantIDStr := tenantUUID.String()

	// Only measured values go on the wire. A key the collector omits arrives at
	// resource-tracker as "not measured" and is not priced; a key present with
	// a zero value means the collector measured zero.
	payload := map[string]interface{}{
		"tenant_id":    tenantIDStr,
		"container_id": metrics.ContainerID,
		"hostname":     metrics.Hostname,
	}
	if metrics.NetworkBytesIn != nil {
		payload["network_bytes_in"] = float64(*metrics.NetworkBytesIn)
	}
	if metrics.NetworkBytesOut != nil {
		payload["network_bytes_out"] = float64(*metrics.NetworkBytesOut)
	}
	if metrics.NetworkBytesDelta != nil {
		// The costable figure, under the key resource-tracker reads.
		payload["network_bytes"] = float64(*metrics.NetworkBytesDelta)
	}

	// Try NATS first
	if rc.natsClient != nil && rc.natsClient.IsConnected() {
		metricsEvent := events.MetricsEvent{
			EventID:   uuid.New(),
			Source:    metrics.ServiceName,
			Timestamp: metrics.Timestamp,
			Metrics:   payload,
		}
		if err := events.PublishJSON(rc.natsClient, events.SubjectMetricsSystem, metricsEvent); err == nil {
			return nil
		}
		rc.logger.Warn("NATS publish failed; falling back to HTTP for metrics")
	}

	// Fallback: HTTP to resource tracker (same JSON shape as RecordResourceMetrics)
	httpPayload := struct {
		TenantID     uuid.UUID `json:"tenant_id"`
		NetworkBytes *int64    `json:"network_bytes,omitempty"`
	}{
		TenantID:     tenantUUID,
		NetworkBytes: metrics.NetworkBytesDelta,
	}

	jsonData, err := json.Marshal(httpPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal metrics: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/resource-tracker/metrics", rc.trackerURL)
	req, err := http.NewRequestWithContext(context.Background(), "POST", url, strings.NewReader(string(jsonData)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Bind tenant ID into the HMAC signature so the receiver can trust it
	// without consulting the (untrusted) request body.
	req.Header.Set(serviceauth.HeaderTenantID, tenantUUID.String())
	serviceauth.SignRequestFromEnv(req)

	resp, err := rc.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("received error response %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
