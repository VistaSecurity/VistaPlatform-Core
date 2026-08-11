package events

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"
)

// streamReplicas returns the NATS stream replica count from NATS_STREAM_REPLICAS
// env var (default 1). Set to 3 in production for HA across a NATS cluster.
func streamReplicas() int {
	if v := os.Getenv("NATS_STREAM_REPLICAS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 1
}

// StreamConfig defines a JetStream stream configuration
type StreamConfig struct {
	Name       string
	Subjects   []string
	MaxAge     time.Duration
	MaxMsgSize int32
	Storage    nats.StorageType
	Replicas   int
}

// DefaultStreams returns the platform's standard JetStream stream configurations.
// Each stream groups related subjects and provides at-least-once delivery guarantees.
// Stream replica count is sourced from NATS_STREAM_REPLICAS (default 1, set to 3
// in production for HA).
var DefaultStreams = buildDefaultStreams()

func buildDefaultStreams() []StreamConfig {
	r := streamReplicas()
	return []StreamConfig{
		{
			Name:       "COMPLIANCE",
			Subjects:   []string{"compliance.>"},
			MaxAge:     72 * time.Hour,
			MaxMsgSize: 1 << 20, // 1 MB
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
		{
			Name:       "INVENTORY_LIFECYCLE",
			Subjects:   []string{"inventory.lifecycle.>"},
			MaxAge:     72 * time.Hour,
			MaxMsgSize: 1 << 20,
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
		{
			Name:       "ALERTS",
			Subjects:   []string{"alerts.>"},
			MaxAge:     72 * time.Hour,
			MaxMsgSize: 1 << 20,
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
		{
			Name:       "DISCOVERY_JOBS",
			Subjects:   []string{"discovery.jobs.>"},
			MaxAge:     24 * time.Hour,
			MaxMsgSize: 1 << 20,
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
		{
			Name:       "REPORT_JOBS",
			Subjects:   []string{"report.jobs.>"},
			MaxAge:     24 * time.Hour,
			MaxMsgSize: 1 << 20,
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
		{
			Name:       "AUDIT",
			Subjects:   []string{"audit.>"},
			MaxAge:     72 * time.Hour,
			MaxMsgSize: 1 << 20,
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
		{
			Name:       "NOTIFICATIONS",
			Subjects:   []string{"notifications.>"},
			MaxAge:     48 * time.Hour,
			MaxMsgSize: 1 << 20,
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
		{
			Name:       "DEVICE_JOBS",
			Subjects:   []string{"device.jobs.>"},
			MaxAge:     24 * time.Hour,
			MaxMsgSize: 1 << 20,
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
		{
			Name:       "WEBHOOK_JOBS",
			Subjects:   []string{"webhooks.>"},
			MaxAge:     48 * time.Hour,
			MaxMsgSize: 1 << 20,
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
		{
			Name:       "METRICS",
			Subjects:   []string{"metrics.>"},
			MaxAge:     24 * time.Hour,
			MaxMsgSize: 1 << 20,
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
		{
			Name:       "PCAP_JOBS",
			Subjects:   []string{"pcap.jobs.>"},
			MaxAge:     24 * time.Hour,
			MaxMsgSize: 1 << 20,
			Storage:    nats.FileStorage,
			Replicas:   r,
		},
	}
}

// EnsureStreams creates or updates JetStream streams from the given configs.
// It is idempotent — safe to call on every startup.
func EnsureStreams(js nats.JetStreamContext, streams []StreamConfig) error {
	for _, sc := range streams {
		cfg := &nats.StreamConfig{
			Name:       sc.Name,
			Subjects:   sc.Subjects,
			MaxAge:     sc.MaxAge,
			MaxMsgSize: sc.MaxMsgSize,
			Storage:    sc.Storage,
			Replicas:   sc.Replicas,
			Retention:  nats.LimitsPolicy,
			Discard:    nats.DiscardOld,
		}

		info, err := js.StreamInfo(sc.Name)
		if err != nil && err != nats.ErrStreamNotFound {
			return fmt.Errorf("failed to query stream %s: %w", sc.Name, err)
		}

		if info == nil {
			_, err = js.AddStream(cfg)
			if err != nil {
				return fmt.Errorf("failed to create stream %s: %w", sc.Name, err)
			}
			log.Printf("[NATS] Created stream %s with subjects %v", sc.Name, sc.Subjects)
		} else {
			_, err = js.UpdateStream(cfg)
			if err != nil {
				return fmt.Errorf("failed to update stream %s: %w", sc.Name, err)
			}
			log.Printf("[NATS] Updated stream %s", sc.Name)
		}
	}
	return nil
}
