package services

import (
	"context"
	"database/sql"
	"log"
	"time"
)

// platformAgentHeartbeatInterval is the default refresh cadence. It must stay
// comfortably under the 15-minute dwell window used by the
// discovery_agent_offline detector in compliance-engine.
const platformAgentHeartbeatInterval = 2 * time.Minute

// PlatformAgentHeartbeat keeps device_agents.last_heartbeat fresh for the
// in-cluster platform device-interrogation agent.
//
// The auto-registration flow stamps last_heartbeat once, at boot
// (handlers/auto_registration.go), and nothing refreshes it afterwards. The
// compliance-engine discovery_agent_offline detector reads last_heartbeat
// directly and raises a high-severity alert for any non-inactive agent silent
// for more than 15 minutes — and, unlike the sensor_offline spec, it does NOT
// exclude platform-owned rows. So a perfectly healthy service raised a false
// offline alert a quarter of an hour after every restart and kept it open until
// the next restart.
//
// This is the counterpart of sensor-manager's SystemSensorHealthService, which
// does the same job for the `sensors` table. It deliberately does not probe
// anything over HTTP: the process writing the row IS the platform agent, so its
// own liveness is the fact being recorded. (Probing itself would also walk into
// the mTLS trap that made both platform agents look permanently offline — see
// the comment on NewSystemSensorHealthService.)
type PlatformAgentHeartbeat struct {
	// bypassDB is the BYPASSRLS connection: this is a cross-tenant background
	// sweep keyed on platform ownership, not on a single tenant.
	bypassDB *sql.DB
	interval time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
}

// NewPlatformAgentHeartbeat creates the refresher. interval <= 0 uses the default.
func NewPlatformAgentHeartbeat(bypassDB *sql.DB, interval time.Duration) *PlatformAgentHeartbeat {
	if interval <= 0 {
		interval = platformAgentHeartbeatInterval
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &PlatformAgentHeartbeat{
		bypassDB: bypassDB,
		interval: interval,
		ctx:      ctx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
}

// Start beats immediately, then on the interval, until Stop. It blocks.
func (h *PlatformAgentHeartbeat) Start() {
	defer close(h.done)
	log.Printf("[PlatformAgentHeartbeat] Platform agent heartbeat started (interval: %s)", h.interval)

	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()

	h.beat()
	for {
		select {
		case <-h.ctx.Done():
			log.Println("[PlatformAgentHeartbeat] Platform agent heartbeat stopping...")
			return
		case <-ticker.C:
			h.beat()
		}
	}
}

// Stop cancels the loop and waits for the in-flight beat to return.
func (h *PlatformAgentHeartbeat) Stop() {
	h.cancel()
	<-h.done
}

func (h *PlatformAgentHeartbeat) beat() {
	if h.bypassDB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(h.ctx, 10*time.Second)
	defer cancel()
	if err := TouchPlatformAgentHeartbeat(ctx, h.bypassDB); err != nil {
		log.Printf("[PlatformAgentHeartbeat] Failed to refresh platform agent heartbeat: %v", err)
	}
}

// TouchPlatformAgentHeartbeat stamps last_heartbeat on every platform-owned
// device_agents row. Exported so the behaviour can be asserted directly against
// a real database.
func TouchPlatformAgentHeartbeat(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `
		UPDATE device_agents
		SET last_heartbeat = NOW(), updated_at = NOW()
		WHERE platform = 'platform' AND deleted_at IS NULL
	`)
	return err
}
