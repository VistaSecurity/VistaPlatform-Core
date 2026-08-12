package services

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strconv"
	"time"
)

// SensorReaperService transitions tenant sensors to 'offline' when they stop
// checking in.
//
// Without it, a sensor's stored status only ever moves *to* 'active' (on a
// heartbeat) and never back, so a sensor that dies keeps showing "active" in
// the UI indefinitely. The recovery direction already exists — the heartbeat
// path flips 'offline' back to 'active' — this closes the loop by setting
// 'offline' in the first place.
//
// Platform/system sensors are intentionally excluded: their status is owned by
// SystemSensorHealthService, which refreshes their last_heartbeat every cycle.
type SensorReaperService struct {
	// db is retained for non-RLS work; the sweep itself runs on bypassDB.
	db *sql.DB
	// bypassDB is the BYPASSRLS (crypto_bypass) handle. The reaper is a
	// cross-tenant background sweep with no tenant in scope, so it cannot set
	// app.tenant_id and must not run on the RLS-scoped handle.
	bypassDB      *sql.DB
	checkInterval time.Duration
	offlineAfter  time.Duration
}

// NewSensorReaperService builds the reaper with a 60s sweep interval. bypassDB
// is the BYPASSRLS handle the cross-tenant sweep runs on.
func NewSensorReaperService(db, bypassDB *sql.DB) *SensorReaperService {
	return &SensorReaperService{
		db:            db,
		bypassDB:      bypassDB,
		checkInterval: 60 * time.Second,
		offlineAfter:  sensorOfflineThreshold(),
	}
}

// sensorOfflineThreshold is how long a sensor may go without a heartbeat before
// it is considered offline. Defaults to 5 minutes (matching the freshness
// window GetPlatformSensorStats already uses); override with
// SENSOR_OFFLINE_THRESHOLD_MINUTES.
func sensorOfflineThreshold() time.Duration {
	const def = 5 * time.Minute
	if v := os.Getenv("SENSOR_OFFLINE_THRESHOLD_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return def
}

// Start begins the background reaping loop. Blocks until ctx is cancelled; run
// it in a goroutine.
func (s *SensorReaperService) Start(ctx context.Context) {
	log.Printf("🪦 Starting sensor offline reaper (interval: %s, offline after: %s)", s.checkInterval, s.offlineAfter)

	// Run once on startup so a restart doesn't leave stale 'active' rows around
	// for a full interval.
	s.reap(ctx)

	ticker := time.NewTicker(s.checkInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("🛑 Sensor offline reaper stopped")
			return
		case <-ticker.C:
			s.reap(ctx)
		}
	}
}

// reap marks active tenant sensors offline once they've gone silent past the
// threshold. COALESCE(last_heartbeat, created_at) catches sensors that
// registered but never checked in.
func (s *SensorReaperService) reap(ctx context.Context) {
	// RLS: cross-tenant — runs on the bypass role. The sweep spans every tenant
	// by design, so there is no app.tenant_id to set. On the RLS-scoped handle
	// this UPDATE matches zero rows and reports success, leaving dead sensors
	// showing "active" forever — the precise failure the reaper exists to stop.
	if s.bypassDB == nil {
		return
	}

	query := `
		UPDATE sensors
		SET status = 'offline',
		    updated_at = NOW()
		WHERE status = 'active'
		  AND platform <> 'platform'
		  AND deleted_at IS NULL
		  AND COALESCE(last_heartbeat, created_at) < NOW() - make_interval(secs => $1)`

	result, err := s.bypassDB.ExecContext(ctx, query, int(s.offlineAfter.Seconds()))
	if err != nil {
		log.Printf("⚠️  Sensor offline reaper query failed: %v", err)
		return
	}

	if n, _ := result.RowsAffected(); n > 0 {
		log.Printf("🪦 Marked %d sensor(s) offline (no heartbeat for >%s)", n, s.offlineAfter)
	}
}
