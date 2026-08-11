package jobs

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/jmoiron/sqlx"
)

const defaultAlertRetentionDays = 90

// AlertRetentionDays resolves the retention window from ALERT_RETENTION_DAYS
// (default 90). A value <= 0 disables cleanup.
func AlertRetentionDays() int {
	if v := os.Getenv("ALERT_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultAlertRetentionDays
}

// AlertRetentionCleanupJob deletes resolved alerts older than the retention
// window (their alert_events cascade via FK). It deliberately KEEPS
// ticket-linked alerts (ticket_id NOT NULL) so a ticket's "View alert"
// reference and inherited evidence timeline are never orphaned — the companion
// to the notification-log retention that could not safely touch this table.
// Cross-tenant via the bypass pool.
type AlertRetentionCleanupJob struct {
	bypassDB      *sqlx.DB
	retentionDays int
	interval      time.Duration
	initialDelay  time.Duration
	stop          chan struct{}
}

func NewAlertRetentionCleanupJob(bypassDB *sqlx.DB, retentionDays int, interval time.Duration) *AlertRetentionCleanupJob {
	return &AlertRetentionCleanupJob{
		bypassDB: bypassDB, retentionDays: retentionDays, interval: interval,
		initialDelay: 10 * time.Minute, stop: make(chan struct{}),
	}
}

func (j *AlertRetentionCleanupJob) Start() {
	go func() {
		initial := time.NewTimer(j.initialDelay)
		defer initial.Stop()
		select {
		case <-j.stop:
			return
		case <-initial.C:
			j.run()
		}
		ticker := time.NewTicker(j.interval)
		defer ticker.Stop()
		for {
			select {
			case <-j.stop:
				return
			case <-ticker.C:
				j.run()
			}
		}
	}()
}

func (j *AlertRetentionCleanupJob) Stop() { close(j.stop) }

func (j *AlertRetentionCleanupJob) run() {
	if j.retentionDays <= 0 {
		return
	}
	res, err := j.bypassDB.Exec(`
		DELETE FROM alerts
		WHERE status = 'resolved' AND ticket_id IS NULL
		  AND resolved_at IS NOT NULL
		  AND resolved_at < NOW() - ($1 || ' days')::interval
	`, fmt.Sprint(j.retentionDays))
	if err != nil {
		log.Printf("[AlertRetentionCleanup] delete failed: %v", err)
		return
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("[AlertRetentionCleanup] removed %d resolved unticketed alert(s) older than %dd", n, j.retentionDays)
	}
}
