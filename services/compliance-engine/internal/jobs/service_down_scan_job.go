package jobs

import (
	"context"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

const serviceDownAlertType = "service_down"

// serviceDownFreshness bounds how recent a "down" health event must be to
// count. A stale down event (monitoring stopped writing for this service) is
// treated as "no current signal" rather than a live outage — otherwise old
// rows in service_health_events raise false alerts for services that are
// actually up.
const serviceDownFreshness = 15 * time.Minute

// serviceSubjectID derives a stable per-service UUID for the alert subject
// (service_health_events keys services by name, not UUID).
func serviceSubjectID(serviceName string) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("service_down:"+serviceName))
}

// ServiceDownScanJob raises a fixed critical PLATFORM-track alert when a
// platform service's latest health event reports it down, and auto-resolves
// when the service reports healthy again. Unlike tenant-track detectors this is
// platform-scoped: it does not iterate tenants — it raises under the sentinel
// platform tenant (services.PlatformAlertTenantID). Source: service_health_events
// (populated by monitoring-service's health-check loop).
type ServiceDownScanJob struct {
	db           *sqlx.DB
	bypassDB     *sqlx.DB
	catalog      *services.AlertCatalogService
	alertEngine  *services.AlertEngineService
	interval     time.Duration
	initialDelay time.Duration
	stop         chan struct{}
}

func NewServiceDownScanJob(db, bypassDB *sqlx.DB, catalog *services.AlertCatalogService,
	alertEngine *services.AlertEngineService, interval time.Duration) *ServiceDownScanJob {
	return &ServiceDownScanJob{
		db: db, bypassDB: bypassDB, catalog: catalog, alertEngine: alertEngine,
		interval: interval, initialDelay: 90 * time.Second, stop: make(chan struct{}),
	}
}

func (j *ServiceDownScanJob) Start() {
	go func() {
		initial := time.NewTimer(j.initialDelay)
		defer initial.Stop()
		select {
		case <-j.stop:
			return
		case <-initial.C:
			j.Scan()
		}
		ticker := time.NewTicker(j.interval)
		defer ticker.Stop()
		for {
			select {
			case <-j.stop:
				return
			case <-ticker.C:
				j.Scan()
			}
		}
	}()
}

func (j *ServiceDownScanJob) Stop() { close(j.stop) }

type downService struct {
	name string
	last time.Time
}

// Scan is platform-scoped (one pass, sentinel tenant). Errors are logged.
func (j *ServiceDownScanJob) Scan() {
	ctx := context.Background()
	tenant := services.PlatformAlertTenantID
	if !j.catalog.IsTypeEnabled(ctx, tenant, serviceDownAlertType) {
		return
	}

	// Latest health event per service (global monitoring table — bypass role).
	rows, err := j.bypassDB.QueryContext(ctx, `
		SELECT DISTINCT ON (service_name) service_name, status, "timestamp"
		FROM service_health_events
		ORDER BY service_name, "timestamp" DESC
	`)
	if err != nil {
		log.Printf("[ServiceDownScan] health query failed: %v", err)
		return
	}
	var down []downService
	for rows.Next() {
		var name, status string
		var ts time.Time
		if err := rows.Scan(&name, &status, &ts); err != nil {
			_ = rows.Close()
			log.Printf("[ServiceDownScan] scan failed: %v", err)
			return
		}
		if status == "down" && time.Since(ts) <= serviceDownFreshness {
			down = append(down, downService{name: name, last: ts})
		}
	}
	_ = rows.Close()

	// Open service_down alerts under the sentinel tenant.
	openSubjects, err := openAlertSubjects(ctx, j.bypassDB, tenant, serviceDownAlertType)
	if err != nil {
		log.Printf("[ServiceDownScan] open-alert query failed: %v", err)
		return
	}

	downSet := make(map[uuid.UUID]bool, len(down))
	for _, d := range down {
		sid := serviceSubjectID(d.name)
		downSet[sid] = true
		j.raise(ctx, tenant, d)
	}
	for sid := range openSubjects {
		if downSet[sid] {
			continue
		}
		j.resolve(ctx, tenant, sid)
	}
}

func (j *ServiceDownScanJob) raise(ctx context.Context, tenant uuid.UUID, d downService) {
	sid := serviceSubjectID(d.name)
	if _, err := j.alertEngine.Raise(ctx, events.AlertRaiseEvent{
		EventID:      uuid.New(),
		TenantID:     tenant,
		AlertType:    serviceDownAlertType,
		Source:       "monitoring",
		SubjectType:  "service",
		SubjectID:    &sid,
		SubjectLabel: d.name,
		Severity:     "critical",
		Title:        "Service down: " + d.name,
		Message:      "Platform service " + d.name + " is failing health checks.",
		Metadata: map[string]interface{}{
			"service_name": d.name,
			"observed_at":  d.last.Format(time.RFC3339),
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[ServiceDownScan] Raise failed (service=%s): %v", d.name, err)
	}
}

func (j *ServiceDownScanJob) resolve(ctx context.Context, tenant, subjectID uuid.UUID) {
	sid := subjectID
	if err := j.alertEngine.ResolveAuto(ctx, events.AlertResolveEvent{
		EventID:   uuid.New(),
		TenantID:  tenant,
		AlertType: serviceDownAlertType,
		SubjectID: &sid,
		Observation: map[string]interface{}{
			"observed":    "service health check recovered",
			"observed_at": time.Now().Format(time.RFC3339),
		},
		Timestamp: time.Now(),
	}); err != nil {
		log.Printf("[ServiceDownScan] Auto-resolve failed (subject=%s): %v", subjectID, err)
	}
}
