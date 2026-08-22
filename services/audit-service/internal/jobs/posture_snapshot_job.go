package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// PostureSnapshotJob captures a once-per-day snapshot of every tenant's
// crypto-risk posture into public.posture_daily_snapshots (ADR-0007). It is the
// forward-accruing feed behind the dashboard "Posture trend" line: the row it
// writes is the same aggregate inventory-service GET /risk/summary returns, so
// the trend and the live posture number can never disagree.
//
// Design (ADR-0007 option A): a nightly job, not event-sourced. One row per
// (tenant, day); re-runs the same day just re-upsert (idempotent on the PK).
// History only accrues forward — there is no backfill. A brand-new tenant's
// pre-history days are seeded at the current live posture by the READ endpoint
// (inventory-service), never written here.
type PostureSnapshotJob struct {
	db                  *sql.DB
	httpClient          *http.Client
	inventoryServiceURL string
	jobExecutionService *services.JobExecutionService
	interval            time.Duration
	logger              *log.Logger
}

// riskSummary mirrors inventory-service models.RiskSummary (the JSON under the
// `risk_summary` envelope key of GET /risk/summary). Kept local — audit-service
// must not import an inventory-service internal package.
type riskSummary struct {
	TotalAssets      int `json:"total_assets"`
	HighRisk         int `json:"high_risk"`
	MediumRisk       int `json:"medium_risk"`
	LowRisk          int `json:"low_risk"`
	UnknownRisk      int `json:"unknown_risk"`
	TotalCrypto      int `json:"total_crypto"`
	CriticalFindings int `json:"critical_findings"`
}

// NewPostureSnapshotJob wires the daily posture-snapshot job. The HTTP client
// presents the platform client cert when mTLS is active (the inventory peer
// then serves only on https:8443), mirroring AlertService's construction.
func NewPostureSnapshotJob(
	db *sql.DB,
	jobExecutionService *services.JobExecutionService,
	inventoryServiceURL string,
	useMTLS bool,
	clientCertPath, clientKeyPath, platformCACertPath string,
) *PostureSnapshotJob {
	var httpClient *http.Client
	if useMTLS && clientCertPath != "" && clientKeyPath != "" && platformCACertPath != "" {
		c, err := sharedhttp.NewMTLSClient(clientCertPath, clientKeyPath, platformCACertPath)
		if err != nil {
			log.Printf("[PostureSnapshotJob] Failed to create mTLS client, falling back to HTTP: %v", err)
			httpClient = &http.Client{Timeout: 30 * time.Second}
		} else {
			c.Timeout = 30 * time.Second
			httpClient = c
		}
	} else {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	return &PostureSnapshotJob{
		db:                  db,
		httpClient:          httpClient,
		inventoryServiceURL: inventoryServiceURL,
		jobExecutionService: jobExecutionService,
		interval:            24 * time.Hour,
		logger:              log.New(log.Writer(), "[PostureSnapshotJob] ", log.LstdFlags),
	}
}

// Start runs a snapshot immediately, then once per interval. Idempotent on the
// (tenant_id, snapshot_date) PK, so a restart-driven re-run within the same day
// simply refreshes that day's row.
func (j *PostureSnapshotJob) Start(ctx context.Context) {
	j.logger.Printf("Starting posture snapshot job (interval: %v)", j.interval)

	j.executeSnapshot(ctx)

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			j.logger.Println("Stopping posture snapshot job")
			return
		case <-ticker.C:
			j.executeSnapshot(ctx)
		}
	}
}

// executeSnapshot iterates active tenants, fetches each one's live risk summary
// from inventory-service, and upserts the day's snapshot row.
func (j *PostureSnapshotJob) executeSnapshot(ctx context.Context) {
	jobID := uuid.New()
	logID, err := j.jobExecutionService.LogJobStart(ctx, jobID, "posture_snapshot", "Daily Posture Snapshot", nil, nil, nil)
	if err != nil {
		// Non-fatal: the snapshot is still worth taking even if we can't log it.
		j.logger.Printf("WARNING: Failed to log job start: %v", err)
	}

	tenantIDs, err := j.activeTenantIDs(ctx)
	if err != nil {
		j.logger.Printf("ERROR: Failed to list tenants: %v", err)
		if logID != uuid.Nil {
			msg := err.Error()
			_ = j.jobExecutionService.LogJobCompletion(ctx, logID, "failed", &msg, nil)
		}
		return
	}

	j.logger.Printf("Snapshotting posture for %d tenant(s)", len(tenantIDs))

	succeeded, failed := 0, 0
	for _, tenantID := range tenantIDs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		summary, err := j.fetchRiskSummary(ctx, tenantID)
		if err != nil {
			j.logger.Printf("ERROR: risk summary for tenant %s: %v", tenantID, err)
			failed++
			continue
		}
		if err := j.upsertSnapshot(ctx, tenantID, summary); err != nil {
			j.logger.Printf("ERROR: upsert snapshot for tenant %s: %v", tenantID, err)
			failed++
			continue
		}
		succeeded++
	}

	if logID != uuid.Nil {
		_ = j.jobExecutionService.LogJobProgress(ctx, logID, len(tenantIDs), succeeded, failed)
		status := "completed"
		if failed > 0 && succeeded == 0 {
			status = "failed"
		}
		_ = j.jobExecutionService.LogJobCompletion(ctx, logID, status, nil, map[string]interface{}{
			"tenants_total":     len(tenantIDs),
			"tenants_succeeded": succeeded,
			"tenants_failed":    failed,
		})
	}
	j.logger.Printf("Posture snapshot cycle complete: %d ok, %d failed", succeeded, failed)
}

// activeTenantIDs returns all non-deleted tenant IDs. This background job
// iterates every tenant, so it runs as the owner role (bypasses RLS) and
// isolates per tenant via the WHERE clause / per-row writes below.
func (j *PostureSnapshotJob) activeTenantIDs(ctx context.Context) ([]uuid.UUID, error) {
	rows, err := j.db.QueryContext(ctx, `SELECT id FROM public.tenants WHERE deleted_at IS NULL ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var ids []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// fetchRiskSummary calls inventory-service GET /risk/summary for one tenant.
// The tenant id is bound into the HMAC signature (set before signing) so the
// receiver trusts it without consulting the request body.
func (j *PostureSnapshotJob) fetchRiskSummary(ctx context.Context, tenantID uuid.UUID) (*riskSummary, error) {
	url := fmt.Sprintf("%s/api/v1/inventory-service/risk/summary", j.inventoryServiceURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(serviceauth.HeaderTenantID, tenantID.String())
	serviceauth.SignRequestFromEnv(req)

	resp, err := j.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("inventory-service responded %d: %s", resp.StatusCode, string(body))
	}

	var payload struct {
		RiskSummary riskSummary `json:"risk_summary"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &payload.RiskSummary, nil
}

// upsertSnapshot writes the day's row (UTC date), idempotent on the PK.
func (j *PostureSnapshotJob) upsertSnapshot(ctx context.Context, tenantID uuid.UUID, s *riskSummary) error {
	const q = `
		INSERT INTO public.posture_daily_snapshots
			(tenant_id, snapshot_date, total_assets, high_risk, medium_risk, low_risk,
			 unknown_risk, total_crypto, critical_findings, created_at, updated_at)
		VALUES ($1, (now() AT TIME ZONE 'UTC')::date, $2, $3, $4, $5, $6, $7, $8, now(), now())
		ON CONFLICT (tenant_id, snapshot_date) DO UPDATE SET
			total_assets      = EXCLUDED.total_assets,
			high_risk         = EXCLUDED.high_risk,
			medium_risk       = EXCLUDED.medium_risk,
			low_risk          = EXCLUDED.low_risk,
			unknown_risk      = EXCLUDED.unknown_risk,
			total_crypto      = EXCLUDED.total_crypto,
			critical_findings = EXCLUDED.critical_findings,
			updated_at        = now()`
	// RLS-scoped write on public.posture_daily_snapshots: the job iterates tenants
	// and upserts one tenant's row at a time with a known tenant id, so each write
	// runs inside WithTenantTx (app.tenant_id satisfies the policy's WITH CHECK).
	return shareddatabase.WithTenantTx(ctx, j.db, tenantID, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, q,
			tenantID, s.TotalAssets, s.HighRisk, s.MediumRisk, s.LowRisk,
			s.UnknownRisk, s.TotalCrypto, s.CriticalFindings,
		)
		return err
	})
}
