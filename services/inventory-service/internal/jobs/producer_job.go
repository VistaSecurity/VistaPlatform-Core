package jobs

import (
	"context"
	"database/sql"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	inventorydb "github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/producers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/riskrollup"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	auditjoblogger "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// FindingProducerJob runs the inventory-service finding producers — `eol`,
// `vulnerability`, `crypto`, `configuration`, `hygiene` and `drift` — and,
// after every pass, recomputes per-asset risk.
//
// Two triggers, and they answer different questions:
//
//   - a NIGHTLY full pass over every tenant, because the catalogues move under
//     a static inventory. A date passes, a CVE is published against a version
//     nobody has touched — nothing about the tenant changed, and the answer did.
//     Without the timer an install would keep the verdict it got on the day it
//     was uploaded.
//   - a TRIGGER after an SBOM upload, because the inventory moved under static
//     catalogues. Waiting until tomorrow to tell somebody the package they just
//     uploaded has a critical CVE makes the upload feel like it did nothing.
//
// Host-inventory materialisation is NOT a trigger today, and the distinction is
// worth stating rather than implying: that path runs in
// device-interrogation-service, so reaching this job from it needs an event on
// the bus rather than the in-process hook an SBOM upload uses. Until it exists,
// an agent-collected package list waits for the nightly pass. Follow-up, not a
// thing this claims to do.
//
// [FindingProducerJob.Trigger] is non-blocking and COALESCED per tenant: a
// hundred SBOM uploads in a minute produce one run plus at most one follow-up,
// not a hundred queued passes over the same inventory. The follow-up matters —
// dropping the request outright would lose the last upload's findings whenever
// it arrived while a pass was already in flight.
//
// # The post-pass recompute is GENERIC, and that is the point
//
// `assets.risk_score` is MAX over the open risk-feeding findings on the asset
// and its descendants, and `assets.risk_assessed_by` is the set of producers
// that have completed a pass over it (ADR-0005 D4). Both are derived, so every
// pass that changes a finding or a coverage row has to be followed by a
// recompute — and there is exactly ONE recompute, in
// `internal/riskrollup`, run here after the whole tenant pass.
//
// It is deliberately not a step each producer performs. A producer that had to
// remember to recompute is a producer that can forget to, and the workstreams
// adding `configuration`, `hygiene` and `drift` would each have to rediscover
// the rule. Running it once per tenant AFTER every producer has spoken is also
// cheaper than running it per producer: the statement is set-based over the
// tenant, so N producers would otherwise pay for N full recomputes to reach the
// same answer the last one gives.
type FindingProducerJob struct {
	external *services.ExternalConnectionsService
	eol      *producers.EOLProducer
	vuln     *producers.VulnerabilityProducer
	crypto   *producers.CryptoProducer
	// config and hygiene are workstream 3.5's producers, drift is 4.7's. They
	// read only the tenant's own inventory — no catalogue, no mirror — so they
	// need one handle and cannot be held up by a feed that has never run.
	config  *producers.ConfigurationProducer
	hygiene *producers.HygieneProducer
	drift   *producers.DriftProducer

	// appDB is the RLS-subject handle the post-pass recompute runs on. The
	// producers hold their own; this one is for the step that belongs to no
	// producer.
	appDB *sql.DB

	// bypassDB is the BYPASSRLS handle, used ONLY by the cross-tenant
	// enumerator. Every per-tenant pass runs on the RLS-scoped handle inside
	// the producer.
	bypassDB *sql.DB

	logger   *log.Logger
	interval time.Duration

	auditServiceURL string
	newJobLogger    func(jobID uuid.UUID) jobExecutionLog
	listTenants     func() ([]uuid.UUID, error)

	// mu guards the coalescer state below.
	mu sync.Mutex
	// running is the set of tenants with a pass in flight; pending is the set
	// that asked for one while it was.
	running map[uuid.UUID]bool
	pending map[uuid.UUID]bool
}

// NewFindingProducerJob builds the job.
//
// appDB is the RLS-subject handle the producers write on; bypassDB is used to
// enumerate tenants and to read the platform catalogues, which carry no
// tenant_id.
func NewFindingProducerJob(appDB, bypassDB *sql.DB) (*FindingProducerJob, error) {
	eol, err := producers.NewEOLProducer(appDB, bypassDB)
	if err != nil {
		return nil, err
	}
	vuln, err := producers.NewVulnerabilityProducer(appDB, bypassDB)
	if err != nil {
		return nil, err
	}
	crypto, err := producers.NewCryptoProducer(appDB)
	if err != nil {
		return nil, err
	}
	config, err := producers.NewConfigurationProducer(appDB)
	if err != nil {
		return nil, err
	}
	hygiene, err := producers.NewHygieneProducer(appDB)
	if err != nil {
		return nil, err
	}
	drift, err := producers.NewDriftProducer(appDB)
	if err != nil {
		return nil, err
	}

	interval := 24 * time.Hour
	if s := os.Getenv("FINDING_PRODUCER_INTERVAL"); s != "" {
		if parsed, err := time.ParseDuration(s); err == nil && parsed > 0 {
			interval = parsed
		}
	}

	auditServiceURL := os.Getenv("AUDIT_SERVICE_URL")
	if auditServiceURL == "" {
		auditServiceURL = sharedconfig.PeerURL("audit-service", sharedconfig.MTLSEnabled())
	}

	externalDB := &inventorydb.DB{DB: sqlx.NewDb(appDB, "postgres")}
	j := &FindingProducerJob{
		external:        services.NewExternalConnectionsService(externalDB, services.NewAlgorithmService(externalDB)),
		eol:             eol,
		vuln:            vuln,
		crypto:          crypto,
		config:          config,
		hygiene:         hygiene,
		drift:           drift,
		appDB:           appDB,
		bypassDB:        bypassDB,
		logger:          log.New(log.Writer(), "[FindingProducerJob] ", log.LstdFlags),
		interval:        interval,
		auditServiceURL: auditServiceURL,
		running:         map[uuid.UUID]bool{},
		pending:         map[uuid.UUID]bool{},
	}
	j.newJobLogger = func(jobID uuid.UUID) jobExecutionLog {
		return auditjoblogger.NewJobLogger(j.auditServiceURL, jobID, "finding_producers", "Finding Producers", nil, nil)
	}
	j.listTenants = j.tenantsToProcess
	return j, nil
}

// Start runs the nightly loop until ctx is cancelled.
//
// The first pass runs immediately, so a fresh install does not wait a day for
// its first end-of-life findings.
func (j *FindingProducerJob) Start(ctx context.Context) {
	j.logger.Printf("Starting finding producers (interval: %v)", j.interval)
	j.runAllTenants(ctx)

	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			j.logger.Println("Stopping finding producers")
			return
		case <-ticker.C:
			j.runAllTenants(ctx)
		}
	}
}

// SoftwareChangeNotifier is anything that can tell this job a tenant's
// software changed. [services.SBOMIngestService] is the one implementation.
//
// An interface so the WIRING is testable: "the hook is installed" is a
// different claim from "the hook works", and it is the one that silently stops
// being true when somebody tidies a constructor.
type SoftwareChangeNotifier interface {
	OnIngested(func(ctx context.Context, tenantID uuid.UUID))
}

// SubscribeToSoftwareChanges makes an SBOM upload trigger a pass for that
// tenant.
//
// Call it once per notifier, at startup. The hook is [FindingProducerJob.Trigger],
// which returns immediately and coalesces per tenant.
func (j *FindingProducerJob) SubscribeToSoftwareChanges(n SoftwareChangeNotifier) {
	if n == nil {
		return
	}
	n.OnIngested(j.Trigger)
}

// CryptoChangeNotifier is anything that can tell this job a tenant's crypto
// posture changed. [services.AssetService] is the one implementation.
//
// An interface for the same reason SoftwareChangeNotifier is one: "the hook is
// installed" is a different claim from "the hook works", and it is the one that
// silently stops being true when somebody tidies a constructor. Ingest no longer
// computes risk itself, so with this hook missing a newly-observed weak
// configuration would not reach the asset's score until the nightly pass.
type CryptoChangeNotifier interface {
	OnCryptoChanged(func(ctx context.Context, tenantID uuid.UUID))
}

// SubscribeToCryptoChanges makes an ingest that wrote a crypto configuration
// trigger a pass for that tenant.
func (j *FindingProducerJob) SubscribeToCryptoChanges(n CryptoChangeNotifier) {
	if n == nil {
		return
	}
	n.OnCryptoChanged(j.Trigger)
}

// Trigger asks for a pass over one tenant, without blocking the caller.
//
// Safe to call from an ingest path: it returns immediately, and a request that
// arrives while a pass is already in flight for that tenant is remembered and
// satisfied by ONE follow-up rather than queueing another pass per call.
//
// Deliberately fire-and-forget. An SBOM upload must not fail because the
// producers could not run — the upload is the user's work and the findings are
// ours, and coupling them would mean a catalogue problem rejected the data.
func (j *FindingProducerJob) Trigger(ctx context.Context, tenantID uuid.UUID) {
	if tenantID == uuid.Nil {
		return
	}
	j.mu.Lock()
	if j.running[tenantID] {
		j.pending[tenantID] = true
		j.mu.Unlock()
		return
	}
	j.running[tenantID] = true
	j.mu.Unlock()

	go j.drain(context.WithoutCancel(ctx), tenantID)
}

// drain runs the tenant's pass, then any follow-up its own run asked for.
//
// `context.WithoutCancel` at the call site is deliberate: the trigger comes
// from an HTTP request whose context is cancelled the moment the response is
// written, and a pass that inherited it would be killed part way through — and
// a pass killed part way through is exactly the run that must not sweep.
func (j *FindingProducerJob) drain(ctx context.Context, tenantID uuid.UUID) {
	for {
		j.runTenant(ctx, tenantID)

		j.mu.Lock()
		if !j.pending[tenantID] {
			delete(j.running, tenantID)
			j.mu.Unlock()
			return
		}
		delete(j.pending, tenantID)
		j.mu.Unlock()
	}
}

// runAllTenants is the nightly pass.
func (j *FindingProducerJob) runAllTenants(ctx context.Context) {
	jobID := uuid.New()
	jobLogger := j.newJobLogger(jobID)
	if _, err := jobLogger.LogStart(ctx, map[string]interface{}{"interval": j.interval.String()}); err != nil {
		j.logger.Printf("WARNING: could not log job start: %v", err)
	}

	tenantIDs, err := j.listTenants()
	if err != nil {
		j.logger.Printf("ERROR: could not enumerate tenants: %v", err)
		msg := err.Error()
		_ = jobLogger.LogCompletion(ctx, "failed", 0, 0, 0, &msg, nil)
		return
	}
	if len(tenantIDs) == 0 {
		// Every path out of here emits a completion, including this one: a
		// start with no completion reads as an execution that is still running
		// forever.
		_ = jobLogger.LogCompletion(ctx, "completed", 0, 0, 0, nil, map[string]interface{}{"tenants_processed": 0})
		return
	}

	processed, succeeded, failed := 0, 0, 0
	for _, tenantID := range tenantIDs {
		select {
		case <-ctx.Done():
			_ = jobLogger.LogCompletion(ctx, "cancelled", processed, succeeded, failed, nil, nil)
			return
		default:
		}
		processed++
		if j.runTenant(ctx, tenantID) {
			succeeded++
		} else {
			failed++
		}
		if processed%10 == 0 {
			_ = jobLogger.LogProgress(ctx, processed, succeeded, failed)
		}
	}
	_ = jobLogger.LogCompletion(ctx, "completed", processed, succeeded, failed, nil,
		map[string]interface{}{"tenants_processed": len(tenantIDs)})
}

// runTenant runs every producer for one tenant, then recomputes risk. Returns
// false if any producer failed.
//
// The producers are independent: a vulnerability catalogue that is empty or a
// mirror that has never run must not stop end-of-life findings from being
// written, and neither the configuration, hygiene nor drift pass depends on a
// catalogue at all. So a failure in one is logged and the others still run.
//
// The recompute runs EVEN IF a producer failed, and that is deliberate rather
// than sloppy. A failed pass wrote nothing — its whole write phase is one
// transaction, so it rolled back its findings AND its coverage claim together —
// so recomputing simply reconciles `assets` with the findings that do exist.
// Skipping it would leave the rollup describing a set of findings the other
// producers have since changed, which is the drift the persisted rollup exists
// to avoid.
func (j *FindingProducerJob) runTenant(ctx context.Context, tenantID uuid.UUID) bool {
	ok := true
	// External-only tenants participate too. Each bounded batch commits on its
	// own; a failed batch keeps its cursor unchanged and retries next pass.
	if j.external != nil {
		after := uuid.Nil
		for {
			next, n, err := j.external.ReassessBatch(ctx, tenantID, after, 200)
			if err != nil {
				ok = false
				j.logger.Printf("ERROR: external strength reassessment failed for tenant %s: %v", tenantID, err)
				break
			}
			if n == 0 {
				break
			}
			after = next
		}
	}

	if run, err := j.eol.Run(ctx, tenantID); err != nil {
		ok = false
		j.logger.Printf("ERROR: eol producer failed for tenant %s: %v", tenantID, err)
	} else if run.Raised > 0 || run.Resolved > 0 || run.MissesDropped > 0 || run.LifecycleSwept > 0 {
		j.logger.Printf("eol tenant=%s raised=%d resolved=%d matched=%d gaps=%d gaps_dropped=%d facts=%d skipped=%d lifecycle=%d lifecycle_swept=%d",
			tenantID, run.Raised, run.Resolved, run.Matched, run.Misses, run.MissesDropped, run.FactsWritten, run.Skipped,
			run.Lifecycle, run.LifecycleSwept)
	}

	if run, err := j.vuln.Run(ctx, tenantID); err != nil {
		ok = false
		j.logger.Printf("ERROR: vulnerability producer failed for tenant %s: %v", tenantID, err)
	} else if run.Raised > 0 || run.Resolved > 0 || run.Unidentifiable > 0 {
		// Unidentifiable and Undecidable are logged even at zero findings: "no
		// known vulnerabilities" and "nothing could be checked" are different
		// answers and the operator needs to be able to tell them apart.
		j.logger.Printf("vulnerability tenant=%s raised=%d resolved=%d installs=%d matched=%d cves=%d unidentifiable=%d undecidable=%d truncated=%v",
			tenantID, run.Raised, run.Resolved, run.Installs, run.Matched, run.CVEs,
			run.Unidentifiable, run.Undecidable, run.AdvisoriesTruncated)
	}

	if run, err := j.crypto.Run(ctx, tenantID); err != nil {
		ok = false
		j.logger.Printf("ERROR: crypto producer failed for tenant %s: %v", tenantID, err)
	} else if run.Raised > 0 || run.Resolved > 0 || run.Unassessable > 0 {
		j.logger.Printf("crypto tenant=%s raised=%d resolved=%d configurations=%d certificates=%d keys=%d assessed=%d unassessable=%d pqc_vulnerable=%d",
			tenantID, run.Raised, run.Resolved, run.Configurations, run.Certificates,
			run.Keys, run.Assessed, run.Unassessable, run.PQCVulnerable)
	}

	if run, err := j.config.Run(ctx, tenantID); err != nil {
		ok = false
		j.logger.Printf("ERROR: configuration producer failed for tenant %s: %v", tenantID, err)
	} else if run.Raised > 0 || run.Resolved > 0 || run.Endpoints > 0 {
		// Endpoints, PlaintextAssessed and Assessed are logged at zero findings
		// too: "nothing is misconfigured" and "nothing has been
		// service-identified or interrogated" are different answers, and the
		// operator has no other way to tell them apart.
		j.logger.Printf("configuration tenant=%s raised=%d resolved=%d assets=%d endpoints=%d by_name=%d by_port=%d plaintext_assessed=%d assessed=%d",
			tenantID, run.Raised, run.Resolved, run.Assets, run.Endpoints,
			run.MatchedByName, run.MatchedByPort, run.PlaintextAssessed, run.Assessed)
	}

	if run, err := j.hygiene.Run(ctx, tenantID); err != nil {
		ok = false
		j.logger.Printf("ERROR: hygiene producer failed for tenant %s: %v", tenantID, err)
	} else if run.Raised > 0 || run.Resolved > 0 || run.Assets > 0 {
		j.logger.Printf("hygiene tenant=%s raised=%d resolved=%d assets=%d endpoints=%d installs=%d edges=%d proposals=%d assessed=%d",
			tenantID, run.Raised, run.Resolved, run.Assets, run.Endpoints,
			run.Installs, run.Relationships, run.Proposals, run.Assessed)
	}

	if run, err := j.drift.Run(ctx, tenantID); err != nil {
		ok = false
		j.logger.Printf("ERROR: drift producer failed for tenant %s: %v", tenantID, err)
	} else if run.WarmingUp {
		// Logged at zero findings on purpose: "we have not been watching this
		// tenant for a full baseline window yet" and "nothing has drifted" are
		// different answers, and the second one is the only one that would show
		// on a screen. It also claims no COVERAGE, so nothing here reads as
		// assessed either.
		j.logger.Printf("drift tenant=%s warming_up window_days=%d assets=%d",
			tenantID, run.BaselineDays, run.Assets)
	} else if run.Raised > 0 || run.Resolved > 0 || run.Reopened > 0 || run.NoBaseline > 0 {
		j.logger.Printf("drift tenant=%s raised=%d resolved=%d reopened=%d assets=%d assessed=%d no_baseline=%d window_days=%d",
			tenantID, run.Raised, run.Resolved, run.Reopened, run.Assets, run.Assessed, run.NoBaseline, run.BaselineDays)
	}

	if err := j.recomputeRisk(ctx, tenantID); err != nil {
		ok = false
		j.logger.Printf("ERROR: risk recompute failed for tenant %s: %v", tenantID, err)
	}

	return ok
}

// recomputeRisk is the generic post-pass step.
//
// Every producer — the three above and the ones workstreams 3.5 and 4.7 add —
// gets this for free by being called from runTenant. A new producer wires
// itself in beside them and needs to know nothing about risk: it writes its
// findings and its coverage through the shared writer, and the rollup is
// recomputed from the registry's `feeds_risk` flags without naming it.
//
// # What it DOES depend on the producer for
//
// The score half is free — the rollup reads whatever findings exist. The
// COVERAGE half is not: `assets.risk_assessed_by` is derived from
// `producer_assessments`, so a producer that never calls
// `producer.Writer.MarkAssessed` contributes nothing to it however many
// findings it writes. An asset that producer scored then reads as a real number
// with an empty coverage array, which every reader — the asset page, the facet
// rail, the compliance `finding` shape — spells NOT ASSESSED. Calling
// MarkAssessed from inside the pass's own write transaction is therefore part
// of a producer's contract, not an optional extra; see the doc on MarkAssessed
// for what belongs in the list.
func (j *FindingProducerJob) recomputeRisk(ctx context.Context, tenantID uuid.UUID) error {
	if j.appDB == nil {
		return nil
	}
	return shareddatabase.WithTenantTx(ctx, j.appDB, tenantID, func(tx *sql.Tx) error {
		n, err := riskrollup.Recompute(ctx, tx, tenantID, uuid.Nil)
		if err != nil {
			return err
		}
		if n > 0 {
			j.logger.Printf("risk rollup tenant=%s assets_changed=%d", tenantID, n)
		}
		return nil
	})
}

// tenantsToProcess enumerates every tenant with inventory to judge.
//
// Cross-tenant, so it runs on the bypass role. Enumerating by "has assets"
// rather than by any settings row, for the reason the stale-asset detector
// learned the hard way: a settings row exists only for tenants who opened the
// page, so enumerating by one silently skips every tenant onboarded through
// signup while the UI shows them the default they were told they had.
//
// With no bypass handle this returns nothing and the whole job no-ops — which
// is why the caller logs the tenant count rather than reporting success on an
// empty list.
func (j *FindingProducerJob) tenantsToProcess() ([]uuid.UUID, error) {
	if j.bypassDB == nil {
		return nil, nil
	}
	rows, err := j.bypassDB.Query(`SELECT tenant_id FROM assets WHERE deleted_at IS NULL UNION SELECT tenant_id FROM external_connections`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			continue
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
