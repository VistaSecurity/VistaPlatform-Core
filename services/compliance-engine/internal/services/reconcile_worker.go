package services

// Reconcile worker plumbing (ADR-0014). Framework activation and platform-framework
// publish enqueue a per-tenant reconcile job on the COMPLIANCE JetStream stream; a
// durable consumer (in EventSubscriberService) drains them by running
// EvaluateTenantFrameworks. Each tenant is its own message, so a large publish
// fan-out is naturally chunked and resumable (JetStream redelivers unacked jobs).
//
// Kill-switch: COMPLIANCE_RECONCILE_WORKER_ENABLED=false disables BOTH the consumer
// subscription and enqueuing, degrading to on-asset-change evaluation only.

import (
	"errors"
	"log"
	"os"
	"sync"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/shared/events"
)

// ReconcileJob is the payload on compliance.reconcile.tenant.
//
// FrameworkID is the optional scope ( control-scoped fan-out): when set, the
// reconcile re-evaluates ONLY that platform framework's controls for the tenant,
// instead of every published framework × every asset. A framework publish or a
// per-tenant activation only changes the controls of the framework being touched,
// so the full cross-product is wasteful; scoping also confines stale-finding
// inactivation to that framework. Empty FrameworkID keeps the original whole-tenant
// behaviour (manual platform-admin re-evaluation).
type ReconcileJob struct {
	TenantID    string `json:"tenant_id"`
	Reason      string `json:"reason"`
	FrameworkID string `json:"framework_id,omitempty"`
}

// ReconcileWorkerEnabled reports whether the async reconcile worker is on (default true).
func ReconcileWorkerEnabled() bool {
	return os.Getenv("COMPLIANCE_RECONCILE_WORKER_ENABLED") != "false"
}

// ReconcileEnqueuer publishes per-tenant reconcile jobs. A nil enqueuer (NATS down or
// not wired) and a disabled worker both make every method a safe no-op.
//
// bypassDB is the BYPASSRLS handle (crypto_bypass): the only DB use here is the
// cross-tenant enumerator in fanOut, which reads every tenant id and must not be
// subject to RLS (Phase 4). It would fail closed on the RLS-bound crypto_app role.
type ReconcileEnqueuer struct {
	client   *events.NATSClient
	bypassDB *sqlx.DB
}

// NewReconcileEnqueuer builds an enqueuer over the shared NATS client + bypass DB pool.
func NewReconcileEnqueuer(client *events.NATSClient, bypassDB *sqlx.DB) *ReconcileEnqueuer {
	return &ReconcileEnqueuer{client: client, bypassDB: bypassDB}
}

func (e *ReconcileEnqueuer) ready() bool {
	return e != nil && e.client != nil && ReconcileWorkerEnabled()
}

// publish emits one reconcile job (best-effort; a publish error is logged, not fatal).
func (e *ReconcileEnqueuer) publish(job ReconcileJob) {
	if !e.ready() {
		return
	}
	if err := events.PublishJSON(e.client, events.SubjectComplianceReconcileTenant, job); err != nil {
		log.Printf("[Reconcile] enqueue tenant=%s framework=%s reason=%s failed: %v",
			job.TenantID, job.FrameworkID, job.Reason, err)
	}
}

// EnqueueTenant requests a whole-tenant reconcile (manual platform-admin re-eval).
func (e *ReconcileEnqueuer) EnqueueTenant(tenantID uuid.UUID, reason string) {
	e.publish(ReconcileJob{TenantID: tenantID.String(), Reason: reason})
}

// EnqueueTenantScoped requests a reconcile of ONLY frameworkID's controls for one
// tenant (e.g. that tenant just activated the framework). Other frameworks' findings
// are left untouched.
func (e *ReconcileEnqueuer) EnqueueTenantScoped(tenantID, frameworkID uuid.UUID, reason string) {
	e.publish(ReconcileJob{TenantID: tenantID.String(), FrameworkID: frameworkID.String(), Reason: reason})
}

// EnqueueAllTenants fans a whole-tenant reconcile out to every tenant.
func (e *ReconcileEnqueuer) EnqueueAllTenants(reason string) {
	e.fanOut(uuid.Nil, reason)
}

// EnqueueAllTenantsScoped fans a reconcile of ONLY frameworkID's controls out to every
// tenant (e.g. the framework was just published or its rules changed).
func (e *ReconcileEnqueuer) EnqueueAllTenantsScoped(frameworkID uuid.UUID, reason string) {
	e.fanOut(frameworkID, reason)
}

// listActiveTenantIDs returns the ids of every non-soft-deleted tenant.
//
// SEC-5: excludes tenants with deleted_at set — without this filter, every
// publish/activation fan-out enqueued a reconcile job for tenants that no
// longer exist in any user-facing sense, wasting worker capacity evaluating
// a tenant nobody can see the findings of.
func listActiveTenantIDs(bypassDB *sqlx.DB) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	err := bypassDB.Select(&ids, `SELECT id FROM tenants WHERE deleted_at IS NULL`)
	return ids, err
}

var errReconcileStillDirty = errors.New("coalesced reconcile still dirty after follow-up budget")

// maxCoalescedFollowups bounds how many extra passes one in-flight runner will make
// to service requests that arrived while it was running. Each pass is a full convergent
// reconcile, so a single follow-up already absorbs everything that queued during the
// previous one; the bound only exists so a tenant under continuous churn cannot hold a
// JetStream message unacked past AckWait forever. If the key is still dirty when the
// bound is hit, return errReconcileStillDirty so the original JetStream message is
// redelivered. Coalesced sibling messages have already ACKed, so ACKing the runner too
// would leave no guaranteed follow-up to cover the final dirty flag.
const maxCoalescedFollowups = 3

// tenantCoalescer collapses concurrent whole-tenant reconcile requests for the same key
// into one in-flight run plus (at most) one follow-up pass per burst.
//
// Why: a whole-tenant reconcile re-evaluates every published control against every asset.
// A cert-heavy ingest batch used to fire one of those per event, so N events did N full
// passes whose results were identical after the first — the reconcile is a convergent
// diff, so a pass that starts AFTER a change lands already covers that change. Running a
// pass concurrently with (or immediately after) another for the same tenant is therefore
// pure waste.
//
// Semantics: the first caller for a key runs; callers arriving while it runs set a dirty
// flag and return immediately (coalesced=true, no work). When the runner finishes it
// re-checks dirty and runs again — so a request that landed mid-pass is never dropped,
// it is merged into the next pass.
//
// MULTI-REPLICA CAVEAT: this is in-process state. The reconcile consumer is a
// queue-grouped JetStream durable ("compliance-engine"), so with more than one replica a
// tenant's jobs can land on different pods and each pod coalesces only its own share.
// That costs dedup rate, never correctness: every pass is an idempotent convergent
// reconcile (reconcilePlan + upsert/inactivate), so overlapping passes converge to the
// same materialized findings. A cross-replica lock (advisory lock / Redis lease) would
// be the fix if the service is ever scaled out and the churn still hurts.
//
// A nil *tenantCoalescer is valid and simply runs fn inline, so tests and any caller
// that builds FindingsService as a struct literal keep working.
type tenantCoalescer struct {
	mu       sync.Mutex
	inFlight map[string]bool
	dirty    map[string]bool
}

func newTenantCoalescer() *tenantCoalescer {
	return &tenantCoalescer{
		inFlight: map[string]bool{},
		dirty:    map[string]bool{},
	}
}

// Run executes fn for key unless a run for the same key is already in flight, in which
// case it marks the key dirty and returns (0, true, nil) without running. It reports how
// many passes it made, whether this call was coalesced away, and the error of the last
// pass it ran.
func (c *tenantCoalescer) Run(key string, fn func() error) (passes int, coalesced bool, err error) {
	if c == nil {
		if err := fn(); err != nil {
			return 1, false, err
		}
		return 1, false, nil
	}

	c.mu.Lock()
	if c.inFlight[key] {
		c.dirty[key] = true
		c.mu.Unlock()
		return 0, true, nil
	}
	c.inFlight[key] = true
	c.dirty[key] = false
	c.mu.Unlock()

	defer func() {
		c.mu.Lock()
		delete(c.inFlight, key)
		c.mu.Unlock()
	}()

	for {
		passes++
		if err = fn(); err != nil {
			// Leave any dirty flag set: the failed pass is redelivered by JetStream and
			// the requests it was meant to absorb are still outstanding.
			return passes, false, err
		}

		c.mu.Lock()
		if !c.dirty[key] {
			c.mu.Unlock()
			return passes, false, nil
		}
		if passes > maxCoalescedFollowups {
			// Still dirty but out of budget — surface an error so the owning
			// message is redelivered instead of ACKing the last pending request.
			c.mu.Unlock()
			log.Printf("[Reconcile] coalescer: key=%s still dirty after %d passes; requesting redelivery", key, passes)
			return passes, false, errReconcileStillDirty
		}
		c.dirty[key] = false
		c.mu.Unlock()
	}
}

// fanOut publishes one reconcile job per tenant. One message per tenant keeps the
// fan-out chunked and resumable rather than one giant job. frameworkID == uuid.Nil
// means a whole-tenant reconcile; otherwise the job is scoped to that framework.
func (e *ReconcileEnqueuer) fanOut(frameworkID uuid.UUID, reason string) {
	if !e.ready() {
		return
	}
	// RLS: cross-tenant enumerator — reads every tenant id on framework publish to
	// fan a per-tenant reconcile job out. Each job is then drained per-message under
	// the resolved tenant's app.tenant_id (handleReconcileTenant → EvaluateTenant*).
	// This enumerate itself runs on the bypass role (Phase 4).
	ids, err := listActiveTenantIDs(e.bypassDB)
	if err != nil {
		log.Printf("[Reconcile] enumerate tenants failed (reason=%s): %v", reason, err)
		return
	}
	var fwStr string
	if frameworkID != uuid.Nil {
		fwStr = frameworkID.String()
	}
	for _, id := range ids {
		e.publish(ReconcileJob{TenantID: id.String(), FrameworkID: fwStr, Reason: reason})
	}
	log.Printf("[Reconcile] fanned out reason=%s framework=%s to %d tenants", reason, fwStr, len(ids))
}
