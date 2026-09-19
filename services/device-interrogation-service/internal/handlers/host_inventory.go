package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/services"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
)

// Host-inventory intake (asset-inventory workstream 2.11a, materialising since
// 2.11b).
//
// A LOCAL collection has no job behind it: the agent describes the host it is
// installed on, on its own schedule, with no credentials and nothing for the
// platform to have queued. It therefore arrives here rather than at /results,
// and this handler CREATES the device_jobs row that records it — agent-
// originated, already completed.
//
// Two steps, in this order and never the other one: the payload is STORED on
// that row, and then services.HostInventoryIngest materialises it into an
// asset, its facts, its endpoints and its software installs. Storing first is
// what makes a failed materialisation survivable — the report is durable and
// the job row says what went wrong, rather than a submission disappearing into
// an error the agent cannot act on.
//
// The same consumer serves the REMOTE path, where a collection arrives as an
// ordinary job result (ResultProcessor.ProcessJobResults). One consumer, two
// doors: a local branch and a remote branch would be two places to disagree
// about what a host inventory is.

// maxHostInventoryBytes bounds a submission.
//
// DERIVED from the collector's own caps rather than picked, because a byte cap
// that a legal collection can exceed is not a bound on abuse — it is a silent
// per-host outage. Measured on a real Ubuntu 24.04 collection: 443 bytes per
// package across the whole submission, and 584 per trust-store certificate.
// At hostinventory's declared ceilings (MaxPackages 20,000; MaxCertsPerStore
// 500 over three stores) the worst legal submission is ~9.3 MiB.
//
// 32 MiB is that worst case times 3.4. The previous 16 MiB was times 1.7,
// which is too thin to be sure of: package names, versions and purls are
// longer on some distributions than on the one that was measured, and being
// wrong costs the platform every future report from that host.
//
// Note the 443 bytes/package is TWO copies of the same list — the report's and
// the observations' — which are identical in size because projectPackage
// enumerates every field Package has. Collapsing them would halve this, but
// the copies are not interchangeable (only the observations half passes
// through di.Sanitize, and it is the half 2.11b materialises), so which one
// survives is the consumer's decision. It is on the 2.11b list in BUILD_PLAN.
const maxHostInventoryBytes = 32 << 20 // 32 MiB

// HostInventorySubmission is the body an agent posts.
//
// Report and Observations are both required. The observations are what 2.11b
// will materialise; the report is the collector's own account of what it ran
// and which sections FAILED, and without it an empty package list is
// indistinguishable from a host with no packages.
type HostInventorySubmission struct {
	AgentID      uuid.UUID             `json:"agent_id"`
	Mode         string                `json:"mode"`
	CollectedAt  time.Time             `json:"collected_at"`
	Report       *hostinventory.Report `json:"report"`
	Observations *di.InterrogateResult `json:"observations"`
	AgentVersion string                `json:"agent_version,omitempty"`
}

// hostInventoryStore is the slice of the database this handler needs, named so
// the handler can be contract-tested without one.
type hostInventoryStore interface {
	// RecordHostInventory writes the completed, agent-originated device_jobs
	// row and returns its id.
	RecordHostInventory(ctx context.Context, tenantID, agentID uuid.UUID, parameters, results []byte) (uuid.UUID, error)
}

// hostInventoryMaterialiser is the consumer that turns a stored collection into
// inventory. An interface for the same reason the store is one: the handler's
// contract — what it accepts, what it refuses, what it answers — is testable
// without a database behind it.
type hostInventoryMaterialiser interface {
	MaterialiseAndRecord(ctx context.Context, tenantID, agentID, jobID uuid.UUID, obs *di.InterrogateResult) (services.HostInventoryCounts, error)
}

// HostInventoryHandler serves the agent-authenticated intake route.
type HostInventoryHandler struct {
	store        hostInventoryStore
	materialiser hostInventoryMaterialiser
}

// NewHostInventoryHandler builds the handler over a real database.
func NewHostInventoryHandler(db, bypassDB *sql.DB) *HostInventoryHandler {
	return &HostInventoryHandler{
		store:        &hostInventoryRepository{db: db, bypassDB: bypassDB},
		materialiser: services.NewHostInventoryIngest(db, bypassDB),
	}
}

// NewHostInventoryHandlerWithStore builds the handler over any store and
// materialiser. Tests use it; nothing in production does. A nil materialiser
// means "store only", which is what the pure-contract tests want.
func NewHostInventoryHandlerWithStore(store hostInventoryStore, materialiser hostInventoryMaterialiser) *HostInventoryHandler {
	return &HostInventoryHandler{store: store, materialiser: materialiser}
}

// Submit accepts a local host-inventory collection from an agent.
//
// The tenant comes from AgentAuth's resolution of the agent id, never from the
// body: a body-supplied tenant on an ingestion path is how one tenant writes
// into another's inventory.
func (h *HostInventoryHandler) Submit(c *gin.Context) {
	agentID, ok := agentIDFromContext(c)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid agent ID"})
		return
	}
	tenantID, ok := tenantIDFromContext(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Agent is not associated with a tenant"})
		return
	}

	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxHostInventoryBytes)

	var body HostInventorySubmission
	if err := c.ShouldBindJSON(&body); err != nil {
		// An over-cap body is its OWN outcome, not a malformed one.
		//
		// Both used to answer 400 "Invalid request", which told the agent
		// nothing it could act on: a malformed body is a bug worth retrying
		// after an upgrade, while an over-cap body will be over-cap again in an
		// hour and every hour after that. Collapsed into one status, a host too
		// big to report became a host that retried forever and never appeared
		// in the inventory, with the reason visible only in the agent's own log.
		//
		// 413 names the cap and what the caller said it was sending, so the
		// agent can say the true size and an operator can size the gap.
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			log.Printf("host inventory intake: agent %s sent an over-cap report (declared %v, cap %d bytes)",
				agentID, declaredLength(c), maxHostInventoryBytes)
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{
				"error":         "Host inventory report is larger than this platform accepts",
				"max_bytes":     maxHostInventoryBytes,
				"declared_size": declaredLength(c),
				"detail": "The report was not stored. This is not a transient failure — the same host will " +
					"produce the same size next run. Reduce the collection (MaxPackages / MaxCertsPerStore) " +
					"or raise the platform's cap.",
			})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}
	if body.Report == nil || body.Observations == nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Both report and observations are required; a report without its observations cannot be materialised, " +
				"and observations without their report cannot say which sections failed",
		})
		return
	}
	// The body's agent_id is a claim; AgentAuth's is the authenticated identity.
	// A mismatch is a bug or an attempt, and either way the authenticated one
	// wins — silently, but the submission is refused so the agent's own logs
	// show something is wrong.
	if body.AgentID != uuid.Nil && body.AgentID != agentID {
		c.JSON(http.StatusForbidden, gin.H{"error": "Submission agent id does not match the authenticated agent"})
		return
	}

	// The package list travels ONCE, and the marker is what says which copy.
	//
	// `packages_omitted` is a POSITIVE assertion by the agent: "I had a list and
	// removed it from the report, because the sanitised copy is in the
	// observations beside it." A submission that makes that claim and carries no
	// observations list is self-contradictory — the only way the pair arises is
	// the surviving copy having been lost — and it is refused here rather than
	// stored, because a stored one reaches the consumer with a successful
	// package section and no packages, which is what would mark the host's whole
	// software inventory uninstalled.
	//
	// The consumer keeps its own guard for the same hazard arriving by another
	// door (the REMOTE path has no intake, and an old agent sends no marker at
	// all). This is the cheap, specific check: it names the problem to the agent
	// while the agent can still act on it, instead of leaving a person to read a
	// count off a job row.
	//
	// WITHOUT the marker nothing changes: an absent list then means a host with
	// no packages, a failed package step, or an agent old enough to send both
	// copies, and all three are legitimate.
	if body.Report.PackagesOmitted && !hasPackageList(body.Observations) {
		log.Printf("host inventory intake: agent %s marked its package list omitted but sent no observations copy", agentID)
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "The report says its package list was omitted, but the observations carry none either",
			"detail": "`report.packages_omitted` means the agent removed the list because the sanitised copy " +
				"travels in `observations.device_info.packages`. Both are absent, so the surviving copy was " +
				"lost in transit. The submission was NOT stored: materialising it would record this host as " +
				"having no software at all.",
		})
		return
	}

	// This endpoint is for LOCAL collections only. A remote collection is a job
	// and goes through /results, where the same hold applies. Accepting a
	// remote report here would create a device_jobs row that no job ever
	// produced, and the job list would then contain a job nobody queued.
	if hostinventory.Mode(body.Mode) != hostinventory.ModeLocal {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "This endpoint accepts local host-inventory collections only; a remote collection is a job and submits through /results",
		})
		return
	}

	// Re-sanitise on the way in. The agent already did (ToObservations ends in
	// deviceinterrogation.Sanitize), and doing it again here costs nothing and
	// removes the assumption that the thing on the far end of the wire ran the
	// version of the agent we think it did.
	di.Sanitize(body.Observations)

	parameters, err := json.Marshal(map[string]any{
		"mode":          string(hostinventory.ModeLocal),
		"platform":      body.Report.Platform,
		"agent_version": body.AgentVersion,
		"collected_at":  body.CollectedAt.UTC().Format(time.RFC3339),
		"origin":        "agent",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	results, err := json.Marshal(map[string]any{
		"success":      true,
		"report":       body.Report,
		"observations": body.Observations,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	jobID, err := h.store.RecordHostInventory(c.Request.Context(), tenantID, agentID, parameters, results)
	if err != nil {
		log.Printf("host inventory intake: failed to record submission for agent %s: %v", agentID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		return
	}

	// Materialise, then answer with what actually landed.
	//
	// AFTER the row exists, not instead of it: the payload is durable before
	// anything reads it, so a materialisation that fails leaves a job row a
	// person can look at rather than a submission that vanished. The counts go
	// onto that same row (MaterialiseAndRecord), so the Job Logs line and this
	// response say the same thing.
	//
	// A materialisation failure is reported as a FAILURE to the agent — 500,
	// with the job id — rather than folded into the 202 the storage earned.
	// "We took your report" and "your host is in the inventory" are different
	// claims, and an agent told the second when only the first is true has no
	// reason to look again.
	if h.materialiser == nil {
		log.Printf("host inventory stored but NOT materialised (no consumer wired): job=%s agent=%s", jobID, agentID)
		c.JSON(http.StatusAccepted, gin.H{
			"job_id": jobID,
			"status": "stored",
			"detail": "Stored as a completed host_inventory job. No materialiser is wired in this build.",
		})
		return
	}

	counts, err := h.materialiser.MaterialiseAndRecord(c.Request.Context(), tenantID, agentID, jobID, body.Observations)
	if err != nil {
		log.Printf("host inventory materialisation failed: job=%s agent=%s platform=%s: %v",
			jobID, agentID, body.Report.Platform, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":  "The host inventory was stored but could not be materialised",
			"job_id": jobID,
			"detail": "The report is on the job row and nothing was lost. See the job's processing summary for what went wrong.",
		})
		return
	}

	log.Printf("host inventory processed: job=%s agent=%s platform=%s asset=%s created=%t facts=%d endpoints=%d installs=+%d~%d-%d sections=%v",
		jobID, agentID, body.Report.Platform, counts.AssetID, counts.AssetCreated,
		counts.Facts, counts.Endpoints,
		counts.InstallsCreated, counts.InstallsUpdated, counts.InstallsRemoved,
		body.Report.Sections)

	status := "materialised"
	if counts.IdentityOutcome == "unresolved" {
		status = "unresolved"
	}
	if counts.Contested {
		// Not a failure and not a success: the engine opened a merge proposal
		// because a human has to say which machine this is. Naming it as its
		// own status is what stops an operator reading `asset_id: ""` as a bug.
		status = "contested"
	}
	c.JSON(http.StatusAccepted, gin.H{
		"job_id": jobID,
		"status": status,
		"counts": counts,
	})
}

// declaredLength reports what the caller said it was sending.
//
// The server cannot report what it MEASURED — MaxBytesReader stops reading at
// the cap, so the true size is not knowable here. Reporting the declared length
// and labelling it as declared is honest; reporting the cap as though it were
// the measurement would not be. A chunked request declares nothing, and says so
// rather than reporting 0 or -1 as if those were sizes.
func declaredLength(c *gin.Context) any {
	if c.Request.ContentLength < 0 {
		return "unknown (chunked)"
	}
	return c.Request.ContentLength
}

// hasPackageList reports whether the observations carry the surviving copy of
// the package list.
//
// Presence, not length. An empty array is a different claim from an absent key
// — it would mean "the projection ran and produced nothing" — but the collector
// omits the key entirely for an empty list, so in practice only a payload that
// has been through something else can produce one, and either way it is not the
// list a marked report promised.
func hasPackageList(obs *di.InterrogateResult) bool {
	if obs == nil || obs.DeviceInfo == nil {
		return false
	}
	v, ok := obs.DeviceInfo["packages"]
	return ok && v != nil
}

// agentIDFromContext reads the identity AgentAuth resolved.
func agentIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, exists := c.Get("agent_id")
	if !exists {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok && id != uuid.Nil
}

// tenantIDFromContext reads the tenant AgentAuth derived from the agent id.
func tenantIDFromContext(c *gin.Context) (uuid.UUID, bool) {
	v, exists := c.Get("tenantID")
	if !exists {
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	return id, ok && id != uuid.Nil
}

// hostInventoryRepository is the real store.
type hostInventoryRepository struct {
	db       *sql.DB
	bypassDB *sql.DB
}

// RecordHostInventory inserts the completed device_jobs row.
//
// RLS: the tenant is an INPUT here — AgentAuth resolved it from the agent id on
// the bypass role already — so the write runs under WithTenantTx with
// app.tenant_id set, which is what satisfies the row's WITH CHECK. The agent id
// is mandatory: the valid_job_assignment CHECK requires it for host_inventory,
// and a row without one could not be attributed to anything.
func (r *hostInventoryRepository) RecordHostInventory(ctx context.Context, tenantID, agentID uuid.UUID, parameters, results []byte) (uuid.UUID, error) {
	if r.db == nil {
		return uuid.Nil, errors.New("host inventory store has no database")
	}
	jobID := uuid.New()
	now := time.Now()

	err := shareddatabase.WithTenantTx(ctx, r.db, tenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, `
			INSERT INTO device_jobs (
				id, tenant_id, job_type, agent_id, status,
				parameters, results, created_at, assigned_at, started_at, completed_at, updated_at
			) VALUES ($1, $2, 'host_inventory', $3, 'completed', $4, $5, $6, $6, $6, $6, $6)
		`, jobID, tenantID, agentID, parameters, results, now)
		return execErr
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to record host inventory: %w", err)
	}
	return jobID, nil
}

// The job-type constant lives in the models package so the handler, the queue
// service and the result processor all name it the same way.
var _ = models.JobTypeHostInventory
