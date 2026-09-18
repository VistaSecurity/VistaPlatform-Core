// Package confighttp is the HTTP surface for desired state, shared by
// sensor-manager and device-interrogation-service.
//
// It exists because the alternative was writing it twice. The rules it encodes
// — that confirmation is decided server-side, that floors are raised and
// reported, that a save answers with what actually changed — are product
// decisions, not per-service ones, and the two halves of this product have
// already drifted apart once from exactly this kind of duplication.
//
// The services supply only what genuinely differs: which runtime they own, how
// to turn a request into an owner, and how to check that the owner belongs to
// the tenant.
package confighttp

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/agentconfig"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/store"
)

// Deps is what a service provides.
type Deps struct {
	// Runtime is the kind of device this service owns.
	Runtime agentconfig.Runtime
	// Store reads and writes desired state.
	Store *store.Store
	// OwnerFrom turns a request into the owner it addresses. It returns false
	// having ALREADY answered the request — a not-found, a bad id — so the
	// service keeps ownership of what those answers look like.
	OwnerFrom func(c *gin.Context, tenantID uuid.UUID) (store.Owner, bool)
	// DeviceVersion reports the version this device last told the platform it
	// was running, empty when it has never said. Per-service because the two
	// runtimes keep it in different tables.
	DeviceVersion func(c *gin.Context, tenantID uuid.UUID, owner store.Owner) string
}

// Handler serves the operator-facing surface.
type Handler struct{ deps Deps }

func New(deps Deps) *Handler { return &Handler{deps: deps} }

// Request is the body for both device and fleet writes.
type Request struct {
	// Values replaces the whole set. A key left out is cleared: a partial write
	// cannot express "remove this one", and guessing which was meant is how a
	// setting comes back from the dead.
	Values agentconfig.Values `json:"values"`
	// Confirmed acknowledges a setting whose registry entry demands it. The
	// SERVER decides whether one is needed; a client cannot waive it by
	// omitting the flag.
	Confirmed bool `json:"confirmed"`
}

// Setting is one resolved setting as a client renders it. The registry's own
// metadata rides along so a client needs no second copy of the rules.
type Setting struct {
	Key         agentconfig.Key    `json:"key"`
	Value       agentconfig.Value  `json:"value"`
	Origin      agentconfig.Origin `json:"origin"`
	Kind        agentconfig.Kind   `json:"kind"`
	Apply       agentconfig.Apply  `json:"apply"`
	Description string             `json:"description"`
	Confirm     string             `json:"confirm,omitempty"`
	Min         int64              `json:"min,omitempty"`
	Max         int64              `json:"max,omitempty"`
	Allowed     []string           `json:"allowed,omitempty"`
}

// Status is the convergence answer.
type Status struct {
	State          agentconfig.State `json:"state"`
	DesiredVersion string            `json:"desired_revision"`
	ReportedAt     *time.Time        `json:"reported_at,omitempty"`
	Failures       map[string]string `json:"failures,omitempty"`
	PendingRestart []string          `json:"pending_restart,omitempty"`
}

// Describe renders resolved settings for the wire.
func Describe(rs []agentconfig.Resolved) []Setting {
	out := make([]Setting, 0, len(rs))
	for _, r := range rs {
		out = append(out, Setting{
			Key: r.Key, Value: r.Value, Origin: r.Origin,
			Kind: r.Field.Kind, Apply: r.Field.Apply,
			Description: r.Field.Description, Confirm: r.Field.Confirm,
			Min: r.Field.Min, Max: r.Field.Max, Allowed: r.Field.Allowed,
		})
	}
	return out
}

// DescribeStatus renders a convergence status for the wire.
func DescribeStatus(st agentconfig.Status) Status {
	out := Status{State: st.State, DesiredVersion: st.Desired}
	if !st.At.IsZero() {
		at := st.At
		out.ReportedAt = &at
	}
	if len(st.Failures) > 0 {
		out.Failures = make(map[string]string, len(st.Failures))
		for k, v := range st.Failures {
			out.Failures[string(k)] = v
		}
	}
	for _, k := range st.PendingRestart {
		out.PendingRestart = append(out.PendingRestart, string(k))
	}
	return out
}

// GetDevice answers one device's effective settings and convergence state.
func (h *Handler) GetDevice(c *gin.Context) {
	tenantID, ok := TenantFrom(c)
	if !ok {
		return
	}
	owner, ok := h.deps.OwnerFrom(c, tenantID)
	if !ok {
		return
	}
	desired, err := h.deps.Store.Load(c.Request.Context(), tenantID, owner)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read the configuration"})
		return
	}
	expected := agentconfig.ExpectedVersion()
	deviceVersion := ""
	if h.deps.DeviceVersion != nil {
		deviceVersion = h.deps.DeviceVersion(c, tenantID, owner)
	}
	c.JSON(http.StatusOK, gin.H{
		"runtime":  h.deps.Runtime,
		"settings": Describe(desired.Resolved),
		"status":   DescribeStatus(desired.Status),
		// Version visibility (owner decision 4). The expected version is the
		// release THIS platform runs, because the device binaries ship from the
		// same tag — so the platform can only say a device is behind once it
		// has itself been upgraded, and it never asks an external service.
		//
		// Both fields are sent even when empty: "the platform does not know its
		// own version" is an answer a console can render honestly, and an
		// absent field would be rendered as up to date by the first client that
		// forgets to check.
		"version": gin.H{
			"device":   deviceVersion,
			"expected": expected,
			"state":    agentconfig.CompareVersions(deviceVersion, expected),
		},
	})
}

// PutDevice replaces one device's override.
func (h *Handler) PutDevice(c *gin.Context) {
	tenantID, ok := TenantFrom(c)
	if !ok {
		return
	}
	owner, ok := h.deps.OwnerFrom(c, tenantID)
	if !ok {
		return
	}
	var req Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	h.write(c, tenantID, req,
		func(vals agentconfig.Values, by uuid.UUID) error {
			return h.deps.Store.SaveOverride(c.Request.Context(), tenantID, owner, vals, by)
		},
		func() (agentconfig.Values, error) {
			d, err := h.deps.Store.Load(c.Request.Context(), tenantID, owner)
			if err != nil {
				return nil, err
			}
			return d.Values, nil
		})
}

// GetDefaults answers the tenant's fleet defaults for this runtime.
func (h *Handler) GetDefaults(c *gin.Context) {
	tenantID, ok := TenantFrom(c)
	if !ok {
		return
	}
	resolved, err := h.deps.Store.LoadDefaults(c.Request.Context(), tenantID, h.deps.Runtime)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read the fleet defaults"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"runtime": h.deps.Runtime, "settings": Describe(resolved)})
}

// PutDefaults replaces the tenant's fleet defaults for this runtime.
func (h *Handler) PutDefaults(c *gin.Context) {
	tenantID, ok := TenantFrom(c)
	if !ok {
		return
	}
	var req Request
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	h.write(c, tenantID, req,
		func(vals agentconfig.Values, by uuid.UUID) error {
			return h.deps.Store.SaveDefaults(c.Request.Context(), tenantID, h.deps.Runtime, vals, by)
		},
		func() (agentconfig.Values, error) {
			rs, err := h.deps.Store.LoadDefaults(c.Request.Context(), tenantID, h.deps.Runtime)
			if err != nil {
				return nil, err
			}
			out := make(agentconfig.Values, len(rs))
			for _, r := range rs {
				out[r.Key] = r.Value
			}
			return out, nil
		})
}

// write is the save path both surfaces share: validate, require any
// confirmation the registry demands, normalize floors, store, and report what
// changed and what was adjusted.
func (h *Handler) write(
	c *gin.Context,
	tenantID uuid.UUID,
	req Request,
	save func(agentconfig.Values, uuid.UUID) error,
	current func() (agentconfig.Values, error),
) {
	rt := h.deps.Runtime
	if err := agentconfig.Validate(rt, req.Values); err != nil {
		writeValidationError(c, err)
		return
	}

	before, err := current()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read the current configuration"})
		return
	}

	// Decided here, against the registry — never by trusting the client's flag
	// to have been sent. A setting whose condition for being remotely settable
	// was that somebody acknowledges what it collects cannot be turned on by a
	// client that simply omits the acknowledgement.
	if needs := agentconfig.NeedsConfirmation(rt, before, req.Values); len(needs) > 0 && !req.Confirmed {
		out := make([]gin.H, 0, len(needs))
		for _, f := range needs {
			out = append(out, gin.H{"key": f.Key, "confirm": f.Confirm})
		}
		c.JSON(http.StatusConflict, gin.H{
			"error":            "This change needs to be confirmed",
			"needs_confirming": out,
		})
		return
	}

	normalized, notes := agentconfig.Normalize(rt, req.Values)
	if err := save(normalized, ActorFrom(c)); err != nil {
		writeValidationError(c, err)
		return
	}

	after, err := current()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Saved, but could not read the result back"})
		return
	}
	changes := agentconfig.Diff(before, after)
	changed := make([]string, 0, len(changes))
	for _, ch := range changes {
		changed = append(changed, ch.String())
	}
	restart := make([]string, 0)
	for _, k := range agentconfig.RestartRequired(changes) {
		restart = append(restart, string(k))
	}
	// json.Marshal encodes a nil slice as `null`. The settings panel maps
	// `adjusted` (and would map `needs_restart` the same way); a successful
	// save with nothing raised then crashes the drawer even though the write
	// landed. `changed` and `restart` are already allocated empty; notes is
	// Normalize's leftover nil.
	if notes == nil {
		notes = []string{}
	}

	c.JSON(http.StatusOK, gin.H{
		"changed": changed,
		// A value the platform raised to its floor. The device does this
		// silently in its own log, so whoever typed it would never otherwise
		// learn it was changed.
		"adjusted": notes,
		// A change the device can only adopt on restart. An operator who is not
		// told reads the resulting awaiting_restart as a failure.
		"needs_restart": restart,
	})
}

func writeValidationError(c *gin.Context, err error) {
	var ve *agentconfig.ValidationError
	if errors.As(err, &ve) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":    "Some settings could not be accepted",
			"problems": ve.Problems,
		})
		return
	}
	if errors.Is(err, store.ErrNoOwner) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid device"})
		return
	}
	// Deliberately not err.Error(): everything with operator meaning is a
	// ValidationError handled above, so anything here is an internal detail.
	c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not save the configuration"})
}

// TenantFrom reads the tenant the auth middleware put in context.
func TenantFrom(c *gin.Context) (uuid.UUID, bool) {
	v, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	switch id := v.(type) {
	case uuid.UUID:
		return id, true
	case string:
		parsed, err := uuid.Parse(id)
		if err == nil {
			return parsed, true
		}
	}
	c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid tenant ID"})
	return uuid.Nil, false
}

// ActorFrom reads the acting user, for the audit trail. A missing user is the
// nil UUID rather than an error: some legitimate callers are service-to-service
// and the audit row records that honestly instead of refusing the change.
func ActorFrom(c *gin.Context) uuid.UUID {
	v, ok := c.Get("userID")
	if !ok {
		return uuid.Nil
	}
	switch id := v.(type) {
	case uuid.UUID:
		return id
	case string:
		if parsed, err := uuid.Parse(id); err == nil {
			return parsed
		}
	}
	return uuid.Nil
}

// ExchangeReport and ExchangePayload are the exchange's wire types. They are
// DEFINED in agentconfig, which has no HTTP dependency, so a package that only
// needs to name the shape — a service's response model, say — does not acquire
// gin along with it. Aliased here because this is where they are used.
type ExchangeReport = agentconfig.ExchangeReport

// ExchangePayload is what the platform sends a device.
type ExchangePayload = agentconfig.ExchangePayload

// Exchange records a device's report and returns what it should be running.
//
// Shared because the two runtimes must not disagree about what a report means:
// a report is recorded even when empty, because "this device checked in and
// told us nothing" is itself the answer for an older build, and recording
// nothing would leave it indistinguishable from never having checked in.
func Exchange(c *gin.Context, s *store.Store, tenantID uuid.UUID, owner store.Owner, rep ExchangeReport) (*ExchangePayload, error) {
	return ExchangeCtx(c.Request.Context(), s, tenantID, owner, rep)
}

// ExchangeCtx is Exchange without a gin context, for callers that already have
// one of their own.
func ExchangeCtx(ctx context.Context, s *store.Store, tenantID uuid.UUID, owner store.Owner, rep ExchangeReport) (*ExchangePayload, error) {
	report := agentconfig.Report{Revision: rep.ConfigRevision, At: time.Now()}
	if len(rep.ConfigFailures) > 0 {
		report.Failures = make(map[agentconfig.Key]string, len(rep.ConfigFailures))
		for k, v := range rep.ConfigFailures {
			report.Failures[agentconfig.Key(k)] = v
		}
	}
	for _, k := range rep.PendingRestart {
		report.PendingRestart = append(report.PendingRestart, agentconfig.Key(k))
	}

	// BEFORE the report is recorded, because recording it is what closes the
	// bootstrap window — a device gets one chance to establish the position it
	// was already in, and it is this one. A device enrolled before desired
	// state existed would otherwise be answered with built-in defaults on its
	// first beat and would switch off whatever its own file had turned on.
	if _, err := s.BootstrapFromReport(ctx, tenantID, owner, rep.Running); err != nil {
		return nil, err
	}

	if err := s.RecordReport(ctx, tenantID, owner, report); err != nil {
		return nil, err
	}
	desired, err := s.Load(ctx, tenantID, owner)
	if err != nil {
		return nil, err
	}
	return &ExchangePayload{
		Revision:           desired.Revision,
		Values:             desired.Values,
		RestartRequestedAt: desired.Restart.At,
		// Computed here, on the platform's clock, so the device never has to
		// compare its clock with ours. Rounded UP: truncating a just-made
		// request to 0 makes it indistinguishable from no request at all.
		RestartRequestAgeSeconds: desired.Restart.WireSeconds(time.Now()),
	}, nil
}

// agentRuntimeGuard keeps the import of agentconfig meaningful to readers of
// this file: the runtimes a service may declare are exactly the two the
// registry knows.
var _ = []agentconfig.Runtime{agentconfig.RuntimeSensor, agentconfig.RuntimeAgent}

// RequestRestart records an operator's restart request for one device.
//
// A POST with no body: there is nothing to configure about a restart, and the
// timestamp is the platform's to set. The response carries it back so the
// console can say when it was asked rather than guessing from its own clock.
func (h *Handler) RequestRestart(c *gin.Context) {
	tenantID, ok := TenantFrom(c)
	if !ok {
		return
	}
	owner, ok := h.deps.OwnerFrom(c, tenantID)
	if !ok {
		return
	}
	at, err := h.deps.Store.RequestRestart(c.Request.Context(), tenantID, owner, ActorFrom(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not request a restart"})
		return
	}
	c.JSON(http.StatusAccepted, gin.H{
		"restart_requested_at": at,
		// Said plainly, because it is the one way this can disappoint: the
		// device EXITS and something else has to start it again. Installed as a
		// service, that is automatic; launched by hand, "restart" means "stop".
		"note": "The device restarts at its next check-in. A device that is not run as a service will stop instead of restarting.",
	})
}

// GetHistory answers with the recorded changes affecting one device.
//
// The agent_config_audit table was written on every save and read by nothing.
// That is the orphaned layer the feature framework forbids, and here it was
// load-bearing: the sensor's DNS decoder is manageable at all only because the
// owner's decision paired it with a recorded confirmation, and a record nobody
// can read does not discharge that obligation.
//
// Fleet-default changes are included alongside the device's own overrides,
// because a device's effective configuration moves when either does. An
// operator asking "why did this turn on" is not served by a history that can
// only answer half the time.
func (h *Handler) GetHistory(c *gin.Context) {
	tenantID, ok := TenantFrom(c)
	if !ok {
		return
	}
	owner, ok := h.deps.OwnerFrom(c, tenantID)
	if !ok {
		return
	}
	changes, err := h.deps.Store.LoadHistory(c.Request.Context(), tenantID, owner, 50)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not read the change history"})
		return
	}
	// Never nil: a device nobody has configured has an empty history, and a
	// client distinguishing null from [] would render "unknown" for "nothing
	// has happened yet".
	out := make([]gin.H, 0, len(changes))
	for _, ch := range changes {
		keys := make([]string, 0, len(ch.Changed()))
		for _, k := range ch.Changed() {
			keys = append(keys, string(k))
		}
		by := ""
		if ch.By != uuid.Nil {
			by = ch.By.String()
		}
		out = append(out, gin.H{
			"changed_at": ch.At.UTC().Format(time.RFC3339),
			"changed_by": by,
			"scope":      ch.Scope,
			"keys":       keys,
			// The values themselves, not only which keys moved: "DNS decoding
			// was turned ON, by this account, at this time" is the sentence the
			// confirmation obligation is about, and it cannot be reconstructed
			// from a key list.
			"values_before": ch.Before,
			"values_after":  ch.After,
		})
	}
	c.JSON(http.StatusOK, gin.H{"changes": out})
}
