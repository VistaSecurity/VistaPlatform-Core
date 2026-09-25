package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	sharedinterrogation "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
	audithelpers "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// Add device and Test connection make the platform open an authenticated
// connection to an address a tenant chose, synchronously, from inside the
// cluster. Two things follow ( review NB-1, NB-8):
//
//   - Every such probe is audited — who, which device type, which target
//     (never its credentials), and the outcome code — whatever the outcome.
//   - Probes are rate limited: per tenant, so the typed outcome codes cannot be
//     used as a fast port-scan oracle for whatever the platform can reach; and
//     per device for Test connection, so a stale password retried in a hurry
//     cannot lock the device's admin account (FortiOS locks after a few
//     failures).
//
// The limits are per process. With several replicas a tenant gets a multiple of
// them, which is still a bound; a shared limiter is not worth a Redis dependency
// for a button. What this is NOT is the cluster-internal refusal list
// (single-label names, *.svc, cluster CIDRs) — that is the E-09 dial-guard
// slice, which covers every transport at once.

const (
	// probeTenantLimit probes per probeTenantWindow, per tenant, across Add
	// device and Test connection together.
	probeTenantLimit  = 20
	probeTenantWindow = time.Minute
	// testConnectionInterval is the minimum gap between two connection tests of
	// the same device.
	testConnectionInterval = 10 * time.Second

	codeRateLimited       = "rate_limited"
	codeTestThrottled     = "test_throttled"
	outcomeOK             = "ok"
	auditEventProbe       = "discovery.device_probe"
	auditEventTestConnect = "discovery.device_connection_test"
)

type probeLimiter struct {
	mu  sync.Mutex
	now func() time.Time

	tenantHits map[uuid.UUID][]time.Time
	deviceLast map[uuid.UUID]time.Time
}

func newProbeLimiter() *probeLimiter {
	return &probeLimiter{
		now:        time.Now,
		tenantHits: map[uuid.UUID][]time.Time{},
		deviceLast: map[uuid.UUID]time.Time{},
	}
}

// allowTenant records a probe for tenant and reports whether it is within the
// limit, and if not, how long until the oldest probe in the window expires.
func (l *probeLimiter) allowTenant(tenant uuid.UUID) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-probeTenantWindow)
	hits := l.tenantHits[tenant]
	kept := hits[:0]
	for _, t := range hits {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= probeTenantLimit {
		l.tenantHits[tenant] = kept
		return false, kept[0].Sub(cutoff)
	}
	l.tenantHits[tenant] = append(kept, now)
	return true, 0
}

// allowDevice records a connection test of device and reports whether it is
// far enough from the previous one.
func (l *probeLimiter) allowDevice(device uuid.UUID) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if last, ok := l.deviceLast[device]; ok {
		if wait := testConnectionInterval - now.Sub(last); wait > 0 {
			return false, wait
		}
	}
	l.deviceLast[device] = now
	// Keep the map from growing with every device ever tested.
	if len(l.deviceLast) > 10000 {
		for id, t := range l.deviceLast {
			if now.Sub(t) > testConnectionInterval {
				delete(l.deviceLast, id)
			}
		}
	}
	return true, 0
}

// writeProbeLimited answers 429 with a Retry-After and a typed code.
func writeProbeLimited(c *gin.Context, code string, wait time.Duration) {
	seconds := int(wait.Round(time.Second) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	c.Header("Retry-After", strconv.Itoa(seconds))
	message := fmt.Sprintf("Too many device connections from this organization in the last minute. Try again in %d seconds.", seconds)
	if code == codeTestThrottled {
		message = fmt.Sprintf("This device was tested moments ago. Wait %d seconds before testing it again — repeated logins with a wrong password can lock the device's account.", seconds)
	}
	c.JSON(http.StatusTooManyRequests, gin.H{"error": code, "message": message})
}

// probeAudit is one audit record of a device probe.
type probeAudit struct {
	event      string
	deviceType string
	// target is the address dialled, run through DisplayAddress: never its
	// userinfo, query or fragment.
	target   string
	deviceID *uuid.UUID
	outcome  string // outcomeOK or a DeviceDiscoveryError code
}

// auditProbe records p through the service's audit middleware (or the test
// sink). It never fails the request.
func (h *DeviceHandlers) auditProbe(c *gin.Context, p probeAudit) {
	entry := &audithelpers.ActivityLogRequest{
		EventType:     p.event,
		EventCategory: audithelpers.EventCategoryDiscovery,
		Action:        "connect",
		UserType:      "tenant",
		ResourceID:    p.deviceID,
		Success:       p.outcome == outcomeOK,
		Metadata: map[string]interface{}{
			"device_type": p.deviceType,
			"target":      sharedinterrogation.DisplayAddress(p.target),
			"outcome":     p.outcome,
		},
		OccurredAt: time.Now().UTC(),
	}
	resourceType := "device"
	entry.ResourceType = &resourceType
	if p.outcome != outcomeOK {
		code := p.outcome
		entry.ErrorCode = &code
	}
	if v, ok := c.Get("tenantID"); ok {
		if id, ok := v.(uuid.UUID); ok {
			entry.TenantID = &id
		}
	}
	if v, ok := c.Get(sharedmw.CtxKeyUserID); ok {
		switch id := v.(type) {
		case uuid.UUID:
			entry.UserID = &id
		case string:
			if parsed, err := uuid.Parse(id); err == nil {
				entry.UserID = &parsed
			}
		}
	}
	if v, ok := c.Get(sharedmw.CtxKeyEmail); ok {
		if email, ok := v.(string); ok && email != "" {
			entry.UserEmail = &email
		}
	}
	if ip := c.ClientIP(); ip != "" {
		entry.IPAddress = &ip
	}

	if h.auditSink != nil {
		h.auditSink(c.Request.Context(), entry)
		return
	}
	if raw, ok := c.Get("audit_middleware"); ok {
		if mw, ok := raw.(*audithelpers.Middleware); ok {
			_ = mw.LogActivity(context.WithoutCancel(c.Request.Context()), entry)
		}
	}
}
