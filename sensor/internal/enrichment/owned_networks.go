package enrichment

import (
	"log"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/probeconsent"
)

// DeliveredOwnershipTTL is how long ownership the PLATFORM delivered keeps
// counting without being delivered again. The platform re-sends it on every
// heartbeat, so a live sensor never gets near it; a sensor that has lost its
// platform for a day stops treating yesterday's declared ranges and elevated
// endpoints as the tenant's ( review) and probes only private space until
// the platform answers. Exclusions never expire — forgetting one is the unsafe
// direction.
const DeliveredOwnershipTTL = 24 * time.Hour

// OwnedNetworks is the tenant's statement of what it owns beyond private space,
// and what it asked never to be probed, as the platform last delivered it on a
// heartbeat ( W5.13) — or, for a sensor the platform has never told, as
// its own configuration file says. The TLS enricher consults it before every
// active handshake.
//
// It lives on the Sensor, not on an enricher, because the enricher is rebuilt
// whenever the capture is (an interface change does that live); a set owned by
// the enricher would be lost on every rebuild and the sensor would fall back to
// private-only until the next heartbeat. Safe for concurrent use: the heartbeat
// loop writes it while enricher workers read it.
type OwnedNetworks struct {
	mu          sync.RWMutex
	scope       probeconsent.Scope
	delivered   bool // the scope came from the platform, and so expires
	deliveredAt time.Time
	ttl         time.Duration
	now         func() time.Time
}

// NewOwnedNetworks starts empty — private space only — which is also what the
// sensor keeps for as long as it talks to a platform too old to send the set.
func NewOwnedNetworks() *OwnedNetworks {
	return &OwnedNetworks{ttl: DeliveredOwnershipTTL, now: time.Now}
}

// Update applies what the platform sent just now. nil means the platform said
// nothing (an older build) and the current set is kept: silence is not an
// instruction. An Incomplete set replaces ownership with none and adds its
// exclusions to the ones already held (probeconsent.Merge).
func (o *OwnedNetworks) Update(n *probeconsent.OwnedNetworks) {
	if o == nil {
		return
	}
	o.UpdateAt(n, o.clock())
}

// UpdateAt is Update for a delivery made at a known time — a recorded delivery
// restored at startup keeps its own age, so a restart cannot make stale
// ownership fresh again.
func (o *OwnedNetworks) UpdateAt(n *probeconsent.OwnedNetworks, at time.Time) {
	if o == nil || n == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	scope, rejected := probeconsent.Merge(o.scope, *n)
	changed := !sameSize(o.scope, scope)
	o.scope, o.delivered, o.deliveredAt = scope, true, at
	if changed || rejected > 0 || n.Incomplete {
		prefixes, endpoints, excluded := scope.Len()
		log.Printf("🔬 Owned networks updated: %d declared prefixes, %d elevated endpoints, %d exclusions (%d entries rejected, incomplete=%t)",
			prefixes, endpoints, excluded, rejected, n.Incomplete)
	}
}

// SetLocal installs the sensor's own configured list. It does not expire — it
// is the operator's file, not a delivery that can go stale — and the first
// platform delivery replaces it.
func (o *OwnedNetworks) SetLocal(n probeconsent.OwnedNetworks) {
	if o == nil {
		return
	}
	scope, rejected := probeconsent.Parse(n)
	o.mu.Lock()
	defer o.mu.Unlock()
	o.scope, o.delivered = scope, false
	prefixes, _, _ := scope.Len()
	log.Printf("🔬 Using %d locally configured owned network(s) (%d rejected); the platform's owned networks replace them once delivered", prefixes, rejected)
}

// Scope is the set in force now: the zero Scope (private space only) until
// something has been installed, and the delivered set stripped of its
// ownership once it is older than the TTL.
func (o *OwnedNetworks) Scope() probeconsent.Scope {
	if o == nil {
		return probeconsent.Scope{}
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	ttl := o.ttl
	if ttl <= 0 {
		ttl = DeliveredOwnershipTTL
	}
	if o.delivered && o.clock().Sub(o.deliveredAt) > ttl {
		return o.scope.WithoutOwnership()
	}
	return o.scope
}

func (o *OwnedNetworks) clock() time.Time {
	if o.now == nil {
		return time.Now()
	}
	return o.now()
}

func sameSize(a, b probeconsent.Scope) bool {
	ap, ae, ax := a.Len()
	bp, be, bx := b.Len()
	return ap == bp && ae == be && ax == bx
}
