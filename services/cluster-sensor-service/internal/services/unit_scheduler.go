package services

// Per-tenant fairness on the Platform Sensor ( hole H33).
//
// Every tenant's scans run in the same cluster-sensor-service pods and share
// one connection budget per process (the engine's descriptor gate). Without a
// share-out, one tenant's Thorough scan of a /24 at the fast pace would take
// most of it, and every other tenant's scan would crawl behind it. So a scan
// plan's work — its units, and its liveness sweeps — draws slots from two
// pools per replica:
//
//   - a per-tenant pool: no tenant runs more than PerTenant units at once,
//     however many jobs it has;
//   - a global pool: the replica runs no more than Global units at once.
//
// A slot is about one host's worth of connections (the pace's per-host
// limit). A unit takes one; a liveness sweep takes as many as it uses, and is
// built to use no more than it was given. The tenant slot is taken first, so a
// tenant waiting at its own cap never holds a global slot another tenant
// could use.
//
// Configured per installation: DISCOVERY_MAX_CONCURRENT_UNITS (Global,
// default 16) and DISCOVERY_MAX_CONCURRENT_UNITS_PER_TENANT (PerTenant,
// default 4), chart values discovery.maxConcurrentUnits and
// discovery.maxConcurrentUnitsPerTenant. Both fail closed to the default.

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	envMaxConcurrentUnits          = "DISCOVERY_MAX_CONCURRENT_UNITS"
	envMaxConcurrentUnitsPerTenant = "DISCOVERY_MAX_CONCURRENT_UNITS_PER_TENANT"
	defaultMaxConcurrentUnits      = 16
	defaultMaxUnitsPerTenant       = 4
	maxUnitSlots                   = 256
)

// unitConcurrency is the two caps.
type unitConcurrency struct {
	Global    int
	PerTenant int
}

// unitConcurrencyFromEnv reads the caps. Unset, or not a whole number in
// 1..256, is the default — and is said in the log. A per-tenant cap above the
// global one is the global one.
func unitConcurrencyFromEnv() unitConcurrency {
	read := func(name string, def int) int {
		raw := strings.TrimSpace(os.Getenv(name))
		if raw == "" {
			return def
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxUnitSlots {
			log.Printf("[discovery] %s=%q is not a whole number between 1 and %d; using %d", name, raw, maxUnitSlots, def)
			return def
		}
		return n
	}
	c := unitConcurrency{Global: read(envMaxConcurrentUnits, defaultMaxConcurrentUnits), PerTenant: read(envMaxConcurrentUnitsPerTenant, defaultMaxUnitsPerTenant)}
	c.PerTenant = min(c.PerTenant, c.Global)
	return c
}

// slotPool is a counting semaphore that grants n slots at once, or waits.
type slotPool struct {
	mu      sync.Mutex
	size    int
	used    int
	peak    int
	changed chan struct{}
}

func newSlotPool(size int) *slotPool { return &slotPool{size: size, changed: make(chan struct{})} }

func (p *slotPool) acquire(ctx context.Context, n int) bool {
	for {
		p.mu.Lock()
		if p.used+n <= p.size {
			p.used += n
			p.peak = max(p.peak, p.used)
			p.mu.Unlock()
			return true
		}
		ch := p.changed
		p.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return false
		}
	}
}

func (p *slotPool) release(n int) {
	p.mu.Lock()
	p.used -= n
	close(p.changed)
	p.changed = make(chan struct{})
	p.mu.Unlock()
}

// unitScheduler is the replica's two pools.
type unitScheduler struct {
	caps   unitConcurrency
	global *slotPool

	mu      sync.Mutex
	tenants map[string]*slotPool
}

func newUnitScheduler(c unitConcurrency) *unitScheduler {
	return &unitScheduler{caps: c, global: newSlotPool(c.Global), tenants: map[string]*slotPool{}}
}

func (s *unitScheduler) tenant(id string) *slotPool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.tenants[id]
	if p == nil {
		p = newSlotPool(s.caps.PerTenant)
		s.tenants[id] = p
	}
	return p
}

// grant returns how many slots a request for want may take: never more than
// either cap allows, never fewer than one.
func (s *unitScheduler) grant(want int) int {
	if s == nil {
		return want
	}
	return max(1, min(min(want, s.caps.PerTenant), s.caps.Global))
}

// acquire takes n slots for tenantID — tenant first, then global — and returns
// the release, or false when ctx ended first. A nil scheduler grants
// everything.
func (s *unitScheduler) acquire(ctx context.Context, tenantID string, n int) (func(), bool) {
	if s == nil {
		return func() {}, true
	}
	t := s.tenant(tenantID)
	if !t.acquire(ctx, n) {
		return nil, false
	}
	if !s.global.acquire(ctx, n) {
		t.release(n)
		return nil, false
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.global.release(n)
			t.release(n)
		})
	}, true
}

// peaks reports the most slots ever held at once, by the replica and by one
// tenant — what a test reads to prove the caps held.
func (s *unitScheduler) peaks(tenantID string) (global, tenant int) {
	t := s.tenant(tenantID)
	s.global.mu.Lock()
	global = s.global.peak
	s.global.mu.Unlock()
	t.mu.Lock()
	tenant = t.peak
	t.mu.Unlock()
	return global, tenant
}
