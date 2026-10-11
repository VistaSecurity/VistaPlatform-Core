package certtrust

import (
	"context"
	"crypto/x509"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
)

// AIA chain completion ( slice 2, E2) — the bounds that keep a dead or
// hostile caIssuers URL from costing more than one fetch an hour.
const (
	// failedURLTTL is how long a caIssuers URL that failed is not fetched
	// again, for any tenant: a dead CA repository is dead for everyone.
	failedURLTTL = time.Hour
	// maxFailedURLs bounds the failure cache.
	maxFailedURLs = 4096
	// tenantFetchWindow / tenantFetchesPerWindow rate-limit AIA fetches per
	// tenant, so one tenant's backfill cannot turn the service into a crawler.
	tenantFetchWindow      = time.Hour
	tenantFetchesPerWindow = 200
	// asyncQueueSize bounds the background completions waiting; a full queue
	// drops the request and the periodic backfill picks the certificate up.
	asyncQueueSize = 256
	// requeueAfter stops the same chain top being queued again while its
	// last attempt is recent.
	requeueAfter = time.Hour
	// asyncJobTimeout bounds one background completion (5 hops x 5 s, plus
	// the re-evaluation of what chains through the top).
	asyncJobTimeout = 2 * time.Minute
)

type localOnlyKey struct{}

// LocalOnly marks ctx so trust evaluation completes chains from local sources
// only (inventory, the public bundle) and never waits on an AIA fetch. Ingest
// and decision requests use it; a top that still needs its issuer is completed
// in the background instead, and by the periodic backfill.
func LocalOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, localOnlyKey{}, true)
}

func isLocalOnly(ctx context.Context) bool {
	v, _ := ctx.Value(localOnlyKey{}).(bool)
	return v
}

func hasHTTPAIA(c *x509.Certificate) bool {
	for _, u := range c.IssuingCertificateURL {
		l := strings.ToLower(strings.TrimSpace(u))
		if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
			return true
		}
	}
	return false
}

// aiaPolicy is the evaluator's AIA state: the address guard, the failed-URL
// cache, the per-tenant rate limit and the background queue.
type aiaPolicy struct {
	guard discovery.AddressGuard

	mu       sync.Mutex
	failed   map[string]time.Time // url -> retry not before
	windows  map[uuid.UUID]*fetchWindow
	queued   map[uuid.UUID]time.Time // chain top -> last queued
	now      func() time.Time
	startJob sync.Once
	jobs     chan aiaJob
}

type fetchWindow struct {
	start time.Time
	n     int
}

type aiaJob struct {
	eval     *Evaluator
	tenantID uuid.UUID
	certID   uuid.UUID
	topID    uuid.UUID
}

func newAIAPolicy(guard discovery.AddressGuard) *aiaPolicy {
	return &aiaPolicy{
		guard:   guard,
		failed:  map[string]time.Time{},
		windows: map[uuid.UUID]*fetchWindow{},
		queued:  map[uuid.UUID]time.Time{},
		now:     time.Now,
	}
}

// platformAIAPolicy guards AIA fetches with the platform's fetch guard — the
// one the OCSP query uses (dispatchguard.PlatformFetchGuard): public
// addresses only, never loopback, link-local/metadata, private space or the
// platform's own prefixes. inventory-service runs inside the cluster, and the
// URL is in a certificate a scanned server sent.
func platformAIAPolicy() *aiaPolicy { return newAIAPolicy(dispatchguard.PlatformFetchGuard()) }

// AIAFetchEnabled reports whether inventory-service may fetch issuers from a
// certificate's caIssuers URL at all. CERT_TRUST_AIA_ENABLED=false turns it
// off (default on): chains are then completed from inventory and the public
// bundle only, and a top whose issuer is elsewhere stays `incomplete`. The
// switch exists for air-gapped deployments and for test runs that ingest real
// certificates, where a background fetch to a CA repository is unwanted egress.
func AIAFetchEnabled() bool {
	return strings.TrimSpace(strings.ToLower(os.Getenv("CERT_TRUST_AIA_ENABLED"))) != "false"
}

// allow is chainfetch's AllowFetch: refuse everything when AIA is switched off,
// refuse a URL that failed within the hour, and count the fetch against the
// tenant's window.
func (p *aiaPolicy) allow(tenantID uuid.UUID, url string) bool {
	if !AIAFetchEnabled() {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if until, ok := p.failed[url]; ok {
		if now.Before(until) {
			return false
		}
		delete(p.failed, url)
	}
	w := p.windows[tenantID]
	if w == nil || now.Sub(w.start) >= tenantFetchWindow {
		w = &fetchWindow{start: now}
		p.windows[tenantID] = w
	}
	if w.n >= tenantFetchesPerWindow {
		return false
	}
	w.n++
	return true
}

// recordFailure is chainfetch's OnFetchFailure.
func (p *aiaPolicy) recordFailure(url string, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	if len(p.failed) >= maxFailedURLs {
		for u, until := range p.failed {
			if !now.Before(until) {
				delete(p.failed, u)
			}
		}
		if len(p.failed) >= maxFailedURLs {
			// Still full of live entries: forget an arbitrary one rather than
			// grow without bound. The cost is one extra fetch.
			for u := range p.failed {
				delete(p.failed, u)
				break
			}
		}
	}
	p.failed[url] = now.Add(failedURLTTL)
	log.Printf("[certtrust] AIA fetch failed, not retried for %s: %s: %v", failedURLTTL, url, err)
}

// enqueue asks for a background completion of the chain above topID, which
// certID's evaluation stopped at. Non-blocking: a full queue, or a top queued
// within requeueAfter, drops the request.
func (p *aiaPolicy) enqueue(e *Evaluator, tenantID, certID, topID uuid.UUID) {
	p.mu.Lock()
	now := p.now()
	if last, ok := p.queued[topID]; ok && now.Sub(last) < requeueAfter {
		p.mu.Unlock()
		return
	}
	p.queued[topID] = now
	if len(p.queued) > 4*asyncQueueSize {
		for id, at := range p.queued {
			if now.Sub(at) >= requeueAfter {
				delete(p.queued, id)
			}
		}
	}
	p.mu.Unlock()

	p.startJob.Do(func() {
		p.jobs = make(chan aiaJob, asyncQueueSize)
		go p.run()
	})
	select {
	case p.jobs <- aiaJob{eval: e, tenantID: tenantID, certID: certID, topID: topID}:
	default:
	}
}

// run is the single background worker: complete the chain with the network
// allowed, then re-evaluate everything that chains through the old top.
func (p *aiaPolicy) run() {
	for job := range p.jobs {
		ctx, cancel := context.WithTimeout(context.Background(), asyncJobTimeout)
		v, err := job.eval.Evaluate(ctx, job.tenantID, job.certID)
		if err == nil && v.Status != StatusIncomplete {
			_, err = job.eval.EvaluateSubtree(LocalOnly(ctx), job.tenantID, job.topID)
		}
		cancel()
		if err != nil {
			log.Printf("[certtrust] tenant %s: background chain completion for certificate %s: %v", job.tenantID, job.certID, err)
		}
	}
}
