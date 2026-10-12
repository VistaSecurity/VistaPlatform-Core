package processor

// Batch claim renewal and fencing, the ordered claim, bounded reads, the
// transient-vs-permanent split and the single-finding bisect — all against a
// real sensor_discoveries table and the real BatchProcessor, with a stand-in
// inventory-service. Skips without TEST_DATABASE_URL (nightly test-backend /
// make test-integration-db).
//
// Mutations (each goes red; see the PR body):
//   - renewal: make renewClaim return nil without updating
//     -> TestIntegration_SlowBatchIsImportedOnceByTwoReplicas
//   - fence: remove the claimed_at predicate from markProcessed's grouped UPDATE
//     -> TestIntegration_LateStampsOfALostClaimAreFenced
//   - fence: remove it from recordRowFailuresFenced
//     -> TestIntegration_LateFailureRecordOfALostClaimIsFenced
//   - ORDER BY min(created_at) / the lost-race retry in claimNextBatch
//     -> TestIntegration_Claim_*
//   - isTransientStatus without 401/403/404 / no bisect in importInChunksRenewing
//     -> TestIntegration_TransientChunkRejection..., TestIntegration_BadFinding...
//   - lookupPTR passed straight to resolveMissingHostname
//     -> TestIntegration_ProcessBatch_ReverseLookupOncePerDestination

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// countingInventory is a configurable import stand-in that counts how many times
// each destination address was imported.
type countingInventory struct {
	mu     sync.Mutex
	srv    *httptest.Server
	byIP   map[string]int
	calls  int
	handle func(call int, ips []string, w http.ResponseWriter) bool // true when it answered
}

func newCountingInventory(t *testing.T, handle func(call int, ips []string, w http.ResponseWriter) bool) *countingInventory {
	t.Helper()
	ci := &countingInventory{byIP: map[string]int{}, handle: handle}
	ci.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Findings []converter.IngestFinding `json:"findings"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		ips := make([]string, len(body.Findings))
		for i, f := range body.Findings {
			if f.IPAddress != nil {
				ips[i] = *f.IPAddress
			}
		}
		ci.mu.Lock()
		ci.calls++
		call := ci.calls
		ci.mu.Unlock()
		if ci.handle != nil && ci.handle(call, ips, w) {
			return
		}
		ci.mu.Lock()
		for _, ip := range ips {
			ci.byIP[ip]++
		}
		ci.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"imported": len(ips)})
	}))
	t.Cleanup(ci.srv.Close)
	return ci
}

func (ci *countingInventory) count(ip string) int {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	return ci.byIP[ip]
}

func (ci *countingInventory) processor(t *testing.T, db *sqlx.DB) *BatchProcessor {
	t.Helper()
	c, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: ci.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	return NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), c, nil)
}

func claimTestDB(t *testing.T) (*sqlx.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	return sqlx.NewDb(raw, "postgres"), testdb.NewTenant(t, raw)
}

func shortClaimTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	prev := batchClaimTimeout
	batchClaimTimeout = d
	t.Cleanup(func() { batchClaimTimeout = prev })
}

// seedBulk seeds n named managed rows (so no reverse lookup is wanted) with
// distinct destinations 10.<octet>.x.y; returns their destination addresses.
func seedBulk(t *testing.T, db *sqlx.DB, tenant uuid.UUID, batchID string, octet, n int) []string {
	t.Helper()
	sensor := uuid.New()
	var ips []string
	for i := 0; i < n; i++ {
		ip := fmt.Sprintf("10.%d.%d.%d", octet, i/200, i%200+1)
		host := fmt.Sprintf("h-%d.corp.example", i)
		seedTLSDiscovery(t, db, tenant, sensor, batchID, ip, 443, &host,
			`{"discovery_method":"passive","cipher_suite":"TLS_AES_128_GCM_SHA256","version":"TLS 1.3"}`)
		ips = append(ips, ip)
	}
	return ips
}

// Two replicas, one batch of three chunks, a claim timeout shorter than the
// import. The owner renews before each chunk, so the second replica never finds
// the claim stale and every finding is imported exactly once.
func TestIntegration_SlowBatchIsImportedOnceByTwoReplicas(t *testing.T) {
	db, tenant := claimTestDB(t)
	shortClaimTimeout(t, 2*time.Second)
	inv := newCountingInventory(t, func(_ int, _ []string, _ http.ResponseWriter) bool {
		time.Sleep(1200 * time.Millisecond) // 3 chunks: 3.6s, longer than the 2s timeout
		return false
	})
	bp := inv.processor(t, db)
	batchID := uuid.New().String()
	ips := seedBulk(t, db, tenant, batchID, 91, 3*importChunkSize)

	newReplica := func() *DiscoveryProcessor {
		return &DiscoveryProcessor{
			db: db, bypassDB: db, config: &config.Config{PollIntervalSeconds: 3600},
			stopChan: make(chan struct{}), wake: make(chan struct{}, 1),
			processBatch: func(b string, tn uuid.UUID, at time.Time) error {
				if tn != tenant {
					return nil // another test's rows: untouched
				}
				return bp.ProcessClaimedBatch(b, tn, at)
			},
			recordBatchFailure: bp.RecordBatchFailure,
		}
	}
	a, b := newReplica(), newReplica()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); a.drain() }()
	// Replica B starts polling only once A holds the claim and is importing (the
	// stand-in has seen its first call), then keeps polling the whole time the
	// batch is in flight, as a fallback poll or a wake on another replica would.
	for start := time.Now(); ; time.Sleep(10 * time.Millisecond) {
		inv.mu.Lock()
		n := inv.calls
		inv.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatal("replica A never started importing")
		}
	}
	deadline := time.Now().Add(7 * time.Second)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
loop:
	for time.Now().Before(deadline) {
		b.drain()
		select {
		case <-done:
			break loop
		case <-time.After(250 * time.Millisecond):
		}
	}
	<-done

	for _, ip := range ips {
		if n := inv.count(ip); n != 1 {
			t.Fatalf("%s was imported %d time(s), want exactly once: a second replica re-claimed a live batch", ip, n)
		}
	}
	for id, s := range readRows(t, db, tenant, batchID) {
		if !s.processed {
			t.Fatalf("row %s left unprocessed", id)
		}
	}
}

// A worker that DID lose its claim (here: stalled inside one import call longer
// than the timeout) must not overwrite the new owner's stamps.
func TestIntegration_LateStampsOfALostClaimAreFenced(t *testing.T) {
	db, tenant := claimTestDB(t)
	started, release := make(chan struct{}), make(chan struct{})
	inv := newCountingInventory(t, func(call int, ips []string, w http.ResponseWriter) bool {
		if call != 1 {
			return false // the new owner's import: answered normally -> status stays `pending`
		}
		close(started)
		<-release
		// The stalled worker's answer says the asset is archived -> `suppressed`,
		// a different final state from the new owner's, so an overwrite shows.
		statuses := make([]string, len(ips))
		for i := range statuses {
			statuses[i] = "archived"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"imported": len(ips), "asset_statuses": statuses})
		return true
	})
	bp := inv.processor(t, db)
	batchID := uuid.New().String()
	seedBulk(t, db, tenant, batchID, 92, 3)

	stampA := takeClaim(t, db, tenant, batchID)
	errA := make(chan error, 1)
	go func() { errA <- bp.ProcessClaimedBatch(batchID, tenant, stampA) }()
	<-started

	// The claim lapses and another worker takes it over, completing the batch.
	stampB := takeClaim(t, db, tenant, batchID)
	if err := bp.ProcessClaimedBatch(batchID, tenant, stampB); err != nil {
		t.Fatalf("new owner: %v", err)
	}
	before := readRows(t, db, tenant, batchID)
	close(release)

	if err := <-errA; !isClaimLost(err) {
		t.Fatalf("stalled worker returned %v, want errClaimLost", err)
	}
	after := readRows(t, db, tenant, batchID)
	for id, s := range after {
		if !s.processed || s.status != before[id].status {
			t.Fatalf("row %s = %+v after the stalled worker finished, was %+v: its late stamp overwrote the new owner's", id, s, before[id])
		}
		if s.status == "suppressed" {
			t.Fatalf("row %s carries the stalled worker's outcome", id)
		}
	}
}

func isClaimLost(err error) bool {
	for e := err; e != nil; {
		if e == errClaimLost {
			return true
		}
		u, ok := e.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		e = u.Unwrap()
	}
	return false
}

// takeClaim stamps every unprocessed row of the batch with a fresh claim, as
// processNextBatch's claim statement does, and returns the stamp.
func takeClaim(t *testing.T, db *sqlx.DB, tenant uuid.UUID, batchID string) time.Time {
	t.Helper()
	var stamp time.Time
	if err := db.QueryRow(`WITH u AS (UPDATE sensor_discoveries SET claimed_at = now()
			WHERE tenant_id = $1 AND batch_id = $2 AND processed_at IS NULL RETURNING claimed_at)
		SELECT max(claimed_at) FROM u`, tenant, batchID).Scan(&stamp); err != nil {
		t.Fatal(err)
	}
	return stamp
}

// The failure record is fenced too: a worker without the claim cannot charge
// attempts or reject rows the new owner is handling.
func TestIntegration_LateFailureRecordOfALostClaimIsFenced(t *testing.T) {
	db, tenant := claimTestDB(t)
	bp := (&countingInventory{srv: httptest.NewServer(http.NotFoundHandler())}).processor(t, db)
	batchID := uuid.New().String()
	seedBulk(t, db, tenant, batchID, 93, 2)
	mine := takeClaim(t, db, tenant, batchID)
	rows := readRows(t, db, tenant, batchID)
	var failures []rowFailure
	for id := range rows {
		failures = append(failures, rowFailure{id: id, err: fmt.Errorf("boom"), permanent: true})
	}

	// Another worker takes the batch over.
	takeClaim(t, db, tenant, batchID)
	stale := &batchClaim{tenantID: tenant, batchID: batchID, at: mine}
	if n, err := bp.recordRowFailuresFenced(context.Background(), tenant, stale, failures); err != nil || n != 0 {
		t.Fatalf("recordRowFailuresFenced = %d, %v; a lost claim must record nothing", n, err)
	}
	for id, s := range readRows(t, db, tenant, batchID) {
		if s.processed || s.attempts != 0 || s.status == "rejected" {
			t.Fatalf("row %s = %+v: the stale claim wrote to it", id, s)
		}
	}
	// With the right stamp it does write.
	var cur time.Time
	for _, s := range readRows(t, db, tenant, batchID) {
		cur = *s.claimedAt
	}
	if n, err := bp.recordRowFailuresFenced(context.Background(), tenant, &batchClaim{tenantID: tenant, batchID: batchID, at: cur}, failures); err != nil || n != 2 {
		t.Fatalf("with the current claim: %d, %v, want 2 terminal", n, err)
	}
}

// renewClaim moves the stamp, and reports a lost claim when rows were taken.
func TestIntegration_RenewClaimMovesTheStampAndDetectsALoss(t *testing.T) {
	db, tenant := claimTestDB(t)
	bp := (&countingInventory{srv: httptest.NewServer(http.NotFoundHandler())}).processor(t, db)
	batchID := uuid.New().String()
	seedBulk(t, db, tenant, batchID, 94, 4)
	at := takeClaim(t, db, tenant, batchID)
	c := &batchClaim{tenantID: tenant, batchID: batchID, at: at, rows: 4}

	time.Sleep(10 * time.Millisecond)
	if err := bp.renewClaim(context.Background(), c); err != nil {
		t.Fatalf("renewClaim: %v", err)
	}
	if !c.at.After(at) {
		t.Fatalf("stamp %v did not move past %v", c.at, at)
	}
	for id, s := range readRows(t, db, tenant, batchID) {
		if s.claimedAt == nil || !s.claimedAt.Equal(c.at) {
			t.Fatalf("row %s claimed_at %v, want the renewed stamp %v", id, s.claimedAt, c.at)
		}
	}
	takeClaim(t, db, tenant, batchID) // someone else
	if err := bp.renewClaim(context.Background(), c); !isClaimLost(err) {
		t.Fatalf("renewClaim after a takeover = %v, want errClaimLost", err)
	}
}

// ---- the ordered, retried, bounded claim ----

func ageBatch(t *testing.T, db *sqlx.DB, tenant uuid.UUID, batchID, ts string) {
	t.Helper()
	if _, err := db.Exec(`UPDATE sensor_discoveries SET created_at = $3::timestamptz WHERE tenant_id = $1 AND batch_id = $2`, tenant, batchID, ts); err != nil {
		t.Fatal(err)
	}
}

func claimProcessor(db *sqlx.DB) *DiscoveryProcessor {
	return &DiscoveryProcessor{db: db, bypassDB: db, config: &config.Config{PollIntervalSeconds: 3600}, stopChan: make(chan struct{}), wake: make(chan struct{}, 1)}
}

// The oldest batch is claimed first, whatever order batches were inserted in:
// twelve batches with shuffled ages come out in age order.
func TestIntegration_Claim_TakesTheOldestBatchFirst(t *testing.T) {
	db, tenant := claimTestDB(t)
	ageOrder := []int{7, 2, 11, 0, 9, 4, 1, 10, 5, 8, 3, 6} // batch i is given age rank ageOrder[i]
	byRank := make([]string, len(ageOrder))
	for _, rank := range ageOrder {
		b := uuid.New().String()
		seedBulk(t, db, tenant, b, 95, 2)
		ageBatch(t, db, tenant, b, fmt.Sprintf("1990-01-%02d", rank+1))
		byRank[rank] = b
	}
	p := claimProcessor(db)
	for rank, want := range byRank {
		got, tn, _, found, err := p.claimNextBatch()
		if err != nil || !found || tn != tenant || got != want {
			t.Fatalf("claim #%d = %s found=%v err=%v, want the batch of age rank %d (%s)", rank, got, found, err, rank, want)
		}
	}
}

// A lost race is not an empty queue. The first claimant's UPDATE is held at the
// row locks while another transaction claims the candidate; the first must
// retry and take the NEXT batch instead of reporting "nothing claimable"
// (which used to end drain).
func TestIntegration_Claim_LostRaceRetriesInsteadOfEndingTheDrain(t *testing.T) {
	db, tenant := claimTestDB(t)
	first, second := uuid.New().String(), uuid.New().String()
	seedBulk(t, db, tenant, first, 97, 2)
	seedBulk(t, db, tenant, second, 98, 2)
	ageBatch(t, db, tenant, first, "1990-01-01")
	ageBatch(t, db, tenant, second, "1990-01-02")
	p := claimProcessor(db)

	// Hold the first batch's rows locked so the claim's UPDATE blocks on them.
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE sensor_discoveries SET claimed_at = now() WHERE tenant_id = $1 AND batch_id = $2`, tenant, first); err != nil {
		t.Fatal(err)
	}
	type res struct {
		batch string
		found bool
		err   error
	}
	out := make(chan res, 1)
	go func() {
		b, _, _, found, err := p.claimNextBatch()
		out <- res{b, found, err}
	}()
	time.Sleep(500 * time.Millisecond)  // the claim has picked `first` and is blocked on its locks
	if err := tx.Commit(); err != nil { // the rival wins `first`
		t.Fatal(err)
	}
	r := <-out
	if r.err != nil || !r.found || r.batch != second {
		t.Fatalf("claim after a lost race = %+v, want to have retried and taken %s", r, second)
	}
}

// One claim takes at most batchClaimRowLimit rows, oldest first; the rest of
// the batch is claimed by the following claims (continuation).
func TestIntegration_Claim_BoundsRowsPerClaimAndContinues(t *testing.T) {
	db, tenant := claimTestDB(t)
	prev := batchClaimRowLimit
	batchClaimRowLimit = 3
	t.Cleanup(func() { batchClaimRowLimit = prev })
	batch := uuid.New().String()
	seedBulk(t, db, tenant, batch, 99, 7)
	// Distinct, increasing created_at so "oldest first" is observable.
	if _, err := db.Exec(`WITH o AS (SELECT id, row_number() OVER (ORDER BY dest_ip) AS n FROM sensor_discoveries WHERE tenant_id = $1 AND batch_id = $2)
		UPDATE sensor_discoveries d SET created_at = '1980-01-01'::timestamptz + (o.n || ' minutes')::interval FROM o WHERE d.tenant_id = $1 AND d.id = o.id`, tenant, batch); err != nil {
		t.Fatal(err)
	}
	p := claimProcessor(db)

	var sizes []int
	seen := map[uuid.UUID]bool{}
	for i := 0; i < 3; i++ {
		b, tn, at, found, err := p.claimNextBatch()
		if err != nil || !found || b != batch || tn != tenant {
			t.Fatalf("claim %d = %s found=%v err=%v", i, b, found, err)
		}
		n := 0
		for id, s := range readRows(t, db, tenant, batch) {
			if s.claimedAt != nil && s.claimedAt.Equal(at) {
				n++
				if seen[id] {
					t.Fatalf("row %s claimed twice", id)
				}
				seen[id] = true
			}
		}
		sizes = append(sizes, n)
	}
	if fmt.Sprint(sizes) != "[3 3 1]" {
		t.Fatalf("claims took %v rows, want [3 3 1]", sizes)
	}
	if _, _, _, found, _ := p.claimNextBatch(); found {
		t.Fatal("a fourth claim found work; the batch had 7 rows")
	}
}

// ProcessClaimedBatch reads at most batchClaimRowLimit rows, whatever was claimed.
func TestIntegration_ProcessBatch_ReadIsBounded(t *testing.T) {
	db, tenant := claimTestDB(t)
	prev := batchClaimRowLimit
	batchClaimRowLimit = 4
	t.Cleanup(func() { batchClaimRowLimit = prev })
	inv := newCountingInventory(t, nil)
	bp := inv.processor(t, db)
	batch := uuid.New().String()
	seedBulk(t, db, tenant, batch, 100, 9)
	_ = bp.ProcessBatch(batch, tenant)
	processed := 0
	for _, s := range readRows(t, db, tenant, batch) {
		if s.processed {
			processed++
		}
	}
	if processed != 4 {
		t.Fatalf("%d rows processed in one read, want the limit of 4", processed)
	}
}

// ---- transient vs permanent, and the bisect ----

// A 401/403/404 for a whole chunk rejects nobody: every row stays retryable.
func TestIntegration_TransientChunkRejectionRejectsNoRows(t *testing.T) {
	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusLocked} {
		t.Run(fmt.Sprint(code), func(t *testing.T) {
			db, tenant := claimTestDB(t)
			inv := newCountingInventory(t, func(_ int, _ []string, w http.ResponseWriter) bool {
				http.Error(w, "nope", code)
				return true
			})
			bp := inv.processor(t, db)
			batch := uuid.New().String()
			seedBulk(t, db, tenant, batch, 101, 5)
			_ = bp.ProcessBatch(batch, tenant)
			for id, s := range readRows(t, db, tenant, batch) {
				if s.processed || s.status == "rejected" || s.attempts != 1 {
					t.Fatalf("after a %d: row %s = %+v, want unprocessed, not rejected, 1 attempt", code, id, s)
				}
			}
		})
	}
}

// One bad finding draws a 400 for its chunk; the chunk is split and re-sent
// until only the bad finding is refused on its own. Its 49 chunk-mates land.
func TestIntegration_BadFindingRejectsOnlyItself(t *testing.T) {
	db, tenant := claimTestDB(t)
	var ips []string
	bad := ""
	inv := newCountingInventory(t, func(_ int, in []string, w http.ResponseWriter) bool {
		for _, ip := range in {
			if ip == bad {
				http.Error(w, "finding failed validation", http.StatusBadRequest)
				return true
			}
		}
		return false
	})
	bp := inv.processor(t, db)
	batch := uuid.New().String()
	ips = seedBulk(t, db, tenant, batch, 102, importChunkSize)
	bad = ips[17]

	_ = bp.ProcessBatch(batch, tenant)

	rejected, landed := 0, 0
	for id, s := range readRows(t, db, tenant, batch) {
		switch {
		case s.processed && s.status == "rejected":
			rejected++
			if !strings.Contains(s.errMsg, "400") {
				t.Errorf("rejected row %s carries %q", id, s.errMsg)
			}
		case s.processed:
			landed++
		}
	}
	if rejected != 1 || landed != importChunkSize-1 {
		t.Fatalf("%d rejected, %d landed; want exactly the one bad finding rejected and %d landed", rejected, landed, importChunkSize-1)
	}
	for _, ip := range ips {
		want := 1
		if ip == bad {
			want = 0
		}
		if inv.count(ip) != want {
			t.Errorf("%s imported %d time(s), want %d", ip, inv.count(ip), want)
		}
	}
}

// ---- reverse lookups ----

// Six rows to one public destination cost one lookup, and the answer reaches
// every row. Mutation: hand lookupPTR itself to resolveMissingHostname.
func TestIntegration_ProcessBatch_ReverseLookupOncePerDestination(t *testing.T) {
	db, tenant := claimTestDB(t)
	var mu sync.Mutex
	lookups := map[string]int{}
	prev := lookupPTR
	lookupPTR = func(ip string) string {
		mu.Lock()
		lookups[ip]++
		mu.Unlock()
		return "ptr.example.net"
	}
	t.Cleanup(func() { lookupPTR = prev })

	inv := newCountingInventory(t, nil)
	bp := inv.processor(t, db)
	batch := uuid.New().String()
	sensor := uuid.New()
	for i := 0; i < 6; i++ {
		seedTLSDiscovery(t, db, tenant, sensor, batch, "8.8.8.8", 443+i, nil, `{"discovery_method":"passive"}`)
	}
	if err := bp.ProcessBatch(batch, tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if lookups["8.8.8.8"] != 1 || len(lookups) != 1 {
		t.Fatalf("lookups = %v, want 8.8.8.8 looked up once for six rows", lookups)
	}
}
