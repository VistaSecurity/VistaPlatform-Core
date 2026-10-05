package services

// How often a run asks the engine, and what a retained context replays
// ( items 24–27).
//
// A real UniFi controller's run carries ~140 facts and ~71 edges about ~59
// peers. Each fact subject and each edge end used to be its own sighting, so
// a pass identified ~210 times; a held peer kept the WHOLE run retained and
// replayed every five minutes, forever, re-posting every peer and re-counting
// every edge; and every new run added another retained context beside the
// last. These tests drive the real Persist / ReplayRetainedPeers and count the
// sightings that reach the route.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// countingPoster passes every post through to the reference route and keeps
// the sightings it carried.
type countingPoster struct {
	inner sightingclient.Poster
	mu    sync.Mutex
	items []sightingclient.Item
}

func (c *countingPoster) PostItems(ctx context.Context, tenantID string, items []sightingclient.Item) ([]sightingclient.Result, error) {
	c.mu.Lock()
	c.items = append(c.items, items...)
	c.mu.Unlock()
	return c.inner.PostItems(ctx, tenantID, items)
}

func (c *countingPoster) take() []sightingclient.Item {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := c.items
	c.items = nil
	return out
}

// countSightings counts what intakes over db post, for the rest of the test.
// Other databases' intakes are left on the package's poster.
func countSightings(t *testing.T, db *sql.DB) *countingPoster {
	t.Helper()
	posterMu.RLock()
	previous := posterFactory
	posterMu.RUnlock()
	counter := &countingPoster{inner: previous(db)}
	SetSightingPosterFactory(func(d *sql.DB) sightingclient.Poster {
		if d == db {
			return counter
		}
		return previous(d)
	})
	t.Cleanup(func() { SetSightingPosterFactory(previous) })
	return counter
}

// postedFor is how many posted sightings carried the identifier value.
func postedFor(items []sightingclient.Item, value string) int {
	n := 0
	for _, item := range items {
		for _, id := range item.Identifiers {
			if id.Value == value {
				n++
				break
			}
		}
	}
	return n
}

// replayFixture is a tenant in enforce mode with a segment its peers'
// addresses fall in, the controller the run is about, and a monitored asset
// an operator links a held peer to.
type replayFixture struct {
	owner, app   *sql.DB
	tenant, self uuid.UUID
	target       uuid.UUID
	sink         *ObservationSink
	posts        *countingPoster
}

func newReplayFixture(t *testing.T) *replayFixture {
	t.Helper()
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	f := &replayFixture{owner: owner, tenant: testdb.NewTenant(t, owner)}
	f.app = testdb.ConnectAsAppRole(t, owner)
	f.app.SetMaxOpenConns(1)
	f.self = subjectAsset(t, owner, f.tenant, "controller")
	f.target = subjectAsset(t, owner, f.tenant, "linked-target")
	if _, err := owner.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')`, f.tenant); err != nil {
		t.Fatal(err)
	}
	// Enforce mode admits a new asset only within the tenant's allowance.
	if _, err := owner.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		SELECT $1,id,'{"quantity":100}'::jsonb,'retained replay' FROM billable_items WHERE key='max_assets'`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata) VALUES($1,'LAN','cidr','198.51.100.0/24','private','production',true,'{"dynamic":true}')`, f.tenant); err != nil {
		t.Fatal(err)
	}
	f.sink = NewObservationSink(f.app)
	f.posts = countSightings(t, f.app)
	return f
}

// directPeer is a neighbour met on one of the controller's interfaces, inside
// the segment: admission establishes it.
func directPeer(name, mac, ip string) di.PeerRef {
	return di.PeerRef{DisplayName: name, IdentityEvidence: di.PeerIdentityEvidence{ConnectedInterface: true}, Identifiers: []di.PeerIdentifier{
		{Kind: di.IdentifierMACAddress, Value: mac},
		{Kind: di.IdentifierIPAddress, Value: ip},
	}}
}

// heldPeer is an advertised bare name: admission holds it
// (no_device_or_address_binding), which no replay of the same evidence clears.
func heldPeer(name string) di.PeerRef {
	return di.PeerRef{DisplayName: name, Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierHostname, Value: name}}}
}

func connectsTo(subject, peer di.PeerRef) di.RelationshipObservation {
	return di.RelationshipObservation{Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Subject: subject, Peer: peer}
}

// monitored resolves peers through a warm-up run and approves the assets it
// made, so a later run finds them already in service.
func (f *replayFixture) monitored(t *testing.T, ctx context.Context, peers ...di.PeerRef) {
	t.Helper()
	obs := InterrogationObservations{ObservedAt: time.Now().UTC().Add(-3 * time.Hour).Truncate(time.Microsecond)}
	for _, p := range peers {
		obs.Relationships = append(obs.Relationships, connectsTo(di.PeerRef{}, p))
	}
	if err := f.sink.Persist(ctx, f.tenant, f.self, peerSource("interrogation:warm-up"), obs); err != nil {
		t.Fatalf("warm-up run: %v", err)
	}
	if _, err := f.owner.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id NOT IN ($2,$3)`, f.tenant, f.self, f.target); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM assets WHERE tenant_id=$1`, f.tenant); n != 2+len(peers) {
		t.Fatalf("warm-up made %d assets, want %d", n, 2+len(peers))
	}
	f.posts.take()
}

// openContext is the run's retained context row.
func (f *replayFixture) openContext(t *testing.T, ref string) (contextID string, observation uuid.UUID, state retainedPeerContext) {
	t.Helper()
	var body []byte
	if err := f.owner.QueryRow(`SELECT context_id,observation_id,payload FROM identity_observation_peer_contexts WHERE tenant_id=$1 AND payload->'source'->>'ref'=$2`, f.tenant, ref).Scan(&contextID, &observation, &body); err != nil {
		t.Fatalf("no retained context for %s: %v", ref, err)
	}
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatal(err)
	}
	return contextID, observation, state
}

// link is the operator settling a held observation onto the target.
func (f *replayFixture) link(t *testing.T, observation uuid.UUID) {
	t.Helper()
	if _, err := f.owner.Exec(`UPDATE identity_observations SET state='linked',asset_id=$3,confirmed_by=$4 WHERE tenant_id=$1 AND id=$2`, f.tenant, observation, f.target, uuid.New()); err != nil {
		t.Fatal(err)
	}
}

func peerAsset(t *testing.T, db *sql.DB, tenant uuid.UUID, mac string) uuid.UUID {
	t.Helper()
	return peerAssetByMAC(t, db, tenant, mac)
}

// TestIntegration_ObservationSink_ResolvesEachPeerOncePerRun: a run naming P
// distinct peers across F facts and R edges posts P sightings, not one per
// mention, and still writes every fact and edge.
//
// MUTATION: make passPeers.resolve call resolvePeer without consulting or
// filling the memo and this posts 11 sightings for 3 peers.
func TestIntegration_ObservationSink_ResolvesEachPeerOncePerRun(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	self := subjectAsset(t, owner, tenant, "controller")
	posts := countSightings(t, app)
	sink := NewObservationSink(app)

	a := di.PeerRef{DisplayName: "ap-a", Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierMACAddress, Value: macUnclassedByRule}}}
	b := di.PeerRef{DisplayName: "ap-b", Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierMACAddress, Value: macUnclassedByRuleB}}}
	c := di.PeerRef{DisplayName: "ap-c", Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierMACAddress, Value: "00:00:01:44:55:77"}}}
	obs := InterrogationObservations{ObservedAt: time.Now().UTC().Truncate(time.Microsecond)}
	for _, p := range []di.PeerRef{a, b, c} {
		obs.Facts = append(obs.Facts,
			di.FactObservation{Subject: p, Key: "hw.model", Value: "Access point", Confidence: .8},
			di.FactObservation{Subject: p, Key: "hw.vendor", Value: "Example", Confidence: .8})
		obs.Relationships = append(obs.Relationships, connectsTo(di.PeerRef{}, p))
	}
	obs.Relationships = append(obs.Relationships, connectsTo(a, b))
	const peers, factCount, edges = 3, 6, 4

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if err := sink.Persist(ctx, tenant, self, peerSource("interrogation:resolve-once"), obs); err != nil {
		t.Fatal(err)
	}
	if got := len(posts.take()); got != peers {
		t.Fatalf("a run with %d peers, %d facts and %d edges posted %d sightings, want %d", peers, factCount, edges, got, peers)
	}
	if n := countRows(t, owner, `SELECT count(*) FROM asset_facts WHERE tenant_id=$1 AND key IN ('hw.model','hw.vendor')`, tenant); n != factCount {
		t.Fatalf("wrote %d facts, want %d", n, factCount)
	}
	if n := countRows(t, owner, `SELECT count(*) FROM asset_relationships WHERE tenant_id=$1`, tenant); n != edges {
		t.Fatalf("wrote %d edges, want %d", n, edges)
	}
}

// TestIntegration_ObservationSink_ReplayOnlyResolvesPendingPeers: one peer of
// a run is held. The first pass writes everything about the others; the
// replay posts a sighting for the held peer alone and writes only what names
// it.
//
// MUTATION: make replayFilter return nil (replay everything) and this posts
// three sightings and rewrites the settled peers' facts and edges.
func TestIntegration_ObservationSink_ReplayOnlyResolvesPendingPeers(t *testing.T) {
	f := newReplayFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a := directPeer("switch-a", macUnclassedByRule, "198.51.100.10")
	b := directPeer("switch-b", macUnclassedByRuleB, "198.51.100.11")
	h := heldPeer("mystery.local")
	f.monitored(t, ctx, a, b)
	assetA, assetB := peerAsset(t, f.owner, f.tenant, macUnclassedByRule), peerAsset(t, f.owner, f.tenant, macUnclassedByRuleB)
	if _, err := f.owner.Exec(`DELETE FROM asset_relationships WHERE tenant_id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}

	const ref = "interrogation:one-held"
	obs := InterrogationObservations{
		ObservedAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond),
		Facts: []di.FactObservation{
			{Subject: h, Key: "hw.model", Value: "Printer", Confidence: .8},
			{Subject: a, Key: "hw.model", Value: "Switch", Confidence: .8},
			{Subject: b, Key: "hw.model", Value: "Switch", Confidence: .8},
		},
		Relationships: []di.RelationshipObservation{connectsTo(di.PeerRef{}, h), connectsTo(di.PeerRef{}, a), connectsTo(a, b)},
	}
	if err := f.sink.Persist(ctx, f.tenant, f.self, peerSource(ref), obs); err != nil {
		t.Fatal(err)
	}
	if got := len(f.posts.take()); got != 3 {
		t.Fatalf("first pass posted %d sightings, want 3", got)
	}
	for _, asset := range []uuid.UUID{assetA, assetB} {
		if n := countRows(t, f.owner, `SELECT count(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND key='hw.model'`, f.tenant, asset); n != 1 {
			t.Fatalf("first pass did not write the settled peer %s's fact", asset)
		}
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM asset_relationships WHERE tenant_id=$1`, f.tenant); n != 2 {
		t.Fatalf("first pass wrote %d edges, want the 2 between settled ends", n)
	}
	_, observation, state := f.openContext(t, ref)
	if state.Progress == nil || len(state.Progress.Pending) != 1 || state.Progress.Pending[0] != retainedPeerKey(h) {
		t.Fatalf("progress = %+v, want only the held peer pending", state.Progress)
	}

	// Anything the replay rewrites about a settled peer reappears.
	if _, err := f.owner.Exec(`DELETE FROM asset_facts WHERE tenant_id=$1 AND asset_id IN ($2,$3)`, f.tenant, assetA, assetB); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(`DELETE FROM asset_relationships WHERE tenant_id=$1`, f.tenant); err != nil {
		t.Fatal(err)
	}
	f.link(t, observation)
	if err := f.sink.ReplayRetainedPeers(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	posted := f.posts.take()
	if len(posted) != 1 || postedFor(posted, "mystery.local") != 1 {
		t.Fatalf("replay posted %d sightings, want 1 for the held peer", len(posted))
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND key='hw.model'`, f.tenant, f.target); n != 1 {
		t.Fatal("the held peer's fact did not land on the asset it was linked to")
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM asset_relationships WHERE tenant_id=$1 AND from_asset_id=$2 AND to_asset_id=$3`, f.tenant, f.self, f.target); n != 1 {
		t.Fatal("the held peer's edge was not written")
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id IN ($2,$3)`, f.tenant, assetA, assetB); n != 0 {
		t.Fatalf("replay rewrote %d facts of peers settled on the first pass", n)
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM asset_relationships WHERE tenant_id=$1`, f.tenant); n != 1 {
		t.Fatalf("replay wrote %d edges, want only the held peer's", n)
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM identity_observation_peer_contexts WHERE tenant_id=$1 AND payload->'source'->>'ref'=$2 AND materialized_at IS NOT NULL`, f.tenant, ref); n != 1 {
		t.Fatal("context not acknowledged once its last peer resolved")
	}
}

// TestIntegration_ObservationSink_NewerRunSupersedesOlderContext: a second
// run of the same source for the same device retires the first run's open
// context, which the replay worker then never touches, while the row stays
// for the identity review page.
//
// MUTATION: delete the supersede UPDATE in finishPeerContext and the old
// context is replayed (one sighting posted, an attempt recorded).
func TestIntegration_ObservationSink_NewerRunSupersedesOlderContext(t *testing.T) {
	f := newReplayFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	run := func(ref, name string, at time.Time) {
		t.Helper()
		obs := InterrogationObservations{ObservedAt: at, Relationships: []di.RelationshipObservation{connectsTo(di.PeerRef{}, heldPeer(name))}}
		if err := f.sink.Persist(ctx, f.tenant, f.self, peerSource(ref), obs); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	run("interrogation:run-1", "old-client.local", now.Add(-2*time.Hour))
	run("interrogation:run-2", "new-client.local", now.Add(-time.Hour))

	var retired bool
	var lastError string
	var oldObservation uuid.UUID
	if err := f.owner.QueryRow(`SELECT retired_at IS NOT NULL,last_error,observation_id FROM identity_observation_peer_contexts WHERE tenant_id=$1 AND payload->'source'->>'ref'='interrogation:run-1'`, f.tenant).Scan(&retired, &lastError, &oldObservation); err != nil {
		t.Fatal(err)
	}
	if !retired || lastError != retainedPeerSupersededReason {
		t.Fatalf("older context retired=%v last_error=%q; want superseded", retired, lastError)
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM identity_observation_peer_contexts WHERE tenant_id=$1 AND payload->'source'->>'ref'='interrogation:run-2' AND retired_at IS NULL AND materialized_at IS NULL`, f.tenant); n != 1 {
		t.Fatal("the newer run's own context was retired")
	}

	f.link(t, oldObservation)
	f.posts.take()
	if err := f.sink.ReplayRetainedPeers(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	if posted := f.posts.take(); postedFor(posted, "old-client.local") != 0 {
		t.Fatal("the replay worker replayed a superseded context")
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM identity_observation_peer_contexts WHERE tenant_id=$1 AND payload->'source'->>'ref'='interrogation:run-1' AND attempts=0 AND materialized_at IS NULL`, f.tenant); n != 1 {
		t.Fatal("the superseded context was attempted or materialized")
	}
}

// TestIntegration_ObservationSink_RetainedContextBacksOffAndExpires: each
// deferral doubles the wait from five minutes up to the cap, and a context
// still open a day after it was observed is retired in one statement and
// never selected again.
//
// MUTATIONS: a fixed `interval '5 minutes'` fails the doubling; making
// expireRetainedPeers a no-op leaves the day-old context open and attempted.
func TestIntegration_ObservationSink_RetainedContextBacksOffAndExpires(t *testing.T) {
	f := newReplayFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const ref = "interrogation:backoff"
	obs := InterrogationObservations{ObservedAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond),
		Relationships: []di.RelationshipObservation{connectsTo(di.PeerRef{}, heldPeer("stuck.local"))}}
	if err := f.sink.Persist(ctx, f.tenant, f.self, peerSource(ref), obs); err != nil {
		t.Fatal(err)
	}
	contextID, observation, _ := f.openContext(t, ref)
	f.link(t, observation)
	// The controller itself awaits approval, so every replay defers.
	if _, err := f.owner.Exec(`UPDATE assets SET asset_status='pending_approval' WHERE tenant_id=$1 AND id=$2`, f.tenant, f.self); err != nil {
		t.Fatal(err)
	}

	limit := retainedPeerBackoffLimit.Seconds()
	for attempt := 1; attempt <= 8; attempt++ {
		if _, err := f.owner.Exec(`UPDATE identity_observation_peer_contexts SET next_attempt_at=now() WHERE tenant_id=$1 AND context_id=$2`, f.tenant, contextID); err != nil {
			t.Fatal(err)
		}
		if err := f.sink.ReplayRetainedPeers(ctx, f.tenant); err != nil {
			t.Fatal(err)
		}
		var attempts int
		var wait float64
		if err := f.owner.QueryRow(`SELECT attempts,extract(epoch FROM next_attempt_at-now())::float8 FROM identity_observation_peer_contexts WHERE tenant_id=$1 AND context_id=$2`, f.tenant, contextID).Scan(&attempts, &wait); err != nil {
			t.Fatal(err)
		}
		want := math.Min(retainedPeerBackoffBase.Seconds()*math.Pow(2, float64(attempt-1)), limit)
		if attempts != attempt || math.Abs(wait-want) > 30 {
			t.Fatalf("after deferral %d: attempts=%d wait=%.0fs, want %d and ~%.0fs", attempt, attempts, wait, attempt, want)
		}
	}

	tenants, err := retainedPeerTenants(ctx, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	if containsTenant(tenants, f.tenant) {
		t.Fatal("a backed-off context was enumerated before it was due")
	}
	// A day after it was observed, and not due for another few hours: it is
	// enumerated so it can expire, retired, and then never selected.
	if _, err := f.owner.Exec(`UPDATE identity_observation_peer_contexts SET observed_at=now()-interval '25 hours' WHERE tenant_id=$1 AND context_id=$2`, f.tenant, contextID); err != nil {
		t.Fatal(err)
	}
	if tenants, err = retainedPeerTenants(ctx, f.owner); err != nil || !containsTenant(tenants, f.tenant) {
		t.Fatalf("an expired context's tenant was not enumerated (%v)", err)
	}
	if _, err := f.owner.Exec(`UPDATE identity_observation_peer_contexts SET next_attempt_at=now() WHERE tenant_id=$1 AND context_id=$2`, f.tenant, contextID); err != nil {
		t.Fatal(err)
	}
	if err := f.sink.ReplayRetainedPeers(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	var retired bool
	var attempts int
	var lastError string
	if err := f.owner.QueryRow(`SELECT retired_at IS NOT NULL,attempts,last_error FROM identity_observation_peer_contexts WHERE tenant_id=$1 AND context_id=$2`, f.tenant, contextID).Scan(&retired, &attempts, &lastError); err != nil {
		t.Fatal(err)
	}
	if !retired || attempts != 8 || lastError != retainedPeerExpiredReason {
		t.Fatalf("day-old context: retired=%v attempts=%d last_error=%q; want retired, not attempted", retired, attempts, lastError)
	}
	if tenants, err = retainedPeerTenants(ctx, f.owner); err != nil || containsTenant(tenants, f.tenant) {
		t.Fatalf("a retired context is still enumerated (%v)", err)
	}
}

func containsTenant(tenants []uuid.UUID, tenant uuid.UUID) bool {
	for _, t := range tenants {
		if t == tenant {
			return true
		}
	}
	return false
}

// TestIntegration_ObservationSink_LegacyContextReplaysOnce: a context retained
// before progress was recorded, holding only the observation-era `peers`
// envelopes, replays every peer once — as it always did — and is then
// acknowledged.
//
// MUTATION: treat a context without progress as having nothing pending
// (replayFilter returning an empty set for nil Progress) and the settled
// peer's fact is never written and nothing is posted.
func TestIntegration_ObservationSink_LegacyContextReplaysOnce(t *testing.T) {
	f := newReplayFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	a := directPeer("switch-a", macUnclassedByRule, "198.51.100.10")
	h := heldPeer("legacy-printer.local")
	f.monitored(t, ctx, a)
	assetA := peerAsset(t, f.owner, f.tenant, macUnclassedByRule)

	const ref = "interrogation:legacy"
	obs := InterrogationObservations{
		ObservedAt: time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond),
		Facts: []di.FactObservation{
			{Subject: h, Key: "hw.model", Value: "Printer", Confidence: .8},
			{Subject: a, Key: "hw.model", Value: "Switch", Confidence: .8},
		},
	}
	if err := f.sink.Persist(ctx, f.tenant, f.self, peerSource(ref), obs); err != nil {
		t.Fatal(err)
	}
	contextID, observation, _ := f.openContext(t, ref)
	// The shape an older build wrote: no progress, no sightings, only the
	// hand-built observations.
	if _, err := f.owner.Exec(`UPDATE identity_observation_peer_contexts SET payload=(payload-'progress'-'sightings')||'{"peers":{"legacy":{"display_name":"legacy"}}}'::jsonb WHERE tenant_id=$1 AND context_id=$2`, f.tenant, contextID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.owner.Exec(`DELETE FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2`, f.tenant, assetA); err != nil {
		t.Fatal(err)
	}
	f.posts.take()
	f.link(t, observation)
	for range 2 {
		if _, err := f.owner.Exec(`UPDATE identity_observation_peer_contexts SET next_attempt_at=now() WHERE tenant_id=$1 AND context_id=$2`, f.tenant, contextID); err != nil {
			t.Fatal(err)
		}
		if err := f.sink.ReplayRetainedPeers(ctx, f.tenant); err != nil {
			t.Fatal(err)
		}
	}
	posted := f.posts.take()
	if len(posted) != 2 || postedFor(posted, "legacy-printer.local") != 1 {
		t.Fatalf("legacy replay posted %d sightings, want each of its 2 peers once", len(posted))
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id IN ($2,$3) AND key='hw.model'`, f.tenant, assetA, f.target); n != 2 {
		t.Fatalf("legacy replay wrote %d of its 2 facts", n)
	}
	if n := countRows(t, f.owner, `SELECT count(*) FROM identity_observation_peer_contexts WHERE tenant_id=$1 AND context_id=$2 AND materialized_at IS NOT NULL`, f.tenant, contextID); n != 1 {
		t.Fatal("legacy context not acknowledged")
	}
}
