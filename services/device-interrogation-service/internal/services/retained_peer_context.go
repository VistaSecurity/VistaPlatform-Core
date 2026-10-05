package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

type peerContextKey struct{}

// How long a retained context is retried, and how often ( items 26–27).
//
// A context is held because a peer was held, and most holds do not clear by
// themselves: an address-only peer in a DHCP range, a bare name, a peer on a
// network with no segment wait for an operator or for a NEW observation, and a
// newer run of the same source carries that observation itself. So a context
// is retried with exponential backoff and retired a day after it was observed;
// retrying it every five minutes forever only re-asserted a stale client list.
const (
	retainedPeerTTL          = 24 * time.Hour
	retainedPeerBackoffBase  = 5 * time.Minute
	retainedPeerBackoffLimit = 4 * time.Hour
)

// The last_error a retired context carries, which is what an operator reads.
const (
	retainedPeerExpiredReason    = "retired: still unresolved 24 hours after it was observed"
	retainedPeerSupersededReason = "retired: superseded by a newer run from the same source"
)

// selfPeerKey stands for the interrogated device itself in a context's pending
// set: its identity, gateway claims and own facts. A retainedPeerKey is hex, so
// it can never collide with this.
const selfPeerKey = "self"

// These are sanitized collector projections, never raw vendor responses or
// credential configuration. Envelopes preserve each peer's sighting exactly as
// first received, so a replay is the same delivery.
type retainedPeerContext struct {
	ContextID     string                    `json:"context_id"`
	OriginAssetID uuid.UUID                 `json:"origin_asset_id"`
	Source        identity.Source           `json:"source"`
	ObservedAt    time.Time                 `json:"observed_at"`
	Observations  InterrogationObservations `json:"observations"`
	// Sightings are the peers' sightings, keyed by retainedPeerKey.
	Sightings map[string]identity.Sighting `json:"sightings,omitempty"`
	// Peers are the hand-built observations a context retained before this
	// service posted sightings. Read, never written: a context that
	// has only these replays by rebuilding each peer's sighting from
	// Observations, which still carries every PeerRef.
	Peers map[string]identity.Observation `json:"peers,omitempty"`
	// Progress is what the passes so far settled ( item 25). Nil on a
	// context retained before it existed; such a context replays every peer
	// once, as it always did, and records its progress then.
	Progress *peerProgress `json:"progress,omitempty"`
	// Pending says a peer was held on this pass, which is what makes the
	// context a row in the first place.
	Pending bool `json:"-"`
	Replay  bool `json:"-"`
}

// peerProgress is a retained context's record of which peers still need work.
type peerProgress struct {
	// Pending are the retainedPeerKeys (and selfPeerKey) a replay still has
	// to resolve and write: held peers, peers that resolved to an asset not
	// yet monitoring, and peers whose resolution or write failed.
	Pending []string `json:"pending"`
	// Resolved maps each settled peer to the asset it resolved to, so an edge
	// from a pending peer to a settled one is written without asking the
	// engine about the settled one again.
	Resolved map[string]string `json:"resolved,omitempty"`
}

// pendingSet is a context's pending keys as a set; nil means "everything",
// which is a first pass or a replay of a context without progress.
type pendingSet map[string]bool

func (p pendingSet) due(key string) bool { return p == nil || p[key] }

// edgeDue reports whether an edge depends on a pending peer.
func (p pendingSet) edgeDue(rel di.RelationshipObservation) bool {
	if p == nil {
		return true
	}
	if !rel.Subject.IsZero() && p[retainedPeerKey(rel.Subject)] {
		return true
	}
	return p[retainedPeerKey(rel.Peer)]
}

// replayFilter returns what a pass has to do: everything, unless it is a
// replay of a context that recorded its progress.
func replayFilter(ctx context.Context) pendingSet {
	state, _ := ctx.Value(peerContextKey{}).(*retainedPeerContext)
	if state == nil || !state.Replay || state.Progress == nil {
		return nil
	}
	out := pendingSet{}
	for _, key := range state.Progress.Pending {
		out[key] = true
	}
	return out
}

func (s *ObservationSink) preparePeerContext(ctx context.Context, tenant, asset uuid.UUID, source identity.Source, at time.Time, obs InterrogationObservations) (context.Context, *retainedPeerContext, error) {
	if previous, ok := ctx.Value(peerContextKey{}).(*retainedPeerContext); ok {
		return ctx, previous, nil
	}
	state := &retainedPeerContext{OriginAssetID: asset, Source: source, ObservedAt: at, Observations: obs, Sightings: map[string]identity.Sighting{}}
	state.Observations.ObservedAt = at
	var peers []di.PeerRef
	for _, fact := range obs.Facts {
		if !fact.Subject.IsZero() {
			peers = append(peers, fact.Subject)
		}
	}
	for _, edge := range obs.Relationships {
		if !edge.Subject.IsZero() {
			peers = append(peers, edge.Subject)
		}
		if !edge.Peer.IsZero() {
			peers = append(peers, edge.Peer)
		}
	}
	for _, peer := range peers {
		key := retainedPeerKey(peer)
		if _, ok := state.Sightings[key]; ok {
			continue
		}
		envelope, _, err := s.peerSighting(ctx, tenant, peer, source, at)
		if err != nil {
			continue
		}
		state.Sightings[key] = envelope
	}
	body, err := json.Marshal(state)
	if err != nil {
		return ctx, nil, err
	}
	digest := sha256.Sum256(body)
	state.ContextID = hex.EncodeToString(digest[:])
	return context.WithValue(ctx, peerContextKey{}, state), state, nil
}

// retainedPeerKey is the key a peer's receipt envelope is stored under in
// retainedPeerContext.Peers, which is marshalled into
// identity_observation_peer_contexts.payload — a jsonb column.
//
// It is deliberately NOT identifierKey. That joins its parts with NUL, which is
// harmless for an in-memory comparison and fatal here: encoding/json writes the
// NUL as \u0000, jsonb refuses that escape (22P05), and so every retained peer
// with two or more identifiers failed its resolution transaction and the fact
// or edge it carried was dropped.
//
// A hex SHA-256 over a length-prefixed encoding of the (kind, value) pairs,
// because:
//   - it is printable and jsonb-safe whatever bytes a collector reported. A
//     NUL, control character or invalid UTF-8 in a value is hashed away rather
//     than rejected, or rewritten to U+FFFD by encoding/json so the key no
//     longer round-trips;
//   - length prefixes, not a separator, delimit the parts, so the encoding is
//     injective: no value can forge a two-identifier peer's key by containing
//     the separator and so inherit that peer's envelope;
//   - it keeps identifierKey's order and exactness, so the peers that share a
//     key are the peers that shared one before.
func retainedPeerKey(peer di.PeerRef) string {
	h := sha256.New()
	for _, id := range peer.Identifiers {
		_, _ = fmt.Fprintf(h, "%d:%s%d:%s", len(id.Kind), id.Kind, len(id.Value), id.Value)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// retainedPeer returns the sighting retained for peer. A context retained
// before sightings has none (only Peers), and the caller then sends the peer's
// sighting as built today.
func (c *retainedPeerContext) retainedPeer(peer di.PeerRef) (identity.Sighting, bool) {
	s, ok := c.Sightings[retainedPeerKey(peer)]
	return s, ok
}

// peerOutcome is one peer's answer, memoized for the length of a pass.
type peerOutcome struct {
	ref identity.AssetRef
	err error
}

// passPeers resolves each distinct peer of one persist pass ONCE ( item
// 24) and remembers what each came to, for the facts and edges that name it
// and for the retained context afterwards.
//
// A UniFi controller reports an access point as the subject of several facts
// and as an end of several edges; each mention used to be its own sighting,
// so one pass identified ~59 peers 210 times. Peers are keyed by
// retainedPeerKey, the key their envelopes are retained under, so "the same
// peer" means the same thing here and on replay.
//
// Resolution stays lazy, in the order facts and edges first name each peer, so
// which peers are sent, and in what order, is what it was: only the repeats
// are gone.
type passPeers struct {
	sink     *ObservationSink
	tenantID uuid.UUID
	source   identity.Source
	at       time.Time
	memo     map[string]peerOutcome
	// failed are keys whose write failed after they resolved; a replay
	// retries them.
	failed map[string]bool
	// earlier is the progress a replay starts from; nil on a first pass.
	earlier *peerProgress
}

func newPassPeers(ctx context.Context, s *ObservationSink, tenantID uuid.UUID, source identity.Source, at time.Time) *passPeers {
	p := &passPeers{sink: s, tenantID: tenantID, source: source, at: at, memo: map[string]peerOutcome{}, failed: map[string]bool{}}
	if state, _ := ctx.Value(peerContextKey{}).(*retainedPeerContext); state != nil && state.Replay {
		p.earlier = state.Progress
	}
	return p
}

// resolve answers for peer, asking the engine only the first time.
func (p *passPeers) resolve(ctx context.Context, peer di.PeerRef) (identity.AssetRef, error) {
	key := retainedPeerKey(peer)
	if out, ok := p.memo[key]; ok {
		return out.ref, out.err
	}
	ref, settled, err := p.settled(ctx, key)
	if err == nil && !settled {
		ref, err = p.sink.resolvePeer(ctx, p.tenantID, peer, p.source, p.at)
	}
	p.memo[key] = peerOutcome{ref: ref, err: err}
	return ref, err
}

// settled is a replay's answer for a peer an earlier pass resolved: the asset
// it resolved to, followed through any merge, while that is still a monitored
// asset. Anything else (not settled, or its asset since deleted or no longer
// monitored) is asked again.
func (p *passPeers) settled(ctx context.Context, key string) (identity.AssetRef, bool, error) {
	if p.earlier == nil {
		return identity.AssetRef{}, false, nil
	}
	for _, pending := range p.earlier.Pending {
		if pending == key {
			return identity.AssetRef{}, false, nil
		}
	}
	id, err := uuid.Parse(p.earlier.Resolved[key])
	if err != nil {
		return identity.AssetRef{}, false, nil
	}
	var live uuid.UUID
	err = shareddatabase.WithTenantTx(ctx, p.sink.db, p.tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, liveMonitoredAssetSQL, p.tenantID, id).Scan(&live)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return identity.AssetRef{}, false, nil
	}
	if err != nil {
		return identity.AssetRef{}, false, err
	}
	return identity.AssetRef{TenantID: p.tenantID.String(), ID: live.String()}, true, nil
}

// fail records that a resolved peer's fact or edge write failed.
func (p *passPeers) fail(key string) { p.failed[key] = true }

// failEdge records a failed edge against its non-self ends.
func (p *passPeers) failEdge(rel di.RelationshipObservation) {
	if !rel.Subject.IsZero() {
		p.fail(retainedPeerKey(rel.Subject))
	}
	if !rel.Peer.IsZero() {
		p.fail(retainedPeerKey(rel.Peer))
	}
}

// outcomeSettles reports whether a peer's failed resolution is final for this
// evidence: a contested identity waits on a merge proposal, synthetic names
// and refused sightings will never resolve. Replaying them cannot help, which
// is how they were treated before (they never held a context).
func outcomeSettles(err error) bool {
	return errors.Is(err, errPeerContested) || errors.Is(err, errPeerSyntheticNamesOnly) || errors.Is(err, errSightingRefused)
}

// progress is what this pass leaves for the next one.
func (p *passPeers) progress() *peerProgress {
	out := &peerProgress{Pending: []string{}, Resolved: map[string]string{}}
	pending := map[string]bool{}
	if p.earlier != nil {
		for key, id := range p.earlier.Resolved {
			out.Resolved[key] = id
		}
	}
	for key, o := range p.memo {
		switch {
		case o.err == nil && !o.ref.Zero():
			out.Resolved[key] = o.ref.ID
		case o.err != nil && outcomeSettles(o.err):
			delete(out.Resolved, key)
		default:
			pending[key] = true
		}
	}
	for key := range p.failed {
		pending[key] = true
	}
	for key := range pending {
		delete(out.Resolved, key)
		out.Pending = append(out.Pending, key)
	}
	sort.Strings(out.Pending)
	return out
}

// retainPeerContext records the interrogation's context against the
// observation inventory-service held for review, on this service's
// transaction after the resolution committed there.
func retainPeerContext(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, res identity.Resolution) error {
	state, ok := ctx.Value(peerContextKey{}).(*retainedPeerContext)
	if !ok || res.ObservationID == "" {
		return nil
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO identity_observation_peer_contexts(tenant_id,context_id,observation_id,origin_asset_id,payload,observed_at)
  VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,context_id) DO NOTHING`, tenant, state.ContextID, res.ObservationID, state.OriginAssetID, string(body), state.ObservedAt)
	return err
}

// finishPeerContext settles the pass's context: acknowledged when nothing is
// left to do, otherwise its progress recorded so a replay does only what is
// still pending. A first pass also retires the older contexts it supersedes.
// errs are the pass's own failures, returned joined with any of this.
func (s *ObservationSink) finishPeerContext(ctx context.Context, tenant uuid.UUID, state *retainedPeerContext, pass *passPeers, errs []error) error {
	err := errors.Join(errs...)
	if state == nil || s.db == nil {
		return err
	}
	progress := pass.progress()
	finishErr := shareddatabase.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		// A replay asks only for monitored assets (resolvePeer); a first pass
		// takes whatever the engine answered. When this pass held a peer, a
		// peer that resolved to an asset still awaiting approval waits with
		// it, exactly as a replay of the whole context used to make it wait.
		if !state.Replay && state.Pending && len(progress.Resolved) > 0 {
			ids := make([]string, 0, len(progress.Resolved))
			for _, id := range progress.Resolved {
				ids = append(ids, id)
			}
			rows, qErr := tx.QueryContext(ctx, `SELECT id::text FROM assets WHERE tenant_id=$1 AND id::text=ANY($2) AND asset_status='monitoring' AND deleted_at IS NULL`, tenant, pq.Array(ids))
			if qErr != nil {
				return qErr
			}
			ready := map[string]bool{}
			for rows.Next() {
				var id string
				if qErr = rows.Scan(&id); qErr != nil {
					_ = rows.Close()
					return qErr
				}
				ready[id] = true
			}
			if qErr = rows.Close(); qErr != nil {
				return qErr
			}
			for key, id := range progress.Resolved {
				if !ready[id] {
					delete(progress.Resolved, key)
					progress.Pending = append(progress.Pending, key)
				}
			}
			sort.Strings(progress.Pending)
		}
		state.Progress = progress

		if err == nil && !state.Pending && len(progress.Pending) == 0 {
			if _, xErr := tx.ExecContext(ctx, `UPDATE identity_observation_peer_contexts SET materialized_at=now(),last_error='' WHERE tenant_id=$1 AND context_id=$2 AND materialized_at IS NULL`, tenant, state.ContextID); xErr != nil {
				return xErr
			}
		} else {
			body, mErr := json.Marshal(state)
			if mErr != nil {
				return mErr
			}
			if _, xErr := tx.ExecContext(ctx, `UPDATE identity_observation_peer_contexts SET payload=$3 WHERE tenant_id=$1 AND context_id=$2 AND materialized_at IS NULL AND retired_at IS NULL`, tenant, state.ContextID, string(body)); xErr != nil {
				return xErr
			}
		}

		// The newest run of a source is the truth about the device's peers
		// ( item 26): an older run's client list replayed later can only
		// reassert addresses the device no longer reports. Superseded, not
		// deleted — the identity review page still shows it as historical
		// evidence. Only by a pass that landed (or holds its own context), so
		// a failed run does not take an older one's evidence with it.
		if state.Replay || (err != nil && !state.Pending) {
			return nil
		}
		res, xErr := tx.ExecContext(ctx, `UPDATE identity_observation_peer_contexts SET retired_at=now(),last_error=$7
  WHERE tenant_id=$1 AND origin_asset_id=$2 AND context_id<>$3 AND observed_at<$4
    AND materialized_at IS NULL AND retired_at IS NULL
    AND payload->'source'->>'kind'=$5 AND COALESCE(payload->'observations'->>'Producer','')=$6`,
			tenant, state.OriginAssetID, state.ContextID, state.ObservedAt, string(state.Source.Kind), state.Observations.Producer, retainedPeerSupersededReason)
		if xErr != nil {
			return xErr
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("[ObservationSink] retired %d retained peer context(s) for asset %s: superseded by run %s", n, state.OriginAssetID, state.Source.Ref)
		}
		return nil
	})
	return errors.Join(err, finishErr)
}

// liveMonitoredAssetSQL follows an asset through merge redirects to the live,
// monitored asset it now is. Merged sources remain as redirects. It follows
// only rows of this tenant; malformed/cyclic chains and unapproved
// destinations answer nothing.
const liveMonitoredAssetSQL = `WITH RECURSIVE owners AS (
     SELECT id,asset_status,deleted_at,metadata,ARRAY[id] AS seen FROM assets WHERE tenant_id=$1 AND id=$2
     UNION ALL SELECT a.id,a.asset_status,a.deleted_at,a.metadata,o.seen||a.id FROM owners o
     JOIN assets a ON a.tenant_id=$1 AND a.id::text=o.metadata->>'merged_into'
     WHERE NOT a.id=ANY(o.seen) AND cardinality(o.seen)<16
    ) SELECT id FROM owners WHERE asset_status='monitoring' AND deleted_at IS NULL
    AND NULLIF(metadata->>'merged_into','') IS NULL LIMIT 1`

// expireRetainedPeers retires, in one statement, every open context of the
// tenant observed more than retainedPeerTTL ago.
func (s *ObservationSink) expireRetainedPeers(ctx context.Context, tenant uuid.UUID) error {
	var n int64
	err := shareddatabase.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `UPDATE identity_observation_peer_contexts SET retired_at=now(),last_error=$3
  WHERE tenant_id=$1 AND materialized_at IS NULL AND retired_at IS NULL AND observed_at<=now()-make_interval(secs=>$2)`,
			tenant, retainedPeerTTL.Seconds(), retainedPeerExpiredReason)
		if err != nil {
			return err
		}
		n, err = res.RowsAffected()
		return err
	})
	if err == nil && n > 0 {
		log.Printf("[ObservationSink] retired %d retained peer context(s) for tenant %s: unresolved %s after they were observed", n, tenant, retainedPeerTTL)
	}
	return err
}

// ReplayRetainedPeers reuses the identity pipeline with the exact receipt
// envelopes. A context waits until each of its peers can be resolved; a
// replay resolves and writes only the peers still pending ( item 25).
// Each deferral backs off exponentially, and a context is retired a day after
// it was observed (item 27).
func (s *ObservationSink) ReplayRetainedPeers(ctx context.Context, tenant uuid.UUID) error {
	if err := s.expireRetainedPeers(ctx, tenant); err != nil {
		return err
	}
	for range 50 {
		var contextID string
		err := shareddatabase.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT p.context_id FROM identity_observation_peer_contexts p
    JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id
    WHERE p.tenant_id=$1 AND p.materialized_at IS NULL AND p.retired_at IS NULL AND p.next_attempt_at<=now() AND o.state='linked'
    ORDER BY p.observed_at,p.context_id LIMIT 1`, tenant).Scan(&contextID)
		})
		if err == sql.ErrNoRows {
			return nil
		}
		if err != nil {
			return err
		}
		deferred := false
		err = shareddatabase.WithSessionAdvisoryLocks(ctx, s.db, []shareddatabase.SessionAdvisoryLock{{Key: pgidentity.HostSnapshotLockKey(tenant)}}, func() error {
			var state retainedPeerContext
			var asset uuid.UUID
			err := shareddatabase.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
				var mode string
				if err := tx.QueryRowContext(ctx, `SELECT COALESCE((SELECT config->'identity_admission'->>'mode' FROM tenant_admin_settings WHERE tenant_id=$1),'disabled')`, tenant).Scan(&mode); err != nil {
					return err
				}
				if mode != "enforce" {
					deferred = true
					return nil
				}
				var body []byte
				err := tx.QueryRowContext(ctx, `SELECT p.payload FROM identity_observation_peer_contexts p JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.materialized_at IS NULL AND p.retired_at IS NULL AND o.state='linked'`, tenant, contextID).Scan(&body)
				if err == sql.ErrNoRows {
					deferred = true
					return nil
				}
				if err != nil {
					return err
				}
				if err = json.Unmarshal(body, &state); err != nil {
					return err
				}
				err = tx.QueryRowContext(ctx, liveMonitoredAssetSQL, tenant, state.OriginAssetID).Scan(&asset)
				if err == sql.ErrNoRows {
					deferred = true
					return nil
				}
				return err
			})
			if err != nil || deferred {
				return err
			}
			state.Replay = true
			replayCtx := context.WithValue(ctx, peerContextKey{}, &state)
			err = s.persist(replayCtx, tenant, asset, state.Source, state.Observations)
			if err == nil && (state.Pending || (state.Progress != nil && len(state.Progress.Pending) > 0)) {
				deferred = true
			}
			return err
		})
		if err != nil || deferred {
			saveErr := shareddatabase.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
				message := "waiting for identity resolution or monitoring approval"
				if err != nil {
					message = "materialization failed; retry scheduled"
				}
				// Doubling from the base to the cap; the exponent is bounded
				// so the arithmetic cannot overflow however long a context
				// has waited.
				_, saveErr := tx.ExecContext(ctx, `UPDATE identity_observation_peer_contexts
  SET attempts=attempts+1,
      next_attempt_at=now()+make_interval(secs=>least($4*power(2,least(attempts,20)),$5)),
      last_error=$3
  WHERE tenant_id=$1 AND context_id=$2 AND materialized_at IS NULL AND retired_at IS NULL`,
					tenant, contextID, message, retainedPeerBackoffBase.Seconds(), retainedPeerBackoffLimit.Seconds())
				return saveErr
			})
			if err != nil || saveErr != nil {
				return errors.Join(err, saveErr)
			}
		}
	}
	return nil
}

// retainedPeerTenants is every tenant with a context due for a replay or due
// to expire. Retired and acknowledged contexts are never work.
func retainedPeerTenants(ctx context.Context, bypass *sql.DB) ([]uuid.UUID, error) {
	rows, err := bypass.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM identity_observation_peer_contexts
  WHERE materialized_at IS NULL AND retired_at IS NULL AND (next_attempt_at<=now() OR observed_at<=now()-make_interval(secs=>$1))`, retainedPeerTTL.Seconds())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var tenants []uuid.UUID
	for rows.Next() {
		var tenant uuid.UUID
		if err := rows.Scan(&tenant); err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}
	return tenants, rows.Err()
}

func (s *ObservationSink) RunRetainedPeers(ctx context.Context, bypass *sql.DB) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		tenants, err := retainedPeerTenants(ctx, bypass)
		if err == nil {
			for _, tenant := range tenants {
				if err := s.ReplayRetainedPeers(ctx, tenant); err != nil {
					log.Printf("[ObservationSink] retained replay failed for tenant %s: %v", tenant, err)
				}
			}
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("[ObservationSink] retained tenant enumeration failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func retainedPeerOutcome(ctx context.Context, res identity.Resolution) error {
	if res.ObservationID == "" {
		return fmt.Errorf("peer has no retained observation")
	}
	if state, ok := ctx.Value(peerContextKey{}).(*retainedPeerContext); ok {
		state.Pending = true
	}
	return &identity.RetainedObservation{Result: res.IngestResult()}
}
