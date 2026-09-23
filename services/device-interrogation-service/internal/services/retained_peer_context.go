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
	"time"

	"github.com/google/uuid"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

type peerContextKey struct{}

// These are sanitized collector projections, never raw vendor responses or
// credential configuration. Envelopes preserve the scope used at first receipt.
type retainedPeerContext struct {
	ContextID     string                          `json:"context_id"`
	OriginAssetID uuid.UUID                       `json:"origin_asset_id"`
	Source        identity.Source                 `json:"source"`
	ObservedAt    time.Time                       `json:"observed_at"`
	Observations  InterrogationObservations       `json:"observations"`
	Peers         map[string]identity.Observation `json:"peers"`
	Pending       bool                            `json:"-"`
	Replay        bool                            `json:"-"`
}

func (s *ObservationSink) preparePeerContext(ctx context.Context, tenant, asset uuid.UUID, source identity.Source, at time.Time, obs InterrogationObservations) (context.Context, *retainedPeerContext, error) {
	if previous, ok := ctx.Value(peerContextKey{}).(*retainedPeerContext); ok {
		return ctx, previous, nil
	}
	state := &retainedPeerContext{OriginAssetID: asset, Source: source, ObservedAt: at, Observations: obs, Peers: map[string]identity.Observation{}}
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
		if _, ok := state.Peers[key]; ok {
			continue
		}
		envelope, _, err := s.peerObservation(ctx, tenant, peer, source, at)
		if err != nil {
			continue
		}
		state.Peers[key] = envelope
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

// retainedPeer returns the receipt envelope retained for peer.
//
// A context written before retainedPeerKey existed is keyed by identifierKey.
// Only NUL-free keys — peers with a single identifier — could have been stored,
// since any NUL failed the insert. A hex digest never contains '=' and every
// such legacy key does, so the fallback can never match an entry in a
// new-format context, and an old context still reads exactly as it was written.
func (c *retainedPeerContext) retainedPeer(peer di.PeerRef) (identity.Observation, bool) {
	if obs, ok := c.Peers[retainedPeerKey(peer)]; ok {
		return obs, true
	}
	obs, ok := c.Peers[identifierKey(peer)]
	return obs, ok
}

func retainPeerContext(ctx context.Context, repo *pgidentity.Repository, tenant uuid.UUID, res identity.Resolution) error {
	state, ok := ctx.Value(peerContextKey{}).(*retainedPeerContext)
	if !ok || res.ObservationID == "" {
		return nil
	}
	body, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = repo.Tx().ExecContext(ctx, `INSERT INTO identity_observation_peer_contexts(tenant_id,context_id,observation_id,origin_asset_id,payload,observed_at)
  VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant_id,context_id) DO NOTHING`, tenant, state.ContextID, res.ObservationID, state.OriginAssetID, string(body), state.ObservedAt)
	return err
}

func (s *ObservationSink) finishPeerContext(ctx context.Context, tenant uuid.UUID, state *retainedPeerContext) error {
	if state == nil || state.Pending {
		return nil
	}
	return shareddatabase.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE identity_observation_peer_contexts SET materialized_at=now(),last_error='' WHERE tenant_id=$1 AND context_id=$2 AND materialized_at IS NULL`, tenant, state.ContextID)
		return err
	})
}

// ReplayRetainedPeers reuses the identity pipeline with the exact receipt
// envelopes. A whole context waits until each of its endpoints can be resolved;
// successfully written facts/edges remain idempotent while other peers wait.
func (s *ObservationSink) ReplayRetainedPeers(ctx context.Context, tenant uuid.UUID) error {
	for range 50 {
		var contextID string
		err := shareddatabase.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT p.context_id FROM identity_observation_peer_contexts p
    JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id
    WHERE p.tenant_id=$1 AND p.materialized_at IS NULL AND p.next_attempt_at<=now() AND o.state='linked'
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
				err := tx.QueryRowContext(ctx, `SELECT p.payload FROM identity_observation_peer_contexts p JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id WHERE p.tenant_id=$1 AND p.context_id=$2 AND p.materialized_at IS NULL AND o.state='linked'`, tenant, contextID).Scan(&body)
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
				// Merged sources remain as redirects. Follow only rows of this tenant;
				// malformed/cyclic chains and unapproved destinations stay deferred.
				err = tx.QueryRowContext(ctx, `WITH RECURSIVE owners AS (
     SELECT id,asset_status,deleted_at,metadata,ARRAY[id] AS seen FROM assets WHERE tenant_id=$1 AND id=$2
     UNION ALL SELECT a.id,a.asset_status,a.deleted_at,a.metadata,o.seen||a.id FROM owners o
     JOIN assets a ON a.tenant_id=$1 AND a.id::text=o.metadata->>'merged_into'
     WHERE NOT a.id=ANY(o.seen) AND cardinality(o.seen)<16
    ) SELECT id FROM owners WHERE asset_status='monitoring' AND deleted_at IS NULL
    AND NULLIF(metadata->>'merged_into','') IS NULL LIMIT 1`, tenant, state.OriginAssetID).Scan(&asset)
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
			if err == nil && state.Pending {
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
				_, saveErr := tx.ExecContext(ctx, `UPDATE identity_observation_peer_contexts SET next_attempt_at=now()+interval '5 minutes',last_error=$3 WHERE tenant_id=$1 AND context_id=$2 AND materialized_at IS NULL`, tenant, contextID, message)
				return saveErr
			})
			if err != nil || saveErr != nil {
				return errors.Join(err, saveErr)
			}
		}
	}
	return nil
}

func (s *ObservationSink) RunRetainedPeers(ctx context.Context, bypass *sql.DB) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		rows, err := bypass.QueryContext(ctx, `SELECT DISTINCT tenant_id FROM identity_observation_peer_contexts WHERE materialized_at IS NULL AND next_attempt_at<=now()`)
		if err == nil {
			var tenants []uuid.UUID
			for rows.Next() {
				var tenant uuid.UUID
				if err = rows.Scan(&tenant); err != nil {
					break
				}
				tenants = append(tenants, tenant)
			}
			if err == nil {
				err = rows.Err()
			}
			_ = rows.Close()
			if err == nil {
				for _, tenant := range tenants {
					if err := s.ReplayRetainedPeers(ctx, tenant); err != nil {
						log.Printf("[ObservationSink] retained replay failed for tenant %s: %v", tenant, err)
					}
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
