package services

// One store and one replay for crypto evidence that is waiting on a decision
// ( F8).
//
// A discovery finding's certificates and crypto configuration are written into
// the inventory only for an asset that is `monitoring`. Everything else waits in
// `deferred_crypto_findings` and is materialized by replayDeferredCrypto, which
// every pending -> monitoring path reaches:
//
//   - ApproveAssets and AutoApproveAgentHost call it directly, after the
//     approval commits;
//   - every other transition (a segment rule promoting an asset during ingest,
//     an Active Scan approving its targets, an interrogated device's
//     auto-approval, an operator linking an observation under identity
//     admission) is picked up by replayDueDeferredCrypto, which the identity
//     evidence worker runs for every tenant every minute.
//
// It replaces three stores that held the same evidence and two replays that
// materialized it: a capped array in assets.metadata replayed at approval, and
// unmaterialized discovery payloads in identity_observation_payloads replayed by
// the identity sweep (which the enrichment coordinator's Materialize pass fed by
// linking their observations). identity_observation_payloads now holds only
// passive host-observation payloads, which are not crypto.
//
// A row waits on exactly one thing:
//
//   - an ASSET (observation_id NULL): written by deferCryptoFinding for a
//     finding on an asset still pending approval;
//   - an OBSERVATION (observation_id set): written on the identity engine's own
//     transaction when the tenant's identity admission is `enforce` or
//     `paused`. It replays once the observation is linked to a monitoring asset
//     by a decision that attached its evidence (not `supporting`; an operator's
//     scan request only for the receipts that scan produced), and not while
//     admission is paused.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/events"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// maxDeferredCryptoRows bounds the unreplayed rows kept per asset (and per
// observation, before it has an asset). With dedup in place an asset reaches it
// only by producing that many genuinely distinct observations while it waits,
// which is pathological: the cap is a backstop against unbounded growth, not a
// routine trim. NEWEST WINS — the rows observed longest ago are dropped first,
// because the newest observations describe the asset's current posture.
const maxDeferredCryptoRows = 50

// deferredCryptoRetryDelay is how long a claimed row is leased, and how long a
// failed replay waits before it is tried again.
const deferredCryptoRetryDelay = 5 * time.Minute

// deferredCryptoReplayedRetention is how long a replayed asset-gated row is
// kept before the sweep deletes it. Observation-gated rows are kept with their
// observation: they are its evidence history (Discovery → Observations).
const deferredCryptoReplayedRetention = 7 * 24 * time.Hour

// deferredCryptoReplaySource is the event source of a replayed
// observation-gated row — what the identity sweep published under before.
const deferredCryptoReplaySource = "retained_observation"

// deferCryptoFinding holds a finding for an asset that is not monitoring yet,
// to be replayed when it is approved.
//
// Deduplicated and capped. Findings that materialize to the same thing (see
// deferredFindingFingerprint) replace their predecessor's body rather than
// stacking, so the store stays the size of the asset's distinct posture. Errors
// are logged rather than returned: one finding that cannot be held must not
// abort the rest of an ingest batch.
func (s *AssetService) deferCryptoFinding(tenantID, assetID uuid.UUID, f IngestFinding) {
	if err := s.deferCryptoForAsset(context.Background(), tenantID, assetID, f); err != nil {
		log.Printf("Warning: failed to defer crypto evidence for asset %s: %v", assetID, err)
	}
}

func (s *AssetService) deferCryptoForAsset(ctx context.Context, tenantID, assetID uuid.UUID, f IngestFinding) error {
	body, err := json.Marshal(f)
	if err != nil {
		return fmt.Errorf("marshal finding: %w", err)
	}
	key := s.deferredFindingFingerprint(f)
	source := findingSource(f).Ref
	seen := deferredCryptoSeenAt(findingObservedAt(f))
	return database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// Serialized per asset, with the crypto upsert's lock: two concurrent
		// ingests of one finding would otherwise both miss the UPDATE and both
		// INSERT.
		if _, err := tx.ExecContext(ctx, lockAssetMaterializationSQL, assetMaterializationLockKey(tenantID, assetID)); err != nil {
			return fmt.Errorf("lock asset materialization: %w", err)
		}
		res, err := tx.ExecContext(ctx, `UPDATE deferred_crypto_findings
			SET finding = $4, source_ref = $5, last_seen_at = GREATEST(last_seen_at, COALESCE($6, now()))
			WHERE tenant_id = $1 AND asset_id = $2 AND observation_id IS NULL AND replayed_at IS NULL AND dedup_key = $3`,
			tenantID, assetID, key, string(body), source, seen)
		if err != nil {
			return fmt.Errorf("refresh deferred finding: %w", err)
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO deferred_crypto_findings (tenant_id, asset_id, source_ref, dedup_key, finding, last_seen_at)
				VALUES ($1, $2, $3, $4, $5, COALESCE($6, now()))`, tenantID, assetID, source, key, string(body), seen); err != nil {
				return fmt.Errorf("hold deferred finding: %w", err)
			}
		}
		return capDeferredCrypto(ctx, tx, tenantID, "asset_id", assetID.String())
	})
}

// deferCryptoForObservation holds an observation's finding on the identity
// engine's transaction, keyed by the observation receipt: a transport replay of
// the same receipt is a no-op. observedAt is the receipt's time, stamped into
// the finding so replaying it is not mistaken for a new sighting.
func deferCryptoForObservation(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, observationID, receiptKey, sourceRef string, f IngestFinding, operatorScanJob string, observedAt time.Time) error {
	if !observedAt.IsZero() {
		raw := make(map[string]interface{}, len(f.RawData)+1)
		for k, v := range f.RawData {
			raw[k] = v
		}
		raw["observed_at"] = observedAt.UTC().Format(time.RFC3339Nano)
		f.RawData = raw
	}
	payload, err := operatorScanPayload(f, operatorScanJob)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO deferred_crypto_findings (tenant_id, observation_id, source_ref, dedup_key, finding, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, COALESCE($6, now()))
		ON CONFLICT (tenant_id, observation_id, dedup_key) WHERE observation_id IS NOT NULL DO NOTHING`,
		tenantID, observationID, sourceRef, receiptKey, string(payload), deferredCryptoSeenAt(observedAt)); err != nil {
		return fmt.Errorf("hold observation finding: %w", err)
	}
	return capDeferredCrypto(ctx, tx, tenantID, "observation_id", observationID)
}

// deferredCryptoSeenAt is when the finding was observed, as a nullable
// parameter: NULL (no clock in the finding) reads as now(). The cap orders by
// it, so "newest" means newest OBSERVED — a transport replay of an old receipt
// that the cap already dropped is dropped again, not mistaken for news.
func deferredCryptoSeenAt(t time.Time) sql.NullTime {
	return sql.NullTime{Time: t.UTC(), Valid: !t.IsZero()}
}

// capDeferredCrypto keeps the newest maxDeferredCryptoRows unreplayed rows
// waiting on one asset or one observation and drops the rest.
func capDeferredCrypto(ctx context.Context, tx *sqlx.Tx, tenantID uuid.UUID, column, id string) error {
	res, err := tx.ExecContext(ctx, `DELETE FROM deferred_crypto_findings WHERE id IN (
		SELECT id FROM deferred_crypto_findings
		 WHERE tenant_id = $1 AND `+column+` = $2 AND replayed_at IS NULL
		 ORDER BY last_seen_at DESC, created_at DESC, id DESC OFFSET $3)`, tenantID, id, maxDeferredCryptoRows)
	if err != nil {
		return fmt.Errorf("cap deferred findings: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("Warning: %s %s holds more than %d distinct deferred crypto findings; dropped the %d observed longest ago",
			column, id, maxDeferredCryptoRows, n)
	}
	return nil
}

// deferredCryptoRow is one claimed row.
type deferredCryptoRow struct {
	id            uuid.UUID
	observationID uuid.NullUUID
	seenAt        time.Time
	finding       []byte
}

// replayDeferredCrypto materializes every row waiting on assetID that is
// eligible now, through the same processDiscoveryCryptoData a live ingest of a
// monitoring asset runs, marks them replayed, and publishes the events a live
// ingest would. It returns how many rows it replayed.
//
// Idempotent: a row is claimed (leased) before it is materialized, so two
// callers never replay the same row at once, the crypto upsert deduplicates
// against configurations the asset already has, and a replayed row is never
// selected again. An asset that is not monitoring replays nothing.
func (s *AssetService) replayDeferredCrypto(ctx context.Context, tenantID, assetID uuid.UUID) (int, error) {
	total := 0
	// Bounded: each round claims at most maxDeferredCryptoRows, and an asset
	// holds at most that many asset-gated rows; observation-gated rows are
	// capped per observation, so a few rounds drain any real asset.
	for round := 0; round < 20; round++ {
		var replayed, claimed int
		err := withAssetLifecycleReadLock(ctx, s.db.DB.DB, tenantID, assetID, func() error {
			var err error
			replayed, claimed, err = s.replayDeferredCryptoRound(ctx, tenantID, assetID)
			return err
		})
		total += replayed
		if err != nil {
			return total, err
		}
		if claimed < maxDeferredCryptoRows {
			return total, nil
		}
	}
	return total, nil
}

// replayDeferredCryptoRound claims and replays one batch. The caller holds the
// asset's lifecycle read lock, so the asset cannot be merged, denied or deleted
// underneath it.
func (s *AssetService) replayDeferredCryptoRound(ctx context.Context, tenantID, assetID uuid.UUID) (int, int, error) {
	var rows []deferredCryptoRow
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var monitoring bool
		if err := tx.QueryRowContext(ctx, `SELECT asset_status = 'monitoring' AND deleted_at IS NULL FROM assets WHERE tenant_id = $1 AND id = $2`,
			tenantID, assetID).Scan(&monitoring); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		if !monitoring {
			return nil
		}
		q, err := tx.QueryContext(ctx, `UPDATE deferred_crypto_findings d
			   SET next_attempt_at = now() + $5::interval, attempt_count = d.attempt_count + 1
			 WHERE d.id IN (
			   SELECT w.id FROM deferred_crypto_findings w
			   LEFT JOIN identity_observations o ON o.tenant_id = w.tenant_id AND o.id = w.observation_id
			   WHERE w.tenant_id = $1 AND w.replayed_at IS NULL AND w.next_attempt_at <= now()
			     AND ((w.observation_id IS NULL AND w.asset_id = $2)
			       OR (w.observation_id IS NOT NULL AND o.asset_id = $2 AND o.state = 'linked'
			           AND o.resolution_outcome IS DISTINCT FROM 'supporting'
			           AND (o.resolution_outcome IS DISTINCT FROM $3 OR w.finding ? $4)
			           AND COALESCE((SELECT config->'identity_admission'->>'mode' FROM tenant_admin_settings WHERE tenant_id = $1), 'disabled') <> 'paused'))
			   ORDER BY w.last_seen_at, w.created_at, w.id
			   LIMIT $6
			   FOR UPDATE OF w SKIP LOCKED)
			RETURNING d.id, d.observation_id, d.last_seen_at, d.finding`,
			tenantID, assetID, pgidentity.ResolutionOperatorScanRequest, operatorScanFindingKey,
			deferredCryptoRetryDelay.String(), maxDeferredCryptoRows)
		if err != nil {
			return err
		}
		defer func() { _ = q.Close() }()
		for q.Next() {
			var r deferredCryptoRow
			if err := q.Scan(&r.id, &r.observationID, &r.seenAt, &r.finding); err != nil {
				return err
			}
			rows = append(rows, r)
		}
		return q.Err()
	})
	if err != nil || len(rows) == 0 {
		return 0, len(rows), err
	}
	// RETURNING has no order; replay oldest first, so the newest body of a
	// duplicated finding is the one that lands.
	sort.SliceStable(rows, func(i, j int) bool {
		if !rows[i].seenAt.Equal(rows[j].seenAt) {
			return rows[i].seenAt.Before(rows[j].seenAt)
		}
		return rows[i].id.String() < rows[j].id.String()
	})

	// Collapse duplicates before replaying: several receipts of one
	// observation (or a legacy asset array moved in by the migration) can carry
	// the same posture, and replaying each would repeat the same certificate
	// lookups and the same events. The newest body of each wins.
	type group struct {
		finding     IngestFinding
		ids         []uuid.UUID
		observation bool
	}
	var groups []*group
	byKey := map[string]*group{}
	var unreadable []uuid.UUID
	for _, r := range rows {
		var f IngestFinding
		if err := json.Unmarshal(r.finding, &f); err != nil {
			unreadable = append(unreadable, r.id)
			continue
		}
		key := s.deferredFindingFingerprint(f)
		g, ok := byKey[key]
		if !ok {
			g = &group{}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.finding = f
		g.ids = append(g.ids, r.id)
		g.observation = g.observation || r.observationID.Valid
	}

	var risk []*events.AssetRiskChangedPayload
	var crypto []*events.CryptoConfigurationAddedPayload
	var certs []*events.CertificateExpiringPayload
	var done, failed []uuid.UUID
	var replayErrs []error
	source := ""
	for _, g := range groups {
		f := g.finding
		if f.RawData == nil {
			f.RawData = map[string]interface{}{}
		}
		err := func() error {
			if g.observation {
				// The link attached this evidence (the claim excludes
				// `supporting`), so the finding's socket is the asset's.
				// Attached here explicitly, as the engine's own match would,
				// before the crypto lookup that never creates one.
				if err := s.attachDecidedFindingEndpoint(ctx, tenantID, assetID, f, identity.DecidedByLinkedObservation); err != nil {
					return err
				}
			}
			return s.processDiscoveryCryptoData(tenantID, assetID, f, &risk, &crypto, &certs)
		}()
		if err != nil {
			failed = append(failed, g.ids...)
			replayErrs = append(replayErrs, err)
			continue
		}
		done = append(done, g.ids...)
		// One source per round: the events are about one asset. Held
		// observation evidence keeps the identity sweep's name.
		switch {
		case g.observation:
			source = deferredCryptoReplaySource
		case source == "":
			source = rawDataString(f.RawData, "source")
		}
	}
	if source == "" {
		source = "discovery"
	}

	if err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		if len(done) > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE deferred_crypto_findings SET replayed_at = now(), asset_id = $2, last_error = ''
				WHERE tenant_id = $1 AND id = ANY($3)`, tenantID, assetID, pq.Array(done)); err != nil {
				return err
			}
		}
		if len(failed) > 0 {
			// An operational reason only: the finding itself is never copied
			// into a field something might display.
			if _, err := tx.ExecContext(ctx, `UPDATE deferred_crypto_findings SET last_error = 'materialization failed; retry scheduled'
				WHERE tenant_id = $1 AND id = ANY($2)`, tenantID, pq.Array(failed)); err != nil {
				return err
			}
		}
		if len(unreadable) > 0 {
			// Nothing will ever read it; retrying would only repeat the error.
			if _, err := tx.ExecContext(ctx, `UPDATE deferred_crypto_findings SET replayed_at = now(), asset_id = $2, last_error = 'finding unreadable; not materialized'
				WHERE tenant_id = $1 AND id = ANY($3)`, tenantID, assetID, pq.Array(unreadable)); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return 0, len(rows), fmt.Errorf("record replay of deferred crypto for asset %s: %w", assetID, err)
	}

	if s.eventPublisher != nil {
		for _, p := range risk {
			_ = s.eventPublisher.PublishAssetRiskChanged(ctx, tenantID, p, source)
		}
		for _, p := range crypto {
			_ = s.eventPublisher.PublishCryptoConfigurationAdded(ctx, tenantID, p, source)
		}
		for _, p := range certs {
			_ = s.eventPublisher.PublishCertificateExpiring(ctx, tenantID, p, source)
		}
	}
	if err := errors.Join(replayErrs...); err != nil {
		log.Printf("[AssetService] Warning: %d deferred crypto finding(s) for asset %s did not materialize and will be retried: %v", len(failed), assetID, err)
		return len(done), len(rows), err
	}
	return len(done), len(rows), nil
}

// replayDueDeferredCrypto is the replay's sweep: every monitoring asset of the
// tenant with an unreplayed row whose lease or retry delay has passed is
// replayed. It is what makes the pending -> monitoring transitions that do not
// call replayDeferredCrypto themselves (see the file comment) replay too, and
// what retries a replay that failed.
func (s *AssetService) replayDueDeferredCrypto(ctx context.Context, tenantID uuid.UUID) (int, error) {
	if err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `DELETE FROM deferred_crypto_findings
			WHERE tenant_id = $1 AND observation_id IS NULL AND replayed_at < now() - $2::interval`,
			tenantID, deferredCryptoReplayedRetention.String())
		return err
	}); err != nil {
		return 0, fmt.Errorf("prune replayed deferred crypto: %w", err)
	}
	// A few passes, each over assets not tried yet: a row's asset is read
	// before its lifecycle lock is taken, and a merge or an operator's Link
	// that commits in between moves it to another asset, which the next pass
	// finds rather than the next tick.
	tried := map[uuid.UUID]bool{}
	total := 0
	var errs []error
	for pass := 0; pass < 5; pass++ {
		assets, err := s.deferredCryptoDueAssets(ctx, tenantID)
		if err != nil {
			return total, errors.Join(append(errs, err)...)
		}
		fresh := 0
		for _, asset := range assets {
			if tried[asset] {
				continue
			}
			tried[asset] = true
			fresh++
			if ctx.Err() != nil {
				return total, ctx.Err()
			}
			n, err := s.replayDeferredCrypto(ctx, tenantID, asset)
			total += n
			if err != nil {
				errs = append(errs, fmt.Errorf("asset %s: %w", asset, err))
			}
		}
		if fresh == 0 {
			break
		}
	}
	return total, errors.Join(errs...)
}

// deferredCryptoDueAssets lists monitoring assets with an unreplayed row whose
// lease or retry delay has passed — the row's own asset, or the asset its
// observation is linked to now.
func (s *AssetService) deferredCryptoDueAssets(ctx context.Context, tenantID uuid.UUID) ([]uuid.UUID, error) {
	var assets []uuid.UUID
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		q, err := tx.QueryContext(ctx, `SELECT DISTINCT a.id
			  FROM deferred_crypto_findings d
			  LEFT JOIN identity_observations o ON o.tenant_id = d.tenant_id AND o.id = d.observation_id
			  JOIN assets a ON a.tenant_id = d.tenant_id AND a.id = COALESCE(d.asset_id, o.asset_id)
			 WHERE d.tenant_id = $1 AND d.replayed_at IS NULL AND d.next_attempt_at <= now()
			   AND a.asset_status = 'monitoring' AND a.deleted_at IS NULL
			 LIMIT 100`, tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = q.Close() }()
		for q.Next() {
			var id uuid.UUID
			if err := q.Scan(&id); err != nil {
				return err
			}
			assets = append(assets, id)
		}
		return q.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("find assets with deferred crypto due: %w", err)
	}
	return assets, nil
}
