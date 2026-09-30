package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// A network segment's DHCP posture, and who is allowed to say it.
//
// Identity reads exactly one key of a segment's metadata: `dynamic`
// ([Repository.ScopeForAddress]). A segment marked dynamic stops letting a bare
// address decide which device it is, because on a DHCP network the address
// names whoever holds the lease this hour. That makes the flag load-bearing,
// and it has three very different origins:
//
//   - operator — a person said so on the Network Segments page;
//   - measured — a device that owns the DHCP server answered
//     (device-interrogation reading a controller's network list);
//   - inferred — a sensor watched a DHCP ACK go by on the segment.
//
// Precedence is operator > measured > inferred. A lower source never overrides
// a higher one, and the same source overwrites itself (the newest measurement
// wins). An operator's setting in particular is never overwritten by a
// measurement: the person looking at the network knows things a controller
// does not.
//
// # Storage
//
// The effective answer is stored where identity already looks, as three keys:
//
//	dynamic           bool    the effective value
//	dynamic_source    string  operator | measured | inferred — whose answer it is
//	dynamic_evidence  object  {source_asset_id?, observed_at} for that answer
//
// Beside them, `dynamic_by_source` keeps each source's own latest statement.
// That is what makes "clear the operator's override" mean something: the
// effective value falls back to the best REMAINING source instead of going
// blank until the next interrogation — and a blank is not neutral, it reads as
// static, which is the unsafe direction on a network that hands out leases.
// A measurement that arrives while an operator's setting is in force is
// recorded in its own slot rather than discarded, for the same reason.
//
// Every write is ONE statement, so two services writing at once cannot
// interleave a read and a write: Postgres re-evaluates an UPDATE against the
// newest version of the row it waited on, and the whole recomputation is a
// function of that row.
//
// Rows written before this existed carry `dynamic` alone. They are read the way
// their writer meant them — see [PostureFromMetadata]. (Cloud-derived segments
// carry a default `dynamic: false` nobody chose; it is ignored, not folded.)

// PostureSource is who stated a segment's DHCP posture.
type PostureSource string

const (
	// PostureInferred: a sensor saw a DHCP ACK assign an address on the segment.
	PostureInferred PostureSource = "inferred"
	// PostureMeasured: a device that answers for the network reported it.
	PostureMeasured PostureSource = "measured"
	// PostureOperator: a person set it.
	PostureOperator PostureSource = "operator"
)

// Rank orders sources: higher outranks lower. Unknown sources rank 0.
func (p PostureSource) Rank() int {
	switch p {
	case PostureOperator:
		return 3
	case PostureMeasured:
		return 2
	case PostureInferred:
		return 1
	}
	return 0
}

// Valid reports whether p is one of the three sources.
func (p PostureSource) Valid() bool { return p.Rank() > 0 }

// PostureEvidence is what backs one statement of posture.
type PostureEvidence struct {
	// SourceAssetID is the asset that answered (the controller a measurement
	// came from). Empty for an operator and for traffic inference.
	SourceAssetID string
	// ObservedAt is when the statement was made or observed. Zero means "now".
	ObservedAt time.Time
}

// PostureQuerier is the one method the helper needs. *sql.DB, *sql.Tx and
// *sqlx.Tx all satisfy it, so callers pass the transaction they already hold
// (the tenant-scoped one, when RLS applies).
type PostureQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// PostureResult is the effective posture of a segment after a write.
type PostureResult struct {
	// Written is true when the statement touched the row. False when the
	// segment does not exist for the tenant, or the write was throttled.
	Written bool
	// Dynamic is the effective value; nil when no source has stated one.
	Dynamic *bool
	// Source is whose statement the effective value is; empty when none.
	Source PostureSource
}

// PostureOption tunes a write.
type PostureOption func(*postureOptions)

type postureOptions struct {
	skipIfNewerThan *time.Time
}

// SkipIfSourceStatedSince makes the write a no-op when this source's own
// statement about the segment is newer than cutoff. It is a throttle, applied
// inside the same statement as the write so two racing callers cannot both
// slip through it: traffic inference sees an ACK every few minutes on a busy
// segment and only needs to say so once a day.
func SkipIfSourceStatedSince(cutoff time.Time) PostureOption {
	return func(o *postureOptions) { o.skipIfNewerThan = &cutoff }
}

// postureUpdateSQL is the whole rule. Parameters:
//
//	$1 tenant id        $2 segment id       $3 source
//	$4 dynamic (NULL clears the source's slot)
//	$5 evidence json    $6 throttle cutoff (NULL = none)
//
// Reading it: `base` is the per-source slots of the row as it is NOW — from
// `dynamic_by_source` or, for a row that predates it, folded from the lone
// `dynamic` key; `slots` is base with this source's slot replaced (or removed);
// `eff` picks the highest-ranked slot present; the final object rewrites the
// three effective keys from it. Rank lives in the CASE order of `eff` and
// nowhere else.
//
// The order of `eff`'s WHEN branches is the precedence. Reordering them is the
// bug this file's tests exist to catch.
const postureUpdateSQL = `
UPDATE public.network_segments AS s
SET metadata = (
	SELECT ((a.m - 'dynamic' - 'dynamic_source' - 'dynamic_evidence' - 'dynamic_by_source')
	        || CASE WHEN c.slots = '{}'::jsonb THEN '{}'::jsonb
	                ELSE jsonb_build_object('dynamic_by_source', c.slots) END)
	       || CASE WHEN d.eff IS NULL THEN '{}'::jsonb
	               ELSE jsonb_build_object(
	                      'dynamic', c.slots -> d.eff -> 'dynamic',
	                      'dynamic_source', d.eff,
	                      'dynamic_evidence', coalesce(c.slots -> d.eff -> 'evidence', '{}'::jsonb)) END
	FROM (SELECT coalesce(s.metadata, '{}'::jsonb) AS m) a
	CROSS JOIN LATERAL (SELECT CASE
			WHEN a.m ? 'dynamic_by_source' THEN a.m -> 'dynamic_by_source'
			WHEN jsonb_typeof(a.m -> 'dynamic') = 'boolean'
			     AND coalesce(a.m ->> 'source', '') <> 'cloud_discovery' THEN jsonb_build_object(
				CASE WHEN a.m ->> 'source' IN ('interrogation', 'unifi') THEN 'measured' ELSE 'operator' END,
				jsonb_build_object('dynamic', a.m -> 'dynamic'))
			ELSE '{}'::jsonb END AS base) b
	CROSS JOIN LATERAL (SELECT CASE
			WHEN $4::boolean IS NULL THEN b.base - $3::text
			ELSE b.base || jsonb_build_object($3::text,
				jsonb_build_object('dynamic', $4::boolean, 'evidence', $5::jsonb)) END AS slots) c
	CROSS JOIN LATERAL (SELECT CASE
			WHEN c.slots ? 'operator' THEN 'operator'
			WHEN c.slots ? 'measured' THEN 'measured'
			WHEN c.slots ? 'inferred' THEN 'inferred'
			END AS eff) d
),
    updated_at = now()
WHERE s.tenant_id = $1::uuid AND s.id = $2::uuid
  AND ($6::timestamptz IS NULL
       OR coalesce((s.metadata -> 'dynamic_by_source' -> $3::text -> 'evidence' ->> 'observed_at')::timestamptz,
                   '-infinity'::timestamptz) <= $6::timestamptz)
RETURNING s.metadata ->> 'dynamic_source',
          CASE WHEN jsonb_typeof(s.metadata -> 'dynamic') = 'boolean' THEN (s.metadata ->> 'dynamic')::boolean END`

// RecordSegmentPosture states a segment's DHCP posture on behalf of source.
//
// dynamic is what that source says: true = the network hands out leases.
// The effective value only changes if no HIGHER source has spoken; the
// statement is recorded in the source's own slot regardless, so it is there to
// fall back to.
//
// A segment that does not exist for the tenant is not an error: Written is
// false. Callers that matched a segment moments ago and lost it to a delete
// have nothing to do, and failing the caller's transaction over it would fail
// the observation that only wanted to leave a note.
func RecordSegmentPosture(ctx context.Context, q PostureQuerier, tenantID, segmentID string,
	source PostureSource, dynamic bool, ev PostureEvidence, opts ...PostureOption) (PostureResult, error) {
	if !source.Valid() {
		return PostureResult{}, fmt.Errorf("identity/postgres: unknown posture source %q", source)
	}
	return runPostureUpdate(ctx, q, tenantID, segmentID, source, &dynamic, ev, opts)
}

// ClearSegmentPosture withdraws one source's statement. It is how an operator
// hands a segment back to automatic: the effective value becomes the best
// remaining source's, or unset when there is none.
func ClearSegmentPosture(ctx context.Context, q PostureQuerier, tenantID, segmentID string, source PostureSource) (PostureResult, error) {
	if !source.Valid() {
		return PostureResult{}, fmt.Errorf("identity/postgres: unknown posture source %q", source)
	}
	return runPostureUpdate(ctx, q, tenantID, segmentID, source, nil, PostureEvidence{}, nil)
}

func runPostureUpdate(ctx context.Context, q PostureQuerier, tenantID, segmentID string,
	source PostureSource, dynamic *bool, ev PostureEvidence, opts []PostureOption) (PostureResult, error) {
	var o postureOptions
	for _, opt := range opts {
		opt(&o)
	}
	var evidence any // NULL when clearing
	if dynamic != nil {
		at := ev.ObservedAt
		if at.IsZero() {
			at = time.Now()
		}
		m := map[string]any{"observed_at": at.UTC().Format(time.RFC3339Nano)}
		if id := strings.TrimSpace(ev.SourceAssetID); id != "" {
			m["source_asset_id"] = id
		}
		b, err := json.Marshal(m)
		if err != nil {
			return PostureResult{}, err
		}
		evidence = string(b)
	}
	var cutoff any
	if o.skipIfNewerThan != nil {
		cutoff = o.skipIfNewerThan.UTC()
	}
	var dyn any
	if dynamic != nil {
		dyn = *dynamic
	}

	var src sql.NullString
	var eff sql.NullBool
	err := q.QueryRowContext(ctx, postureUpdateSQL, tenantID, segmentID, string(source), dyn, evidence, cutoff).Scan(&src, &eff)
	if errors.Is(err, sql.ErrNoRows) {
		return PostureResult{}, nil
	}
	if err != nil {
		return PostureResult{}, fmt.Errorf("identity/postgres: record segment posture: %w", err)
	}
	res := PostureResult{Written: true, Source: PostureSource(src.String)}
	if eff.Valid {
		v := eff.Bool
		res.Dynamic = &v
	}
	return res, nil
}

// PostureFromMetadata reads the effective posture off a segment's metadata, for
// display. It is the Go twin of the legacy fold in [postureUpdateSQL], and the
// integration test pins the two together.
//
// A row written before `dynamic_source` existed states `dynamic` alone. Who
// said it is recoverable from `metadata.source`: a row device-interrogation
// created (`interrogation`, or `unifi` before every vendor could produce one)
// holds that device's measurement; any other row is an operator's — the only
// way to put `dynamic` on one was to type it. Reading a legacy operator flag as
// a measurement would let the next interrogation overwrite it.
//
// Returns (nil, "") when nothing has been stated.
func PostureFromMetadata(meta map[string]any) (dynamic *bool, source PostureSource) {
	if meta == nil {
		return nil, ""
	}
	v, hasBool := meta["dynamic"].(bool)
	if s, ok := meta["dynamic_source"].(string); ok && PostureSource(s).Valid() {
		if hasBool {
			return &v, PostureSource(s)
		}
		return nil, PostureSource(s)
	}
	if !hasBool {
		return nil, ""
	}
	switch src, _ := meta["source"].(string); src {
	case "interrogation", "unifi":
		return &v, PostureMeasured
	case "cloud_discovery":
		// A cloud run writes `dynamic: false` on every segment it derives, so
		// the row states its own default. Nobody measured or decided that: it
		// is silence written down, and reading it as an operator's answer
		// would both mislabel it and stop a controller's measurement of the
		// same network from ever landing.
		return nil, ""
	}
	return &v, PostureOperator
}

// PostureEvidenceAssetID returns the asset a segment's effective posture was
// measured from, or "". It prefers the evidence recorded with the posture and
// falls back to `source_asset_id` — the key device-interrogation has always
// stamped on a segment it learned — for a measured row that predates evidence.
func PostureEvidenceAssetID(meta map[string]any, source PostureSource) string {
	if ev, ok := meta["dynamic_evidence"].(map[string]any); ok {
		if id, _ := ev["source_asset_id"].(string); id != "" {
			return id
		}
	}
	if source == PostureMeasured {
		if id, _ := meta["source_asset_id"].(string); id != "" {
			return id
		}
	}
	return ""
}
