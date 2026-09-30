package postgres_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	pgrepo "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The helper is the ONE place a segment's DHCP posture is decided, so these
// tests drive it against a real row and read the row back — they assert what
// ScopeForAddress will see, not what the helper says it did.

func TestIntegration_SegmentPosture_EffectiveValueAndFallback(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	newSegment := func(cidr, metadata string) (string, func() map[string]any) {
		var id string
		if err := db.QueryRow(`INSERT INTO network_segments(tenant_id,name,segment_type,value,network_type,environment,is_active,metadata)
			VALUES($1,$2,'cidr',$2,'private','production',true,$3::jsonb) RETURNING id::text`, tenant, cidr, metadata).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id, func() map[string]any {
			var raw []byte
			if err := db.QueryRow(`SELECT metadata FROM network_segments WHERE id = $1`, id).Scan(&raw); err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			return m
		}
	}
	at := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

	t.Run("clearing the operator falls back to the best remaining source", func(t *testing.T) {
		id, read := newSegment("192.0.2.0/24", `{"keep":"me"}`)
		mustRecord(t, db, tenant, id, pgrepo.PostureMeasured, true, pgrepo.PostureEvidence{SourceAssetID: "asset-1", ObservedAt: at})
		mustRecord(t, db, tenant, id, pgrepo.PostureOperator, false, pgrepo.PostureEvidence{})
		m := read()
		if m["dynamic"] != false || m["dynamic_source"] != "operator" {
			t.Fatalf("operator false over measured true: %v", m)
		}
		// A measurement while the operator's answer is in force is recorded, not
		// applied and not lost.
		mustRecord(t, db, tenant, id, pgrepo.PostureMeasured, true, pgrepo.PostureEvidence{SourceAssetID: "asset-2", ObservedAt: at.Add(time.Hour)})
		if m := read(); m["dynamic"] != false || m["dynamic_source"] != "operator" {
			t.Fatalf("a measurement overwrote the operator: %v", m)
		}
		res, err := pgrepo.ClearSegmentPosture(ctx, db, tenant.String(), id, pgrepo.PostureOperator)
		if err != nil || !res.Written {
			t.Fatalf("clear: %+v %v", res, err)
		}
		m = read()
		if m["dynamic"] != true || m["dynamic_source"] != "measured" {
			t.Fatalf("after clearing the operator the effective value must be the measurement (the NEWEST one): %v", m)
		}
		if ev, _ := m["dynamic_evidence"].(map[string]any); ev["source_asset_id"] != "asset-2" {
			t.Fatalf("evidence = %v, want the newest measurement's", m["dynamic_evidence"])
		}
		if m["keep"] != "me" {
			t.Fatalf("unrelated metadata lost: %v", m)
		}
	})

	t.Run("clearing the only source leaves the value unset", func(t *testing.T) {
		id, read := newSegment("192.0.2.64/26", `{}`)
		mustRecord(t, db, tenant, id, pgrepo.PostureOperator, true, pgrepo.PostureEvidence{})
		if _, err := pgrepo.ClearSegmentPosture(ctx, db, tenant.String(), id, pgrepo.PostureOperator); err != nil {
			t.Fatal(err)
		}
		m := read()
		for _, k := range []string{"dynamic", "dynamic_source", "dynamic_evidence", "dynamic_by_source"} {
			if _, has := m[k]; has {
				t.Fatalf("%s left behind after the last source was withdrawn: %v", k, m)
			}
		}
	})

	t.Run("a row written before dynamic_source is read the way its writer meant it", func(t *testing.T) {
		// An operator's flag typed into metadata: an operator's, so a measurement
		// must not overwrite it.
		id, read := newSegment("198.51.100.0/24", `{"dynamic":true}`)
		mustRecord(t, db, tenant, id, pgrepo.PostureMeasured, false, pgrepo.PostureEvidence{})
		if m := read(); m["dynamic"] != true || m["dynamic_source"] != "operator" {
			t.Fatalf("a measurement overwrote a legacy operator flag: %v", m)
		}
		// A flag on a row interrogation created is a measurement: the next one replaces it.
		id2, read2 := newSegment("198.51.100.128/25", `{"source":"interrogation","dhcp":"enabled","dynamic":true}`)
		mustRecord(t, db, tenant, id2, pgrepo.PostureMeasured, false, pgrepo.PostureEvidence{})
		if m := read2(); m["dynamic"] != false || m["dynamic_source"] != "measured" {
			t.Fatalf("a legacy measurement was not replaced by the next one: %v", m)
		}
		// ...but an inferred statement does not outrank it.
		id3, read3 := newSegment("203.0.113.0/24", `{"source":"unifi","dynamic":false}`)
		mustRecord(t, db, tenant, id3, pgrepo.PostureInferred, true, pgrepo.PostureEvidence{})
		if m := read3(); m["dynamic"] != false || m["dynamic_source"] != "measured" {
			t.Fatalf("traffic inference overwrote a legacy measurement: %v", m)
		}
	})

	t.Run("the Go reader agrees with the SQL about legacy rows", func(t *testing.T) {
		for _, c := range []struct {
			meta    string
			wantDyn *bool
			want    pgrepo.PostureSource
		}{
			{`{"dynamic":true}`, ptr(true), pgrepo.PostureOperator},
			{`{"source":"interrogation","dynamic":false}`, ptr(false), pgrepo.PostureMeasured},
			{`{"source":"unifi","dynamic":true}`, ptr(true), pgrepo.PostureMeasured},
			{`{"source":"cloud_discovery","dynamic":false}`, nil, ""},
			{`{"dhcp":"unknown"}`, nil, ""},
			{`{}`, nil, ""},
		} {
			id, read := newSegment(uuid.NewString(), c.meta)
			var m map[string]any
			if err := json.Unmarshal([]byte(c.meta), &m); err != nil {
				t.Fatal(err)
			}
			gotDyn, gotSrc := pgrepo.PostureFromMetadata(m)
			if gotSrc != c.want || (gotDyn == nil) != (c.wantDyn == nil) || (gotDyn != nil && *gotDyn != *c.wantDyn) {
				t.Errorf("PostureFromMetadata(%s) = %v %q, want %v %q", c.meta, gotDyn, gotSrc, c.wantDyn, c.want)
			}
			// The SQL's fold: a same-rank write on top must leave the OTHER
			// source's slot exactly as the Go reader would have called it.
			mustRecord(t, db, tenant, id, pgrepo.PostureInferred, true, pgrepo.PostureEvidence{})
			after := read()
			wantEff := c.want
			if wantEff == "" {
				wantEff = pgrepo.PostureInferred
			}
			if after["dynamic_source"] != string(wantEff) {
				t.Errorf("SQL folded %s to effective source %v, Go reader said %q", c.meta, after["dynamic_source"], c.want)
			}
		}
	})

	t.Run("the throttle skips a source that spoke recently and only that source", func(t *testing.T) {
		id, read := newSegment("192.0.2.128/25", `{}`)
		now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
		res, err := pgrepo.RecordSegmentPosture(ctx, db, tenant.String(), id, pgrepo.PostureInferred, true,
			pgrepo.PostureEvidence{ObservedAt: now}, pgrepo.SkipIfSourceStatedSince(now.Add(-24*time.Hour)))
		if err != nil || !res.Written {
			t.Fatalf("first inference not written: %+v %v", res, err)
		}
		// Twelve hours later: inside the 24h window, so nothing is written.
		res, err = pgrepo.RecordSegmentPosture(ctx, db, tenant.String(), id, pgrepo.PostureInferred, true,
			pgrepo.PostureEvidence{ObservedAt: now.Add(12 * time.Hour)}, pgrepo.SkipIfSourceStatedSince(now.Add(12*time.Hour-24*time.Hour)))
		if err != nil || res.Written {
			t.Fatalf("inference inside the window was written: %+v %v", res, err)
		}
		if ev, _ := read()["dynamic_evidence"].(map[string]any); ev["observed_at"] != now.Format(time.RFC3339Nano) {
			t.Fatalf("throttled write changed the evidence: %v", ev)
		}
		// A day and an hour later it goes through.
		res, err = pgrepo.RecordSegmentPosture(ctx, db, tenant.String(), id, pgrepo.PostureInferred, true,
			pgrepo.PostureEvidence{ObservedAt: now.Add(25 * time.Hour)}, pgrepo.SkipIfSourceStatedSince(now.Add(time.Hour)))
		if err != nil || !res.Written {
			t.Fatalf("inference outside the window was throttled: %+v %v", res, err)
		}
		// Another source is never throttled by this one's slot.
		res, err = pgrepo.RecordSegmentPosture(ctx, db, tenant.String(), id, pgrepo.PostureMeasured, false,
			pgrepo.PostureEvidence{ObservedAt: now.Add(25 * time.Hour)}, pgrepo.SkipIfSourceStatedSince(now.Add(time.Hour)))
		if err != nil || !res.Written {
			t.Fatalf("measured was throttled by the inferred slot: %+v %v", res, err)
		}
	})

	t.Run("a segment that is not the tenant's is not touched", func(t *testing.T) {
		id, read := newSegment("192.0.2.192/26", `{}`)
		other := testdb.NewTenant(t, db)
		res, err := pgrepo.RecordSegmentPosture(ctx, db, other.String(), id, pgrepo.PostureOperator, true, pgrepo.PostureEvidence{})
		if err != nil || res.Written {
			t.Fatalf("wrote another tenant's segment: %+v %v", res, err)
		}
		if _, has := read()["dynamic"]; has {
			t.Fatal("cross-tenant write landed")
		}
	})

	t.Run("an unknown source is refused before it reaches SQL", func(t *testing.T) {
		id, _ := newSegment("192.0.2.240/28", `{}`)
		if _, err := pgrepo.RecordSegmentPosture(ctx, db, tenant.String(), id, pgrepo.PostureSource("admin"), true, pgrepo.PostureEvidence{}); err == nil {
			t.Fatal("an unknown source was accepted")
		}
	})
}

func ptr(b bool) *bool { return &b }

func mustRecord(t *testing.T, q pgrepo.PostureQuerier, tenant uuid.UUID, id string, src pgrepo.PostureSource, dyn bool, ev pgrepo.PostureEvidence) {
	t.Helper()
	if _, err := pgrepo.RecordSegmentPosture(context.Background(), q, tenant.String(), id, src, dyn, ev); err != nil {
		t.Fatal(err)
	}
}
