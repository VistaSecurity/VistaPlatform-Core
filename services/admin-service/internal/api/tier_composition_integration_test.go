package api

// Plans & Pricing composition writes, through the REAL router against a real
// Postgres (admin-UI data review RC-11).
//
// The bug: a matrix cell edit sent a bulk PUT built from the react-query cache
// and the server deleted every row the body did not carry, so an empty or
// stale cache erased a tier's composition and its capacity caps fell back to
// the catalogue default of 0. The plan builder's save was two PUTs, so a
// rejected composition left the price change applied.
//
// What this file pins, each against the production wiring (route, permission
// middleware, crypto_app pool, tier row lock, history, platform audit):
//
//   - the single-item cell edit touches exactly one row;
//   - the multi-item write never deletes by omission, needs the version GET
//     returned (428 without, 409 when stale) and writes nothing when refused;
//   - a concurrent writer holding the tier lock makes a write computed from the
//     pre-commit version wait and then fail 409 — or succeed once it rolls back;
//   - PUT /tiers/:id applies identity and composition atomically: any refusal
//     leaves both unchanged and records no history;
//   - every change leaves a subscription_tier_history row naming the actor and
//     a platform audit event.
//
// Scratch database per test (schema + seed applied fresh), so the seeded tiers
// can be rewritten freely. Needs TEST_DATABASE_URL and CREATEDB; skips
// otherwise. `make test-integration-db` runs it.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type tierCompFixture struct {
	t      *testing.T
	owner  *sql.DB
	srv    *Server
	admin  uuid.UUID // platform_admin: holds platform.settings
	agent  uuid.UUID // support_agent: does not
	tier   uuid.UUID // the seeded "pro" tier
	audits chan map[string]interface{}
}

func newTierCompFixture(t *testing.T) *tierCompFixture {
	t.Helper()
	owner := testdb.ScratchDatabase(t)
	app := testdb.ConnectScratchAsAppRole(t, owner)
	bypass := testdb.ConnectScratchAsBypassRole(t, owner)
	f := &tierCompFixture{t: t, owner: owner}
	f.admin = f.platformUser("platform_admin")
	f.agent = f.platformUser("support_agent")
	if err := owner.QueryRow(`SELECT id FROM subscription_tiers WHERE name = 'pro'`).Scan(&f.tier); err != nil {
		t.Fatalf("seeded pro tier: %v", err)
	}

	// Capture platform audit events: NewServerWithConnections wires the
	// emitter from the environment.
	f.audits = make(chan map[string]interface{}, 64)
	auditSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		select {
		case f.audits <- body:
		default:
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + uuid.NewString() + `"}`))
	}))
	t.Cleanup(auditSrv.Close)
	t.Setenv("AUDIT_SERVICE_URL", auditSrv.URL)
	t.Setenv("AUDIT_LOGGING_ENABLED", "true")

	f.srv = NewServerWithConnections(
		&config.Config{Environment: "test", JWTSecret: roleAssignJWTSecret},
		app, bypass, EditionHooks{},
	)
	return f
}

func (f *tierCompFixture) platformUser(role string) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.owner.QueryRow(`
		INSERT INTO platform_users (email, password_hash, first_name, last_name, role_id, is_active)
		SELECT $1, 'not-a-real-hash', 'Tier', 'Test', id, true FROM platform_roles WHERE name = $2
		RETURNING id`, role+"-"+uuid.NewString()[:8]+"@tier.example.test", role).Scan(&id); err != nil {
		f.t.Fatalf("create %s user: %v", role, err)
	}
	return id
}

func (f *tierCompFixture) request(caller uuid.UUID, method, path, body string) *http.Request {
	f.t.Helper()
	claims := models.JWTClaims{
		UserID: caller, Email: "operator@example.test", Role: "platform_admin", Type: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(roleAssignJWTSecret))
	if err != nil {
		f.t.Fatalf("sign: %v", err)
	}
	req := httptest.NewRequest(method, "/api/v1/admin-service/admin"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// do sends a request as caller and returns the status and decoded body.
func (f *tierCompFixture) do(caller uuid.UUID, method, path, body string) (int, map[string]interface{}) {
	f.t.Helper()
	w := httptest.NewRecorder()
	f.srv.Router().ServeHTTP(w, f.request(caller, method, path, body))
	var out map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (f *tierCompFixture) expect(what string, gotCode int, body map[string]interface{}, want int) {
	f.t.Helper()
	if gotCode != want {
		f.t.Fatalf("%s: status %d, want %d; body %v", what, gotCode, want, body)
	}
}

// composition is the tier's rows as key → included_value text, read directly
// (owner connection), plus the version the API reports.
func (f *tierCompFixture) composition(tier uuid.UUID) (map[string]string, string) {
	f.t.Helper()
	rows, err := f.owner.Query(`
		SELECT bi.key, te.included_value::text FROM tier_entitlements te
		JOIN billable_items bi ON bi.id = te.item_id WHERE te.tier_id = $1`, tier)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			f.t.Fatal(err)
		}
		out[k] = v
	}
	code, body := f.do(f.admin, http.MethodGet, "/tiers/"+tier.String()+"/entitlements", "")
	f.expect("GET entitlements", code, body, http.StatusOK)
	version, _ := body["version"].(string)
	if version == "" {
		f.t.Fatalf("GET entitlements carried no version: %v", body)
	}
	return out, version
}

func (f *tierCompFixture) historyRows(tier uuid.UUID) int {
	f.t.Helper()
	var n int
	if err := f.owner.QueryRow(`SELECT COUNT(*) FROM subscription_tier_history WHERE tier_id = $1`, tier).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

// lastHistory is the newest actor-attributed history row (the table trigger
// also writes an unattributed row for every subscription_tiers UPDATE).
func (f *tierCompFixture) lastHistory(tier uuid.UUID) (changedBy uuid.NullUUID, changes map[string]json.RawMessage) {
	f.t.Helper()
	var raw []byte
	if err := f.owner.QueryRow(`
		SELECT changed_by, changes_json FROM subscription_tier_history
		WHERE tier_id = $1 AND notes IS NOT NULL
		ORDER BY changed_at DESC LIMIT 1`, tier).Scan(&changedBy, &raw); err != nil {
		f.t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &changes); err != nil {
		f.t.Fatalf("decode changes_json %s: %v", raw, err)
	}
	return changedBy, changes
}

// awaitAudit waits for the audit event of the given type (the emitter posts
// asynchronously) and returns it.
func (f *tierCompFixture) awaitAudit(eventType string) map[string]interface{} {
	f.t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-f.audits:
			if ev["event_type"] == eventType {
				return ev
			}
		case <-deadline:
			f.t.Fatalf("no %q platform audit event was recorded", eventType)
			return nil
		}
	}
}

func (f *tierCompFixture) drainAudits() {
	for {
		select {
		case <-f.audits:
		case <-time.After(300 * time.Millisecond):
			return
		}
	}
}

func (f *tierCompFixture) tierColumns(tier uuid.UUID) (displayName string, price int) {
	f.t.Helper()
	if err := f.owner.QueryRow(`SELECT display_name, price_cents FROM subscription_tiers WHERE id = $1`, tier).
		Scan(&displayName, &price); err != nil {
		f.t.Fatal(err)
	}
	return displayName, price
}

func TestIntegration_TierComposition_CellEdit(t *testing.T) {
	f := newTierCompFixture(t)
	base := "/tiers/" + f.tier.String() + "/entitlements"
	before, v0 := f.composition(f.tier)
	if len(before) < 5 {
		t.Fatalf("premise: seeded pro tier composes %d items; the test needs several", len(before))
	}
	hist := f.historyRows(f.tier)

	t.Run("sets one item and leaves every other row alone", func(t *testing.T) {
		code, body := f.do(f.admin, http.MethodPut, base+"/max_sensors", `{"included_value":{"quantity":40}}`)
		f.expect("cell edit", code, body, http.StatusOK)
		after, v1 := f.composition(f.tier)
		if len(after) != len(before) {
			t.Fatalf("a cell edit changed the row count %d → %d", len(before), len(after))
		}
		for k, v := range before {
			if k != "max_sensors" && after[k] != v {
				t.Errorf("cell edit of max_sensors also changed %s: %s → %s", k, v, after[k])
			}
		}
		if after["max_sensors"] != `{"quantity": 40}` {
			t.Errorf("max_sensors = %s, want quantity 40", after["max_sensors"])
		}
		if v1 == v0 || body["version"] != v1 {
			t.Errorf("version: before %s, response %v, after %s — want a new version echoed", v0, body["version"], v1)
		}
		if got := f.historyRows(f.tier); got != hist+1 {
			t.Errorf("history rows %d → %d, want one more", hist, got)
		}
		by, changes := f.lastHistory(f.tier)
		if !by.Valid || by.UUID != f.admin {
			t.Errorf("history changed_by = %v, want the acting admin %s", by, f.admin)
		}
		var diff []struct {
			ItemKey string `json:"item_key"`
			Before  *struct {
				IncludedValue json.RawMessage `json:"included_value"`
			} `json:"before"`
			After *struct {
				IncludedValue json.RawMessage `json:"included_value"`
			} `json:"after"`
		}
		if err := json.Unmarshal(changes["entitlements"], &diff); err != nil || len(diff) != 1 ||
			diff[0].ItemKey != "max_sensors" || diff[0].Before == nil || diff[0].After == nil ||
			!strings.Contains(string(diff[0].After.IncludedValue), "40") {
			t.Errorf("history does not carry exactly the max_sensors before/after: %s", changes["entitlements"])
		}
		ev := f.awaitAudit("subscription_tier.entitlement_set")
		if ev["resource_id"] != f.tier.String() || ev["user_id"] != f.admin.String() {
			t.Errorf("audit event names the wrong tier/actor: %v", ev)
		}
	})

	t.Run("an identical edit is a no-op: no history, no audit", func(t *testing.T) {
		f.drainAudits()
		h := f.historyRows(f.tier)
		code, body := f.do(f.admin, http.MethodPut, base+"/max_sensors", `{"included_value":{"quantity":40}}`)
		f.expect("identical cell edit", code, body, http.StatusOK)
		if got := f.historyRows(f.tier); got != h {
			t.Errorf("an identical edit wrote %d history rows", got-h)
		}
		select {
		case ev := <-f.audits:
			t.Errorf("an identical edit was audited: %v", ev)
		case <-time.After(500 * time.Millisecond):
		}
	})

	t.Run("refuses an inactive item, writing nothing", func(t *testing.T) {
		if _, err := f.owner.Exec(`UPDATE billable_items SET is_active = false WHERE key = 'max_users'`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = f.owner.Exec(`UPDATE billable_items SET is_active = true WHERE key = 'max_users'`) })
		_, vBefore := f.composition(f.tier)
		code, body := f.do(f.admin, http.MethodPut, base+"/max_users", `{"included_value":{"quantity":1}}`)
		f.expect("cell edit of an inactive item", code, body, http.StatusBadRequest)
		if body["item_key"] != "max_users" {
			t.Errorf("400 does not name the item: %v", body)
		}
		if _, vAfter := f.composition(f.tier); vAfter != vBefore {
			t.Error("a refused cell edit changed the composition")
		}
	})

	t.Run("a malformed value is a 400 naming the shape", func(t *testing.T) {
		code, body := f.do(f.admin, http.MethodPut, base+"/max_sensors", `{"included_value":{}}`)
		f.expect("empty value", code, body, http.StatusBadRequest)
		if d, _ := body["detail"].(string); !strings.Contains(d, "quantity") {
			t.Errorf("400 detail does not describe the expected shape: %v", body)
		}
	})

	t.Run("unknown tier is 404", func(t *testing.T) {
		code, body := f.do(f.admin, http.MethodPut, "/tiers/"+uuid.NewString()+"/entitlements/max_sensors", `{"included_value":{"quantity":1}}`)
		f.expect("unknown tier", code, body, http.StatusNotFound)
	})

	t.Run("needs platform.settings", func(t *testing.T) {
		code, body := f.do(f.agent, http.MethodPut, base+"/max_sensors", `{"included_value":{"quantity":2}}`)
		f.expect("support_agent cell edit", code, body, http.StatusForbidden)
	})
}

func TestIntegration_TierComposition_MultiItemWrite(t *testing.T) {
	f := newTierCompFixture(t)
	base := "/tiers/" + f.tier.String() + "/entitlements"
	put := func(body string) (int, map[string]interface{}) {
		return f.do(f.admin, http.MethodPut, base, body)
	}

	t.Run("no version: 428, nothing written", func(t *testing.T) {
		before, v := f.composition(f.tier)
		// The exact shape the old matrix sent from an EMPTY cache — which used
		// to erase the tier — and a one-item body from a partial one.
		for _, body := range []string{`{"entitlements":[]}`, `{"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":1}}]}`} {
			code, resp := put(body)
			f.expect("versionless multi-item write "+body, code, resp, http.StatusPreconditionRequired)
		}
		after, v2 := f.composition(f.tier)
		if v2 != v || len(after) != len(before) {
			t.Fatal("a versionless write changed the composition")
		}
	})

	t.Run("current version: upserts what it names, removes what it lists, keeps the rest", func(t *testing.T) {
		before, v := f.composition(f.tier)
		code, resp := put(`{"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":12}}],"remove":["storage_gb"],"version":"` + v + `"}`)
		f.expect("multi-item write", code, resp, http.StatusOK)
		after, _ := f.composition(f.tier)
		if len(after) != len(before)-1 {
			t.Fatalf("rows %d → %d, want exactly one removed", len(before), len(after))
		}
		if _, still := after["storage_gb"]; still {
			t.Error("storage_gb was listed for removal but is still composed")
		}
		for k, val := range before {
			if k != "max_sensors" && k != "storage_gb" && after[k] != val {
				t.Errorf("%s changed although the write did not name it: %s → %s", k, val, after[k])
			}
		}
		ev := f.awaitAudit("subscription_tier.entitlements_updated")
		if fields, _ := ev["changed_fields"].([]interface{}); len(fields) != 2 {
			t.Errorf("audit changed_fields = %v, want the two changed items", ev["changed_fields"])
		}
	})

	t.Run("stale version: 409 naming the current one, nothing written", func(t *testing.T) {
		_, stale := f.composition(f.tier)
		code, body := f.do(f.admin, http.MethodPut, base+"/max_assets", `{"included_value":{"quantity":77}}`)
		f.expect("someone else's cell edit", code, body, http.StatusOK)
		before, current := f.composition(f.tier)

		code, resp := put(`{"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":13}}],"version":"` + stale + `"}`)
		f.expect("write from a stale read", code, resp, http.StatusConflict)
		if resp["current_version"] != current {
			t.Errorf("409 current_version = %v, want %s", resp["current_version"], current)
		}
		after, v := f.composition(f.tier)
		if v != current || after["max_sensors"] != before["max_sensors"] {
			t.Error("the refused write changed the composition")
		}
	})
}

// raceComposition holds the tier lock in an open transaction that also
// changes max_users (what a concurrent composition writer does), sends a
// multi-item write computed from the version BEFORE that change, proves the
// request is waiting on the lock, then ends the transaction with finish.
func (f *tierCompFixture) raceComposition(t *testing.T, finish func(*sql.Tx) error) (int, map[string]interface{}) {
	t.Helper()
	_, readVersion := f.composition(f.tier)

	tx, err := f.owner.Begin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err := tx.Exec(`SELECT 1 FROM subscription_tiers WHERE id = $1 FOR UPDATE`, f.tier); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`
		UPDATE tier_entitlements SET included_value = '{"quantity": 4242}'
		WHERE tier_id = $1 AND item_id = (SELECT id FROM billable_items WHERE key = 'max_users')`, f.tier); err != nil {
		t.Fatal(err)
	}

	type result struct {
		code int
		body map[string]interface{}
	}
	done := make(chan result, 1)
	req := f.request(f.admin, http.MethodPut, "/tiers/"+f.tier.String()+"/entitlements",
		`{"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":21}}],"version":"`+readVersion+`"}`)
	go func() {
		w := httptest.NewRecorder()
		f.srv.Router().ServeHTTP(w, req)
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		done <- result{w.Code, body}
	}()

	select {
	case r := <-done:
		t.Fatalf("the write did not wait for the concurrent composition writer (status %d, body %v) — "+
			"the version check is not serialised by the tier lock", r.code, r.body)
	case <-time.After(750 * time.Millisecond):
	}
	if err := finish(tx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		return r.code, r.body
	case <-time.After(10 * time.Second):
		t.Fatal("the write never completed after the concurrent transaction ended")
		return 0, nil
	}
}

func TestIntegration_TierComposition_ConcurrentEdit(t *testing.T) {
	f := newTierCompFixture(t)

	t.Run("concurrent writer commits: 409", func(t *testing.T) {
		code, body := f.raceComposition(t, (*sql.Tx).Commit)
		f.expect("write racing a committed composition change", code, body, http.StatusConflict)
		after, _ := f.composition(f.tier)
		if after["max_users"] != `{"quantity": 4242}` {
			t.Errorf("the concurrent writer's change was lost: max_users = %s", after["max_users"])
		}
		if after["max_sensors"] == `{"quantity": 21}` {
			t.Error("the stale write was applied")
		}
	})

	t.Run("concurrent writer rolls back: 200", func(t *testing.T) {
		code, body := f.raceComposition(t, (*sql.Tx).Rollback)
		f.expect("write after the concurrent change rolled back", code, body, http.StatusOK)
		after, _ := f.composition(f.tier)
		if after["max_sensors"] != `{"quantity": 21}` {
			t.Errorf("the permitted write was not applied: max_sensors = %s", after["max_sensors"])
		}
	})
}

func TestIntegration_TierComposition_UpdateTierAtomic(t *testing.T) {
	f := newTierCompFixture(t)
	path := "/tiers/" + f.tier.String()

	// Every refusal must leave identity, price, composition and history exactly
	// as they were — the plan builder used to commit the price first.
	// Each of these is refused AFTER the column UPDATE has run inside the
	// transaction, so "nothing changed" proves the rollback, not merely early
	// validation. `why` pins the refusal reason: a 400 for some OTHER cause
	// (a broken UPDATE, a bind failure) would otherwise pass as the one meant.
	refusals := []struct {
		name string
		body func(version string) string
		want int
		why  func(body map[string]interface{}) bool
	}{
		{"malformed value after a valid one", func(v string) string {
			return `{"display_name":"Renamed","price_cents":1,"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":3}},{"item_key":"max_assets","included_value":{}}],"entitlements_version":"` + v + `"}`
		}, http.StatusBadRequest, func(b map[string]interface{}) bool {
			d, _ := b["detail"].(string)
			return strings.Contains(d, "max_assets")
		}},
		{"unknown item", func(v string) string {
			return `{"display_name":"Renamed","price_cents":1,"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":3}},{"item_key":"no_such_lever","included_value":{"enabled":true}}],"entitlements_version":"` + v + `"}`
		}, http.StatusBadRequest, func(b map[string]interface{}) bool { return b["item_key"] == "no_such_lever" }},
		{"stale version", func(string) string {
			return `{"display_name":"Renamed","price_cents":1,"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":3}}],"entitlements_version":"not-the-current-version"}`
		}, http.StatusConflict, func(b map[string]interface{}) bool { return b["current_version"] != nil }},
		{"no version", func(string) string {
			return `{"display_name":"Renamed","price_cents":1,"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":3}}]}`
		}, http.StatusPreconditionRequired, func(b map[string]interface{}) bool {
			e, _ := b["error"].(string)
			return strings.Contains(e, "version")
		}},
	}
	for _, tc := range refusals {
		t.Run("refused ("+tc.name+"): nothing changes", func(t *testing.T) {
			name, price := f.tierColumns(f.tier)
			comp, v := f.composition(f.tier)
			hist := f.historyRows(f.tier)

			code, body := f.do(f.admin, http.MethodPut, path, tc.body(v))
			f.expect(tc.name, code, body, tc.want)
			if !tc.why(body) {
				t.Fatalf("%s: refused for the wrong reason: %v", tc.name, body)
			}

			if n, p := f.tierColumns(f.tier); n != name || p != price {
				t.Errorf("identity/price changed by a refused update: %q/%d → %q/%d", name, price, n, p)
			}
			after, v2 := f.composition(f.tier)
			if v2 != v || after["max_sensors"] != comp["max_sensors"] {
				t.Error("composition changed by a refused update")
			}
			if got := f.historyRows(f.tier); got != hist {
				t.Errorf("a refused update wrote %d history rows", got-hist)
			}
		})
	}

	t.Run("identity and composition commit together", func(t *testing.T) {
		f.drainAudits()
		_, v := f.composition(f.tier)
		code, body := f.do(f.admin, http.MethodPut, path,
			`{"display_name":"Pro Plus","price_cents":12345,"entitlements":[{"item_key":"max_sensors","included_value":{"quantity":55}}],"entitlements_version":"`+v+`"}`)
		f.expect("plan builder save", code, body, http.StatusOK)
		if n, p := f.tierColumns(f.tier); n != "Pro Plus" || p != 12345 {
			t.Errorf("identity/price = %q/%d, want Pro Plus/12345", n, p)
		}
		after, _ := f.composition(f.tier)
		if after["max_sensors"] != `{"quantity": 55}` {
			t.Errorf("max_sensors = %s, want quantity 55", after["max_sensors"])
		}
		by, changes := f.lastHistory(f.tier)
		if !by.Valid || by.UUID != f.admin {
			t.Errorf("history changed_by = %v, want %s", by, f.admin)
		}
		for _, k := range []string{"display_name", "price_cents", "entitlements"} {
			if _, ok := changes[k]; !ok {
				t.Errorf("history row does not record %s: %v", k, changes)
			}
		}
		ev := f.awaitAudit("subscription_tier.updated")
		fields, _ := ev["changed_fields"].([]interface{})
		joined := ""
		for _, x := range fields {
			joined += x.(string) + ","
		}
		for _, want := range []string{"display_name", "price_cents", "entitlements.max_sensors"} {
			if !strings.Contains(joined, want+",") {
				t.Errorf("audit changed_fields %v missing %s", fields, want)
			}
		}
	})

	t.Run("identity-only update needs no version", func(t *testing.T) {
		code, body := f.do(f.admin, http.MethodPut, path, `{"display_name":"Pro"}`)
		f.expect("rename", code, body, http.StatusOK)
	})

	t.Run("remove entitlement through the unified tier update", func(t *testing.T) {
		before, v := f.composition(f.tier)
		if _, ok := before["max_assets"]; !ok {
			t.Fatal("fixture has no max_assets row to remove")
		}
		code, body := f.do(f.admin, http.MethodPut, path,
			`{"remove_entitlements":["max_assets"],"entitlements_version":"`+v+`"}`)
		f.expect("remove entitlement", code, body, http.StatusOK)
		after, _ := f.composition(f.tier)
		if _, ok := after["max_assets"]; ok {
			t.Fatal("remove_entitlements did not remove max_assets")
		}
	})

	t.Run("create writes the tier, its composition and history atomically", func(t *testing.T) {
		code, body := f.do(f.admin, http.MethodPost, "/tiers",
			`{"name":"p7-new","display_name":"P7 New","billing_interval":"month","billing_method":"invoice","entitlements":[{"item_key":"max_sensors","included_value":{"quantity":9}},{"item_key":"max_assets","included_value":{}}]}`)
		f.expect("create with a malformed entitlement", code, body, http.StatusBadRequest)
		var n int
		if err := f.owner.QueryRow(`SELECT COUNT(*) FROM subscription_tiers WHERE name = 'p7-new'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatal("a refused create left the tier row behind (with no composition, every cap resolves to 0)")
		}

		code, body = f.do(f.admin, http.MethodPost, "/tiers",
			`{"name":"p7-new","display_name":"P7 New","billing_interval":"month","billing_method":"invoice","entitlements":[{"item_key":"max_sensors","included_value":{"quantity":9}}]}`)
		f.expect("create", code, body, http.StatusCreated)
		id := uuid.MustParse(body["id"].(string))
		comp, _ := f.composition(id)
		if len(comp) != 1 || comp["max_sensors"] != `{"quantity": 9}` {
			t.Errorf("new tier composition = %v", comp)
		}
		by, changes := f.lastHistory(id)
		if !by.Valid || by.UUID != f.admin || changes["entitlements"] == nil {
			t.Errorf("initial composition history = %v by %v", changes, by)
		}
		f.awaitAudit("subscription_tier.created")

		// Deprecate read the same never-set "user_id" key and 401'd.
		code, body = f.do(f.admin, http.MethodDelete, "/tiers/"+id.String(), "")
		f.expect("deprecate", code, body, http.StatusOK)
		f.awaitAudit("subscription_tier.deprecated")
	})
}

func TestIntegration_UpdateTierWaitsForTierLock(t *testing.T) {
	f := newTierCompFixture(t)
	tx, err := f.owner.Begin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err := tx.Exec(`SELECT 1 FROM subscription_tiers WHERE id = $1 FOR UPDATE`, f.tier); err != nil {
		t.Fatal(err)
	}

	type result struct {
		code int
		body map[string]interface{}
	}
	done := make(chan result, 1)
	req := f.request(f.admin, http.MethodPut, "/tiers/"+f.tier.String(), `{"display_name":"Waited for lock"}`)
	go func() {
		w := httptest.NewRecorder()
		f.srv.Router().ServeHTTP(w, req)
		var body map[string]interface{}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		done <- result{w.Code, body}
	}()
	select {
	case r := <-done:
		t.Fatalf("UpdateTier bypassed the tier lock: status %d body %v", r.code, r.body)
	case <-time.After(750 * time.Millisecond):
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		f.expect("update after lock release", r.code, r.body, http.StatusOK)
	case <-time.After(10 * time.Second):
		t.Fatal("UpdateTier did not finish after the tier lock was released")
	}
}

func TestIntegration_DeprecateUnknownTierIsNotAcknowledged(t *testing.T) {
	f := newTierCompFixture(t)
	code, body := f.do(f.admin, http.MethodDelete, "/tiers/"+uuid.NewString(), "")
	f.expect("deprecate unknown tier", code, body, http.StatusNotFound)
}
