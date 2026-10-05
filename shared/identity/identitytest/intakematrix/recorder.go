package intakematrix

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// Snapshot is what the tenant looked like before a path ran. Effect diffs a
// later read against it, so a row records only what THAT path wrote.
type Snapshot struct {
	receipts    map[string]bool
	identifiers map[string]bool
	// sourceKinds is each identifier row's source_kind, so a path that
	// re-sources a row it did not add (a declaration over a measurement) shows.
	sourceKinds map[string]string
	endpoints   map[string]bool
	assets      map[string]bool
	proposals   int
}

// Take reads the tenant's identity state.
func (f *Fixture) Take(t *testing.T) Snapshot {
	t.Helper()
	return Snapshot{
		receipts:    f.set(t, `SELECT observation_id::text||'|'||receipt_key FROM identity_observation_receipts WHERE tenant_id=$1`),
		identifiers: f.set(t, `SELECT asset_id::text||'|'||kind||'|'||lower(value)||'|'||coalesce(scope,'') FROM asset_identifiers WHERE tenant_id=$1`),
		sourceKinds: f.pairs(t, `SELECT asset_id::text||'|'||kind||'|'||lower(value)||'|'||coalesce(scope,''), source_kind FROM asset_identifiers WHERE tenant_id=$1`),
		endpoints:   f.set(t, `SELECT asset_id::text||'|'||coalesce(host(address),fqdn,'')||'|'||coalesce(port::text,'') FROM asset_endpoints WHERE tenant_id=$1`),
		assets:      f.set(t, `SELECT id::text FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`),
		proposals:   f.count(t, `SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND action='merge_proposed'`),
	}
}

// Effect is one path's footprint, rendered by String for the table.
type Effect struct {
	// Outcome is the path's own answer: the engine outcome, or what the
	// engine-less path reported (`attached`, `refused`, `error`, ...).
	Outcome string
	// Observations are the engine receipts the path stored — the observation
	// exactly as its adapter built it. Empty means the path never reached the
	// engine's durable admission.
	Observations []ObservationEffect
	// IDs are identifier rows added to the established asset (`kind@scope`).
	IDs []string
	// Resourced are the established asset's EXISTING identifier rows whose
	// source_kind the path changed (`kind@scope:old>new`).
	Resourced []string
	// Ports are endpoint rows added to the established asset.
	Ports []string
	// NewAssets counts assets that did not exist before; OtherIDs and
	// OtherPorts are rows written to assets other than the established one.
	NewAssets, OtherIDs, OtherPorts int
	// Proposals counts merge proposals opened.
	Proposals int
}

// ObservationEffect is what one stored receipt says the adapter produced, plus
// where the engine left the observation row.
type ObservationEffect struct {
	Source    string   // kind/producer/mode, e.g. measured/sensor/passive
	Scope     string   // Network.SegmentID, symbolised
	Dynamic   []string // DynamicScopes marked true, symbolised
	IPScopes  []string // the scope each ip_address identifier carried
	Kinds     []string // the device-binding kinds carried (mac, ssh)
	Admission []string // direct, auth, relayed, op_confirmed
	Reasons   []string // the admission decision's reasons
	State     string   // identity_observations.state after the path
	OnAsset   string   // `fixture`, `other` or `-`
}

func (o ObservationEffect) String() string {
	return fmt.Sprintf("{src=%s scope=%s dyn=%s ip=%s kinds=%s adm=%s reasons=%s state=%s asset=%s}",
		o.Source, o.Scope, list(o.Dynamic), list(o.IPScopes), list(o.Kinds), list(o.Admission), list(o.Reasons), o.State, o.OnAsset)
}

// String is the matrix's spelling of an effect. Identical observations (one
// per port is common) are folded into `Nx{...}` so a three-port scan reads as
// one fact said three times.
func (e Effect) String() string {
	counts := map[string]int{}
	var order []string
	for _, o := range e.Observations {
		s := o.String()
		if counts[s] == 0 {
			order = append(order, s)
		}
		counts[s]++
	}
	sort.Strings(order)
	obs := make([]string, 0, len(order))
	for _, s := range order {
		obs = append(obs, fmt.Sprintf("%dx%s", counts[s], s))
	}
	return fmt.Sprintf("outcome=%s obs=%s ids=%s resourced=%s ports=%s new_assets=%d other_ids=%d other_ports=%d proposals=%d",
		e.Outcome, list(obs), list(e.IDs), list(e.Resourced), list(e.Ports), e.NewAssets, e.OtherIDs, e.OtherPorts, e.Proposals)
}

// Effect reads what changed since before. outcome is the path's own answer.
func (f *Fixture) Effect(t *testing.T, before Snapshot, outcome string) Effect {
	t.Helper()
	after := f.Take(t)
	e := Effect{Outcome: outcome, Proposals: after.proposals - before.proposals}
	asset := f.Asset.String()
	for k := range after.assets {
		if !before.assets[k] {
			e.NewAssets++
		}
	}
	for k := range after.identifiers {
		if before.identifiers[k] {
			continue
		}
		parts := strings.SplitN(k, "|", 4)
		if parts[0] != asset {
			e.OtherIDs++
			continue
		}
		e.IDs = append(e.IDs, shortKind(parts[1])+"@"+f.Symbol(parts[3]))
	}
	for k, was := range before.sourceKinds {
		now, ok := after.sourceKinds[k]
		parts := strings.SplitN(k, "|", 4)
		if !ok || now == was || parts[0] != asset {
			continue
		}
		e.Resourced = append(e.Resourced, shortKind(parts[1])+"@"+f.Symbol(parts[3])+":"+was+">"+now)
	}
	sort.Strings(e.Resourced)
	for k := range after.endpoints {
		if before.endpoints[k] {
			continue
		}
		parts := strings.SplitN(k, "|", 3)
		if parts[0] != asset {
			e.OtherPorts++
			continue
		}
		e.Ports = append(e.Ports, parts[2])
	}
	sort.Strings(e.IDs)
	sortPorts(e.Ports)

	var fresh []string
	for k := range after.receipts {
		if !before.receipts[k] {
			fresh = append(fresh, k)
		}
	}
	sort.Strings(fresh)
	for _, k := range fresh {
		parts := strings.SplitN(k, "|", 2)
		e.Observations = append(e.Observations, f.observation(t, parts[0], parts[1]))
	}
	return e
}

func (f *Fixture) observation(t *testing.T, observationID, receiptKey string) ObservationEffect {
	t.Helper()
	var raw []byte
	var reasons pq.StringArray
	var state string
	var assetID sql.NullString
	if err := f.DB.QueryRow(`SELECT r.evidence, o.admission_reasons, o.state, o.asset_id::text
		FROM identity_observation_receipts r JOIN identity_observations o ON o.tenant_id=r.tenant_id AND o.id=r.observation_id
		WHERE r.tenant_id=$1 AND r.observation_id=$2 AND r.receipt_key=$3`, f.Tenant, observationID, receiptKey).
		Scan(&raw, &reasons, &state, &assetID); err != nil {
		t.Fatalf("intakematrix: read receipt: %v", err)
	}
	var obs identity.Observation
	if err := json.Unmarshal(raw, &obs); err != nil {
		t.Fatalf("intakematrix: decode receipt evidence: %v", err)
	}
	mode := string(obs.Source.Mode)
	if mode == "" {
		mode = "-"
	}
	out := ObservationEffect{Source: string(obs.Source.Kind) + "/" + obs.Source.Producer() + "/" + mode, Scope: f.Symbol(obs.Network.SegmentID), State: state, Reasons: append([]string(nil), reasons...)}
	for scope, dyn := range obs.DynamicScopes {
		if dyn {
			out.Dynamic = append(out.Dynamic, f.Symbol(scope))
		}
	}
	for _, id := range obs.Identifiers {
		switch id.Kind {
		case identity.KindIPAddress:
			out.IPScopes = append(out.IPScopes, f.Symbol(id.Scope))
		case identity.KindMACAddress, identity.KindSSHHostKeyFingerprint:
			out.Kinds = append(out.Kinds, shortKind(string(id.Kind)))
		}
	}
	a := obs.Admission
	for _, flag := range []struct {
		on   bool
		name string
	}{{a.Direct, "direct"}, {a.Authoritative, "auth"}, {a.Relayed, "relayed"}, {a.OperatorConfirmed, "op_confirmed"}} {
		if flag.on {
			out.Admission = append(out.Admission, flag.name)
		}
	}
	switch {
	case !assetID.Valid:
		out.OnAsset = "-"
	case assetID.String == f.Asset.String():
		out.OnAsset = "fixture"
	default:
		out.OnAsset = "other"
	}
	sort.Strings(out.Dynamic)
	sort.Strings(out.IPScopes)
	sort.Strings(out.Kinds)
	sort.Strings(out.Reasons)
	return out
}

func shortKind(kind string) string {
	switch identity.Kind(kind) {
	case identity.KindIPAddress:
		return "ip"
	case identity.KindMACAddress:
		return "mac"
	case identity.KindSSHHostKeyFingerprint:
		return "ssh"
	}
	return kind
}

func list(v []string) string {
	if len(v) == 0 {
		return "-"
	}
	return "[" + strings.Join(v, ",") + "]"
}

func sortPorts(p []string) {
	sort.Slice(p, func(i, j int) bool {
		if len(p[i]) != len(p[j]) {
			return len(p[i]) < len(p[j])
		}
		return p[i] < p[j]
	})
}

func (f *Fixture) set(t *testing.T, query string) map[string]bool {
	t.Helper()
	rows, err := f.DB.QueryContext(context.Background(), query, f.Tenant)
	if err != nil {
		t.Fatalf("intakematrix: %s: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			t.Fatalf("intakematrix: scan: %v", err)
		}
		out[k] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("intakematrix: %v", err)
	}
	return out
}

func (f *Fixture) pairs(t *testing.T, query string) map[string]string {
	t.Helper()
	rows, err := f.DB.QueryContext(context.Background(), query, f.Tenant)
	if err != nil {
		t.Fatalf("intakematrix: %s: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			t.Fatalf("intakematrix: scan: %v", err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("intakematrix: %v", err)
	}
	return out
}

func (f *Fixture) count(t *testing.T, query string) int {
	t.Helper()
	var n int
	if err := f.DB.QueryRow(query, f.Tenant).Scan(&n); err != nil {
		t.Fatalf("intakematrix: %s: %v", query, err)
	}
	return n
}

// Check compares an effect to the row's expectation and fails with both
// spellings, so updating a row is copying one line.
func Check(t *testing.T, got Effect, want string) {
	t.Helper()
	if g := got.String(); g != want {
		t.Errorf("intake matrix row changed\n got: %s\nwant: %s", g, want)
	}
}
