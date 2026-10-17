package dcimfixture

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"hash"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Epoch anchors every generated timestamp. Fixed, not time.Now(), so two runs
// with the same seed write the same rows.
var Epoch = time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)

// Summary reports what Populate wrote and what it did not.
type Summary struct {
	Tenant uuid.UUID
	Scale  Scale
	// Counts is rows written, keyed by populator name.
	Counts map[string]int
	// Skipped lists populators that did not run, each as "name: reason" (a
	// required table is absent from the connected database, or there was
	// nothing to attach to).
	Skipped []string
	// AssetIDs are the generated asset ids in generation order.
	AssetIDs []uuid.UUID
	// AssetNames are the generated asset hostnames in generation order.
	AssetNames []string
	// PatchedInterfaces are interfaces whose cable path crosses two patch
	// panels (row 3.2's cable populator): the trace budget's origins.
	PatchedInterfaces []uuid.UUID
	// Digest is a sha256 over every generated name, id and address. Equal
	// digests mean equal name sets; it is the determinism witness.
	Digest  string
	Elapsed time.Duration
}

// Env is what a populator reads and extends. Later workstreams' populators
// append to it (e.g. a 1.2 interface populator reads Assets and adds
// Interfaces for the cable populator).
type Env struct {
	Tenant uuid.UUID
	Scale  Scale
	Rng    *rand.Rand
	Assets []Asset
	Tags   []uuid.UUID
	// Interfaces is written by the interfaces populator (row 1.2).
	Interfaces []Interface
	// Sites (by site index) and each site's Locations are written by the
	// sites populator (row 2.1), before the assets placed in them.
	Sites     []uuid.UUID
	Locations [][]uuid.UUID
	// ConsolePorts, RearPorts and FrontPorts are written by the component
	// populators (row 3.1).
	ConsolePorts, RearPorts, FrontPorts []Port
	// Racks (by site index, then rack index) are written by the racks
	// populator (row 2.3).
	Racks [][]uuid.UUID
	// PatchedInterfaces are the interfaces whose cable path the cable
	// populator (row 3.2) runs through two patch panels: the trace budget's
	// origins.
	PatchedInterfaces []uuid.UUID

	digest hash.Hash
}

// Asset is one generated asset.
type Asset struct {
	ID         uuid.UUID
	Name       string
	Site, Rack int
	Slot       int
	Class      string
}

// Witness folds s into the determinism digest. A populator must call it for
// every name or id it generates, so the digest covers its output.
func (e *Env) Witness(s string) {
	e.digest.Write([]byte(s))
	e.digest.Write([]byte{0})
}

// Populator fills one table family. Requires lists the tables that must exist
// in the connected database; Populate skips the populator, and says so in
// Summary.Skipped, when any is missing.
type Populator struct {
	Name     string
	Requires []string
	Run      func(ctx context.Context, tx *sql.Tx, env *Env) (int, error)
}

// Populators is the ordered registry. Sites come first because assets are
// placed in them; assets next because every other populator hangs off
// Env.Assets. A later row adds its populator by appending
// here (README.md, "Adding a populator").
func Populators() []Populator {
	return append([]Populator{
		{Name: "sites", Requires: []string{"regions", "site_groups", "sites", "locations"}, Run: populateSites},
		{Name: "assets", Requires: []string{"assets"}, Run: populateAssets},
		{Name: "tags", Requires: []string{"tags"}, Run: populateTags},
		{Name: "object_tags", Requires: []string{"object_tags", "tags"}, Run: populateObjectTags},
		{Name: "object_changes", Requires: []string{"object_changes"}, Run: populateObjectChanges},
		{Name: "journal_entries", Requires: []string{"journal_entries"}, Run: populateJournal},
		{Name: "unresolved_terminations", Requires: []string{"unresolved_terminations"}, Run: populateUnresolved},
		{Name: "interfaces", Requires: []string{"interfaces", "mac_addresses"}, Run: populateInterfaces},
		{Name: "console_ports", Requires: []string{"console_ports"}, Run: populateConsolePorts},
		{Name: "rear_ports", Requires: []string{"rear_ports"}, Run: populateRearPorts},
		{Name: "front_ports", Requires: []string{"front_ports", "rear_ports"}, Run: populateFrontPorts},
		{Name: "device_types", Requires: []string{"manufacturers", "device_types", "interface_templates", "device_roles"}, Run: populateCatalogue},
		{Name: "clusters", Requires: []string{"cluster_types", "cluster_groups", "clusters", "cluster_hosts", "virtual_disks"}, Run: populateVirtualization},
		{Name: "wireless_lan_groups", Requires: []string{"wireless_lan_groups"}, Run: populateWirelessGroups},
		{Name: "wireless_lans", Requires: []string{"wireless_lans", "wireless_lan_groups", "algorithms"}, Run: populateWirelessLANs},
		{Name: "contacts", Requires: []string{"contacts", "contact_roles", "contact_assignments"}, Run: populateContacts},
		{Name: "config_contexts", Requires: []string{"config_contexts"}, Run: populateConfigContexts},
		{Name: "tunnels", Requires: []string{"tunnels", "tunnel_terminations", "ike_proposals", "ike_policies", "ike_policy_proposals",
			"ipsec_proposals", "ipsec_policies", "ipsec_policy_proposals", "ipsec_profiles"}, Run: populateVPN},
		{Name: "circuits", Requires: []string{"providers", "provider_networks", "circuit_types", "circuits", "circuit_terminations"}, Run: populateCircuits},
		{Name: "racks", Requires: []string{"racks", "rack_utilization", "sites", "locations"}, Run: populateRacks},
		{Name: "cables", Requires: []string{"cables", "cable_terminations", "cable_paths", "interfaces", "front_ports", "rear_ports"}, Run: populateCables},
		// Cloud resources (row 4.6): an account, per-site regions, instances in a
		// security group, functions, buckets and a DNS zone, with the lifecycle
		// facts.
		{Name: "asset_relationships", Requires: []string{"assets", "asset_relationships", "asset_facts"}, Run: populateCloud},
		{Name: "inventory_items", Requires: []string{"module_bays", "modules", "inventory_items", "inventory_item_roles", "virtual_chassis", "module_types"}, Run: populateHardware},
	}, ipamPopulators()...)
}

// Populate generates the scale tenant under tenant (create it with
// testdb.NewTenant first) and returns what it wrote. It fails the test on any
// error.
func Populate(ctx context.Context, t testing.TB, db *sql.DB, tenant uuid.UUID, s Scale) Summary {
	t.Helper()
	return populate(ctx, t, db, tenant, s, Populators())
}

func populate(ctx context.Context, t testing.TB, db *sql.DB, tenant uuid.UUID, s Scale, pops []Populator) Summary {
	t.Helper()
	start := time.Now()
	env := &Env{
		Tenant: tenant,
		Scale:  s,
		Rng:    rand.New(rand.NewPCG(s.Seed, s.Seed^0x9e3779b97f4a7c15)),
		digest: sha256.New(),
	}
	sum := Summary{Tenant: tenant, Scale: s, Counts: map[string]int{}}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("dcimfixture: begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, p := range pops {
		if missing, err := missingTable(ctx, tx, p.Requires); err != nil {
			t.Fatalf("dcimfixture: %s: to_regclass: %v", p.Name, err)
		} else if missing != "" {
			sum.Skipped = append(sum.Skipped, fmt.Sprintf("%s: table %s does not exist", p.Name, missing))
			continue
		}
		n, err := p.Run(ctx, tx, env)
		if err != nil {
			t.Fatalf("dcimfixture: %s: %v", p.Name, err)
		}
		if n < 0 { // the populator found nothing to attach to
			sum.Skipped = append(sum.Skipped, fmt.Sprintf("%s: nothing to populate", p.Name))
			continue
		}
		sum.Counts[p.Name] = n
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("dcimfixture: commit: %v", err)
	}

	for _, a := range env.Assets {
		sum.AssetIDs = append(sum.AssetIDs, a.ID)
		sum.AssetNames = append(sum.AssetNames, a.Name)
	}
	sum.PatchedInterfaces = env.PatchedInterfaces
	sort.Strings(sum.Skipped)
	sum.Digest = hex.EncodeToString(env.digest.Sum(nil))
	sum.Elapsed = time.Since(start)
	return sum
}

// missingTable returns the first table in names that does not exist in public,
// or "". This is the phase-awareness check: without it a populator whose
// table has not landed yet would fail the whole run.
func missingTable(ctx context.Context, tx *sql.Tx, names []string) (string, error) {
	for _, n := range names {
		var ok bool
		if err := tx.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "public."+n).Scan(&ok); err != nil {
			return "", err
		}
		if !ok {
			return n, nil
		}
	}
	return "", nil
}

// copyRows streams rows into table with COPY.
func copyRows(ctx context.Context, tx *sql.Tx, table string, cols []string, n int, row func(i int) []any) error {
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = pq.QuoteIdentifier(c)
	}
	stmt, err := tx.PrepareContext(ctx, "COPY public."+pq.QuoteIdentifier(table)+" ("+strings.Join(quoted, ", ")+") FROM STDIN")
	if err != nil {
		return err
	}
	for i := 0; i < n; i++ {
		if _, err := stmt.ExecContext(ctx, row(i)...); err != nil {
			_ = stmt.Close()
			return err
		}
	}
	if _, err := stmt.ExecContext(ctx); err != nil {
		_ = stmt.Close()
		return err
	}
	return stmt.Close()
}

func (e *Env) newUUID() uuid.UUID {
	var b [16]byte
	for i := 0; i < 16; i += 8 {
		v := e.Rng.Uint64()
		for j := 0; j < 8; j++ {
			b[i+j] = byte(v >> (8 * j))
		}
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return uuid.UUID(b)
}

func addr(n int) string {
	n++
	return fmt.Sprintf("10.%d.%d.%d", (n>>16)&255, (n>>8)&255, n&255)
}

var classPaths = map[string]string{
	"switch":   "hardware.network_device.switch",
	"router":   "hardware.network_device.router",
	"firewall": "hardware.network_device.firewall",
	"server":   "hardware.computer.server",
}

func populateAssets(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	s := e.Scale
	e.Assets = make([]Asset, 0, s.Assets())
	for site := 0; site < s.Sites; site++ {
		for rack := 0; rack < s.RacksPerSite; rack++ {
			for slot := 0; slot < s.AssetsPerRack; slot++ {
				class := "server"
				switch {
				case slot == 0:
					class = "switch"
				case e.Rng.IntN(20) == 0:
					class = "firewall"
				case e.Rng.IntN(20) == 0:
					class = "router"
				}
				a := Asset{ID: e.newUUID(), Name: AssetName(site, rack, slot), Site: site, Rack: rack, Slot: slot, Class: class}
				e.Assets = append(e.Assets, a)
				e.Witness(a.Name + "|" + a.ID.String() + "|" + class)
			}
		}
	}
	risk := make([]int, len(e.Assets))
	status := make([]string, len(e.Assets))
	for i := range e.Assets {
		risk[i] = e.Rng.IntN(101)
		status[i] = "monitoring"
		if e.Rng.IntN(20) == 0 {
			status[i] = "pending_approval"
		}
	}
	cols := []string{"id", "tenant_id", "class_key", "class_path", "display_name", "hostname", "primary_address",
		"site_id", "location_id", "zone", "asset_status", "asset_ownership", "identity_status", "risk_score",
		"first_discovered_at", "last_seen_at", "created_at", "updated_at"}
	err := copyRows(ctx, tx, "assets", cols, len(e.Assets), func(i int) []any {
		a := e.Assets[i]
		ip := addr(i)
		e.Witness(ip)
		ts := Epoch.Add(time.Duration(i%1440) * time.Minute)
		site, loc := e.placement(a)
		return []any{a.ID, e.Tenant, a.Class, classPaths[a.Class], a.Name, a.Name, ip,
			site, loc, RackName(a.Site, a.Rack), status[i], "internal", "established", risk[i],
			ts, ts, ts, ts}
	})
	return len(e.Assets), err
}

const tagCount = 20

func populateTags(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	for i := 0; i < tagCount; i++ {
		slug := fmt.Sprintf("tag-%02d", i)
		e.Witness(slug)
		var id uuid.UUID
		if err := tx.QueryRowContext(ctx,
			`INSERT INTO tags (tenant_id, name, slug) VALUES ($1, $2, $3) RETURNING id`,
			e.Tenant, "Tag "+slug, slug).Scan(&id); err != nil {
			return 0, err
		}
		e.Tags = append(e.Tags, id)
	}
	return tagCount, nil
}

func populateObjectTags(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 || len(e.Tags) == 0 {
		return -1, nil
	}
	cols := []string{"tenant_id", "object_kind", "object_id", "tag_id"}
	err := copyRows(ctx, tx, "object_tags", cols, len(e.Assets), func(i int) []any {
		return []any{e.Tenant, "asset", e.Assets[i].ID, e.Tags[i%len(e.Tags)]}
	})
	return len(e.Assets), err
}

// populateObjectChanges writes a create and an update per asset: the change
// log the §12 "change log page < 200 ms" budget reads.
func populateObjectChanges(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 {
		return -1, nil
	}
	cols := []string{"tenant_id", "object_kind", "object_id", "action", "prechange_data", "postchange_data",
		"changed_fields", "source", "created_at"}
	n := len(e.Assets) * 2
	err := copyRows(ctx, tx, "object_changes", cols, n, func(i int) []any {
		a := e.Assets[i/2]
		at := Epoch.Add(time.Duration(i%(90*24)) * time.Hour)
		if i%2 == 0 {
			return []any{e.Tenant, "asset", a.ID, "create", nil, fmt.Sprintf(`{"hostname":%q}`, a.Name),
				pq.Array([]string{}), "system", at}
		}
		return []any{e.Tenant, "asset", a.ID, "update", `{"asset_status":"pending_approval"}`,
			`{"asset_status":"monitoring"}`, pq.Array([]string{"asset_status"}), "intake:sensor", at.Add(time.Minute)}
	})
	return n, err
}

func populateJournal(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 {
		return -1, nil
	}
	n := (len(e.Assets) + 9) / 10
	cols := []string{"tenant_id", "object_kind", "object_id", "kind", "comments", "created_at", "updated_at"}
	err := copyRows(ctx, tx, "journal_entries", cols, n, func(i int) []any {
		a := e.Assets[i*10]
		at := Epoch.Add(time.Duration(i%2000) * time.Minute)
		return []any{e.Tenant, "asset", a.ID, "info", "Racked and cabled: " + a.Name, at, at}
	})
	return n, err
}

func populateUnresolved(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Assets) == 0 {
		return -1, nil
	}
	n := (len(e.Assets) + 49) / 50
	cols := []string{"tenant_id", "producer", "origin_kind", "origin_id", "far_identity", "intent",
		"first_seen_at", "last_seen_at", "expires_at"}
	err := copyRows(ctx, tx, "unresolved_terminations", cols, n, func(i int) []any {
		a := e.Assets[i*50]
		far := fmt.Sprintf(`{"chassis_id":"02:00:00:%02x:%02x:%02x","port_id":%q}`, i>>16&255, i>>8&255, i&255, InterfaceName(i%48))
		return []any{e.Tenant, "lldp", "asset", a.ID, far, "cable", Epoch, Epoch, Epoch.Add(30 * 24 * time.Hour)}
	})
	return n, err
}
