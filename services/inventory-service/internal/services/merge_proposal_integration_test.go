package services

// Merge proposals and edge promotion against a real Postgres.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	identitypg "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// seedUser writes a real user row. `asset_history.actor_user_id` has a foreign
// key to it, so a merge decided by a random uuid is rejected by the database —
// which is correct, and is why the reviewer these tests record is a real one.
func seedUser(t *testing.T, db *database.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO users (id, tenant_id, email, is_active, created_at, updated_at)
		VALUES ($1, $2, $3, true, NOW(), NOW())`,
		id, tenant, "reviewer-"+id.String()[:8]+"@example.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// openProposal writes the asset_history row the identification engine writes on
// a conflict (shared/identity/postgres.OpenMergeProposal). Written out here
// rather than produced by calling the engine, so a change to that shape shows
// up as a loud failure instead of being silently followed.
func openProposal(t *testing.T, db *database.DB, tenant, observation, candidate uuid.UUID) uuid.UUID {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"kind":                 "merge_proposal",
		"status":               "pending",
		"observation_asset_id": observation.String(),
		"reason":               "two kinds matched different assets",
		"source_kind":          "measured",
		"candidates": []map[string]any{{
			"asset_id":            candidate.String(),
			"matched_identifiers": []map[string]any{{"kind": "mac_address", "value": "aa:bb:cc:dd:ee:ff"}},
			"score":               0.0,
		}},
	})
	if err != nil {
		t.Fatalf("marshal proposal: %v", err)
	}
	var id uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO asset_history (asset_id, tenant_id, source, action, changes_json, created_at)
		VALUES ($1,$2,'sensor','merge_proposed',$3::jsonb, NOW()) RETURNING id`,
		observation, tenant, payload).Scan(&id); err != nil {
		t.Fatalf("open proposal: %v", err)
	}
	return id
}

func TestIntegration_MergeProposal_AcceptMovesEverythingAndArchives(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewMergeProposalService(db)
	ctx := context.Background()

	// The two assets OVERLAP: seedAsset gives both endpoints on 198.51.100.10
	// starting at port 440, so the survivor has 440-441 and the observation has
	// 440-442. That overlap is deliberate and is the normal case — a shared
	// endpoint is usually WHY a merge was proposed — and it is what a bare
	// `UPDATE … SET asset_id` trips over: the unique index on
	// (tenant, asset, address, fqdn, port, transport) rejects it.
	survivor := seedAsset(t, db, tenant, "web-01.example.test", "server", "hardware.computer.server", "production", 40, 2)
	observation := seedAsset(t, db, tenant, "web01.example.test", "server", "hardware.computer.server", "production", 0, 3)
	proposalID := openProposal(t, db, tenant, observation, survivor)

	// A crypto configuration on one of the observation's COLLIDING endpoints.
	// Its endpoint row is about to be deleted as a duplicate, so unless the
	// configuration is re-pointed at the survivor's equivalent first, the FK
	// takes it with the row.
	var collidingEndpoint uuid.UUID
	if err := db.QueryRow(`SELECT id FROM asset_endpoints
		WHERE tenant_id=$1 AND asset_id=$2 AND port = 440`, tenant, observation).Scan(&collidingEndpoint); err != nil {
		t.Fatalf("find colliding endpoint: %v", err)
	}
	implID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, endpoint_id, protocol, discovery_method, risk_score, created_at, updated_at)
		VALUES ($1,$2,$3,$4,'TLS','passive',60,NOW(),NOW())`,
		implID, tenant, observation, collidingEndpoint); err != nil {
		t.Fatalf("insert configuration on the colliding endpoint: %v", err)
	}

	// Facts, relationships and software installs, each seeded in the three
	// shapes a merge has to tell apart: one only the observation has, one BOTH
	// have (a collision on the child's own unique key), and — for edges — one
	// that joins the two assets being merged, which cannot survive in any form
	// because `asset_relationships_no_self_edge_check` forbids from = to.
	neighbour := seedAsset(t, db, tenant, "sw-01.example.test", "switch", "hardware.network.switch", "production", 0, 1)
	fact := func(asset uuid.UUID, key, sourceRef, value string) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
			VALUES ($1,$2,$3,to_jsonb($4::text),'measured',$5,NOW())`,
			tenant, asset, key, value, sourceRef); err != nil {
			t.Fatalf("insert fact %s on %s: %v", key, asset, err)
		}
	}
	fact(survivor, "os.name", "sensor", "linux")
	fact(observation, "os.name", "sensor", "linux") // collides
	fact(observation, "hw.serial", "sensor", "J7K2QX1")

	edge := func(from, to uuid.UUID, kind string) uuid.UUID {
		t.Helper()
		id := uuid.New()
		if _, err := db.Exec(`
			INSERT INTO asset_relationships (id, tenant_id, from_asset_id, to_asset_id, type, source_kind, status)
			VALUES ($1,$2,$3,$4,$5,'measured','active')`, id, tenant, from, to, kind); err != nil {
			t.Fatalf("insert edge: %v", err)
		}
		return id
	}
	edgeOnlyObservation := edge(observation, neighbour, "connects_to")
	edgeInbound := edge(neighbour, observation, "manages")
	edge(survivor, neighbour, "depends_on")
	edgeCollides := edge(observation, neighbour, "depends_on") // the survivor has this one
	edgeBetween := edge(observation, survivor, "connects_to")  // would become a self-edge

	product := func(name, version string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := db.QueryRow(`
			INSERT INTO software_products (tenant_id, name, version) VALUES ($1,$2,$3) RETURNING id`,
			tenant, name, version).Scan(&id); err != nil {
			t.Fatalf("insert product %s: %v", name, err)
		}
		return id
	}
	install := func(asset, prod uuid.UUID) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO software_installs (tenant_id, asset_id, product_id, source_kind, first_seen_at, last_seen_at)
			VALUES ($1,$2,$3,'measured',NOW(),NOW())`, tenant, asset, prod); err != nil {
			t.Fatalf("insert install: %v", err)
		}
	}
	shared := product("openssl", "3.0.2")
	install(survivor, shared)
	install(observation, shared) // collides
	install(observation, product("nginx", "1.27.0"))

	t.Run("the queue shows it with both sides named", func(t *testing.T) {
		proposals, _, err := svc.ListPending(ctx, tenant, 50, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(proposals) != 1 {
			t.Fatalf("expected one pending proposal, got %d", len(proposals))
		}
		p := proposals[0]
		if p.Observation == nil || p.Observation.DisplayName == "" {
			t.Error("the observation card must be decorated; a reviewer choosing between two things has to read both")
		}
		if len(p.Candidates) != 1 || p.Candidates[0].DisplayName == "" {
			t.Fatalf("the candidate must be decorated, got %+v", p.Candidates)
		}
		if p.Candidates[0].ClassLabel == "" {
			t.Error("the candidate must carry a class label for the card")
		}
		if len(p.Candidates[0].MatchedIdentifiers) == 0 {
			t.Error("a proposal with no evidence can only be rubber-stamped")
		}
	})

	t.Run("the survivor must be one of the candidates", func(t *testing.T) {
		if _, err := svc.Accept(ctx, tenant, proposalID, uuid.New(), uuid.Nil); !errors.Is(err, ErrMergeCandidateNotInProposal) {
			t.Fatalf("an arbitrary asset id must be refused, got %v", err)
		}
	})

	actor := seedUser(t, db, tenant)
	if _, err := svc.Accept(ctx, tenant, proposalID, survivor, actor); err != nil {
		t.Fatalf("accept: %v", err)
	}

	t.Run("children moved to the survivor, duplicates folded", func(t *testing.T) {
		var endpoints, identifiers int
		if err := db.QueryRow(`SELECT COUNT(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, tenant, survivor).Scan(&endpoints); err != nil {
			t.Fatalf("count endpoints: %v", err)
		}
		// THREE, not five: ports 440 and 441 were the same endpoint seen on
		// both assets, and a merge that doubled them would leave the survivor
		// claiming two listeners on one socket.
		if endpoints != 3 {
			t.Errorf("the survivor should carry the UNION of the two endpoint sets (440,441,442), got %d", endpoints)
		}

		// The configuration that sat on a deleted duplicate is re-pointed at
		// the survivor's equivalent endpoint, not orphaned and not cascaded away.
		var implAsset, implEndpoint uuid.UUID
		if err := db.QueryRow(`SELECT asset_id, endpoint_id FROM crypto_implementations WHERE id=$1`, implID).Scan(&implAsset, &implEndpoint); err != nil {
			t.Fatalf("the configuration on the colliding endpoint was lost in the merge: %v", err)
		}
		if implAsset != survivor {
			t.Errorf("configuration asset = %s, want the survivor %s", implAsset, survivor)
		}
		if implEndpoint == collidingEndpoint {
			t.Error("the configuration still points at the deleted duplicate endpoint")
		}
		var owner uuid.UUID
		if err := db.QueryRow(`SELECT asset_id FROM asset_endpoints WHERE id=$1`, implEndpoint).Scan(&owner); err != nil {
			t.Fatalf("the configuration's endpoint does not exist: %v", err)
		}
		if owner != survivor {
			t.Errorf("the configuration's endpoint belongs to %s, want the survivor", owner)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM asset_identifiers WHERE tenant_id=$1 AND asset_id=$2`, tenant, survivor).Scan(&identifiers); err != nil {
			t.Fatalf("count identifiers: %v", err)
		}
		if identifiers != 2 {
			t.Errorf("the survivor should carry both identifiers, got %d", identifiers)
		}
		var left int
		if err := db.QueryRow(`SELECT COUNT(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, tenant, observation).Scan(&left); err != nil {
			t.Fatalf("count leftovers: %v", err)
		}
		if left != 0 {
			t.Errorf("the merged-away asset must keep nothing, got %d endpoints", left)
		}
	})

	// A merged-away asset is ARCHIVED, not deleted, so anything left pointing at
	// it is not cascaded away — it is stranded on a tombstone that every list
	// excludes. That is why these have to move rather than being left to the FK:
	// the survivor would come out of the merge with a graph, a fact store and a
	// software inventory missing everything the observation carried, and nothing
	// anywhere would say so.
	t.Run("facts, edges and software installs move too", func(t *testing.T) {
		owner := func(table, col string, id uuid.UUID) (uuid.UUID, bool) {
			t.Helper()
			var got uuid.UUID
			err := db.QueryRow(`SELECT `+col+` FROM `+table+` WHERE id=$1`, id).Scan(&got)
			if err != nil {
				return uuid.Nil, false
			}
			return got, true
		}

		var facts int
		if err := db.QueryRow(`SELECT COUNT(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2`,
			tenant, survivor).Scan(&facts); err != nil {
			t.Fatalf("count facts: %v", err)
		}
		// TWO, not three: `os.name` from the same source_ref is one fact, and
		// the survivor's row is the one that stays.
		if facts != 2 {
			t.Errorf("the survivor should carry the UNION of the fact keys (os.name, hw.serial), got %d", facts)
		}
		var left int
		if err := db.QueryRow(`SELECT COUNT(*) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2`,
			tenant, observation).Scan(&left); err != nil {
			t.Fatalf("count leftover facts: %v", err)
		}
		if left != 0 {
			t.Errorf("the merged-away asset must keep no facts, got %d", left)
		}

		if got, ok := owner("asset_relationships", "from_asset_id", edgeOnlyObservation); !ok || got != survivor {
			t.Errorf("an outbound edge only the observation had must move to the survivor (found=%t, owner=%s)", ok, got)
		}
		if got, ok := owner("asset_relationships", "to_asset_id", edgeInbound); !ok || got != survivor {
			t.Errorf("an INBOUND edge must move too; moving only from_asset_id strands every edge that pointed at the observation (found=%t, owner=%s)", ok, got)
		}
		if _, ok := owner("asset_relationships", "from_asset_id", edgeCollides); ok {
			t.Error("a duplicate edge must be folded into the survivor's, not left as a second row")
		}
		if _, ok := owner("asset_relationships", "from_asset_id", edgeBetween); ok {
			t.Error("the edge BETWEEN the two merged assets must be gone; re-pointing it would violate the no-self-edge CHECK and abort the merge")
		}
		var edges int
		if err := db.QueryRow(`SELECT COUNT(*) FROM asset_relationships WHERE tenant_id=$1 AND (from_asset_id=$2 OR to_asset_id=$2)`,
			tenant, observation).Scan(&edges); err != nil {
			t.Fatalf("count leftover edges: %v", err)
		}
		if edges != 0 {
			t.Errorf("no edge may still name the merged-away asset, got %d", edges)
		}

		var installs, staleInstalls int
		if err := db.QueryRow(`SELECT COUNT(*) FROM software_installs WHERE tenant_id=$1 AND asset_id=$2`,
			tenant, survivor).Scan(&installs); err != nil {
			t.Fatalf("count installs: %v", err)
		}
		// TWO: openssl was on both assets and is one install on the survivor;
		// nginx was only on the observation and has to arrive.
		if installs != 2 {
			t.Errorf("the survivor should carry the UNION of the installs (openssl once, nginx), got %d", installs)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM software_installs WHERE tenant_id=$1 AND asset_id=$2`,
			tenant, observation).Scan(&staleInstalls); err != nil {
			t.Fatalf("count leftover installs: %v", err)
		}
		if staleInstalls != 0 {
			t.Errorf("the merged-away asset must keep no installs, got %d", staleInstalls)
		}
	})

	t.Run("the observation is archived, not deleted", func(t *testing.T) {
		var status string
		var metadata []byte
		if err := db.QueryRow(`SELECT asset_status, metadata FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, observation).Scan(&status, &metadata); err != nil {
			t.Fatalf("the merged asset must still exist as a tombstone: %v", err)
		}
		if status != "archived" {
			t.Errorf("merged asset status = %q, want archived", status)
		}
		var meta map[string]any
		_ = json.Unmarshal(metadata, &meta)
		if meta["merged_into"] != survivor.String() {
			t.Errorf("the tombstone must point at the survivor, got %v", meta["merged_into"])
		}
	})

	// The tombstone is only useful if a client can FOLLOW it. A stale id — in a
	// ticket, a bookmark, an integration that stores asset ids — lands on
	// GetAssetByID, so that is the read that has to say "this is now that"
	// rather than 404ing or burying the answer in a metadata key nobody can
	// find in a schema.
	t.Run("the merged-away id still resolves, and names its survivor", func(t *testing.T) {
		assets := &AssetService{db: db}

		tombstone, err := assets.GetAssetByID(tenant, observation)
		if err != nil {
			t.Fatalf("a merged-away id must still resolve, not 404: %v", err)
		}
		if tombstone.AssetStatus != "archived" {
			t.Errorf("the tombstone's status = %q, want archived", tombstone.AssetStatus)
		}
		if tombstone.MergedInto == nil {
			t.Fatal("merged_into must be a first-class field on the asset; a pointer " +
				"nobody can find in the schema is a pointer nobody follows")
		}
		if *tombstone.MergedInto != survivor {
			t.Errorf("merged_into = %s, want the survivor %s", *tombstone.MergedInto, survivor)
		}

		// And the other polarity: every asset that was NOT merged away leaves it
		// nil, so a client can use its presence as the signal.
		alive, err := assets.GetAssetByID(tenant, survivor)
		if err != nil {
			t.Fatalf("GetAssetByID(survivor): %v", err)
		}
		if alive.MergedInto != nil {
			t.Errorf("the survivor must not claim to have been merged away, got %s", *alive.MergedInto)
		}
	})

	t.Run("history records both sides, and who decided", func(t *testing.T) {
		for _, tc := range []struct {
			asset  uuid.UUID
			action string
		}{
			{observation, "merged_into"},
			{survivor, "merged_from"},
		} {
			var n int
			var gotActor *uuid.UUID
			if err := db.QueryRow(`SELECT COUNT(*), MIN(actor_user_id::text)::uuid FROM asset_history
				WHERE tenant_id=$1 AND asset_id=$2 AND action=$3`,
				tenant, tc.asset, tc.action).Scan(&n, &gotActor); err != nil {
				t.Fatalf("count %s: %v", tc.action, err)
			}
			if n != 1 {
				t.Errorf("%s on %s: got %d entries, want 1 — a timeline that ends mid-sentence is the bug", tc.action, tc.asset, n)
			}
			// A1's carried note: actor_user_id was populated by NOTHING, so the
			// History tab could name a source but never a person. A merge is
			// the decision where that matters most.
			if gotActor == nil || *gotActor != actor {
				t.Errorf("%s records actor %v, want the reviewer %s", tc.action, gotActor, actor)
			}
		}
		// The observation's own history moved with it, so the merged asset's
		// timeline includes what happened BEFORE the merge.
		var moved int
		if err := db.QueryRow(`SELECT COUNT(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2`, tenant, survivor).Scan(&moved); err != nil {
			t.Fatalf("count survivor history: %v", err)
		}
		if moved < 2 {
			t.Errorf("the survivor should carry the merged asset's history too, got %d entries", moved)
		}
	})

	t.Run("the proposal leaves the queue and cannot be decided twice", func(t *testing.T) {
		proposals, _, err := svc.ListPending(ctx, tenant, 50, 0)
		if err != nil {
			t.Fatalf("list: %v", err)
		}
		if len(proposals) != 0 {
			t.Errorf("a decided proposal must leave the pending queue, got %d", len(proposals))
		}
		if _, err := svc.Accept(ctx, tenant, proposalID, survivor, actor); !errors.Is(err, ErrMergeProposalResolved) {
			t.Fatalf("a second click must say it was already decided, got %v", err)
		}
	})
}

func TestIntegration_MergeProposal_KeepSeparateLeavesTheAssetPending(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewMergeProposalService(db)
	ctx := context.Background()

	survivor := seedAsset(t, db, tenant, "keep-a.example.test", "server", "hardware.computer.server", "production", 0, 1)
	observation := seedAsset(t, db, tenant, "keep-b.example.test", "server", "hardware.computer.server", "production", 0, 1)
	if _, err := db.Exec(`UPDATE assets SET asset_status='pending_approval' WHERE tenant_id=$1 AND id=$2`, tenant, observation); err != nil {
		t.Fatalf("pin observation pending: %v", err)
	}
	proposalID := openProposal(t, db, tenant, observation, survivor)

	if _, err := svc.KeepSeparate(ctx, tenant, proposalID, seedUser(t, db, tenant)); err != nil {
		t.Fatalf("keep-separate: %v", err)
	}

	// Deciding the PROPOSAL is not deciding the ASSET. The reviewer said "this
	// is not that", not "this belongs in inventory" — promoting it here would
	// turn one decision into two, and the second would be ours.
	var status string
	if err := db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, observation).Scan(&status); err != nil {
		t.Fatalf("read observation: %v", err)
	}
	if status != "pending_approval" {
		t.Errorf("observation status = %q, want pending_approval", status)
	}

	// Nothing moved.
	var endpoints int
	if err := db.QueryRow(`SELECT COUNT(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, tenant, observation).Scan(&endpoints); err != nil {
		t.Fatalf("count endpoints: %v", err)
	}
	if endpoints != 1 {
		t.Errorf("keep-separate must move nothing, the observation now has %d endpoints", endpoints)
	}

	proposals, _, err := svc.ListPending(ctx, tenant, 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(proposals) != 0 {
		t.Errorf("a resolved proposal must leave the queue, got %d", len(proposals))
	}
}

// TestIntegration_ApprovalPromotesEdges is sub-task C's carried item: an edge is
// only as approved as the two assets it joins, and until now NOTHING promoted a
// pending edge after the interrogation writer created it — so the Relationships
// tab was empty on every freshly approved asset while the customer doc said
// approving the asset would make its relationships live.
func TestIntegration_ApprovalPromotesEdges(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := &AssetService{db: db}

	monitored := seedAsset(t, db, tenant, "hv-01.example.test", "hypervisor", "hardware.computer.hypervisor", "production", 0, 1)
	pendingPeer := seedAsset(t, db, tenant, "vm-02.example.test", "virtual_machine", "hardware.computer.virtual_machine", "production", 0, 1)
	subject := seedAsset(t, db, tenant, "vm-01.example.test", "virtual_machine", "hardware.computer.virtual_machine", "production", 0, 1)
	for _, id := range []uuid.UUID{subject, pendingPeer} {
		if _, err := db.Exec(`UPDATE assets SET asset_status='pending_approval' WHERE tenant_id=$1 AND id=$2`, tenant, id); err != nil {
			t.Fatalf("pin pending: %v", err)
		}
	}

	edge := func(from, to uuid.UUID, status string) uuid.UUID {
		id := uuid.New()
		if _, err := db.Exec(`
			INSERT INTO asset_relationships (id, tenant_id, from_asset_id, to_asset_id, type, source_kind, status)
			VALUES ($1,$2,$3,$4,'hosted_on','measured',$5)`, id, tenant, from, to, status); err != nil {
			t.Fatalf("insert edge: %v", err)
		}
		return id
	}
	statusOf := func(id uuid.UUID) string {
		var s string
		if err := db.QueryRow(`SELECT status FROM asset_relationships WHERE id=$1`, id).Scan(&s); err != nil {
			t.Fatalf("read edge %s: %v", id, err)
		}
		return s
	}

	toMonitored := edge(subject, monitored, "pending")
	toPending := edge(subject, pendingPeer, "pending")
	alreadyRejected := edge(pendingPeer, monitored, "rejected")

	if err := svc.ApproveAssets(tenant, []uuid.UUID{subject}, uuid.Nil); err != nil {
		t.Fatalf("approve: %v", err)
	}

	if got := statusOf(toMonitored); got != "active" {
		t.Errorf("an edge to an already-monitored peer must become active, got %q", got)
	}
	// The other polarity, and the one that matters: promoting on ONE end would
	// surface an edge pointing at a thing the user has not accepted.
	if got := statusOf(toPending); got != "pending" {
		t.Errorf("an edge to a still-pending peer must stay pending, got %q", got)
	}
	if got := statusOf(alreadyRejected); got != "rejected" {
		t.Errorf("a rejected edge is a human decision and must survive an unrelated approval, got %q", got)
	}

	t.Run("approving the peer promotes the second edge", func(t *testing.T) {
		if err := svc.ApproveAssets(tenant, []uuid.UUID{pendingPeer}, uuid.Nil); err != nil {
			t.Fatalf("approve peer: %v", err)
		}
		if got := statusOf(toPending); got != "active" {
			t.Errorf("once both ends are monitored the edge must be active, got %q", got)
		}
		if got := statusOf(alreadyRejected); got != "rejected" {
			t.Errorf("a rejection must not be undone by approving its assets, got %q", got)
		}
	})

	t.Run("denying an asset rejects its edges", func(t *testing.T) {
		denied := seedAsset(t, db, tenant, "vm-03.example.test", "virtual_machine", "hardware.computer.virtual_machine", "production", 0, 1)
		e := edge(denied, monitored, "active")
		if err := svc.DenyAssets(tenant, []uuid.UUID{denied}, seedUser(t, db, tenant)); err != nil {
			t.Fatalf("deny: %v", err)
		}
		if got := statusOf(e); got != "rejected" {
			t.Errorf("an edge to a denied asset must be rejected, got %q", got)
		}
	})
}

// TestIntegration_MergeProposal_MovesEveryReferrer is B4.
//
// Five tables name an asset and three name an endpoint, and the merge moved one
// of the eight. Every one of those foreign keys is ON DELETE SET NULL, and the
// source asset is ARCHIVED rather than deleted — so nothing errored, nothing
// logged, and the survivor simply showed no SSH host keys, no external
// connections, no interrogation jobs and no disk-encryption state for hardware
// it had just absorbed. A merge that loses half the evidence is worse than no
// merge, because it looks finished.
//
// The endpoint half is the sharper edge: the duplicate endpoint rows ARE
// deleted, so a row still pointing at one had its endpoint_id silently set to
// NULL.
func TestIntegration_MergeProposal_MovesEveryReferrer(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewMergeProposalService(db)
	ctx := context.Background()

	survivor := seedAsset(t, db, tenant, "keep-01.example.test", "server", "hardware.computer.server", "production", 40, 2)
	observation := seedAsset(t, db, tenant, "keep01.example.test", "server", "hardware.computer.server", "production", 0, 3)
	proposalID := openProposal(t, db, tenant, observation, survivor)
	actor := seedUser(t, db, tenant)

	// The observation's endpoint on port 440, which the survivor ALSO has — so
	// it is about to be deleted as a duplicate and anything pointing at it must
	// be re-pointed first.
	var colliding uuid.UUID
	if err := db.QueryRow(`SELECT id FROM asset_endpoints
		WHERE tenant_id=$1 AND asset_id=$2 AND port = 440`, tenant, observation).Scan(&colliding); err != nil {
		t.Fatalf("find colliding endpoint: %v", err)
	}

	sshKeyID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO ssh_keys (id, tenant_id, asset_id, endpoint_id, key_type, fingerprint_sha256, key_source, created_at, updated_at)
		VALUES ($1,$2,$3,$4,'ssh-ed25519',$5,'host_key',NOW(),NOW())`,
		sshKeyID, tenant, observation, colliding, "SHA256:"+sshKeyID.String()); err != nil {
		t.Fatalf("insert ssh key: %v", err)
	}
	connID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO external_connections (id, tenant_id, source_asset_id, source_endpoint_id,
			source_ip, dest_ip, dest_port, protocol)
		VALUES ($1,$2,$3,$4,'198.51.100.10','203.0.113.7',443,'TLS')`,
		connID, tenant, observation, colliding); err != nil {
		t.Fatalf("insert external connection: %v", err)
	}
	jobID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO device_jobs (id, tenant_id, asset_id, job_type)
		VALUES ($1,$2,$3,'device_interrogation')`,
		jobID, tenant, observation); err != nil {
		t.Fatalf("insert device job: %v", err)
	}
	encID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO database_encryption_states (id, tenant_id, asset_id, db_engine)
		VALUES ($1,$2,$3,'postgresql')`,
		encID, tenant, observation); err != nil {
		t.Fatalf("insert database encryption state: %v", err)
	}
	appID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO crypto_applications (id, tenant_id, asset_id, resource_type, resource_identifier,
			encryption_context)
		VALUES ($1,$2,$3,'disk_volume',$4,'at_rest')`,
		appID, tenant, observation, "vol-"+appID.String()); err != nil {
		t.Fatalf("insert crypto application: %v", err)
	}
	classHistoryID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO asset_class_history (id, tenant_id, asset_id, from_class_key, to_class_key, source)
		VALUES ($1,$2,$3,'unknown','hardware.computer.server','classifier')`,
		classHistoryID, tenant, observation); err != nil {
		t.Fatalf("insert asset class history: %v", err)
	}

	if _, err := svc.Accept(ctx, tenant, proposalID, survivor, actor); err != nil {
		t.Fatalf("accept: %v", err)
	}

	// Every asset_id column now names the survivor.
	for _, c := range []struct {
		table, column, id string
		row               uuid.UUID
	}{
		{"ssh_keys", "asset_id", "id", sshKeyID},
		{"external_connections", "source_asset_id", "id", connID},
		{"device_jobs", "asset_id", "id", jobID},
		{"database_encryption_states", "asset_id", "id", encID},
		{"crypto_applications", "asset_id", "id", appID},
		{"asset_class_history", "asset_id", "id", classHistoryID},
	} {
		var owner *uuid.UUID
		if err := db.QueryRow(
			`SELECT `+c.column+` FROM `+c.table+` WHERE tenant_id=$1 AND `+c.id+`=$2`,
			tenant, c.row).Scan(&owner); err != nil {
			t.Fatalf("read %s.%s: %v", c.table, c.column, err)
		}
		if owner == nil {
			t.Errorf("%s.%s is NULL after the merge; the archived source took it with it", c.table, c.column)
			continue
		}
		if *owner != survivor {
			t.Errorf("%s.%s = %s after the merge, want the survivor %s — the row still names the tombstone",
				c.table, c.column, *owner, survivor)
		}
	}

	// And every endpoint_id was re-pointed at the survivor's equivalent BEFORE
	// the duplicate row was deleted, rather than being SET NULL by the FK.
	for _, c := range []struct {
		table, column string
		row           uuid.UUID
	}{
		{"ssh_keys", "endpoint_id", sshKeyID},
		{"external_connections", "source_endpoint_id", connID},
	} {
		var ep *uuid.UUID
		if err := db.QueryRow(
			`SELECT `+c.column+` FROM `+c.table+` WHERE tenant_id=$1 AND id=$2`,
			tenant, c.row).Scan(&ep); err != nil {
			t.Fatalf("read %s.%s: %v", c.table, c.column, err)
		}
		if ep == nil {
			t.Errorf("%s.%s was set to NULL; the duplicate endpoint was deleted out from under it",
				c.table, c.column)
			continue
		}
		var owner uuid.UUID
		if err := db.QueryRow(`SELECT asset_id FROM asset_endpoints WHERE tenant_id=$1 AND id=$2`,
			tenant, *ep).Scan(&owner); err != nil {
			t.Fatalf("read the endpoint %s names: %v", c.table, err)
		}
		if owner != survivor {
			t.Errorf("%s.%s points at an endpoint of %s, want the survivor %s", c.table, c.column, owner, survivor)
		}
	}
}

// A conflicted sighting may never create an observation asset. Trying to
// accept it is a domain conflict, and must leave both candidates untouched.
func TestIntegration_MergeProposal_MissingObservation(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewMergeProposalService(db)
	source := seedAsset(t, db, tenant, "conflict-source", "server", "hardware.computer.server", "production", 0, 0)
	target := seedAsset(t, db, tenant, "conflict-target", "server", "hardware.computer.server", "production", 0, 0)
	for _, autoAccepted := range []bool{false, true} {
		proposal := openProposal(t, db, tenant, source, target)
		_, err := db.Exec(`UPDATE asset_history SET changes_json = changes_json ||
   jsonb_build_object('observation_asset_id', '', 'auto_accepted', $2::boolean)
   WHERE id = $1`, proposal, autoAccepted)
		if err != nil {
			t.Fatal(err)
		}
		_, err = svc.Accept(context.Background(), tenant, proposal, target, uuid.Nil)
		if !errors.Is(err, ErrMergeObservationMissing) {
			t.Fatalf("auto=%v: got %v", autoAccepted, err)
		}
		var status string
		if err := db.QueryRow(`SELECT changes_json->>'status' FROM asset_history WHERE id=$1`, proposal).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "pending" {
			t.Fatalf("proposal changed: %s", status)
		}
	}
	var archived int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND asset_status='archived'`, tenant).Scan(&archived); err != nil {
		t.Fatal(err)
	}
	if archived != 0 {
		t.Fatal("a candidate was archived")
	}
}

func TestIntegration_MergePreview_CandidateSelectionRevisionAndReplay(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	actor := seedUser(t, db, tenant)
	svc := NewMergeProposalService(db)
	ctx := context.Background()
	survivor := seedAsset(t, db, tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 2)
	source := seedAsset(t, db, tenant, "source.example.test", "server", "hardware.computer.server", "production", 0, 3)
	untouched := seedAsset(t, db, tenant, "third.example.test", "server", "hardware.computer.server", "production", 0, 0)
	proposal := openProposal(t, db, tenant, source, survivor)
	candidates, _ := json.Marshal([]map[string]any{{"asset_id": survivor}, {"asset_id": source}, {"asset_id": untouched}})
	if _, err := db.Exec(`UPDATE asset_history SET changes_json=(changes_json-'observation_asset_id')||jsonb_build_object('candidates',$2::jsonb) WHERE id=$1`, proposal, candidates); err != nil {
		t.Fatal(err)
	}
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor, FieldResolutions: map[string]uuid.UUID{"display_name": survivor, "hostname": survivor}}
	preview, err := svc.PreviewMerge(ctx, tenant, proposal, selection)
	if err != nil {
		t.Fatal(err)
	}
	if len(preview.Assets) != 2 || preview.Revision == "" {
		t.Fatalf("bad preview: %+v", preview)
	}
	request := MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Confirmed same device from controller evidence"}
	if _, err := db.Exec(`UPDATE assets SET description='changed concurrently' WHERE tenant_id=$1 AND id=$2`, tenant, source); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteMerge(ctx, tenant, proposal, actor, request); !errors.Is(err, ErrMergePreviewChanged) {
		t.Fatalf("stale preview: %v", err)
	}
	preview, err = svc.PreviewMerge(ctx, tenant, proposal, selection)
	if err != nil {
		t.Fatal(err)
	}
	request.Revision = preview.Revision
	result, err := svc.ExecuteMerge(ctx, tenant, proposal, actor, request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := svc.ExecuteMerge(ctx, tenant, proposal, actor, request)
	if err != nil {
		t.Fatal(err)
	}
	if !replay.Replayed || replay.ID != result.ID {
		t.Fatalf("bad replay: %+v", replay)
	}
	var status string
	var count int
	if err := db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, untouched).Scan(&status); err != nil || status == "archived" {
		t.Fatalf("unselected candidate changed: %s %v", status, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, tenant, survivor).Scan(&count); err != nil || count != 3 {
		t.Fatalf("endpoint preservation: %d %v", count, err)
	}
	if err := db.QueryRow(`SELECT changes_json->>'status' FROM asset_history WHERE tenant_id=$1 AND id=$2`, tenant, proposal).Scan(&status); err != nil || status != "pending" {
		t.Fatalf("third candidate question lost: %s %v", status, err)
	}
	other := testdb.NewTenant(t, raw)
	if _, err := svc.PreviewMerge(ctx, other, uuid.Nil, selection); !errors.Is(err, ErrMergeProposalNotFound) {
		t.Fatalf("cross-tenant preview: %v", err)
	}
	if _, err := svc.ExecuteMerge(ctx, other, proposal, actor, request); !errors.Is(err, ErrMergeProposalNotFound) {
		t.Fatalf("cross-tenant replay: %v", err)
	}
}

func TestIntegration_MergePreview_DeclaredFieldsAndManagementHistory(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	actor := seedUser(t, db, tenant)
	svc := NewMergeProposalService(db)
	ctx := context.Background()
	survivor := seedAsset(t, db, tenant, "old.example.test", "server", "hardware.computer.server", "production", 0, 0)
	source := seedAsset(t, db, tenant, "new.example.test", "server", "hardware.computer.server", "production", 0, 0)
	for _, id := range []uuid.UUID{source, survivor} {
		if _, err := db.Exec(`INSERT INTO asset_management(tenant_id,asset_id,management_url,management_protocol) VALUES($1,$2,$3,'ssh')`, tenant, id, "ssh://"+id.String()+".example.test"); err != nil {
			t.Fatal(err)
		}
	}
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}
	preview, err := svc.PreviewMerge(ctx, tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	request := MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Same physical server verified"}
	if _, err := svc.ExecuteMerge(ctx, tenant, uuid.Nil, actor, request); !errors.Is(err, ErrMergeFieldResolution) {
		t.Fatalf("declared conflict merged: %v", err)
	}
	selection.FieldResolutions = map[string]uuid.UUID{"hostname": survivor, "display_name": survivor, "management_profile": source}
	preview, err = svc.PreviewMerge(ctx, tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	request.MergeSelection = selection
	request.Revision = preview.Revision
	result, err := svc.ExecuteMerge(ctx, tenant, uuid.Nil, actor, request)
	if err != nil {
		t.Fatal(err)
	}
	var url string
	if err := db.QueryRow(`SELECT management_url FROM asset_management WHERE tenant_id=$1 AND asset_id=$2`, tenant, survivor).Scan(&url); err != nil || url != "ssh://"+source.String()+".example.test" {
		t.Fatalf("selected management: %s %v", url, err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM asset_merge_management_history WHERE tenant_id=$1 AND asset_id=$2`, tenant, survivor).Scan(&count); err != nil || count != 1 {
		t.Fatalf("previous profile lost: %d %v", count, err)
	}
	var audit string
	if err := db.QueryRow(`SELECT audit::text FROM asset_merge_audits WHERE tenant_id=$1 AND id=$2`, tenant, result.ID).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(audit, "management_profile_references") || strings.Contains(audit, "password_enc") {
		t.Fatalf("incorrect profile audit projection: %s", audit)
	}
}

func TestIntegration_MergePreview_KeepSeparateSurvivesOtherMerge(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	actor := seedUser(t, db, tenant)
	svc := NewMergeProposalService(db)
	ctx := context.Background()
	a := seedAsset(t, db, tenant, "a.example.test", "server", "hardware.computer.server", "production", 0, 0)
	b := seedAsset(t, db, tenant, "b.example.test", "server", "hardware.computer.server", "production", 0, 0)
	c := seedAsset(t, db, tenant, "c.example.test", "server", "hardware.computer.server", "production", 0, 0)
	proposal := openProposal(t, db, tenant, a, c)
	if _, err := svc.KeepSeparate(ctx, tenant, proposal, actor); err != nil {
		t.Fatal(err)
	}
	blocked := MergeSelection{SourceAssetIDs: []uuid.UUID{a}, SurvivorAssetID: c}
	if _, err := svc.PreviewMerge(ctx, tenant, uuid.Nil, blocked); !errors.Is(err, ErrMergeKeptSeparate) {
		t.Fatalf("ignored keep separate: %v", err)
	}
	selected := MergeSelection{SourceAssetIDs: []uuid.UUID{a}, SurvivorAssetID: b, FieldResolutions: map[string]uuid.UUID{"hostname": b, "display_name": b}}
	preview, err := svc.PreviewMerge(ctx, tenant, uuid.Nil, selected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteMerge(ctx, tenant, uuid.Nil, actor, MergeExecutionRequest{MergeSelection: selected, Revision: preview.Revision, Reason: "Operator verified A and B"}); err != nil {
		t.Fatal(err)
	}
	blocked.SourceAssetIDs = []uuid.UUID{b}
	if _, err := svc.PreviewMerge(ctx, tenant, uuid.Nil, blocked); !errors.Is(err, ErrMergeKeptSeparate) {
		t.Fatalf("lost inherited keep separate: %v", err)
	}
}

func TestIntegration_MergePreview_PreservesDistinctEndpointCertificatesAndFindingHistory(t *testing.T) {
	f := newLeafLinkFixture(t)
	ctx := context.Background()
	actor := seedUser(t, f.db, f.tenant)
	survivor := seedAsset(t, f.db, f.tenant, "stable.example.test", "server", "hardware.computer.server", "production", 0, 0)
	source := seedAsset(t, f.db, f.tenant, "alias.example.test", "server", "hardware.computer.server", "production", 0, 0)
	seen := time.Now().UTC().Add(-48 * time.Hour).Truncate(time.Microsecond)
	for index, id := range []uuid.UUID{survivor, source} {
		finding := leafCertFinding("stable.example.test", "198.51.100.70", 443+index*400, strings.Repeat(string(rune('a'+index)), 64))
		finding.RawData["observed_at"] = seen.Format(time.RFC3339Nano)
		if err := f.svc.processDiscoveryCryptoData(f.tenant, id, finding, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.Exec(`UPDATE assets SET last_seen_at=$3 WHERE tenant_id=$1 AND id=ANY($2)`, f.tenant, pq.Array([]uuid.UUID{source, survivor}), seen); err != nil {
		t.Fatal(err)
	}
	for _, id := range []uuid.UUID{survivor, source} {
		if _, err := f.db.Exec(`INSERT INTO findings(tenant_id,producer,kind,subject_type,subject_id,severity,summary,workflow_status,first_seen,last_seen) VALUES($1,'crypto','weak_protocol','asset',$2,'high','historical finding','SUPPRESSED',$3,$3)`, f.tenant, id, seen); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewMergeProposalService(f.db)
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor, FieldResolutions: map[string]uuid.UUID{"hostname": survivor, "display_name": survivor}}
	preview, err := svc.PreviewMerge(ctx, f.tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteMerge(ctx, f.tenant, uuid.Nil, actor, MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Verified endpoints on one physical asset"}); err != nil {
		t.Fatal(err)
	}
	var endpoints, certificates, attachments int
	if err := f.db.QueryRow(`SELECT count(DISTINCT i.endpoint_id),count(DISTINCT c.certificate_id),count(*) FROM crypto_implementations i JOIN crypto_implementation_certificates c ON c.crypto_implementation_id=i.id WHERE i.tenant_id=$1 AND i.asset_id=$2`, f.tenant, survivor).Scan(&endpoints, &certificates, &attachments); err != nil || endpoints != 2 || certificates != 2 || attachments != 2 {
		t.Fatalf("attachments lost: endpoints=%d certs=%d attachments=%d err=%v", endpoints, certificates, attachments, err)
	}
	var retained, suppressed int
	if err := f.db.QueryRow(`SELECT count(*),count(*) FILTER(WHERE workflow_status='SUPPRESSED') FROM findings WHERE tenant_id=$1 AND subject_type='asset' AND subject_id=$2`, f.tenant, survivor).Scan(&retained, &suppressed); err != nil || retained != 2 || suppressed != 2 {
		t.Fatalf("finding history lost: %d/%d %v", retained, suppressed, err)
	}
	var lastSeen time.Time
	if err := f.db.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id=$1 AND id=$2`, f.tenant, survivor).Scan(&lastSeen); err != nil || !lastSeen.Equal(seen) {
		t.Fatalf("merge fabricated freshness: %s %v", lastSeen, err)
	}
	repo := identitypg.New(f.db.DB.DB)
	err = repo.UpsertEndpoints(ctx, identity.AssetRef{TenantID: f.tenant.String(), ID: source.String()}, []identity.EndpointObservation{{Address: "198.51.100.71", Port: 443, Transport: "tcp"}})
	if !errors.Is(err, identity.ErrAssetNotFound) {
		t.Fatalf("late endpoint attached to archived source: %v", err)
	}
}

func TestIntegration_MergePreview_ConcurrentEvidenceInvalidatesRevision(t *testing.T) {
	f := newLeafLinkFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	actor := seedUser(t, f.db, f.tenant)
	survivor := seedAsset(t, f.db, f.tenant, "race-keep.example.test", "server", "hardware.computer.server", "production", 0, 0)
	source := seedAsset(t, f.db, f.tenant, "race-source.example.test", "server", "hardware.computer.server", "production", 0, 0)
	svc := NewMergeProposalService(f.db)
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}
	preview, err := svc.PreviewMerge(ctx, f.tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	err = identitypg.WithAssetLifecycleReadLock(ctx, f.db.DB.DB, f.tenant, source, func() error {
		go func() {
			_, err := svc.ExecuteMerge(ctx, f.tenant, uuid.Nil, actor, MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Review before the next observation"})
			result <- err
		}()
		waitForIdentityReplayLock(t, ctx, f, identitypg.AssetLifecycleLockKey(f.tenant, source), "ExclusiveLock", false)
		return identitypg.New(f.db.DB.DB).UpsertEndpoints(ctx, identity.AssetRef{TenantID: f.tenant.String(), ID: source.String()}, []identity.EndpointObservation{{Address: "198.51.100.78", Port: 8443, Transport: "tcp", SeenAt: time.Now().UTC()}})
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if !errors.Is(err, ErrMergePreviewChanged) {
			t.Fatalf("concurrent evidence was not refreshable: %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var status string
	var count int
	if err := f.db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id=$1 AND id=$2`, f.tenant, source).Scan(&status); err != nil || status == "archived" {
		t.Fatalf("stale decision archived source: %s %v", status, err)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, f.tenant, source).Scan(&count); err != nil || count != 1 {
		t.Fatalf("lost concurrent evidence: %d %v", count, err)
	}
}

func TestIntegration_MergePreview_SharedCertificateAndAlgorithmRowsKeepDistinctAuditKeys(t *testing.T) {
	f := newLeafLinkFixture(t)
	ctx := context.Background()
	actor := seedUser(t, f.db, f.tenant)
	survivor := seedAsset(t, f.db, f.tenant, "shared-cert-keep.example.test", "server", "hardware.computer.server", "production", 0, 0)
	source := seedAsset(t, f.db, f.tenant, "shared-cert-source.example.test", "server", "hardware.computer.server", "production", 0, 0)
	for index, id := range []uuid.UUID{survivor, source} {
		finding := leafCertFinding("shared-cert.example.test", "198.51.100.74", 443+index*400, strings.Repeat("d", 64))
		if err := f.svc.processDiscoveryCryptoData(f.tenant, id, finding, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := f.db.Exec(`UPDATE crypto_implementation_certificates SET certificate_role='intermediate' WHERE crypto_implementation_id IN(SELECT id FROM crypto_implementations WHERE tenant_id=$1 AND asset_id=$2)`, f.tenant, source); err != nil {
		t.Fatal(err)
	}
	svc := NewMergeProposalService(f.db)
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}
	preview, err := svc.PreviewMerge(ctx, f.tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	merged, err := svc.ExecuteMerge(ctx, f.tenant, uuid.Nil, actor, MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Confirmed two endpoints serving shared certificate"})
	if err != nil {
		t.Fatal(err)
	}
	var certRows, roleCount, algorithmRows int
	if err := f.db.QueryRow(`SELECT count(*),count(DISTINCT record->>'certificate_role') FROM asset_merge_record_snapshots WHERE tenant_id=$1 AND merge_id=$2 AND record_table='crypto_implementation_certificates'`, f.tenant, merged.ID).Scan(&certRows, &roleCount); err != nil || certRows != 2 || roleCount != 2 {
		t.Fatalf("shared certificate snapshots collided: rows=%d roles=%d err=%v", certRows, roleCount, err)
	}
	if err := f.db.QueryRow(`SELECT count(*) FROM asset_merge_record_snapshots WHERE tenant_id=$1 AND merge_id=$2 AND record_table='crypto_implementation_algorithms'`, f.tenant, merged.ID).Scan(&algorithmRows); err != nil || algorithmRows < 2 {
		t.Fatalf("algorithm snapshots collided: rows=%d err=%v", algorithmRows, err)
	}
}

func TestIntegration_MergePreview_RelatedCandidateQuestionsAreSuperseded(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	actor := seedUser(t, db, tenant)
	svc := NewMergeProposalService(db)
	ctx := context.Background()
	survivor := seedAsset(t, db, tenant, "group-keep.example.test", "server", "hardware.computer.server", "production", 0, 0)
	source := seedAsset(t, db, tenant, "group-source.example.test", "server", "hardware.computer.server", "production", 0, 0)
	third := seedAsset(t, db, tenant, "group-third.example.test", "server", "hardware.computer.server", "production", 0, 0)
	for _, id := range []uuid.UUID{source, survivor} {
		proposal := openProposal(t, db, tenant, id, third)
		changes := map[string]any{"kind": "merge_proposal", "status": "pending", "candidates": []any{map[string]any{"asset_id": id.String()}, map[string]any{"asset_id": third.String()}}}
		changes["fingerprint"] = reconciledProposalFingerprint(changes)
		encoded, _ := json.Marshal(changes)
		if _, err := db.Exec(`UPDATE asset_history SET changes_json=$2::jsonb WHERE id=$1`, proposal, encoded); err != nil {
			t.Fatal(err)
		}
	}
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}
	preview, err := svc.PreviewMerge(ctx, tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteMerge(ctx, tenant, uuid.Nil, actor, MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Merge selected records; keep third candidate unresolved"}); err != nil {
		t.Fatal(err)
	}
	var pending, superseded int
	if err := db.QueryRow(`SELECT count(*) FILTER(WHERE changes_json->>'status'='pending'),count(*) FILTER(WHERE changes_json->>'status'='superseded') FROM asset_history WHERE tenant_id=$1 AND action='merge_proposed'`, tenant).Scan(&pending, &superseded); err != nil || pending != 1 || superseded != 1 {
		t.Fatalf("duplicate questions persisted: pending=%d superseded=%d err=%v", pending, superseded, err)
	}
}

func TestIntegration_MergePreview_MissingFieldsUseRawValues(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	source := seedAsset(t, db, tenant, "source.example.test", "server", "hardware.computer.server", "production", 0, 0)
	survivor := seedAsset(t, db, tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
	if _, err := db.Exec(`UPDATE assets SET attributes=CASE WHEN id=$2 THEN '{"api_token":"preserve-original-private-value","model":"R650"}'::jsonb ELSE '{}'::jsonb END WHERE tenant_id=$1`, tenant, source); err != nil {
		t.Fatal(err)
	}
	svc := NewMergeProposalService(db)
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor, FieldResolutions: map[string]uuid.UUID{"hostname": survivor, "display_name": survivor}}
	preview, err := svc.PreviewMerge(t.Context(), tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	projected, _ := json.Marshal(preview)
	if strings.Contains(string(projected), "preserve-original-private-value") {
		t.Fatal("preview leaked private field")
	}
	result, err := svc.ExecuteMerge(t.Context(), tenant, uuid.Nil, seedUser(t, db, tenant), MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Operator verified duplicate inventory records"})
	if err != nil {
		t.Fatal(err)
	}
	var value, audit string
	if err := db.QueryRow(`SELECT attributes->>'api_token' FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, survivor).Scan(&value); err != nil || value != "preserve-original-private-value" {
		t.Fatalf("redacted projection corrupted stored field: %q %v", value, err)
	}
	if err := db.QueryRow(`SELECT audit::text FROM asset_merge_audits WHERE tenant_id=$1 AND id=$2`, tenant, result.ID).Scan(&audit); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(audit, "preserve-original-private-value") {
		t.Fatal("public merge audit leaked private field")
	}
}

func TestIntegration_MergePreview_ManagementSelectionPreservesAbsentHalf(t *testing.T) {
	for _, absent := range []string{"credential", "connection"} {
		t.Run(absent, func(t *testing.T) {
			raw := testdb.Connect(t)
			testdb.ApplySchemaAndSeed(t, raw)
			db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
			tenant := testdb.NewTenant(t, raw)
			survivor := seedAsset(t, db, tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
			chosen := seedAsset(t, db, tenant, "chosen.example.test", "server", "hardware.computer.server", "production", 0, 0)
			other := seedAsset(t, db, tenant, "other.example.test", "server", "hardware.computer.server", "production", 0, 0)
			for _, asset := range []uuid.UUID{survivor, chosen, other} {
				if asset != chosen || absent != "connection" {
					if _, err := db.Exec(`INSERT INTO asset_management(tenant_id,asset_id,management_url,management_protocol) VALUES($1,$2,$3,'ssh')`, tenant, asset, "ssh://"+asset.String()+".example.test"); err != nil {
						t.Fatal(err)
					}
				}
				if asset != chosen || absent != "credential" {
					if _, err := db.Exec(`INSERT INTO asset_credentials(tenant_id,asset_id,username) VALUES($1,$2,$3)`, tenant, asset, asset.String()); err != nil {
						t.Fatal(err)
					}
				}
			}
			svc := NewMergeProposalService(db)
			selection := MergeSelection{SourceAssetIDs: []uuid.UUID{chosen, other}, SurvivorAssetID: survivor, FieldResolutions: map[string]uuid.UUID{"hostname": survivor, "display_name": survivor, "management_profile": chosen}}
			preview, err := svc.PreviewMerge(t.Context(), tenant, uuid.Nil, selection)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := svc.ExecuteMerge(t.Context(), tenant, uuid.Nil, seedUser(t, db, tenant), MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Verified explicit management profile selection"}); err != nil {
				t.Fatal(err)
			}
			var count int
			table := "asset_credentials"
			if absent == "connection" {
				table = "asset_management"
			}
			if err := db.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id=$1 AND asset_id=$2`, tenant, survivor).Scan(&count); err != nil || count != 0 {
				t.Fatalf("unselected source filled intentionally absent %s: %d %v", absent, count, err)
			}
			table = "asset_management"
			column := "management_url"
			want := "ssh://" + chosen.String() + ".example.test"
			if absent == "connection" {
				table = "asset_credentials"
				column = "username"
				want = chosen.String()
			}
			var value string
			if err := db.QueryRow(`SELECT `+column+` FROM `+table+` WHERE tenant_id=$1 AND asset_id=$2`, tenant, survivor).Scan(&value); err != nil || value != want {
				t.Fatalf("selected profile changed: %q %v", value, err)
			}
		})
	}
}

func TestIntegration_MergePreview_RejectsNonexistentManagementChoice(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	survivor := seedAsset(t, db, tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
	empty := seedAsset(t, db, tenant, "empty.example.test", "server", "hardware.computer.server", "production", 0, 0)
	if _, err := db.Exec(`INSERT INTO asset_management(tenant_id,asset_id,management_url) VALUES($1,$2,'ssh://survivor.example.test')`, tenant, survivor); err != nil {
		t.Fatal(err)
	}
	_, err := NewMergeProposalService(db).PreviewMerge(t.Context(), tenant, uuid.Nil, MergeSelection{SourceAssetIDs: []uuid.UUID{empty}, SurvivorAssetID: survivor, FieldResolutions: map[string]uuid.UUID{"management_profile": empty}})
	if !errors.Is(err, ErrMergeSelection) {
		t.Fatalf("forged profile choice accepted: %v", err)
	}
}

func TestIntegration_MergePreview_ReconcilesObservedStateAndCoverage(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	survivor := seedAsset(t, db, tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
	source := seedAsset(t, db, tenant, "source.example.test", "server", "hardware.computer.server", "production", 0, 0)
	old := time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Microsecond)
	newer := old.Add(time.Hour)
	type stateCase struct {
		name, dstKind, srcKind, dstStatus, srcStatus, want string
		srcTime                                            time.Time
	}
	cases := []stateCase{{"newer presence", "measured", "measured", "removed", "active", "active", newer}, {"older presence", "measured", "measured", "removed", "active", "removed", old.Add(-time.Hour)}, {"preserve declared", "declared", "measured", "removed", "active", "removed", newer}, {"no provenance demotion", "measured", "imported", "removed", "active", "removed", newer}}
	for i, tc := range cases {
		var product uuid.UUID
		if err := db.QueryRow(`INSERT INTO software_products(tenant_id,name,version) VALUES($1,$2,'1') RETURNING id`, tenant, tc.name).Scan(&product); err != nil {
			t.Fatal(err)
		}
		for _, row := range []struct {
			asset             uuid.UUID
			kind, status, ref string
			at                time.Time
		}{{survivor, tc.dstKind, tc.dstStatus, "old", old}, {source, tc.srcKind, tc.srcStatus, "new", tc.srcTime}} {
			if _, err := db.Exec(`INSERT INTO software_installs(tenant_id,asset_id,product_id,source_kind,source_ref,status,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,$5,$6,$7,$7)`, tenant, row.asset, product, row.kind, row.ref, row.status, row.at); err != nil {
				t.Fatal(err)
			}
			status := row.status
			if status == "removed" {
				status = "closed"
			}
			if _, err := db.Exec(`INSERT INTO asset_endpoints(tenant_id,asset_id,address,port,transport,source_kind,source_ref,status,first_seen_at,last_seen_at) VALUES($1,$2,'192.0.2.20',$3,'tcp',$4,$5,$6,$7,$7)`, tenant, row.asset, 8440+i, row.kind, row.ref, status, row.at); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A disjoint measured package and an imported package must count separately.
	for _, kind := range []string{"measured", "imported"} {
		var product uuid.UUID
		if err := db.QueryRow(`INSERT INTO software_products(tenant_id,name,version) VALUES($1,$2,'1') RETURNING id`, tenant, "only-source-"+kind).Scan(&product); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO software_installs(tenant_id,asset_id,product_id,source_kind,status,first_seen_at,last_seen_at) VALUES($1,$2,$3,$4,'active',$5,$5)`, tenant, source, product, kind, newer); err != nil {
			t.Fatal(err)
		}
	}
	for _, kind := range []string{"measured", "imported", "declared"} {
		if _, err := db.Exec(`INSERT INTO asset_facts(tenant_id,asset_id,key,value,source_kind,source_ref,observed_at) VALUES($1,$2,'sw.package_count','99'::jsonb,$3,$3,$4)`, tenant, survivor, kind, old); err != nil {
			t.Fatal(err)
		}
	}
	svc := NewMergeProposalService(db)
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor, FieldResolutions: map[string]uuid.UUID{"hostname": survivor, "display_name": survivor}}
	preview, err := svc.PreviewMerge(t.Context(), tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteMerge(t.Context(), tenant, uuid.Nil, seedUser(t, db, tenant), MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Confirmed duplicate device records"}); err != nil {
		t.Fatal(err)
	}
	for i, tc := range cases {
		var status, ref string
		if err := db.QueryRow(`SELECT i.status,i.source_ref FROM software_installs i JOIN software_products p ON p.tenant_id=i.tenant_id AND p.id=i.product_id WHERE i.tenant_id=$1 AND i.asset_id=$2 AND p.name=$3`, tenant, survivor, tc.name).Scan(&status, &ref); err != nil || status != tc.want {
			t.Fatalf("%s software state=%s err=%v", tc.name, status, err)
		}
		wantRef := "old"
		if tc.want == "active" {
			wantRef = "new"
		}
		if ref != wantRef {
			t.Fatalf("%s provenance=%s", tc.name, ref)
		}
		want := tc.want
		if want == "removed" {
			want = "closed"
		}
		if err := db.QueryRow(`SELECT status,source_ref FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2 AND port=$3`, tenant, survivor, 8440+i).Scan(&status, &ref); err != nil || status != want || ref != wantRef {
			t.Fatalf("%s endpoint state=%s source=%s err=%v", tc.name, status, ref, err)
		}
	}
	for kind, want := range map[string]int{"measured": 2, "imported": 1, "declared": 99} {
		var count int
		var at time.Time
		if err := db.QueryRow(`SELECT value::text::int,observed_at FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND key='sw.package_count' AND source_kind=$3`, tenant, survivor, kind).Scan(&count, &at); err != nil || count != want || !at.Equal(old) {
			t.Fatalf("%s package count=%d at=%v err=%v", kind, count, at, err)
		}
	}
}

func TestIntegration_MergePreview_RetainedContextsInvalidateRevisionAndRemainAuditable(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewMergeProposalService(db)
	survivor := seedAsset(t, db, tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
	source := seedAsset(t, db, tenant, "source.example.test", "server", "hardware.computer.server", "production", 0, 0)
	observation := uuid.New()
	if _, err := db.Exec(`INSERT INTO identity_observations(id,tenant_id,fingerprint,source_kind,source_ref,evidence,asset_id,first_seen_at,last_seen_at) VALUES($1::uuid,$2,$1::text,'measured','controller','{}',$3,now()-interval '1 day',now()-interval '1 day')`, observation, tenant, source); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identity_observation_peer_contexts(tenant_id,context_id,observation_id,origin_asset_id,payload,observed_at) VALUES($1,'peer-receipt',$2,$3,'{}',now()-interval '1 day')`, tenant, observation, source); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identity_observation_cloud_contexts(tenant_id,observation_id,receipt_key,context_enc,observed_at) VALUES($1,$2,'cloud-receipt','enc:v1:opaque-test-context',now()-interval '1 day')`, tenant, observation); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identity_enrichment_jobs(tenant_id,observation_id,generation,action,executor_scope,plan) VALUES($1,$2,'generation','configured_source','configured_sources','{}')`, tenant, observation); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identity_source_refreshes(tenant_id,id,observation_id,fingerprint,state) VALUES($1,$2,$2,'fingerprint','queued')`, tenant, observation); err != nil {
		t.Fatal(err)
	}
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}
	preview, err := svc.PreviewMerge(t.Context(), tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE identity_observation_peer_contexts SET payload='{"new_evidence":true}' WHERE tenant_id=$1 AND observation_id=$2`, tenant, observation); err != nil {
		t.Fatal(err)
	}
	actor := seedUser(t, db, tenant)
	request := MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Operator verified device against controller and provider"}
	if _, err := svc.ExecuteMerge(t.Context(), tenant, uuid.Nil, actor, request); !errors.Is(err, ErrMergePreviewChanged) {
		t.Fatalf("changed retained evidence accepted: %v", err)
	}
	preview, err = svc.PreviewMerge(t.Context(), tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"identity_enrichment_jobs", "identity_source_refreshes"} {
		if _, err := db.Exec(`UPDATE `+table+` SET state='completed' WHERE tenant_id=$1 AND observation_id=$2`, tenant, observation); err != nil {
			t.Fatal(err)
		}
		request.Revision = preview.Revision
		if _, err := svc.ExecuteMerge(t.Context(), tenant, uuid.Nil, actor, request); !errors.Is(err, ErrMergePreviewChanged) {
			t.Fatalf("changed enrichment job accepted: %v", err)
		}
		preview, err = svc.PreviewMerge(t.Context(), tenant, uuid.Nil, selection)
		if err != nil {
			t.Fatal(err)
		}
	}
	request.Revision = preview.Revision
	result, err := svc.ExecuteMerge(t.Context(), tenant, uuid.Nil, actor, request)
	if err != nil {
		t.Fatal(err)
	}
	var linked uuid.UUID
	if err := db.QueryRow(`SELECT asset_id FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, observation).Scan(&linked); err != nil || linked != survivor {
		t.Fatalf("link=%s err=%v", linked, err)
	}
	for _, table := range []string{"identity_enrichment_jobs", "identity_source_refreshes"} {
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM asset_merge_record_snapshots WHERE tenant_id=$1 AND merge_id=$2 AND record_table=$3`, tenant, result.ID, table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("audit %s=%d err=%v", table, count, err)
		}
		if err := db.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id=$1 AND observation_id=$2 AND state='completed'`, tenant, observation).Scan(&count); err != nil || count != 1 {
			t.Fatalf("retained job %s=%d err=%v", table, count, err)
		}
	}
	for _, table := range []string{"identity_observation_peer_contexts", "identity_observation_cloud_contexts"} {
		var count int
		if err := db.QueryRow(`SELECT count(*) FROM asset_merge_record_snapshots WHERE tenant_id=$1 AND merge_id=$2 AND record_table=$3`, tenant, result.ID, table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("audit %s=%d err=%v", table, count, err)
		}
		if err := db.QueryRow(`SELECT count(*) FROM `+table+` WHERE tenant_id=$1 AND observation_id=$2 AND materialized_at IS NULL`, tenant, observation).Scan(&count); err != nil || count != 1 {
			t.Fatalf("pending context %s=%d err=%v", table, count, err)
		}
	}
}

func TestIntegration_MergePreview_PreservesDeclaredDonorNamesAgainstPromotion(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	survivor := seedAsset(t, db, tenant, "survivor.example.test", "server", "hardware.computer.server", "production", 0, 0)
	source := seedAsset(t, db, tenant, "operator.example.test", "server", "hardware.computer.server", "production", 0, 0)
	if _, err := db.Exec(`UPDATE assets SET hostname=NULL,display_name=NULL,metadata='{"name_source_kind":"measured-passive","preserve_me":true}' WHERE id=$1`, survivor); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE assets SET metadata='{"name_source_kind":"declared","do_not_copy":true}' WHERE id=$1`, source); err != nil {
		t.Fatal(err)
	}
	svc := NewMergeProposalService(db)
	selection := MergeSelection{SourceAssetIDs: []uuid.UUID{source}, SurvivorAssetID: survivor}
	preview, err := svc.PreviewMerge(t.Context(), tenant, uuid.Nil, selection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteMerge(t.Context(), tenant, uuid.Nil, seedUser(t, db, tenant), MergeExecutionRequest{MergeSelection: selection, Revision: preview.Revision, Reason: "Confirmed same operator-named device"}); err != nil {
		t.Fatal(err)
	}
	repo := identitypg.New(raw)
	if err := repo.PromoteNames(t.Context(), identity.AssetRef{ID: survivor.String(), TenantID: tenant.String()}, "better-observed.example.test", "better-observed.example.test", "measured-active"); err != nil {
		t.Fatal(err)
	}
	var name, kind string
	var preserved, copied bool
	if err := db.QueryRow(`SELECT hostname,metadata->>'name_source_kind',metadata ? 'preserve_me',metadata ? 'do_not_copy' FROM assets WHERE id=$1`, survivor).Scan(&name, &kind, &preserved, &copied); err != nil {
		t.Fatal(err)
	}
	if name != "operator.example.test" || kind != "declared" || !preserved || copied {
		t.Fatalf("name=%s provenance=%s preserved=%v copied=%v", name, kind, preserved, copied)
	}
}
