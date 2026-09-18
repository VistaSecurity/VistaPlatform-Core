package services

// Merge proposals and edge promotion against a real Postgres.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

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
