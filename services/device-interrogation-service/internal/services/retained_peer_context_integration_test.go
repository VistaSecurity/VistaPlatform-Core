package services

// A retained peer described by more than one identifier must reach Postgres.
//
// The key its receipt envelope was stored under in retainedPeerContext.Peers
// joined the identifiers with NUL. encoding/json writes that as \u0000, the
// payload column is jsonb, and jsonb refuses the escape (22P05). The resolution
// transaction failed, resolvePeer returned the error, and persist dropped the
// fact or edge: on a live UniFi interrogation 139 of 143 facts and every edge.
//
// TestIntegration_ObservationSink_RetainsWeakPeerFactsAndEdges never saw it
// because its peer has one identifier, so its key had no separator in it.
//
// MUTATION: make retainedPeerKey return identifierKey(peer) and this fails
// with `pq: unsupported Unicode escape sequence (22P05)`.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_ObservationSink_RetainsMultiIdentifierPeerContext(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	app.SetMaxOpenConns(1)
	self := subjectAsset(t, owner, tenant, "controller")
	if _, err := owner.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}')`, tenant); err != nil {
		t.Fatal(err)
	}

	sink := NewObservationSink(app)
	_, repo, err := sink.engine()
	if err != nil {
		t.Fatal(err)
	}
	// Admission is what retains a weakly-evidenced peer instead of creating an
	// asset for it; force it on whatever this build's capabilities say.
	if sink.eng, err = identity.New(identity.Config{Repo: repo, AdmissionEnabled: true}); err != nil {
		t.Fatal(err)
	}

	// Three identifiers and no identity evidence: an advertised neighbour, so
	// admission retains it rather than resolving it.
	peer := di.PeerRef{DisplayName: "ap-two", Identifiers: []di.PeerIdentifier{
		{Kind: di.IdentifierMACAddress, Value: macUnclassedByRule},
		{Kind: di.IdentifierIPAddress, Value: "192.0.2.44"},
		{Kind: di.IdentifierHostname, Value: "ap-two.local"},
	}}
	obs := InterrogationObservations{
		ObservedAt:    time.Now().UTC().Truncate(time.Microsecond),
		Facts:         []di.FactObservation{{Subject: peer, Key: "hw.model", Value: "Access point", Confidence: .8}},
		Relationships: []di.RelationshipObservation{{Type: string(relationships.ConnectsTo), Direction: di.SubjectToPeer, Peer: peer}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sink.Persist(ctx, tenant, self, peerSource("interrogation:multi-identifier-peer"), obs); err != nil {
		t.Fatalf("persisting a retained multi-identifier peer dropped observations: %v", err)
	}

	if n := countRows(t, owner, `SELECT count(*) FROM assets WHERE tenant_id=$1`, tenant); n != 1 {
		t.Fatalf("the peer was resolved to an asset (%d assets), so the retained path was not exercised", n)
	}
	var observation uuid.UUID
	var body []byte
	if err := owner.QueryRow(`SELECT observation_id,payload FROM identity_observation_peer_contexts WHERE tenant_id=$1`, tenant).Scan(&observation, &body); err != nil {
		t.Fatalf("no retained peer context row: %v", err)
	}
	if observation == uuid.Nil {
		t.Fatal("peer context carries no observation id")
	}

	// The row has to read back the way replay reads it: the envelope found by
	// the same key it was stored under.
	var state retainedPeerContext
	if err := json.Unmarshal(body, &state); err != nil {
		t.Fatalf("decode retained payload: %v", err)
	}
	if len(state.Peers) != 1 {
		t.Fatalf("retained %d peer envelopes, want 1", len(state.Peers))
	}
	for key := range state.Peers {
		if raw, err := hex.DecodeString(key); err != nil || len(raw) != 32 {
			t.Fatalf("peer key %q is not a hex SHA-256", key)
		}
	}
	envelope, ok := state.retainedPeer(peer)
	if !ok {
		t.Fatal("the retained envelope cannot be found by the peer it was stored for")
	}
	if len(envelope.Identifiers) != len(peer.Identifiers) {
		t.Fatalf("envelope carries %d identifiers, want %d", len(envelope.Identifiers), len(peer.Identifiers))
	}
}
