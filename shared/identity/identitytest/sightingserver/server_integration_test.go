package sightingserver_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest/sightingserver"
	"github.com/vistasecurity/vistaplatform/shared/identity/sightingclient"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_SightingServer_ResolvesOverTheRoute: a signed post creates,
// the same device posted again matches, and an unsigned post is refused.
func TestIntegration_SightingServer_ResolvesOverTheRoute(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db).String()
	client, resolver := sightingserver.Start(t, db)

	s := identity.Sighting{
		TenantID: tenant, Channel: identity.ChannelAuthenticatedSession, ObservedAt: time.Now().UTC(),
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "agent:test", Mode: identity.ModeActive},
		Identifiers: []identity.SightedIdentifier{{Kind: identity.KindAgentID, Value: "11111111-2222-3333-4444-555555555555"}},
	}
	first, err := client.Post(context.Background(), tenant, []identity.Sighting{s})
	if err != nil {
		t.Fatal(err)
	}
	if first[0].Outcome != identity.OutcomeCreated || first[0].AssetID == "" {
		t.Fatalf("first: %+v", first[0])
	}
	s.ObservedAt = s.ObservedAt.Add(time.Minute)
	second, err := client.Post(context.Background(), tenant, []identity.Sighting{s})
	if err != nil {
		t.Fatal(err)
	}
	if second[0].Outcome != identity.OutcomeMatched || second[0].AssetID != first[0].AssetID {
		t.Fatalf("second: %+v, want matched %s", second[0], first[0].AssetID)
	}
	if resolver.Calls() != 2 {
		t.Errorf("calls %d", resolver.Calls())
	}

	unsigned := sightingclient.New(resolver.URL, nil, sightingclient.WithSigner(func(*http.Request) {}), sightingclient.WithRetry(1, 0))
	var rej *sightingclient.RejectedError
	if _, err := unsigned.Post(context.Background(), tenant, []identity.Sighting{s}); !errors.As(err, &rej) || rej.Status != http.StatusUnauthorized {
		t.Fatalf("unsigned post: %v", err)
	}
}
