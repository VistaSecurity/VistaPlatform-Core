package identity_test

// The engine half of the claimed-address rule (claimed.go), for an
// observation built by hand rather than through Intake. Intake refuses a claim
// that is not first-hand; the engine must not honour one that reached it
// another way. The full rule is held by identitytest.RunClaimedAddressContract.

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

func TestClaimedAddress_EngineIgnoresAClaimThatIsNotFirstHand(t *testing.T) {
	ctx := context.Background()
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)
	const tenant, seg = "tenant-claim-engine", "seg-lan"

	for name, admission := range map[string]identity.AdmissionEvidence{
		"an l2 frame (direct only)":            {Direct: true},
		"a controller listing (authoritative)": {Authoritative: true},
		"a relayed advertisement":              {Direct: true, Authoritative: true, Relayed: true},
	} {
		t.Run(name, func(t *testing.T) {
			r := memory.New()
			gw, err := r.CreateAsset(ctx, tenant, identity.NewAsset{
				ClassKey: "router", ClassSourceKind: identity.ClassSourceMeasured, Status: identity.StatusMonitoring,
				Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "test"},
				Identifiers: []identity.Identifier{{Kind: identity.KindSerialNumber, Value: "SN-ENGINE-1", Confidence: 1}},
				FirstSeenAt: at, LastSeenAt: at,
			})
			if err != nil {
				t.Fatal(err)
			}
			guess, err := r.CreateAsset(ctx, tenant, identity.NewAsset{
				ClassKey: "unknown_host", ClassSourceKind: identity.ClassSourceMeasured, Status: identity.StatusPendingApproval,
				IdentityStatus: string(identity.IdentityProvisional),
				Source:         identity.Source{Kind: identity.SourceMeasured, Ref: "test"},
				Identifiers:    []identity.Identifier{{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: seg, Confidence: 1}},
				FirstSeenAt:    at, LastSeenAt: at,
			})
			if err != nil {
				t.Fatal(err)
			}
			eng, err := identity.New(identity.Config{Repo: r, ProvisionalInventory: true})
			if err != nil {
				t.Fatal(err)
			}
			_, err = eng.Resolve(ctx, identity.Observation{
				TenantID: tenant, ObservedAt: at.Add(time.Hour), Confidence: 1, Admission: admission,
				Source: identity.Source{Kind: identity.SourceMeasured, Ref: "test", Mode: identity.ModeActive},
				Identifiers: []identity.Identifier{
					{Kind: identity.KindIPAddress, Value: "192.0.2.1", Scope: seg, Confidence: 1, Pinned: true, Claimed: true},
					{Kind: identity.KindSerialNumber, Value: "SN-ENGINE-1", Confidence: 1},
				},
			})
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			owners, err := r.FindByIdentifier(ctx, tenant, identity.KindIPAddress, "192.0.2.1", seg)
			if err != nil {
				t.Fatal(err)
			}
			if len(owners) != 1 || owners[0].ID != guess.ID {
				t.Fatalf("the address is held by %+v, want it left on %s (the gateway is %s): a claim that is not first-hand moved it",
					owners, guess.ID, gw.ID)
			}
		})
	}
}
