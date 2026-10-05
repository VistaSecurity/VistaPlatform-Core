// Package intakematrix is the shared fixture and recorder behind the identity
// intake characterization matrix: one table per service that drives the SAME
// device evidence through every intake path and records what each path did
// with it.
//
// It exists because the paths do not agree. Each adapter decides an
// observation's scope, its dynamic flag and its admission flags for itself,
// and several paths write identifiers or endpoints without the engine at all.
// The matrix pins TODAY's answer for every path, so a change to one adapter
// shows up as exactly the rows it moves. README.md in this package says how to
// read and update a row.
//
// The fixture is modelled on a gateway that owns its addresses in three
// different kinds of place:
//
//   - DynamicAddr, inside DynamicCIDR, a segment flagged dynamic by a
//     measurement (`dynamic_source=measured`) — the LAN a router serves DHCP on;
//   - StaticAddr, inside StaticCIDR, a segment nobody has flagged;
//   - TenantAddr, inside no segment at all, so it is scoped to the tenant
//     default.
//
// The established asset holds an ip_address identifier for each (the dynamic
// and tenant ones measured, the static one declared), plus the device's MAC
// and SSH host key, so "the same device" is literally the same device: every
// evidence shape the matrix sends names identifiers this asset already owns.
package intakematrix

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
)

// Private (RFC 1918) addresses, as a gateway's are: a public address in no
// segment classifies third_party and is routed to external_connections before
// identity runs, which would characterize ownership classification instead of
// identity. 10.20.0.0/16 is no lab or customer range (the public export rejects
// those). The MAC is an RFC 7042 universally-administered documentation MAC — a
// locally-administered one would be dropped before the engine saw it.
const (
	DynamicCIDR = "10.20.1.0/24"
	DynamicAddr = "10.20.1.1"
	StaticCIDR  = "10.20.2.0/24"
	StaticAddr  = "10.20.2.1"
	TenantAddr  = "10.20.9.2"

	MAC        = "00:00:5e:00:53:01"
	SSHHostKey = "SHA256:intake-matrix-gateway-host-key-aaaaaaaaaaaaaaaaaaaa"
	AssetName  = "matrix-gateway"
)

// Ports are the three listeners the gateway answers on.
var Ports = []int{443, 8443, 9443}

// Place is where an address sits relative to the tenant's segments.
type Place int

const (
	InDynamicSegment Place = iota
	InStaticSegment
	InNoSegment
)

// Places is every Place, in table order.
var Places = []Place{InDynamicSegment, InStaticSegment, InNoSegment}

func (p Place) String() string {
	switch p {
	case InDynamicSegment:
		return "dyn_segment"
	case InStaticSegment:
		return "static_segment"
	case InNoSegment:
		return "no_segment"
	}
	return "unknown_place"
}

// Addr is the fixture address at this place.
func (p Place) Addr() string {
	switch p {
	case InDynamicSegment:
		return DynamicAddr
	case InStaticSegment:
		return StaticAddr
	}
	return TenantAddr
}

// Shape is which device-binding identifiers ride along with the address.
type Shape struct {
	MAC    bool
	SSHKey bool
}

// Shapes is every evidence shape, in table order.
var Shapes = []Shape{{}, {MAC: true}, {SSHKey: true}, {MAC: true, SSHKey: true}}

func (s Shape) String() string {
	out := "ip"
	if s.MAC {
		out += "+mac"
	}
	if s.SSHKey {
		out += "+ssh"
	}
	return out
}

// Fixture is one tenant's copy of the gateway scenario.
type Fixture struct {
	DB             *sql.DB
	Tenant         uuid.UUID
	DynamicSegment uuid.UUID
	StaticSegment  uuid.UUID
	// Asset is the established gateway: monitoring, identity established.
	Asset uuid.UUID
	Now   time.Time
}

// Setup builds the fixture in tenant, which the caller took with
// testdb.NewTenant (and which is cleaned up with it). db must be an owner
// connection: the fixture writes rows a tenant role may not.
func Setup(t *testing.T, db *sql.DB, tenant uuid.UUID) *Fixture {
	t.Helper()
	ctx := context.Background()
	f := &Fixture{
		DB: db, Tenant: tenant, DynamicSegment: uuid.New(), StaticSegment: uuid.New(),
		Now: time.Now().UTC().Truncate(time.Microsecond),
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("intakematrix fixture: %s: %v", q, err)
		}
	}
	exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment) VALUES($1,$2,'matrix dynamic LAN','cidr',$3,true,'production')`, f.DynamicSegment, tenant, DynamicCIDR)
	exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment) VALUES($1,$2,'matrix static LAN','cidr',$3,true,'production')`, f.StaticSegment, tenant, StaticCIDR)
	// Enforce admission, as on the cluster this matrix was written about, and
	// room for the assets the create rows mint.
	exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant)
	exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason) SELECT $1,id,'{"quantity":50}','intake matrix fixture' FROM billable_items WHERE key='max_assets'`, tenant)

	repo := pgidentity.New(db)
	seen := f.Now.Add(-24 * time.Hour)
	measured := func(ref string) identity.Source { return identity.Source{Kind: identity.SourceMeasured, Ref: ref} }
	ref, err := repo.CreateAsset(ctx, tenant.String(), identity.NewAsset{
		ClassKey: string(assetclass.KeyRouter), ClassSourceKind: identity.ClassSourceDeclared, ClassConfidence: 1,
		DisplayName: AssetName, Hostname: AssetName, PrimaryAddress: TenantAddr,
		Status: identity.StatusMonitoring, IdentityStatus: string(identity.IdentityEstablished),
		DiscoveryMethod: "intake-matrix", FirstSeenAt: seen, LastSeenAt: seen,
		Identifiers: []identity.Identifier{
			// The dynamic-LAN address, as a sensor measured it.
			{Kind: identity.KindIPAddress, Value: DynamicAddr, Scope: f.DynamicSegment.String(), Confidence: 1, Source: measured("sensor"), SeenAt: seen},
			// The static-LAN address, as an operator declared it.
			{Kind: identity.KindIPAddress, Value: StaticAddr, Scope: f.StaticSegment.String(), Confidence: 1, Source: identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}, SeenAt: seen},
			// The address in no segment, as interrogation measured it.
			{Kind: identity.KindIPAddress, Value: TenantAddr, Scope: identity.ScopeTenantDefault, Confidence: 1, Source: measured("interrogation"), SeenAt: seen},
			{Kind: identity.KindMACAddress, Value: MAC, Confidence: 1, Source: measured("sensor"), SeenAt: seen},
			{Kind: identity.KindSSHHostKeyFingerprint, Value: SSHHostKey, Confidence: 1, Source: measured("scan"), SeenAt: seen},
		},
	})
	if err != nil {
		t.Fatalf("intakematrix fixture: create the established asset: %v", err)
	}
	f.Asset = uuid.MustParse(ref.ID)

	// The DHCP posture the way a controller states it: measured, with the
	// gateway as the device that answered.
	res, err := pgidentity.RecordSegmentPosture(ctx, db, tenant.String(), f.DynamicSegment.String(),
		pgidentity.PostureMeasured, true, pgidentity.PostureEvidence{SourceAssetID: f.Asset.String(), ObservedAt: seen})
	if err != nil || !res.Written {
		t.Fatalf("intakematrix fixture: record the dynamic posture: written=%v err=%v", res.Written, err)
	}
	return f
}

// Scope is the identifier scope an address at this place carries in the
// fixture: the segment id, or the tenant default.
func (f *Fixture) Scope(p Place) string {
	switch p {
	case InDynamicSegment:
		return f.DynamicSegment.String()
	case InStaticSegment:
		return f.StaticSegment.String()
	}
	return identity.ScopeTenantDefault
}

// Symbol renders a scope string as the matrix spells it, so expectations hold
// no uuids: `dyn`, `static`, `tenant`, `-` for empty, `other` for anything
// else (a scope the fixture did not create is itself a finding).
func (f *Fixture) Symbol(scope string) string {
	switch scope {
	case f.DynamicSegment.String():
		return "dyn"
	case f.StaticSegment.String():
		return "static"
	case identity.ScopeTenantDefault:
		return "tenant"
	case "":
		return "-"
	}
	return "other"
}
