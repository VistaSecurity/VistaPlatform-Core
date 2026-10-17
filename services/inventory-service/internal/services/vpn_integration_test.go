package services

// VPN (DCIM row 4.3) over the real schema. Each test names the rule it holds
// and the mutation that must turn it red.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// A device sighting carrying a tunnel that offers DH group 14 with SHA-1,
// through the REAL internal sightings intake: the tunnel, its termination and
// policies are written, and the tunnel's IKE configuration is a crypto
// configuration whose catalogue risk is non-zero and whose PQC class is
// needs-migration — scored by the same catalogue and denylist as TLS.
//
// Mutations: drop the `link(...)` calls in materializeTunnelCrypto → the risk
// is unassessed and the PQC class unclassified, red; drop the UpsertObservedTunnels
// call from IngestSightings → no tunnel, red.
func TestIntegration_VPN_SightingTunnelIsScoredThroughTheCatalogue(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	sg := identity.Sighting{
		Source:     identity.Source{Kind: identity.SourceMeasured, Ref: interrogationSourcePrefix + "fw-edge", Mode: identity.ModeActive},
		Channel:    identity.ChannelAuthenticatedSession,
		ObservedAt: time.Now().UTC(),
		ReceiptID:  "vpn-receipt-1",
		Identifiers: []identity.SightedIdentifier{
			{Kind: identity.KindSerialNumber, Value: "FGT60F-VPN-001"},
			{Kind: identity.KindIPAddress, Value: "198.51.100.40"},
		},
		Interfaces: []identity.ObservedInterface{{Name: "to-branch", Type: "virtual"}},
		Tunnels: []identity.ObservedTunnel{{
			Name: "to-branch", Encapsulation: "ipsec-tunnel", LocalInterface: "to-branch", PeerIP: "203.0.113.9",
			IKEVersion: 1, IKEMode: "main", AuthenticationMethod: "preshared-keys", PresharedKeyPresent: true,
			IKEProposals:   []identity.ObservedIKEProposal{{Encryption: "aes256", Integrity: "sha1", Group: 14, LifetimeSeconds: 86400}},
			IPsecProposals: []identity.ObservedIPsecProposal{{Encryption: "aes128", Integrity: "sha1"}},
			PFSGroup:       14,
		}},
	}
	res, err := svc.IngestSightings(context.Background(), tenant, []SightingItem{{Sighting: sg}})
	if err != nil {
		t.Fatalf("IngestSightings: %v", err)
	}
	if res[0].AssetID == "" {
		t.Fatalf("the sighting resolved to no asset: %+v", res[0])
	}
	asset := uuid.MustParse(res[0].AssetID)

	var tunnelID uuid.UUID
	var peers []string
	if err := raw.QueryRow(`SELECT id, observed_peer_addresses::text[] FROM tunnels WHERE tenant_id = $1 AND name = 'to-branch'`, tenant).
		Scan(&tunnelID, pq.Array(&peers)); err != nil {
		t.Fatalf("no tunnel was recorded: %v", err)
	}
	if len(peers) != 1 || !strings.HasPrefix(peers[0], "203.0.113.9") {
		t.Errorf("peer addresses = %v", peers)
	}
	var terminations int
	if err := raw.QueryRow(`SELECT count(*) FROM tunnel_terminations tt JOIN interfaces i ON i.id = tt.termination_id
	                         WHERE tt.tenant_id = $1 AND tt.tunnel_id = $2 AND i.asset_id = $3`, tenant, tunnelID, asset).Scan(&terminations); err != nil || terminations != 1 {
		t.Errorf("terminations on the device = %d (%v), want 1", terminations, err)
	}
	var pskPresent bool
	if err := raw.QueryRow(`SELECT preshared_key_present FROM ike_policies WHERE tenant_id = $1 AND name = 'to-branch IKE'`, tenant).Scan(&pskPresent); err != nil || !pskPresent {
		t.Errorf("IKE policy preshared_key_present = %v (%v)", pskPresent, err)
	}

	var implID uuid.UUID
	var risk *int
	if err := raw.QueryRow(`SELECT id, risk_score FROM crypto_implementations WHERE tenant_id = $1 AND asset_id = $2 AND protocol = 'IKE' AND deleted_at IS NULL`,
		tenant, asset).Scan(&implID, &risk); err != nil {
		t.Fatalf("no IKE crypto configuration for the tunnel: %v", err)
	}
	if risk == nil || *risk <= 0 {
		t.Fatalf("the IKE configuration's catalogue risk = %v, want non-zero (group 14 and HMAC-SHA1-96 are catalogued)", risk)
	}

	var vulnerable bool
	var vulnCodes []string
	q := `WITH ` + cryptoassess.PQCClassCTE(`SELECT id, tenant_id FROM crypto_implementations WHERE id = $1`, "$2", "$3") +
		` SELECT vulnerable, vulnerable_codes FROM impl_class`
	if err := raw.QueryRow(q, implID, pq.Array(pqcComponentRoles), pq.Array(quantumVulnerablePrimitives)).Scan(&vulnerable, pq.Array(&vulnCodes)); err != nil {
		t.Fatal(err)
	}
	if !vulnerable || len(vulnCodes) == 0 || vulnCodes[0] != "DH-MODP-2048" {
		t.Fatalf("PQC class: vulnerable=%v codes=%v — want needs-migration on DH-MODP-2048", vulnerable, vulnCodes)
	}

	// The Tunnels lens's row carries the same answer.
	rows, _, err := NewVPNService(raw).List(context.Background(), tenant, "tunnels", IPAMListParams{Limit: 10})
	if err != nil || len(rows) != 1 {
		t.Fatalf("list tunnels: %v %d", err, len(rows))
	}
	var row struct {
		PQC     string                 `json:"pqc_status"`
		Weakest *struct{ Code string } `json:"weakest_component"`
		Version *int                   `json:"ike_version"`
		Terms   []any                  `json:"terminations"`
	}
	if err := json.Unmarshal(rows[0], &row); err != nil {
		t.Fatal(err)
	}
	if row.PQC != "needs_migration" || row.Weakest == nil || row.Weakest.Code != "AUTH-HMAC-SHA1-96" || row.Version == nil || *row.Version != 1 || len(row.Terms) != 1 {
		t.Fatalf("tunnel row = %s", rows[0])
	}

	// Re-observed: one tunnel, one IKE configuration — refreshed, not appended.
	sg.ReceiptID = "vpn-receipt-2"
	if _, err := svc.IngestSightings(context.Background(), tenant, []SightingItem{{Sighting: sg}}); err != nil {
		t.Fatal(err)
	}
	var tunnels, ikeRows, obs int
	_ = raw.QueryRow(`SELECT count(*), max(observation_count) FROM tunnels WHERE tenant_id = $1`, tenant).Scan(&tunnels, &obs)
	_ = raw.QueryRow(`SELECT count(*) FROM crypto_implementations WHERE tenant_id = $1 AND protocol = 'IKE' AND deleted_at IS NULL`, tenant).Scan(&ikeRows)
	if tunnels != 1 || ikeRows != 1 || obs != 2 {
		t.Fatalf("after a re-observation: %d tunnels (observations %d), %d IKE configurations — want 1 (2), 1", tunnels, obs, ikeRows)
	}
}

// Tunnels are tenant-isolated under the app role: another tenant's list does
// not see them, and an insert naming another tenant is refused by the policy
// (RLS USING doubles as WITH CHECK).
//
// Mutation: drop 'tunnels' from the RLS loop of the 4.3 schema block → red.
func TestIntegration_VPN_TunnelsAreTenantIsolated(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	a, b := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)
	svc := NewVPNService(app)
	ctx := ipamTestCtx()
	if _, err := svc.Create(ctx, a, "tunnels", []byte(`{"name":"hq-to-dc","encapsulation":"gre"}`)); err != nil {
		t.Fatalf("create: %v", err)
	}
	rows, total, err := svc.List(ctx, b, "tunnels", IPAMListParams{Limit: 10})
	if err != nil || total != 0 || len(rows) != 0 {
		t.Fatalf("tenant B sees %d tunnels (%v)", total, err)
	}
	err = database.WithTenantTx(context.Background(), &database.DB{DB: sqlx.NewDb(app, "postgres")}, b, func(tx *sqlx.Tx) error {
		_, err := tx.Exec(`INSERT INTO tunnels (tenant_id, name, encapsulation) VALUES ($1, 'smuggled', 'gre')`, a)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Fatalf("an insert for tenant A under tenant B's session was not refused by RLS: %v", err)
	}
}

// An IKE proposal created through the API resolves its algorithms to the
// catalogue (the link the scoring reads) and to NetBox's spelling.
//
// Mutation: make prepareIKEProposal not set group_algorithm_id → red.
func TestIntegration_VPN_ProposalResolvesCatalogueRows(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)
	svc := NewVPNService(app)
	ctx := ipamTestCtx()
	raw, err := svc.Create(ctx, tenant, "ike-proposals", []byte(`{"name":"legacy","encryption_algorithm":"3des","authentication_algorithm":"md5","group":2}`))
	if err != nil {
		t.Fatal(err)
	}
	var p struct {
		Enc   string `json:"encryption_algorithm"`
		Group *struct {
			Code string `json:"code"`
		} `json:"group_assessment"`
		Auth *struct {
			Code string `json:"code"`
			Risk int    `json:"risk_score"`
		} `json:"authentication_assessment"`
	}
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if p.Enc != "3des-cbc" || p.Group == nil || p.Group.Code != "DH-1024" || p.Auth == nil || p.Auth.Code != "AUTH-HMAC-MD5-96" || p.Auth.Risk < 90 {
		t.Fatalf("proposal = %s", raw)
	}
	// A policy's proposals round-trip through the junction.
	pol, err := svc.Create(ctx, tenant, "ike-policies", []byte(`{"name":"legacy-policy","version":1,"proposals":["`+uuidOf(t, raw)+`"]}`))
	if err != nil || !strings.Contains(string(pol), uuidOf(t, raw)) {
		t.Fatalf("policy = %s (%v)", pol, err)
	}
}

func uuidOf(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	var m struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m.ID
}
