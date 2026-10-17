package dcimfixture

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/uuid"
)

// The VPN populator (DCIM BUILD_PLAN row 4.3): a small catalogue of IKE and
// IPsec proposals (one modern, one legacy), and one IPsec tunnel per
// VPNAssetsPerTunnel assets, each with its own IKE / IPsec policy and profile
// and a termination on its asset's last interface — the rows the Tunnels lens,
// Settings → VPN Policies and the tunnel.* query fields read. A proposal's
// algorithm ids are resolved from the `algorithms` catalogue when the test
// database is seeded, and left NULL (unassessed) when it is not.
const VPNAssetsPerTunnel = 50

// VPNTunnels is how many tunnels the populator writes for n assets.
func VPNTunnels(n int) int {
	if n == 0 {
		return 0
	}
	return (n + VPNAssetsPerTunnel - 1) / VPNAssetsPerTunnel
}

func populateVPN(ctx context.Context, tx *sql.Tx, e *Env) (int, error) {
	if len(e.Interfaces) == 0 {
		return -1, nil
	}
	alg := func(code string) any {
		var id uuid.UUID
		if err := tx.QueryRowContext(ctx, `SELECT id FROM algorithms WHERE code = $1`, code).Scan(&id); err != nil {
			return nil
		}
		return id
	}
	type proposal struct {
		name, enc, auth, encCode, authCode string
		group                              int
		groupCode                          string
	}
	ike := []proposal{
		{"Fixture IKE aes-256-gcm / group 20", "aes-256-gcm", "", "ENCR-AES-GCM-256", "", 20, "DH-ECP-384"},
		{"Fixture IKE 3des-cbc / hmac-sha1 / group 2", "3des-cbc", "hmac-sha1", "ENCR-3DES", "AUTH-HMAC-SHA1-96", 2, "DH-1024"},
	}
	var ikeIDs, espIDs []uuid.UUID
	for _, p := range ike {
		e.Witness(p.name)
		var id uuid.UUID
		if err := tx.QueryRowContext(ctx, `INSERT INTO ike_proposals (tenant_id, name, encryption_algorithm, authentication_algorithm, "group",
			encryption_algorithm_id, authentication_algorithm_id, group_algorithm_id) VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, $7, $8) RETURNING id`,
			e.Tenant, p.name, p.enc, p.auth, p.group, alg(p.encCode), alg(p.authCode), alg(p.groupCode)).Scan(&id); err != nil {
			return 0, err
		}
		ikeIDs = append(ikeIDs, id)
	}
	for _, p := range []proposal{{"Fixture IPsec aes-256-gcm", "aes-256-gcm", "", "ENCR-AES-GCM-256", "", 0, ""}} {
		e.Witness(p.name)
		var id uuid.UUID
		if err := tx.QueryRowContext(ctx, `INSERT INTO ipsec_proposals (tenant_id, name, encryption_algorithm, encryption_algorithm_id)
			VALUES ($1, $2, $3, $4) RETURNING id`, e.Tenant, p.name, p.enc, alg(p.encCode)).Scan(&id); err != nil {
			return 0, err
		}
		espIDs = append(espIDs, id)
	}
	// The last interface of every VPNAssetsPerTunnel-th asset.
	last := map[uuid.UUID]uuid.UUID{}
	for _, i := range e.Interfaces {
		last[i.AssetID] = i.ID
	}
	n := 0
	for a := 0; a < len(e.Assets); a += VPNAssetsPerTunnel {
		asset := e.Assets[a]
		iface, ok := last[asset.ID]
		if !ok {
			continue
		}
		name := fmt.Sprintf("fixture-tunnel-%04d", n+1)
		e.Witness(name)
		var ikePol, espPol, prof, tun uuid.UUID
		if err := tx.QueryRowContext(ctx, `INSERT INTO ike_policies (tenant_id, name, version, preshared_key_present) VALUES ($1, $2, $3, true) RETURNING id`,
			e.Tenant, name+" IKE", 1+n%2).Scan(&ikePol); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ike_policy_proposals (tenant_id, ike_policy_id, ike_proposal_id) VALUES ($1, $2, $3)`,
			e.Tenant, ikePol, ikeIDs[n%len(ikeIDs)]); err != nil {
			return 0, err
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO ipsec_policies (tenant_id, name, pfs_group, pfs_group_algorithm_id) VALUES ($1, $2, 14, $3) RETURNING id`,
			e.Tenant, name+" IPsec", alg("DH-MODP-2048")).Scan(&espPol); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO ipsec_policy_proposals (tenant_id, ipsec_policy_id, ipsec_proposal_id) VALUES ($1, $2, $3)`,
			e.Tenant, espPol, espIDs[0]); err != nil {
			return 0, err
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO ipsec_profiles (tenant_id, name, ike_policy_id, ipsec_policy_id) VALUES ($1, $2, $3, $4) RETURNING id`,
			e.Tenant, name, ikePol, espPol).Scan(&prof); err != nil {
			return 0, err
		}
		if err := tx.QueryRowContext(ctx, `INSERT INTO tunnels (tenant_id, name, encapsulation, ipsec_profile_id, source_kind, observed_peer_addresses)
			VALUES ($1, $2, 'ipsec-tunnel', $3, 'measured', ARRAY[$4::inet]) RETURNING id`,
			e.Tenant, name, prof, fmt.Sprintf("203.0.113.%d", 1+n%254)).Scan(&tun); err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO tunnel_terminations (tenant_id, tunnel_id, termination_id, source_kind) VALUES ($1, $2, $3, 'measured')`,
			e.Tenant, tun, iface); err != nil {
			return 0, err
		}
		n++
	}
	return n, nil
}
