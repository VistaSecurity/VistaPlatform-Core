package services

// The observed-tunnel writer (DCIM row 4.3, ADR-0010 D8): what a collector
// read of a device's VPN tunnels — identity.ObservedTunnel on the sighting —
// becomes tunnels, a termination on the device's interface, IKE / IPsec
// proposals and policies, an IPsec profile, AND the tunnel's two crypto
// configurations (protocol IKE for phase 1, IPSec for phase 2), all on the
// engine's transaction, so a sighting's tunnels land with its asset or not at
// all.
//
// The crypto configurations go through the SAME materialization the finding
// ingest uses: upsertCryptoImplementationTracked's natural key (so a tunnel
// re-observed hourly refreshes one row, never appends), the junction to the
// `algorithms` catalogue, and catalogueRiskForImplementation's worst-component
// score, persisted with persistCryptoRiskScore. A tunnel that offers DH group
// 14 is therefore scored by the DH-MODP-2048 row and classified by the PQC
// denylist exactly as a TLS key exchange is — no second opinion.
//
// Identity: a tunnel is (tenant, name) among rows not rejected; proposals are
// content-named ("aes-256-cbc / hmac-sha256 / group 14"), so two tunnels
// offering the same proposal share one row, as an operator would model it in
// NetBox; a tunnel's IKE policy, IPsec policy and profile are named after the
// tunnel. Observed values refresh measured columns only.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// tunnelChangeSource is the object_changes source of an observed tunnel write.
var tunnelChangeSource = changes.IntakeSource("tunnel")

// ObservedTunnelResult is what one recording did, for logs and tests.
type ObservedTunnelResult struct {
	TunnelsCreated, TunnelsUpdated int
	CryptoConfigurations           []uuid.UUID
	Skipped                        []string
}

// maxPolicyName bounds a tunnel-derived name so its suffix still fits the
// 100-character name columns.
const maxPolicyName = 90

type vpnWriter struct {
	ctx    context.Context
	tx     *sql.Tx
	eng    *IPAMService
	tenant uuid.UUID
	asset  uuid.UUID
	at     time.Time
	ref    string
	res    *ObservedTunnelResult
}

// UpsertObservedTunnels records a sighting's tunnels for asset on tx (the
// engine's transaction; app.tenant_id already set).
func UpsertObservedTunnels(ctx context.Context, tx *sqlx.Tx, tenant, asset uuid.UUID, tunnels []identity.ObservedTunnel, src identity.Source, at time.Time) (ObservedTunnelResult, error) {
	var res ObservedTunnelResult
	tunnels, dropped := identity.NormalizeObservedTunnels(tunnels)
	res.Skipped = append(res.Skipped, dropped...)
	if len(tunnels) == 0 {
		return res, nil
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	ref := strings.TrimSpace(src.Ref)
	if ref == "" {
		ref = "intake:tunnel"
	}
	ctx = changes.WithSource(ctx, tunnelChangeSource)
	w := &vpnWriter{ctx: ctx, tx: tx.Tx, eng: newObjectEngine(nil, vpnSpecs()), tenant: tenant, asset: asset, at: at.UTC(), ref: ref, res: &res}
	status, err := w.assetComponentStatus()
	if err != nil {
		return res, err
	}
	for _, t := range tunnels {
		if err := w.tunnel(t, status); err != nil {
			return res, fmt.Errorf("tunnel %q: %w", t.Name, err)
		}
	}
	// The crypto configurations, under the per-asset materialization lock the
	// finding ingest takes, so the two writers never race on one natural key.
	if _, err := tx.ExecContext(ctx, lockAssetMaterializationSQL, assetMaterializationLockKey(tenant, asset)); err != nil {
		return res, fmt.Errorf("lock asset materialization: %w", err)
	}
	for _, t := range tunnels {
		ids, err := materializeTunnelCrypto(ctx, tx, tenant, asset, t, w.at)
		if err != nil {
			return res, fmt.Errorf("tunnel %q crypto configuration: %w", t.Name, err)
		}
		res.CryptoConfigurations = append(res.CryptoConfigurations, ids...)
	}
	return res, nil
}

// assetComponentStatus is the lifecycle status a component the observation
// creates takes from its asset: active on a monitored asset, pending
// otherwise (the asset lifecycle; DATA_MODEL §0).
func (w *vpnWriter) assetComponentStatus() (string, error) {
	var st sql.NullString
	err := w.tx.QueryRowContext(w.ctx, `SELECT asset_status FROM public.assets WHERE tenant_id = $1 AND id = $2`, w.tenant, w.asset).Scan(&st)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if st.String == "monitoring" {
		return "active", nil
	}
	return "pending", nil
}

func (w *vpnWriter) spec(route string) *ipamSpec {
	sp, _ := w.eng.spec(route)
	return sp
}

// findByName returns the id of route's row named name (case-insensitive), or
// uuid.Nil.
func (w *vpnWriter) findByName(table, name, extra string) (uuid.UUID, error) {
	var id uuid.UUID
	err := w.tx.QueryRowContext(w.ctx, fmt.Sprintf(`SELECT id FROM public.%s WHERE tenant_id = $1 AND lower(name) = lower($2) %s ORDER BY created_at LIMIT 1`,
		pq.QuoteIdentifier(table), extra), w.tenant, name).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// ensure creates route's row named name from patch when there is none, and
// otherwise applies the measured fields of patch that differ.
func (w *vpnWriter) ensure(route, name string, patch map[string]any, measured []string) (uuid.UUID, bool, error) {
	sp := w.spec(route)
	id, err := w.findByName(sp.Table, name, "")
	if err != nil {
		return uuid.Nil, false, err
	}
	if id == uuid.Nil {
		patch["name"] = name
		patch["source_kind"] = "measured"
		patch["source_ref"] = w.ref
		row, err := w.eng.createTx(w.ctx, w.tx, sp, w.tenant, patch, tunnelChangeSource)
		if err != nil {
			return uuid.Nil, false, err
		}
		id, err = uuid.Parse(fmt.Sprint(row["id"]))
		return id, true, err
	}
	return id, false, w.applyMeasured(sp, id, patch, measured)
}

// applyMeasured writes the measured fields of patch that differ from the row.
func (w *vpnWriter) applyMeasured(sp *ipamSpec, id uuid.UUID, patch map[string]any, measured []string) error {
	if len(measured) == 0 {
		return nil
	}
	pre, err := getRow(w.ctx, w.tx, sp, id, false)
	if err != nil {
		return err
	}
	upd := map[string]any{}
	for _, k := range measured {
		v, ok := patch[k]
		if !ok {
			continue
		}
		a, _ := json.Marshal(pre[k])
		b, _ := json.Marshal(v)
		if string(a) != string(b) {
			upd[k] = v
		}
	}
	if len(upd) == 0 {
		return nil
	}
	_, err = w.eng.updateTx(w.ctx, w.tx, sp, w.tenant, id, upd, tunnelChangeSource)
	return err
}

func ikeProposalName(p identity.ObservedIKEProposal) string {
	parts := []string{nonEmpty(p.Encryption, "none")}
	if p.Integrity != "" {
		parts = append(parts, p.Integrity)
	}
	if p.Group > 0 {
		parts = append(parts, "group "+strconv.Itoa(p.Group))
	}
	if p.LifetimeSeconds > 0 {
		parts = append(parts, strconv.Itoa(p.LifetimeSeconds)+"s")
	}
	return "IKE " + strings.Join(parts, " / ")
}

func ipsecProposalName(p identity.ObservedIPsecProposal) string {
	parts := []string{nonEmpty(p.Encryption, "none")}
	if p.Integrity != "" {
		parts = append(parts, p.Integrity)
	}
	if p.LifetimeSeconds > 0 {
		parts = append(parts, strconv.Itoa(p.LifetimeSeconds)+"s")
	}
	if p.LifetimeKB > 0 {
		parts = append(parts, strconv.Itoa(p.LifetimeKB)+"KB")
	}
	return "IPsec " + strings.Join(parts, " / ")
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func optInt(n int) any {
	if n <= 0 {
		return nil
	}
	return int64(n)
}

func optStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func truncName(s string) string {
	if len(s) > maxPolicyName {
		return strings.TrimSpace(s[:maxPolicyName])
	}
	return s
}

func (w *vpnWriter) tunnel(t identity.ObservedTunnel, status string) error {
	var profileID uuid.UUID
	if strings.HasPrefix(t.Encapsulation, "ipsec-") && (len(t.IKEProposals) > 0 || len(t.IPsecProposals) > 0) {
		var err error
		if profileID, err = w.profile(t); err != nil {
			return err
		}
	}

	sp := w.spec("tunnels")
	id, err := w.findByName(sp.Table, t.Name, "AND status <> 'rejected'")
	if err != nil {
		return err
	}
	patch := map[string]any{"encapsulation": t.Encapsulation, "operational_status": t.Status}
	if profileID != uuid.Nil {
		patch["ipsec_profile_id"] = profileID.String()
	}
	if id == uuid.Nil {
		patch["name"] = t.Name
		patch["status"] = status
		patch["source_kind"] = "measured"
		patch["source_ref"] = w.ref
		row, err := w.eng.createTx(w.ctx, w.tx, sp, w.tenant, patch, tunnelChangeSource)
		if err != nil {
			return err
		}
		if id, err = uuid.Parse(fmt.Sprint(row["id"])); err != nil {
			return err
		}
		w.res.TunnelsCreated++
	} else {
		if err := w.applyMeasured(sp, id, patch, []string{"encapsulation", "operational_status", "ipsec_profile_id"}); err != nil {
			return err
		}
		w.res.TunnelsUpdated++
	}
	// The measured lifecycle columns: seen now, once more, and the remote
	// gateway this device names (kept until the far end is an interface that
	// can carry a termination of its own).
	var peer any
	if t.PeerIP != "" {
		peer = t.PeerIP
	}
	if _, err := w.tx.ExecContext(w.ctx, `UPDATE public.tunnels
		   SET last_seen_at = GREATEST(last_seen_at, $3), observation_count = observation_count + 1,
		       observed_peer_addresses = CASE WHEN $4::inet IS NULL OR $4::inet = ANY(observed_peer_addresses) THEN observed_peer_addresses
		                                      ELSE (observed_peer_addresses || $4::inet)[greatest(1, cardinality(observed_peer_addresses) - 14):] END
		 WHERE tenant_id = $1 AND id = $2`, w.tenant, id, w.at, peer); err != nil {
		return err
	}
	return w.termination(t, id)
}

// termination puts the tunnel's end on the observed device's interface.
func (w *vpnWriter) termination(t identity.ObservedTunnel, tunnelID uuid.UUID) error {
	if t.LocalInterface == "" {
		w.res.Skipped = append(w.res.Skipped, fmt.Sprintf("tunnel %q: the collector named no local interface; no termination recorded", t.Name))
		return nil
	}
	var ifaceID uuid.UUID
	err := w.tx.QueryRowContext(w.ctx, `SELECT id FROM public.interfaces WHERE tenant_id = $1 AND asset_id = $2 AND name = $3`,
		w.tenant, w.asset, t.LocalInterface).Scan(&ifaceID)
	if errors.Is(err, sql.ErrNoRows) {
		w.res.Skipped = append(w.res.Skipped, fmt.Sprintf("tunnel %q: interface %q is not an interface of the device; no termination recorded", t.Name, t.LocalInterface))
		return nil
	}
	if err != nil {
		return err
	}
	var existing uuid.UUID
	err = w.tx.QueryRowContext(w.ctx, `SELECT tunnel_id FROM public.tunnel_terminations WHERE tenant_id = $1 AND termination_kind = 'interface' AND termination_id = $2`,
		w.tenant, ifaceID).Scan(&existing)
	switch {
	case err == nil && existing == tunnelID:
		return nil
	case err == nil:
		w.res.Skipped = append(w.res.Skipped, fmt.Sprintf("tunnel %q: interface %q already terminates another tunnel", t.Name, t.LocalInterface))
		return nil
	case !errors.Is(err, sql.ErrNoRows):
		return err
	}
	patch := map[string]any{"tunnel_id": tunnelID.String(), "role": "peer", "termination_kind": "interface", "termination_id": ifaceID.String(),
		"source_kind": "measured", "source_ref": w.ref}
	if t.LocalIP != "" {
		var ipID uuid.UUID
		err := w.tx.QueryRowContext(w.ctx, `SELECT ip.id FROM public.ip_addresses ip
			  JOIN public.interfaces i ON i.tenant_id = ip.tenant_id AND i.id = ip.assigned_id AND ip.assigned_kind = 'interface'
			 WHERE ip.tenant_id = $1 AND i.asset_id = $2 AND ip.host = $3::inet LIMIT 1`, w.tenant, w.asset, t.LocalIP+"/"+hostBits(t.LocalIP)).Scan(&ipID)
		if err == nil {
			patch["outside_ip_id"] = ipID.String()
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
	}
	_, err = w.eng.createTx(w.ctx, w.tx, w.spec("tunnel-terminations"), w.tenant, patch, tunnelChangeSource)
	return err
}

func hostBits(addr string) string {
	if strings.Contains(addr, ":") {
		return "128"
	}
	return "32"
}

// profile writes the tunnel's proposals, its two policies and its profile.
func (w *vpnWriter) profile(t identity.ObservedTunnel) (uuid.UUID, error) {
	base := truncName(t.Name)
	var ikeIDs, ipsecIDs []uuid.UUID
	for _, p := range t.IKEProposals {
		patch := map[string]any{"encryption_algorithm": optStr(p.Encryption), "authentication_algorithm": optStr(p.Integrity),
			"group": optInt(p.Group), "sa_lifetime_seconds": optInt(p.LifetimeSeconds)}
		if t.AuthenticationMethod != "" {
			patch["authentication_method"] = t.AuthenticationMethod
		}
		id, _, err := w.ensure("ike-proposals", ikeProposalName(p), patch, []string{"authentication_method"})
		if err != nil {
			return uuid.Nil, err
		}
		ikeIDs = append(ikeIDs, id)
	}
	for _, p := range t.IPsecProposals {
		patch := map[string]any{"encryption_algorithm": optStr(p.Encryption), "authentication_algorithm": optStr(p.Integrity),
			"sa_lifetime_seconds": optInt(p.LifetimeSeconds), "sa_lifetime_data_kb": optInt(p.LifetimeKB)}
		id, _, err := w.ensure("ipsec-proposals", ipsecProposalName(p), patch, nil)
		if err != nil {
			return uuid.Nil, err
		}
		ipsecIDs = append(ipsecIDs, id)
	}
	ikePatch := map[string]any{"version": optInt(t.IKEVersion), "mode": optStr(t.IKEMode), "preshared_key_present": t.PresharedKeyPresent}
	ikePolicy, _, err := w.ensure("ike-policies", base+" IKE", ikePatch, []string{"version", "mode", "preshared_key_present"})
	if err != nil {
		return uuid.Nil, err
	}
	if err := setPolicyProposals(w.ctx, w.tx, "ike-policies", w.tenant, ikePolicy, ikeIDs, tunnelChangeSource); err != nil {
		return uuid.Nil, err
	}
	ipsecPolicy, _, err := w.ensure("ipsec-policies", base+" IPsec", map[string]any{"pfs_group": optInt(t.PFSGroup)}, []string{"pfs_group"})
	if err != nil {
		return uuid.Nil, err
	}
	if err := setPolicyProposals(w.ctx, w.tx, "ipsec-policies", w.tenant, ipsecPolicy, ipsecIDs, tunnelChangeSource); err != nil {
		return uuid.Nil, err
	}
	profile, _, err := w.ensure("ipsec-profiles", base, map[string]any{"mode": nonEmpty(t.IPsecMode, "esp"),
		"ike_policy_id": ikePolicy.String(), "ipsec_policy_id": ipsecPolicy.String()}, []string{"mode", "ike_policy_id", "ipsec_policy_id"})
	return profile, err
}

// tunnelCryptoPhase is one phase of a tunnel as a crypto configuration: the
// preferred (first) proposal's components on the row, every offered
// algorithm in the catalogue junction.
type tunnelCryptoPhase struct {
	protocol, version       string
	symmetric, hash, kex    string // preferred, catalogue codes
	kexBits                 int
	offeredSym, offeredHash []string
	offeredKex              []string
}

func tunnelPhases(t identity.ObservedTunnel) []tunnelCryptoPhase {
	var out []tunnelCryptoPhase
	if len(t.IKEProposals) > 0 {
		ph := tunnelCryptoPhase{protocol: "IKE"}
		if t.IKEVersion > 0 {
			ph.version = "IKEv" + strconv.Itoa(t.IKEVersion)
		}
		for i, p := range t.IKEProposals {
			_, enc := cryptoparse.CanonicalIKEEncryption(p.Encryption)
			_, integ := cryptoparse.CanonicalIKEIntegrity(p.Integrity)
			kex := cryptoparse.IKEGroupCode(p.Group)
			if i == 0 {
				ph.symmetric, ph.hash, ph.kex = enc, integ, kex
				if g, ok := cryptoparse.IKEKeyExchangeMethod(p.Group); ok && kex != "" {
					ph.kexBits = g.Bits
				}
			}
			ph.offeredSym, ph.offeredHash, ph.offeredKex = append(ph.offeredSym, enc), append(ph.offeredHash, integ), append(ph.offeredKex, kex)
		}
		out = append(out, ph)
	}
	if len(t.IPsecProposals) > 0 {
		ph := tunnelCryptoPhase{protocol: "IPSec", kex: cryptoparse.IKEGroupCode(t.PFSGroup)}
		if g, ok := cryptoparse.IKEKeyExchangeMethod(t.PFSGroup); ok && ph.kex != "" {
			ph.kexBits = g.Bits
		}
		for i, p := range t.IPsecProposals {
			_, enc := cryptoparse.CanonicalIKEEncryption(p.Encryption)
			_, integ := cryptoparse.CanonicalIKEIntegrity(p.Integrity)
			if i == 0 {
				ph.symmetric, ph.hash = enc, integ
			}
			ph.offeredSym, ph.offeredHash = append(ph.offeredSym, enc), append(ph.offeredHash, integ)
		}
		out = append(out, ph)
	}
	return out
}

func strPtrOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// materializeTunnelCrypto writes a tunnel's phase configurations, links their
// algorithms and scores them from the catalogue.
func materializeTunnelCrypto(ctx context.Context, tx *sqlx.Tx, tenant, asset uuid.UUID, t identity.ObservedTunnel, at time.Time) ([]uuid.UUID, error) {
	var ids []uuid.UUID
	for _, ph := range tunnelPhases(t) {
		key := cryptoImplementationKey{
			AssetID: asset, Protocol: ph.protocol, ProtocolVersion: strPtrOrNil(ph.version),
			KeyExchange: strPtrOrNil(ph.kex), Symmetric: strPtrOrNil(ph.symmetric), Hash: strPtrOrNil(ph.hash),
			DiscoveryMethod: "device_interrogation",
		}
		if ph.kexBits > 0 {
			bits := ph.kexBits
			key.KeySize = &bits
		}
		raw, _ := json.Marshal(map[string]any{"source": "tunnel", "tunnel": t.Name, "phase": strings.ToLower(ph.protocol), "peer_ip": t.PeerIP})
		id, _, _, err := upsertCryptoImplementationTracked(tx, tenant, key, nil, nil, raw, at)
		if err != nil {
			return ids, err
		}
		link := func(code, role string, inferred bool) error {
			if code == "" {
				return nil
			}
			_, err := tx.ExecContext(ctx, `INSERT INTO crypto_implementation_algorithms (crypto_implementation_id, algorithm_id, algorithm_type, is_inferred)
				SELECT $1, a.id, $3, $4 FROM algorithms a WHERE a.code = $2
				ON CONFLICT (crypto_implementation_id, algorithm_id, algorithm_type) DO NOTHING`, id, code, role, inferred)
			return err
		}
		// Preferred first, as measured; then every offer, as inferred (the
		// junction is first-write-wins), exactly as SSH's offered lists.
		for _, l := range []struct {
			code, role string
		}{{ph.symmetric, "symmetric"}, {ph.hash, "hash"}, {ph.kex, "key_exchange"}} {
			if err := link(l.code, l.role, false); err != nil {
				return ids, err
			}
		}
		for i := range ph.offeredSym {
			if i >= sshMaxOfferedPerRole {
				break
			}
			if err := link(ph.offeredSym[i], "symmetric", true); err != nil {
				return ids, err
			}
			if err := link(ph.offeredHash[i], "hash", true); err != nil {
				return ids, err
			}
			if i < len(ph.offeredKex) {
				if err := link(ph.offeredKex[i], "key_exchange", true); err != nil {
					return ids, err
				}
			}
		}
		worst, _, ok, err := catalogueRiskForImplementation(tx, id)
		if err != nil {
			return ids, err
		}
		if ok {
			if _, err := persistCryptoRiskScore(tx, id, *worst.RiskScore); err != nil {
				return ids, err
			}
		}
		ids = append(ids, id)
	}
	return ids, nil
}
