package services

// The faceplate's crypto overlay (DCIM BUILD_PLAN row 3.4, ADR-0010 D10: the
// crypto overlay ships with its surface): per interface of one asset, what is
// cryptographically observed BEHIND that port — the crypto configurations
// measured on endpoints bound to the interface's addresses — and the asset's
// worst open finding, in one read.
//
// The join is endpoints → ip_addresses → interface: an endpoint's resolved
// `ip_address_id` when set, else its address's host equal to an address
// assigned to the interface (the resolver does not write ip_address_id on
// every path yet). Only the asset's own endpoints count.
//
// Nothing is scored here. The numeric risk is the configuration's stored
// catalogue score, certified by cryptoRiskScoreAssessedSQL (a stored zero with
// no numeric corroboration is "not assessed", never "clean"); the qualitative
// verdict is shared/strength's Weakest over the catalogue strengths of the
// configuration's components; "weak protocol" is a protocol_version component
// the catalogue rates weak. The UI bands the score through the generated
// ratings module.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/severity"
	"github.com/vistasecurity/vistaplatform/shared/strength"
)

// InterfacePostureConfig is the crypto configuration that sets an
// interface's overlay: its worst assessed score, else its weakest component.
type InterfacePostureConfig struct {
	ID              uuid.UUID `json:"id"`
	Protocol        string    `json:"protocol"`
	ProtocolVersion *string   `json:"protocol_version"`
	CipherSuite     *string   `json:"cipher_suite"`
	Port            *int      `json:"port"`
	RiskScore       *int      `json:"risk_score"`
	Assessed        bool      `json:"risk_score_assessed"`
	Strength        *string   `json:"strength"`
}

// InterfacePosture is one interface's overlay posture.
type InterfacePosture struct {
	InterfaceID uuid.UUID `json:"interface_id"`
	// Configurations is how many crypto configurations were observed behind
	// the interface; 0 means nothing observed (not "clean").
	Configurations int `json:"configurations"`
	// Assessed: at least one of them carries a certified numeric score.
	Assessed bool `json:"assessed"`
	// WorstScore is the highest certified score (0–100), null when none is.
	WorstScore *int `json:"worst_score"`
	// WeakestStrength is the weakest catalogue strength among the components,
	// null when no component resolved to a known strength.
	WeakestStrength *string `json:"weakest_strength"`
	// WeakProtocol: a protocol version component the catalogue rates weak.
	WeakProtocol bool                    `json:"weak_protocol"`
	Worst        *InterfacePostureConfig `json:"worst_configuration"`
}

// InterfacePostureFinding is the asset's worst open finding.
type InterfacePostureFinding struct {
	ID       uuid.UUID `json:"id"`
	Producer string    `json:"producer"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Score    int       `json:"score"`
	Summary  string    `json:"summary"`
}

// AssetInterfacePosture answers GET /dcim/assets/{id}/interface-posture.
type AssetInterfacePosture struct {
	AssetID      uuid.UUID                `json:"asset_id"`
	OpenFindings int                      `json:"open_findings"`
	TopFinding   *InterfacePostureFinding `json:"top_finding"`
	Interfaces   []InterfacePosture       `json:"interfaces"`
}

// interfacePostureSQL: $1 tenant, $2 asset, $3 catalogue risk roles. One row
// per (interface, configuration).
var interfacePostureSQL = `
WITH addr AS (
    SELECT ia.assigned_id AS interface_id, ia.id, ia.host
      FROM public.ip_addresses ia
      JOIN public.interfaces i ON i.tenant_id = ia.tenant_id AND i.id = ia.assigned_id
     WHERE ia.tenant_id = $1 AND i.asset_id = $2 AND ia.assigned_kind = 'interface' AND ia.status <> 'rejected'
),
ep AS (
    SELECT DISTINCT addr.interface_id, e.id, e.port
      FROM public.asset_endpoints e
      JOIN addr ON (e.ip_address_id = addr.id
                    OR (e.ip_address_id IS NULL AND e.address IS NOT NULL AND public.ipam_host(e.address) = addr.host))
     WHERE e.tenant_id = $1 AND e.asset_id = $2 AND e.status <> 'closed'
)
SELECT ep.interface_id, ci.id, ci.protocol::text, ci.protocol_version, ci.cipher_suite, ep.port, ci.risk_score,
       ` + cryptoRiskScoreAssessedSQL("$3") + `,
       COALESCE((SELECT array_agg(DISTINCT alg.strength::text)
                   FROM public.crypto_implementation_algorithms cia
                   JOIN public.algorithms alg ON alg.id = cia.algorithm_id
                  WHERE cia.crypto_implementation_id = ci.id AND cia.algorithm_type = ANY($3) AND alg.strength IS NOT NULL), '{}'),
       EXISTS (SELECT 1 FROM public.crypto_implementation_algorithms cia
                 JOIN public.algorithms alg ON alg.id = cia.algorithm_id
                WHERE cia.crypto_implementation_id = ci.id AND cia.algorithm_type = 'protocol_version' AND alg.strength = 'weak')
  FROM ep
  JOIN public.crypto_implementations ci ON ci.tenant_id = $1 AND ci.endpoint_id = ep.id AND ci.asset_id = $2 AND ci.deleted_at IS NULL
 ORDER BY ep.interface_id, ci.id`

var ifPostureSubjectType = regexp.MustCompile(`^[a-z_]+$`)

// assetTopFindingSQL: $1 tenant, $2 asset. The open-finding count and the
// worst open finding over every subject findings.AssetSubjects says is "on"
// the asset; severity order is shared/severity's RankSQL.
var assetTopFindingSQL = buildAssetTopFindingSQL()

func buildAssetTopFindingSQL() string {
	n := 0
	uniq := func(prefix string) string { n++; return prefix + fmt.Sprint(n) }
	var parts []string
	for _, s := range findings.AssetSubjects("s", uniq) {
		if !ifPostureSubjectType.MatchString(s.Type) {
			panic("interface posture: subject type " + s.Type + " is not a bare identifier")
		}
		if s.Self {
			parts = append(parts, "SELECT '"+s.Type+"'::text AS subject_type, s.id AS subject_id FROM dev s")
			continue
		}
		parts = append(parts, "SELECT '"+s.Type+"'::text AS subject_type, x.id AS subject_id FROM dev s, LATERAL ("+s.IDs+") AS x(id)")
	}
	return `
WITH dev AS (
    SELECT a.tenant_id, a.id FROM public.assets a WHERE a.tenant_id = $1 AND a.id = $2
),
subject AS (
    ` + strings.Join(parts, "\n    UNION\n    ") + `
),
open AS (
    SELECT DISTINCT f.id, f.producer, f.kind, f.severity, f.score, f.summary
      FROM subject sub
      JOIN public.findings f ON f.tenant_id = $1 AND f.subject_type = sub.subject_type AND f.subject_id = sub.subject_id
     WHERE ` + findings.OpenSQL("f") + `
)
SELECT (SELECT count(*) FROM open),
       (SELECT jsonb_build_object('id', o.id, 'producer', o.producer, 'kind', o.kind, 'severity', o.severity,
                                  'score', o.score, 'summary', o.summary)
          FROM open o ORDER BY ` + severity.RankSQL("o.severity") + ` DESC NULLS LAST, o.score DESC, o.id LIMIT 1)`
}

// postureRow is one (interface, configuration) row of interfacePostureSQL.
type postureRow struct {
	iface        uuid.UUID
	cfg          InterfacePostureConfig
	strengths    []string
	weakProtocol bool
}

// foldInterfacePosture folds an interface's configuration rows into its
// overlay posture. The worst configuration is the highest certified score;
// with no certified score, the weakest strength.
func foldInterfacePosture(id uuid.UUID, rows []postureRow) InterfacePosture {
	out := InterfacePosture{InterfaceID: id, Configurations: len(rows)}
	var all []string
	worstRank := len(strength.Definitions())
	for i := range rows {
		r := &rows[i]
		all = append(all, r.strengths...)
		if r.weakProtocol {
			out.WeakProtocol = true
		}
		if w, _ := strength.Weakest(r.strengths...); w != "" {
			v := w
			r.cfg.Strength = &v
		}
		if r.cfg.Assessed && r.cfg.RiskScore != nil {
			out.Assessed = true
			if out.WorstScore == nil || *r.cfg.RiskScore > *out.WorstScore {
				s := *r.cfg.RiskScore
				out.WorstScore = &s
				c := r.cfg
				out.Worst = &c
			}
		}
	}
	if out.Worst == nil {
		for i := range rows {
			if rows[i].cfg.Strength == nil {
				continue
			}
			if rk, ok := strength.Rank(*rows[i].cfg.Strength); ok && rk < worstRank {
				worstRank = rk
				c := rows[i].cfg
				out.Worst = &c
			}
		}
	}
	if w, _ := strength.Weakest(all...); w != "" {
		out.WeakestStrength = &w
	}
	return out
}

// InterfacePosture returns the overlay posture of every interface of the
// asset. Interfaces with nothing observed behind them answer
// configurations = 0. ErrIPAMNotFound when the asset is not the tenant's.
func (s *CableService) InterfacePosture(ctx context.Context, tenant, asset uuid.UUID) (AssetInterfacePosture, error) {
	out := AssetInterfacePosture{AssetID: asset, Interfaces: []InterfacePosture{}}
	err := database.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL)`, tenant, asset).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrIPAMNotFound
		}
		ifaces, err := tx.QueryContext(ctx, `SELECT id FROM public.interfaces WHERE tenant_id = $1 AND asset_id = $2 ORDER BY id`, tenant, asset)
		if err != nil {
			return err
		}
		var ids []uuid.UUID
		for ifaces.Next() {
			var id uuid.UUID
			if err := ifaces.Scan(&id); err != nil {
				_ = ifaces.Close()
				return err
			}
			ids = append(ids, id)
		}
		if err := ifaces.Close(); err != nil {
			return err
		}

		byIface := map[uuid.UUID][]postureRow{}
		rows, err := tx.QueryContext(ctx, interfacePostureSQL, tenant, asset, pq.Array(cryptoassess.CatalogueRiskRoles))
		if err != nil {
			return err
		}
		for rows.Next() {
			var (
				r              postureRow
				version, suite sql.NullString
				port, score    sql.NullInt64
				strengths      pq.StringArray
			)
			if err := rows.Scan(&r.iface, &r.cfg.ID, &r.cfg.Protocol, &version, &suite, &port, &score, &r.cfg.Assessed, &strengths, &r.weakProtocol); err != nil {
				_ = rows.Close()
				return err
			}
			r.cfg.ProtocolVersion, r.cfg.CipherSuite = nullStrPtr(version), nullStrPtr(suite)
			if port.Valid {
				p := int(port.Int64)
				r.cfg.Port = &p
			}
			if score.Valid {
				sc := int(score.Int64)
				r.cfg.RiskScore = &sc
			}
			r.strengths = strengths
			byIface[r.iface] = append(byIface[r.iface], r)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, id := range ids {
			out.Interfaces = append(out.Interfaces, foldInterfacePosture(id, byIface[id]))
		}

		var top []byte
		if err := tx.QueryRowContext(ctx, assetTopFindingSQL, tenant, asset).Scan(&out.OpenFindings, &top); err != nil {
			return err
		}
		if len(top) > 0 {
			out.TopFinding = &InterfacePostureFinding{}
			if err := json.Unmarshal(top, out.TopFinding); err != nil {
				return err
			}
		}
		return nil
	})
	return out, mapIPAMError(err, false)
}
