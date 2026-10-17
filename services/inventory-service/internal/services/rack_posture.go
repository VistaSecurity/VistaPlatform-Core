package services

// The rack elevation's crypto overlay (DCIM BUILD_PLAN row 2.5, ADR-0010 D10:
// the crypto overlay ships with its surface): per racked device, the worst
// OPEN finding, the open-finding count, whether one of them is a weak protocol
// version, and the soonest certificate expiry within the overlay window — for
// every device of one rack in one read, so the elevation does not fan out one
// request per block.
//
// Which findings are "on" an asset is findings.AssetSubjects' answer (the same
// paths the asset page's Findings tab, the query language's finding:(…) and
// the risk rollup walk) and "open" is findings.OpenSQL; neither is restated
// here. Severity order is shared/severity's RankSQL, not a hand-written ladder.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/severity"
)

// CertExpiryWindow is how far ahead the overlay flags a certificate expiry.
const CertExpiryWindow = 30 * 24 * time.Hour

// DevicePosture is one racked device's overlay posture.
type DevicePosture struct {
	// Assessed is true when at least one risk-feeding producer has assessed
	// the asset (assets.risk_assessed_by non-empty): "no open findings" on an
	// asset nobody assessed is not "clean".
	Assessed     bool        `json:"assessed"`
	OpenFindings int         `json:"open_findings"`
	TopFinding   *TopFinding `json:"top_finding"`
	// WeakProtocol is true when an open crypto/weak_configuration finding
	// names a protocol version the catalogue rates weak (TLS 1.0, SSLv3 …).
	WeakProtocol bool `json:"weak_protocol"`
	// CertExpiresAt is the soonest not_after among the asset's certificates
	// when it falls within CertExpiryWindow (or has passed); null otherwise.
	CertExpiresAt *time.Time `json:"cert_expires_at"`
}

// TopFinding is the device's worst open finding: highest severity, then score.
type TopFinding struct {
	ID       uuid.UUID `json:"id"`
	Producer string    `json:"producer"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Score    int       `json:"score"`
	Summary  string    `json:"summary"`
}

var postureSubjectType = regexp.MustCompile(`^[a-z_]+$`)

// rackPostureSQL: $1 tenant, $2 rack, $3 expiry horizon.
var rackPostureSQL = buildRackPostureSQL()

func buildRackPostureSQL() string {
	n := 0
	uniq := func(prefix string) string { n++; return prefix + fmt.Sprint(n) }
	var parts []string
	certIDs := ""
	for _, s := range findings.AssetSubjects("s", uniq) {
		if !postureSubjectType.MatchString(s.Type) {
			panic("rack posture: subject type " + s.Type + " is not a bare identifier")
		}
		if s.Self {
			parts = append(parts, "SELECT s.id AS asset_id, '"+s.Type+"'::text AS subject_type, s.id AS subject_id FROM dev s")
			continue
		}
		parts = append(parts, "SELECT s.id AS asset_id, '"+s.Type+"'::text AS subject_type, x.id AS subject_id FROM dev s, LATERAL ("+s.IDs+") AS x(id)")
		if s.Type == findings.SubjectCertificate {
			certIDs = s.IDs
		}
	}
	if certIDs == "" {
		panic("rack posture: findings.AssetSubjects has no certificate path")
	}
	rank := severity.RankSQL("o.severity")
	return `
WITH dev AS (
    SELECT a.tenant_id, a.id, a.risk_assessed_by
      FROM assets a
     WHERE a.tenant_id = $1 AND a.rack_id = $2 AND a.position IS NOT NULL AND a.deleted_at IS NULL
       AND a.device_bay_id IS NULL AND a.parent_asset_id IS NULL
),
subject AS (
    ` + strings.Join(parts, "\n    UNION\n    ") + `
),
open AS (
    SELECT DISTINCT sub.asset_id, f.id, f.producer, f.kind, f.severity, f.score, f.summary,
           (f.producer = '` + findings.ProducerCrypto + `' AND f.kind = '` + findings.KindWeakConfiguration + `'
            AND jsonb_path_exists(f.evidence, '$.components[*] ? (@.role == "protocol_version" && @.strength == "weak")')) AS weak_protocol
      FROM subject sub
      JOIN findings f ON f.tenant_id = $1 AND f.subject_type = sub.subject_type AND f.subject_id = sub.subject_id
     WHERE ` + findings.OpenSQL("f") + `
)
SELECT d.id,
       cardinality(d.risk_assessed_by) > 0,
       (SELECT count(*) FROM open o WHERE o.asset_id = d.id),
       COALESCE((SELECT bool_or(o.weak_protocol) FROM open o WHERE o.asset_id = d.id), false),
       (SELECT jsonb_build_object('id', o.id, 'producer', o.producer, 'kind', o.kind, 'severity', o.severity,
                                  'score', o.score, 'summary', o.summary)
          FROM open o WHERE o.asset_id = d.id
         ORDER BY ` + rank + ` DESC NULLS LAST, o.score DESC, o.id LIMIT 1),
       (SELECT min(c.not_after) FROM certificates c
         WHERE c.id IN (SELECT x.id FROM dev s, LATERAL (` + certIDs + `) AS x(id) WHERE s.id = d.id)
           AND c.not_after IS NOT NULL AND c.not_after <= $3)
  FROM dev d`
}

// ElevationPosture returns the overlay posture of every racked device of the
// rack, keyed by asset id. A rack of another tenant reads as no devices (RLS
// and the tenant predicate); the caller has already resolved the rack.
func (s *PlacementService) ElevationPosture(ctx context.Context, tenant, rack uuid.UUID) (map[uuid.UUID]*DevicePosture, error) {
	out := map[uuid.UUID]*DevicePosture{}
	horizon := time.Now().Add(CertExpiryWindow)
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, rackPostureSQL, tenant, rack, horizon)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				id     uuid.UUID
				p      DevicePosture
				top    []byte
				expiry sql.NullTime
			)
			if err := rows.Scan(&id, &p.Assessed, &p.OpenFindings, &p.WeakProtocol, &top, &expiry); err != nil {
				return err
			}
			if len(top) > 0 {
				p.TopFinding = &TopFinding{}
				if err := json.Unmarshal(top, p.TopFinding); err != nil {
					return err
				}
			}
			if expiry.Valid {
				t := expiry.Time.UTC()
				p.CertExpiresAt = &t
			}
			out[id] = &p
		}
		return rows.Err()
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return out, nil
}
