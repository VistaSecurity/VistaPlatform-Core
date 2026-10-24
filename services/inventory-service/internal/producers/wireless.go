package producers

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	"github.com/vistasecurity/vistaplatform/shared/riskbands"
)

// WirelessAuthProducer raises `crypto/weak_wireless_auth` (DCIM BUILD_PLAN row
// 4.4; ADR-0010 D8): an access point serves a wireless LAN whose link-layer
// protection the algorithms catalogue rates weak -- open, WEP or TKIP.
//
// The judgement is the catalogue's, not this file's. A wireless LAN points at
// its cipher row (wireless_lans.algorithm_id, set from auth_type and
// auth_cipher by the service); the finding is raised when that row's strength
// is `weak`, with the row's risk_score as its score and riskbands' ladder as
// its severity. Edit the catalogue row to change what it says. A LAN with no
// algorithm_id (cipher `auto`, or no authentication recorded) is NOT assessed:
// it raises nothing and is counted, never read as clean.
//
// The subject is the access point asset, because a wireless LAN is not an
// asset and a finding must be about one. Several weak LANs on one AP are one
// finding whose evidence names each; a weak LAN no interface serves has no
// subject and is counted as Unserved. A client's radio that joined the LAN
// (rf_role `station`) does not serve it and is not a subject.
//
// It writes through its own crypto-producer Writer and sweeps only its own
// kind, so it cannot resolve the crypto pass's rows. It claims no coverage
// (MarkAssessed): "assessed" on the crypto controls means configurations and
// certificates were read, which this pass did not do.
type WirelessAuthProducer struct {
	db     *sql.DB
	writer *producer.Writer
}

// NewWirelessAuthProducer builds the producer over the RLS-subject handle.
func NewWirelessAuthProducer(appDB *sql.DB) (*WirelessAuthProducer, error) {
	w, err := producer.New(findings.ProducerCrypto)
	if err != nil {
		return nil, err
	}
	return &WirelessAuthProducer{db: appDB, writer: w}, nil
}

// WirelessRun is one pass over one tenant.
type WirelessRun struct {
	Raised   int
	Resolved int
	// LANs is how many wireless LANs the pass read; Unassessed how many had no
	// catalogue row to judge by; Unserved how many weak ones no access point
	// serves.
	LANs       int
	Unassessed int
	Unserved   int
}

type wirelessLANEvidence struct {
	SSID       string
	AuthType   string
	AuthCipher string
	Code       string
	Risk       int
}

// Run judges every wireless LAN of the tenant in one transaction.
func (p *WirelessAuthProducer) Run(ctx context.Context, tenantID uuid.UUID) (WirelessRun, error) {
	var run WirelessRun
	err := shareddatabase.WithTenantTx(ctx, p.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT l.id, l.ssid, COALESCE(l.auth_type, ''), COALESCE(l.auth_cipher, ''),
			       a.code, a.strength, a.risk_score, i.asset_id, COALESCE(NULLIF(s.display_name, ''), NULLIF(s.hostname, ''), i.asset_id::text)
			  FROM public.wireless_lans l
			  LEFT JOIN public.algorithms a ON a.id = l.algorithm_id
			  LEFT JOIN public.interfaces i ON i.tenant_id = l.tenant_id AND l.id = ANY(i.wireless_lan_ids) AND i.status <> 'rejected'
			        AND i.rf_role IS DISTINCT FROM 'station'
			  LEFT JOIN public.assets s ON s.tenant_id = i.tenant_id AND s.id = i.asset_id AND s.deleted_at IS NULL
			 WHERE l.tenant_id = $1 AND l.status <> 'rejected'
			 ORDER BY l.ssid, l.id, i.asset_id`, tenantID)
		if err != nil {
			return err
		}
		type apGroup struct {
			label string
			lans  map[uuid.UUID]wirelessLANEvidence
		}
		aps := map[uuid.UUID]*apGroup{}
		seenLAN := map[uuid.UUID]bool{}
		servedWeak := map[uuid.UUID]bool{}
		weakLAN := map[uuid.UUID]bool{}
		for rows.Next() {
			var (
				lanID                  uuid.UUID
				ssid, authType, cipher string
				code, strength         sql.NullString
				risk                   sql.NullInt64
				asset                  uuid.NullUUID
				label                  sql.NullString
			)
			if err := rows.Scan(&lanID, &ssid, &authType, &cipher, &code, &strength, &risk, &asset, &label); err != nil {
				_ = rows.Close()
				return err
			}
			if !seenLAN[lanID] {
				seenLAN[lanID] = true
				run.LANs++
				if !code.Valid {
					run.Unassessed++
				}
			}
			if !code.Valid || strength.String != "weak" {
				continue
			}
			weakLAN[lanID] = true
			if !asset.Valid {
				continue
			}
			servedWeak[lanID] = true
			g := aps[asset.UUID]
			if g == nil {
				g = &apGroup{label: label.String, lans: map[uuid.UUID]wirelessLANEvidence{}}
				aps[asset.UUID] = g
			}
			g.lans[lanID] = wirelessLANEvidence{SSID: ssid, AuthType: authType, AuthCipher: cipher, Code: code.String, Risk: int(risk.Int64)}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		_ = rows.Close()
		for id := range weakLAN {
			if !servedWeak[id] {
				run.Unserved++
			}
		}

		var seen []producer.Subject
		ids := make([]uuid.UUID, 0, len(aps))
		for id := range aps {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i].String() < ids[j].String() })
		for _, assetID := range ids {
			g := aps[assetID]
			var (
				lans  []wirelessLANEvidence
				score int
			)
			for _, e := range g.lans {
				lans = append(lans, e)
				if e.Risk > score {
					score = e.Risk
				}
			}
			sort.Slice(lans, func(i, j int) bool { return lans[i].SSID < lans[j].SSID })
			subject := producer.Subject{Type: findings.SubjectAsset, ID: assetID}
			evidence := make([]any, 0, len(lans))
			var parts []string
			for _, e := range lans {
				evidence = append(evidence, map[string]any{
					"ssid": e.SSID, "auth_type": e.AuthType, "auth_cipher": e.AuthCipher,
					"algorithm": e.Code, "risk_score": e.Risk,
				})
				parts = append(parts, fmt.Sprintf("%q (%s)", e.SSID, describeWirelessAuth(e)))
			}
			if _, err := p.writer.Upsert(ctx, tx, tenantID, producer.Finding{
				Kind:         findings.KindWeakWirelessAuth,
				Subject:      subject,
				SubjectLabel: g.label,
				Severity:     string(riskbands.Severity(score)),
				Score:        score,
				Summary:      fmt.Sprintf("%s serves weak wireless authentication: %s", g.label, strings.Join(parts, ", ")),
				Evidence:     map[string]any{"wireless_lans": evidence},
			}); err != nil {
				return err
			}
			run.Raised++
			seen = append(seen, subject)
		}
		n, err := p.writer.Sweep(ctx, tx, tenantID, findings.KindWeakWirelessAuth, seen)
		if err != nil {
			return err
		}
		run.Resolved = n
		return nil
	})
	if err != nil {
		return WirelessRun{}, fmt.Errorf("wireless auth producer: tenant %s: %w", tenantID, err)
	}
	return run, nil
}

func describeWirelessAuth(e wirelessLANEvidence) string {
	switch e.AuthType {
	case "open":
		return "open, no encryption"
	case "wep":
		return "WEP"
	}
	if e.AuthCipher != "" {
		return strings.ToUpper(e.AuthCipher)
	}
	return e.AuthType
}
