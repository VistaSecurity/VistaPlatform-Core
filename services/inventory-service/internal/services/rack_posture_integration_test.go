package services

// The elevation's crypto-overlay posture (DCIM BUILD_PLAN row 2.5) against
// Postgres on the app role: open findings on the asset AND on what it owns
// (a configuration behind its endpoint, a certificate that configuration
// serves) roll up to the racked device; a resolved finding does not count; a
// weak protocol version is flagged; the soonest certificate expiry inside the
// window is reported and a later one is not; an asset nobody assessed reads
// as not assessed rather than clean.
//
// Mutations: replace findings.OpenSQL("f") with TRUE → the resolved critical
// becomes the top finding and the count is 3; drop the certificate path → the
// expiry is null; drop the weak_protocol jsonpath → the flag is false.

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_RackElevation_Posture(t *testing.T) {
	f := newRackFix(t)
	r := f.simpleRack(t, "R-posture")
	dt := f.deviceType(t, "1", true)
	sw := f.asset(t, "core-sw-1", dt)
	clean := f.asset(t, "clean-1", dt)
	unassessed := f.asset(t, "fresh-1", dt)
	for i, a := range []uuid.UUID{sw, clean, unassessed} {
		if _, err := f.place.Place(f.ctx, f.tenant, a, PlaceInput{RackID: r, Position: float64(40 - 10*i), Face: "front"}); err != nil {
			t.Fatalf("place %d: %v", i, err)
		}
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := f.owner.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`UPDATE assets SET risk_assessed_by = ARRAY['crypto'] WHERE id = ANY($1::uuid[])`, "{"+sw.String()+","+clean.String()+"}")

	ep, ci := uuid.New(), uuid.New()
	exec(`INSERT INTO asset_endpoints(id,tenant_id,asset_id,address,port,transport) VALUES($1,$2,$3,'192.0.2.40',443,'tcp')`, ep, f.tenant, sw)
	exec(`INSERT INTO crypto_implementations(id,tenant_id,asset_id,endpoint_id,protocol,protocol_version,discovery_method,risk_score,created_at,updated_at)
		VALUES($1,$2,$3,$4,'TLS','TLS1.0','passive',80,NOW(),NOW())`, ci, f.tenant, sw, ep)
	cert := func(days int) {
		id := uuid.New()
		fp := strings.ReplaceAll(id.String(), "-", "")
		exec(`INSERT INTO certificates(id,tenant_id,subject_dn,issuer_dn,fingerprint_sha256,not_after) VALUES($1,$2,'CN=sw','CN=ca',$3,$4)`,
			id, f.tenant, fp+fp, time.Now().Add(time.Duration(days)*24*time.Hour))
		exec(`INSERT INTO crypto_implementation_certificates(crypto_implementation_id,certificate_id,certificate_role) VALUES($1,$2,'leaf')`, ci, id)
	}
	cert(10)
	cert(200)
	finding := func(subjectType string, subject uuid.UUID, producer, kind, sev string, score int, workflow, evidence string) {
		exec(`INSERT INTO findings(tenant_id,producer,kind,subject_type,subject_id,severity,score,summary,evidence,workflow_status)
			VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10)`, f.tenant, producer, kind, subjectType, subject, sev, score, kind+" on "+subjectType, evidence, workflow)
	}
	finding("crypto_configuration", ci, "crypto", "weak_configuration", "high", 80, "NEW",
		`{"components":[{"role":"protocol_version","code":"TLS1.0","strength":"weak"},{"role":"hash","code":"SHA1","strength":"weak"}]}`)
	finding("asset", sw, "hygiene", "no_owner", "low", 10, "NEW", `{}`)
	finding("asset", sw, "hygiene", "stale", "critical", 95, "RESOLVED", `{}`)
	// A weak HASH alone is not a weak protocol.
	finding("asset", clean, "crypto", "weak_configuration", "medium", 50, "RESOLVED",
		`{"components":[{"role":"protocol_version","code":"TLS1.0","strength":"weak"}]}`)

	got, err := f.place.ElevationPosture(f.ctx, f.tenant, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("posture for %d devices, want 3", len(got))
	}
	p := got[sw]
	if !p.Assessed || p.OpenFindings != 2 || !p.WeakProtocol || p.TopFinding == nil || p.TopFinding.Severity != "high" || p.TopFinding.Kind != "weak_configuration" {
		t.Fatalf("switch posture %+v top %+v: want assessed, 2 open, weak protocol, top = the high weak_configuration", p, p.TopFinding)
	}
	if p.CertExpiresAt == nil || time.Until(*p.CertExpiresAt) > 11*24*time.Hour || time.Until(*p.CertExpiresAt) < 9*24*time.Hour {
		t.Fatalf("switch certificate expiry %v: want the one in 10 days", p.CertExpiresAt)
	}
	if c := got[clean]; !c.Assessed || c.OpenFindings != 0 || c.TopFinding != nil || c.WeakProtocol || c.CertExpiresAt != nil {
		t.Fatalf("clean posture %+v: want assessed with nothing open", c)
	}
	if u := got[unassessed]; u.Assessed || u.OpenFindings != 0 {
		t.Fatalf("unassessed posture %+v: want not assessed", u)
	}
	// Another tenant reads nothing of this rack.
	other := testdb.NewTenant(t, f.owner)
	if g, err := f.place.ElevationPosture(f.ctx, other, r); err != nil || len(g) != 0 {
		t.Fatalf("other tenant: %v %v", g, err)
	}
}
