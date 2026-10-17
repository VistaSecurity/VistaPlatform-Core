package jobs

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Drive the production scheduler's tenant pass (DCIM row 4.4): an access point
// serving a TKIP wireless LAN gets a crypto/weak_wireless_auth finding whose
// score and severity come from the catalogue row the LAN points at; moving the
// LAN to AES resolves it; a LAN whose cipher is `auto` raises nothing.
//
// Mutations (each red, then restored green):
//   - delete the `j.wireless.Run` block from FindingProducerJob.runTenant ->
//     the finding is never raised;
//   - in WirelessAuthProducer.Run, skip the Sweep -> the finding stays ACTIVE
//     after the LAN is fixed;
//   - judge by `auth_cipher = 'tkip'` instead of the catalogue strength and
//     edit the WIFI-TKIP row to `acceptable` -> the finding wrongly stays.
func TestIntegration_FindingProducerJob_RaisesWeakWirelessAuth(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	app := testdb.ConnectAsAppRole(t, owner)
	tenant := testdb.NewTenant(t, owner)

	asset, iface, lan, auto := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := owner.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO assets(id,tenant_id,hostname,display_name,class_key,class_path,asset_status) VALUES($1,$2,'ap-lobby','AP Lobby','switch','hardware.network.switch','monitoring')`, asset, tenant)
	exec(`INSERT INTO wireless_lans(id,tenant_id,ssid,auth_type,auth_cipher,auth_psk_present,source_kind,status,algorithm_id)
	      VALUES($1,$2,'Legacy','wpa-personal','tkip',true,'measured','active',(SELECT id FROM algorithms WHERE code='WIFI-TKIP'))`, lan, tenant)
	exec(`INSERT INTO wireless_lans(id,tenant_id,ssid,auth_type,auth_cipher,source_kind,status)
	      VALUES($1,$2,'Negotiated','wpa-personal','auto','measured','active')`, auto, tenant)
	exec(`INSERT INTO interfaces(id,tenant_id,asset_id,name,type,wireless_lan_ids) VALUES($1,$2,$3,'ra0','ieee802.11n',ARRAY[$4::uuid,$5::uuid])`, iface, tenant, asset, lan, auto)

	job, err := NewFindingProducerJob(app, owner)
	if err != nil {
		t.Fatal(err)
	}
	pass := func() {
		t.Helper()
		testdb.WithSchemaShareLock(t, owner, func() {
			if !job.runTenant(context.Background(), tenant) {
				t.Fatal("tenant producer pass failed")
			}
		})
	}
	state := func() (n int, active int, severity string, score int, summary string) {
		t.Helper()
		if err := owner.QueryRow(`SELECT count(*), count(*) FILTER (WHERE detection_state = 'ACTIVE'), COALESCE(max(severity), ''), COALESCE(max(score), 0), COALESCE(max(summary), '')
			FROM findings WHERE tenant_id = $1 AND producer = 'crypto' AND kind = 'weak_wireless_auth' AND subject_type = 'asset' AND subject_id = $2`,
			tenant, asset).Scan(&n, &active, &severity, &score, &summary); err != nil {
			t.Fatal(err)
		}
		return
	}

	pass()
	n, active, sev, score, summary := state()
	if n != 1 || active != 1 || score != 90 || sev != "critical" {
		t.Fatalf("after the first pass: %d findings, %d active, severity %q, score %d (%q); want 1/1/critical/90", n, active, sev, score, summary)
	}
	if !strings.Contains(summary, "Legacy") || strings.Contains(summary, "Negotiated") {
		t.Errorf("summary %q should name the weak SSID and not the unassessed one", summary)
	}
	var riskOnAsset int
	if err := owner.QueryRow(`SELECT risk_score FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, asset).Scan(&riskOnAsset); err != nil || riskOnAsset != 90 {
		t.Errorf("asset risk_score = %d (%v), want 90 from the catalogue-scored finding", riskOnAsset, err)
	}

	// Idempotent: a second pass is the same one open finding.
	pass()
	if n, active, _, _, _ := state(); n != 1 || active != 1 {
		t.Fatalf("re-run: %d findings, %d active", n, active)
	}
	// Not resurfaced by the crypto pass sweeping it and this one re-raising it.
	var resurfaced bool
	if err := owner.QueryRow(`SELECT resurfaced_at IS NOT NULL FROM findings WHERE tenant_id=$1 AND kind='weak_wireless_auth' AND subject_id=$2`, tenant, asset).Scan(&resurfaced); err != nil || resurfaced {
		t.Fatalf("resurfaced = %v (%v) after two passes: something resolves and re-raises it every run", resurfaced, err)
	}

	// Fix the LAN: AES. The finding resolves.
	exec(`UPDATE wireless_lans SET auth_cipher='aes', algorithm_id=(SELECT id FROM algorithms WHERE code='WIFI-CCMP') WHERE id=$1`, lan)
	pass()
	if n, active, _, _, _ := state(); n != 1 || active != 0 {
		t.Fatalf("after the fix: %d findings, %d active — want the finding resolved", n, active)
	}

	// The catalogue drives it: an edit to the ROW, not to Go. Rate TKIP
	// acceptable and the finding resolves; rate it weak again and it returns.
	exec(`UPDATE wireless_lans SET auth_cipher='tkip', algorithm_id=(SELECT id FROM algorithms WHERE code='WIFI-TKIP') WHERE id=$1`, lan)
	t.Cleanup(func() { _, _ = owner.Exec(`UPDATE algorithms SET strength = 'weak' WHERE code = 'WIFI-TKIP'`) })
	exec(`UPDATE algorithms SET strength = 'acceptable' WHERE code = 'WIFI-TKIP'`)
	pass()
	if _, active, _, _, _ := state(); active != 0 {
		t.Fatalf("TKIP rated acceptable by the catalogue but the finding is still active (%d)", active)
	}
	exec(`UPDATE algorithms SET strength = 'weak' WHERE code = 'WIFI-TKIP'`)
	pass()
	if _, active, sev, score, _ := state(); active != 1 || score != 90 || sev != "critical" {
		t.Fatalf("after rating TKIP weak again: active %d, severity %q, score %d; want 1/critical/90", active, sev, score)
	}
}
