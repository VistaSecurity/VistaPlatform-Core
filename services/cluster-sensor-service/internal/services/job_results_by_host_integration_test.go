package services

// GET /discovery/jobs/{id}/results?group=host pages by HOST ( H21): a
// host's ports are never split across pages, addresses sort as addresses,
// and a host never resolved is grouped under the name it was scanned by.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"strings"
	"testing"
)

func TestIntegration_ResultsByHost_PagesByHost(t *testing.T) {
	f, _ := newUnitFixture(t)
	jobID := f.createPlanJob(t, "22", "10.183.9.9", "10.183.9.10")
	var targetID string
	if err := f.raw.QueryRow(`SELECT id FROM discovery_targets WHERE job_id = $1 LIMIT 1`, jobID).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	insert := func(ip interface{}, host string, port int, protocol string) {
		t.Helper()
		if _, err := f.raw.Exec(`INSERT INTO discovery_findings (job_id, target_id, tenant_id, executed_via, protocol, port, resolved_ip, hostname, details)
			VALUES ($1, $2, $3, 'scan-engine', $4, $5, $6, $7, '{"transport":"tcp"}')`, jobID, targetID, f.tenant, protocol, port, ip, host); err != nil {
			t.Fatal(err)
		}
	}
	// 10.183.9.10 has 30 ports; 10.183.9.9 one; and one finding never resolved.
	for p := 1; p <= 30; p++ {
		insert("10.183.9.10", "10.183.9.10", 8000+p, "tcp")
	}
	insert("10.183.9.9", "10.183.9.9", 443, "TLS")
	insert(nil, "unresolved.example.test", 443, "TLS")

	page1, err := f.svc.GetJobResultsByHost(f.tenant.String(), jobID, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if page1.TotalHosts != 3 || len(page1.Hosts) != 2 {
		t.Fatalf("page 1 = %d host(s) of %d, want 2 of 3", len(page1.Hosts), page1.TotalHosts)
	}
	if page1.Hosts[0].Address != "10.183.9.9" || page1.Hosts[1].Address != "10.183.9.10" {
		t.Errorf("order = %s, %s; want addresses in address order", page1.Hosts[0].Address, page1.Hosts[1].Address)
	}
	if n := len(page1.Hosts[1].Ports); n != 30 {
		t.Errorf("10.183.9.10 carries %d ports on its page, want all 30", n)
	}
	page2, err := f.svc.GetJobResultsByHost(f.tenant.String(), jobID, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2.Hosts) != 1 || page2.Hosts[0].Address != "unresolved.example.test" || len(page2.Hosts[0].Ports) != 1 {
		t.Fatalf("page 2 = %+v, want the unresolved name with its one port", page2.Hosts)
	}
	// Another tenant reads nothing of it.
	other, _ := newUnitFixture(t)
	if got, err := f.svc.GetJobResultsByHost(other.tenant.String(), jobID, 1, 20); err != nil || got.TotalHosts != 0 {
		t.Fatalf("another tenant's read = %+v, %v; want nothing", got, err)
	}
}

// Every host that responded is listed, not only the hosts with findings
// (: a /24 said "25 responded" and listed 10). A host that answered with
// nothing open comes back with no ports and nothing_open; an address that
// never answered is not a host; the order is address order across the union
// and pages split it by host; and the count is the coverage's own.
func TestIntegration_ResultsByHost_ListsEveryRespondingHost(t *testing.T) {
	f, _ := newUnitFixture(t)
	jobID := f.createPlanJob(t, "22", "10.183.6.0/24")
	var targetID string
	if err := f.raw.QueryRow(`SELECT id FROM discovery_targets WHERE job_id = $1 LIMIT 1`, jobID).Scan(&targetID); err != nil {
		t.Fatal(err)
	}
	unit := func(addr string, open, closed, filtered int, liveness, evidence string) {
		t.Helper()
		if _, err := f.raw.Exec(`INSERT INTO discovery_job_units (tenant_id, job_id, target_id, address, status, liveness_state, liveness_evidence,
				ports_requested, open_count, closed_count, filtered_count, finished_at)
			VALUES ($1, $2, $3, $4, 'done', $5, NULLIF($6, ''), $7, $8, $9, $10, NOW())`,
			f.tenant, jobID, targetID, addr, liveness, evidence, open+closed+filtered, open, closed, filtered); err != nil {
			t.Fatal(err)
		}
	}
	finding := func(ip string, port int) {
		t.Helper()
		if _, err := f.raw.Exec(`INSERT INTO discovery_findings (job_id, target_id, tenant_id, executed_via, protocol, port, resolved_ip, details)
			VALUES ($1, $2, $3, 'scan-engine', 'SSH', $4, $5, '{"transport":"tcp"}')`, jobID, targetID, f.tenant, port, ip); err != nil {
			t.Fatal(err)
		}
	}
	// Three hosts with an open port.
	for _, a := range []string{"10.183.6.2", "10.183.6.10", "10.183.6.30"} {
		unit(a, 1, 77, 0, "up", "tcp-open:22")
		finding(a, 22)
	}
	// Two that answered with nothing open: one refused every port, one only
	// refused the liveness probe while every scanned port was filtered.
	unit("10.183.6.5", 0, 78, 0, "up", "tcp-refused:443")
	unit("10.183.6.20", 0, 0, 78, "up", "tcp-refused:22")
	// Four that never answered.
	for _, a := range []string{"10.183.6.3", "10.183.6.4", "10.183.6.11", "10.183.6.100"} {
		unit(a, 0, 0, 78, "no_answer", "")
	}

	var got []string
	quiet := map[string]bool{}
	for page := 1; page <= 3; page++ {
		res, err := f.svc.GetJobResultsByHost(f.tenant.String(), jobID, page, 2)
		if err != nil {
			t.Fatal(err)
		}
		if res.TotalHosts != 5 {
			t.Fatalf("page %d: total_hosts = %d, want 5 (3 with findings + 2 that answered with nothing open)", page, res.TotalHosts)
		}
		if want := min(2, 5-(page-1)*2); len(res.Hosts) != want {
			t.Fatalf("page %d holds %d host(s), want %d", page, len(res.Hosts), want)
		}
		for _, h := range res.Hosts {
			got = append(got, h.Address)
			if h.NothingOpen {
				quiet[h.Address] = true
				if len(h.Ports) != 0 || h.Ports == nil {
					t.Errorf("%s: nothing_open with ports %v, want an empty list", h.Address, h.Ports)
				}
			} else if len(h.Ports) != 1 {
				t.Errorf("%s: %d port(s), want its one finding", h.Address, len(h.Ports))
			}
			if h.Unit == nil {
				t.Fatalf("%s: no unit outcome", h.Address)
			}
		}
	}
	if want := "10.183.6.2 10.183.6.5 10.183.6.10 10.183.6.20 10.183.6.30"; strings.Join(got, " ") != want {
		t.Fatalf("hosts across pages = %v, want %s (address order over the union, no address twice)", got, want)
	}
	if !quiet["10.183.6.5"] || !quiet["10.183.6.20"] || len(quiet) != 2 {
		t.Fatalf("nothing_open hosts = %v, want exactly .5 and .20", quiet)
	}
	res, _ := f.svc.GetJobResultsByHost(f.tenant.String(), jobID, 1, 25)
	for _, h := range res.Hosts {
		if h.Address == "10.183.6.5" && (h.Unit.ClosedCount != 78 || h.Unit.LivenessEvidence != "tcp-refused:443") {
			t.Errorf(".5's unit = %+v, want 78 refused and its liveness evidence", h.Unit)
		}
	}

	cov, _, ok, err := f.svc.JobUnitCoverage(f.tenant.String(), jobID, "completed", "platform")
	if err != nil || !ok {
		t.Fatalf("coverage: ok=%v err=%v", ok, err)
	}
	if cov.HostsResponded != res.TotalHosts {
		t.Fatalf("coverage says %d responded, results list %d hosts — the two must agree", cov.HostsResponded, res.TotalHosts)
	}
}

// End to end through the real processor: a finished scan lists exactly the
// hosts its coverage says responded, and a finding on an address scanned by
// address carries no hostname (it used to carry the address as its "name",
// which identity then rejected as an FQDN on every finding).
func TestIntegration_ResultsByHost_TotalMatchesCoverageEndToEnd(t *testing.T) {
	f, fake := newUnitFixture(t)
	for _, h := range []string{"10.183.5.1", "10.183.5.2", "10.183.5.3"} {
		fake.Host(h, map[uint16]string{25: ServeBanner(t, "220 mx.example.test ESMTP\r\n")}, nil)
	}
	fake.Host("10.183.5.4", nil, nil) // refuses every port
	fake.Host("10.183.5.5", nil, nil)
	// 10.183.5.6-9 are not registered: no answer.
	jobID := f.createPlanJob(t, "25,80", "10.183.5.1-10.183.5.9")
	if err := f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}); err != nil {
		t.Fatal(err)
	}
	if s := f.jobStatus(t, jobID); s != "completed" {
		t.Fatalf("job = %s, want completed", s)
	}
	cov, _, ok, err := f.svc.JobUnitCoverage(f.tenant.String(), jobID, "completed", "platform")
	if err != nil || !ok {
		t.Fatalf("coverage: ok=%v err=%v", ok, err)
	}
	res, err := f.svc.GetJobResultsByHost(f.tenant.String(), jobID, 1, 25)
	if err != nil {
		t.Fatal(err)
	}
	if cov.HostsResponded != 5 || res.TotalHosts != cov.HostsResponded || len(res.Hosts) != 5 {
		t.Fatalf("coverage responded = %d, results total = %d listing %d; want 5 = 5 = 5", cov.HostsResponded, res.TotalHosts, len(res.Hosts))
	}
	for _, h := range res.Hosts {
		wantQuiet := h.Address == "10.183.5.4" || h.Address == "10.183.5.5"
		if h.NothingOpen != wantQuiet {
			t.Errorf("%s: nothing_open = %v, want %v", h.Address, h.NothingOpen, wantQuiet)
		}
		if h.Hostname != "" {
			t.Errorf("%s: hostname %q, want none — it was scanned by address", h.Address, h.Hostname)
		}
	}
	var named int
	if err := f.raw.QueryRow(`SELECT
			(SELECT COUNT(*) FROM discovery_findings WHERE job_id = $1 AND COALESCE(hostname, '') <> '') +
			(SELECT COUNT(*) FROM sensor_discoveries WHERE batch_id = $1::text AND hostname IS NOT NULL)`, jobID).Scan(&named); err != nil {
		t.Fatal(err)
	}
	if named != 0 || f.findingCount(t, jobID) != 3 {
		t.Fatalf("%d finding/queue row(s) carry a hostname (want 0); findings = %d (want 3)", named, f.findingCount(t, jobID))
	}
}
