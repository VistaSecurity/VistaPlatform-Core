package services

import (
	"context"
	"database/sql"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

// Explicit external targets, dispatch half ( W5.13b). Public addresses are
// example.com's historical allocation (93.184.216.0/24): the RFC 5737 ranges
// are themselves reserved by the guard and so can only play the refused part.

// flipResolver answers from a map that a test rewrites mid-flight — the shape
// of a DNS rebinding attack.
type flipResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	lookups int
}

func (r *flipResolver) set(host string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[host] = addrs
}

func (r *flipResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups++
	var out []netip.Addr
	for _, a := range r.answers[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	if len(out) == 0 {
		return nil, errors.New("no such host")
	}
	return out, nil
}

// recordingScanner stands in for nmap: it records which address each dispatch
// connected to and under which SNI name, and sends nothing anywhere.
type recordingScanner struct {
	mu        sync.Mutex
	addresses []string
	hostnames []string
}

func (s *recordingScanner) ScanTarget(target string, _ []int32, _ []string, originalHostname *string, _ map[string]interface{}) ([]models.DiscoveryFinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addresses = append(s.addresses, target)
	if originalHostname != nil {
		s.hostnames = append(s.hostnames, *originalHostname)
	} else {
		s.hostnames = append(s.hostnames, "")
	}
	return nil, nil
}

func (f *dispatchFixture) tenantUser(t *testing.T) string {
	t.Helper()
	id := uuid.New()
	if _, err := f.raw.Exec(`INSERT INTO users (id, tenant_id, email) VALUES ($1, $2, $3)`, id, f.tenant, "scan-"+id.String()[:8]+"@example.com"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id.String()
}

func (f *dispatchFixture) onlyTarget(t *testing.T, jobID string) models.DiscoveryTarget {
	t.Helper()
	var target models.DiscoveryTarget
	if err := f.raw.QueryRow(`SELECT id, input FROM discovery_targets WHERE tenant_id=$1 AND job_id=$2`, f.tenant, jobID).Scan(&target.ID, &target.Input); err != nil {
		t.Fatalf("read target: %v", err)
	}
	target.Protocols = []string{"TLS"}
	target.Ports = []int32{443}
	return target
}

// TestIntegration_DNSRebindingScansOnlyThePinnedAddress: the name resolves to a
// public address when the person confirms the scan, and to something else by
// the time the scanner runs. The scanner must reach only the address that was
// authorized — whether the new answer is the metadata service (which the
// re-check would refuse anyway) or another public host (which it would not:
// only the pin stops that one).
func TestIntegration_DNSRebindingScansOnlyThePinnedAddress(t *testing.T) {
	for name, rebindTo := range map[string]string{
		"to the metadata service": "169.254.169.254",
		"to another public host":  "93.184.216.99",
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
			f := newDispatchFixture(t)
			resolver := &flipResolver{answers: map[string][]string{}}
			resolver.set("rebind.example.com", "93.184.216.34")
			f.svc.WithResolver(resolver)
			scanner := &recordingScanner{}
			f.jp.portScanner = scanner

			req := models.CreateDiscoveryJobRequest{
				Targets: []string{"https://rebind.example.com/"}, Protocols: []string{"TLS"}, Ports: []int{443},
				ExecutionMode: "auto", ExternalTargetsConfirmed: true,
				Options: map[string]interface{}{"origin": "manual"},
			}
			job, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), req)
			if err != nil {
				t.Fatalf("confirmed external hostname refused: %v", err)
			}
			want := []models.ExternalScanTarget{{Target: "https://rebind.example.com/", Addresses: []string{"93.184.216.34"}}}
			if !reflect.DeepEqual(job.ExternalTargets, want) {
				t.Fatalf("job.ExternalTargets = %+v, want %+v", job.ExternalTargets, want)
			}

			resolver.set("rebind.example.com", rebindTo)
			target := f.onlyTarget(t, job.ID)
			if target.Input != "rebind.example.com" {
				t.Fatalf("stored input = %q, want the URL reduced to its host", target.Input)
			}
			if err := f.jp.processTarget(job, &target, req.Options); err != nil {
				t.Fatalf("processTarget: %v", err)
			}
			if !reflect.DeepEqual(scanner.addresses, []string{"93.184.216.34"}) {
				t.Fatalf("scanner contacted %v, want only the pinned [93.184.216.34] (DNS now says %s)", scanner.addresses, rebindTo)
			}
			if !reflect.DeepEqual(scanner.hostnames, []string{"rebind.example.com"}) {
				t.Fatalf("SNI names = %v, want the hostname kept for SNI", scanner.hostnames)
			}
		})
	}
}

// TestIntegration_UnconfirmedJobNeverScansPublicAtDispatch — the processor's
// re-check reads the consent from the JOB, not from anything a caller can
// supply at scan time. A job with no recorded confirmation (created before
// this existed, or tampered into discovery_targets) whose target is public is
// refused at dispatch and the scanner is never reached; the same job with
// the consent recorded scans.
func TestIntegration_UnconfirmedJobNeverScansPublicAtDispatch(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newDispatchFixture(t)
	scanner := &recordingScanner{}
	f.jp.portScanner = scanner
	job, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
		Targets: []string{"10.0.0.5"}, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "auto",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`UPDATE discovery_targets SET input='93.184.216.34' WHERE job_id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	target := f.onlyTarget(t, job.ID)
	if err := f.jp.processTarget(job, &target, nil); !errors.Is(err, dispatchguard.ErrDenied) {
		t.Fatalf("unconfirmed public target at dispatch: err=%v, want ErrDenied", err)
	}
	if len(scanner.addresses) != 0 {
		t.Fatalf("scanner reached %v for a job nobody confirmed", scanner.addresses)
	}

	// Consent recorded for a DIFFERENT range: still refused — consent covers
	// what was confirmed, not the job ( W5.13b review, item 5).
	if _, err := f.raw.Exec(`UPDATE discovery_jobs SET metadata = jsonb_set(COALESCE(metadata,'{}'::jsonb), '{external_targets}', '{"confirmed":true,"targets":[{"target":"93.184.217.0/28","addresses":["93.184.217.0/28"]}]}') WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.jp.processTarget(job, &target, nil); !errors.Is(err, dispatchguard.ErrDenied) {
		t.Fatalf("public target outside the confirmed range: err=%v, want ErrDenied", err)
	}
	if len(scanner.addresses) != 0 {
		t.Fatalf("scanner reached %v, which nobody confirmed", scanner.addresses)
	}
	if _, err := f.raw.Exec(`UPDATE discovery_jobs SET metadata = jsonb_set(metadata, '{external_targets}', '{"confirmed":true,"targets":[{"target":"93.184.216.34","addresses":["93.184.216.34"]}]}') WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`UPDATE discovery_targets SET status='pending' WHERE job_id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.jp.processTarget(job, &target, nil); err != nil {
		t.Fatalf("confirmed public target at dispatch: %v", err)
	}
	if !reflect.DeepEqual(scanner.addresses, []string{"93.184.216.34"}) {
		t.Fatalf("scanner contacted %v, want [93.184.216.34]", scanner.addresses)
	}
}

// TestIntegration_ExternalTargetsCreateJob drives CreateJob against a real
// database for the verdicts the API maps to status codes, and checks the
// server-written record the processor relies on.
func TestIntegration_ExternalTargetsCreateJob(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newDispatchFixture(t)
	resolver := &flipResolver{answers: map[string][]string{}}
	resolver.set("www.example.com", "93.184.216.34")
	resolver.set("metadata.example.com", "169.254.169.254")
	f.svc.WithResolver(resolver)
	user := f.tenantUser(t)
	base := func(targets ...string) models.CreateDiscoveryJobRequest {
		return models.CreateDiscoveryJobRequest{Targets: targets, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "auto", Options: map[string]interface{}{"origin": "manual"}}
	}
	countJobs := func() int {
		var n int
		if err := f.raw.QueryRow(`SELECT count(*) FROM discovery_jobs WHERE tenant_id=$1`, f.tenant).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// Unconfirmed: refused, listing the external targets, and NO job row.
	_, err := f.svc.CreateJob(f.tenant.String(), user, base("10.0.0.5", "93.184.216.0/28", "www.example.com"))
	ext, ok := dispatchguard.IsExternalTargetsError(err)
	if !ok || ext.Code != dispatchguard.CodeExternalTargetsUnconfirmed || len(ext.Targets) != 2 {
		t.Fatalf("unconfirmed err = %v, want external_targets_unconfirmed listing the two public targets", err)
	}
	if n := countJobs(); n != 0 {
		t.Fatalf("an unconfirmed request created %d job(s)", n)
	}

	// Reserved via a name: refused even when confirmed.
	req := base("metadata.example.com")
	req.ExternalTargetsConfirmed = true
	if _, err := f.svc.CreateJob(f.tenant.String(), user, req); err == nil {
		t.Fatal("a name resolving to the metadata service was scanned")
	} else if _, ok := dispatchguard.IsRefusedTargetsError(err); !ok {
		t.Fatalf("metadata name err = %v, want RefusedTargetsError", err)
	}

	// Automatic origin, even carrying the flag: public space is never theirs.
	req = base("93.184.216.34")
	req.ExternalTargetsConfirmed = true
	req.Options = map[string]interface{}{"origin": "auto_scan"}
	if _, err := f.svc.CreateJob(f.tenant.String(), "system", req); err == nil {
		t.Fatal("an automatic scan reached a public address")
	}
	// A service caller with no person behind it, likewise.
	req.Options = map[string]interface{}{"origin": "manual"}
	if _, err := f.svc.CreateJob(f.tenant.String(), "system", req); err == nil {
		t.Fatal("a service call with no user scanned a public address")
	}

	// Operator switch off: today's refusal, with its own code.
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "false")
	req = base("93.184.216.34")
	req.ExternalTargetsConfirmed = true
	if _, err := f.svc.CreateJob(f.tenant.String(), user, req); err == nil {
		t.Fatal("switch off, public address still scanned")
	} else if ext, ok := dispatchguard.IsExternalTargetsError(err); !ok || ext.Code != dispatchguard.CodeExternalTargetsDisabled {
		t.Fatalf("switch off err = %v, want external_targets_disabled", err)
	}
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")

	// Confirmed: created, consent and pin recorded server-side, URL port joined.
	req = base("https://www.example.com:8443/", "93.184.216.0/28")
	req.ExternalTargetsConfirmed = true
	job, err := f.svc.CreateJob(f.tenant.String(), user, req)
	if err != nil {
		t.Fatalf("confirmed request refused: %v", err)
	}
	var confirmed, confirmedBy string
	var pinned []byte
	if err := f.raw.QueryRow(`SELECT metadata->'external_targets'->>'confirmed', metadata->'external_targets'->>'confirmed_by', metadata->'pinned_addresses'->'www.example.com' FROM discovery_jobs WHERE id=$1`, job.ID).Scan(&confirmed, &confirmedBy, &pinned); err != nil {
		t.Fatal(err)
	}
	if confirmed != "true" || confirmedBy != user || string(pinned) != `["93.184.216.34"]` {
		t.Fatalf("recorded confirmed=%q by=%q pinned=%s", confirmed, confirmedBy, pinned)
	}
	var ports []int32
	rows, err := f.raw.Query(`SELECT DISTINCT unnest(ports) FROM discovery_targets WHERE job_id=$1 ORDER BY 1`, job.ID)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var p int32
		if err := rows.Scan(&p); err != nil {
			t.Fatal(err)
		}
		ports = append(ports, p)
	}
	_ = rows.Close()
	if !reflect.DeepEqual(ports, []int32{443, 8443}) {
		t.Fatalf("job ports = %v, want [443 8443] — the URL's explicit port joins the scan", ports)
	}
}

// TestIntegration_SwitchOffStopsQueuedConfirmedWork: a job confirmed while the
// capability was on, still queued when the operator turns it off, scans
// nothing ( W5.13b review, item 2 — this mutation survived before).
func TestIntegration_SwitchOffStopsQueuedConfirmedWork(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newDispatchFixture(t)
	scanner := &recordingScanner{}
	f.jp.portScanner = scanner
	job, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
		Targets: []string{"93.184.216.34"}, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "auto", ExternalTargetsConfirmed: true,
	})
	if err != nil {
		t.Fatalf("confirmed job refused: %v", err)
	}
	target := f.onlyTarget(t, job.ID)

	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "false")
	err = f.jp.processTarget(job, &target, nil)
	if ext, ok := dispatchguard.IsExternalTargetsError(err); !ok || ext.Code != dispatchguard.CodeExternalTargetsDisabled {
		t.Fatalf("switch off at scan time: err=%v, want external_targets_disabled", err)
	}
	if len(scanner.addresses) != 0 {
		t.Fatalf("scanner reached %v after the operator turned external targets off", scanner.addresses)
	}

	// Positive polarity: switched back on, the same queued job scans.
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	if _, err := f.raw.Exec(`UPDATE discovery_targets SET status='pending' WHERE job_id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.jp.processTarget(job, &target, nil); err != nil {
		t.Fatalf("switch back on: %v", err)
	}
	if !reflect.DeepEqual(scanner.addresses, []string{"93.184.216.34"}) {
		t.Fatalf("scanner contacted %v, want [93.184.216.34]", scanner.addresses)
	}
}

// TestIntegration_ExternalTargetsNeverGoToATenantSensor ( W5.13b review,
// item 2): creation refuses them in sensors mode, and dispatch refuses a job
// that carries them anyway.
func TestIntegration_ExternalTargetsNeverGoToATenantSensor(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newDispatchFixture(t)
	resolver := &flipResolver{answers: map[string][]string{}}
	resolver.set("www.example.com", "93.184.216.34")
	f.svc.WithResolver(resolver)
	sensor := f.liveSensor(t, "external-refusal")
	user := f.tenantUser(t)
	for _, target := range []string{"www.example.com", "93.184.216.34"} {
		_, err := f.svc.CreateJob(f.tenant.String(), user, models.CreateDiscoveryJobRequest{
			Targets: []string{target}, Protocols: []string{"TLS"}, Ports: []int{443},
			ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor.String()}, ExternalTargetsConfirmed: true,
		})
		refused, ok := dispatchguard.IsRefusedTargetsError(err)
		if !ok || len(refused.Targets) != 1 || !strings.Contains(refused.Targets[0].Reason, "platform sensor") {
			t.Fatalf("%s in sensors mode: err=%v, want refused naming the platform sensor", target, err)
		}
	}

	// A sensors job that carries confirmed external targets anyway is failed
	// at dispatch, and no command is written.
	job := f.createSensorsJob(t, sensor)
	if _, err := f.raw.Exec(`UPDATE discovery_jobs SET metadata = jsonb_set(COALESCE(metadata,'{}'::jsonb), '{external_targets}', '{"confirmed":true,"targets":[]}') WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.jp.dispatchToSensor(job); err != nil {
		t.Fatal(err)
	}
	var commands int
	var status string
	if err := f.raw.QueryRow(`SELECT count(*) FROM sensor_commands WHERE sensor_id=$1`, sensor).Scan(&commands); err != nil {
		t.Fatal(err)
	}
	if err := f.raw.QueryRow(`SELECT status FROM discovery_jobs WHERE id=$1`, job.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if commands != 0 || status != "failed" {
		t.Fatalf("sensor job with external targets: commands=%d status=%s, want 0 and failed", commands, status)
	}
}

// TestIntegration_TooBroadLegacySegmentIsNotOwnership: a declared segment
// wider than /8 (the segment API refuses new ones; old rows remain) must not
// make every public address "registered" and skip the confirmation ( /
// W5.13a rule, applied to scan authorization). A /8 still counts.
func TestIntegration_TooBroadLegacySegmentIsNotOwnership(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newDispatchFixture(t)
	user := f.tenantUser(t)
	seed := func(name, seg string) {
		t.Helper()
		if _, err := f.raw.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,network_type,is_active) VALUES($1,$2,$3,'cidr',$4,'production','public',true)`, uuid.New(), f.tenant, name+" "+seg, seg); err != nil {
			t.Fatalf("seed segment %s: %v", seg, err)
		}
	}
	for _, seg := range []string{"0.0.0.0/0", "92.0.0.0/7", "::/0"} {
		seed("legacy", seg)
	}
	req := models.CreateDiscoveryJobRequest{Targets: []string{"93.184.216.34", "2606:2800:21f:cb07::1"}, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "auto"}
	_, err := f.svc.CreateJob(f.tenant.String(), user, req)
	if ext, ok := dispatchguard.IsExternalTargetsError(err); !ok || ext.Code != dispatchguard.CodeExternalTargetsUnconfirmed || len(ext.Targets) != 2 {
		t.Fatalf("public targets under a legacy too-broad segment: err=%v, want both still needing confirmation", err)
	}

	// The unattended guard on its own (it is defence in depth behind the
	// manual scope above, so it is exercised directly): a PRIVATE-typed
	// 0.0.0.0/0 — mislabelled, pre-existing — must not hand the automatic
	// sweep a public address either.
	if _, err := f.raw.Exec(`UPDATE network_segments SET network_type='private' WHERE tenant_id=$1 AND value='0.0.0.0/0'`, f.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := f.raw.Exec(`INSERT INTO assets(id,tenant_id,hostname,primary_address,class_key,class_path,asset_status) VALUES($1,$2,'public-web','93.184.216.34','server','hardware.computer.server','monitoring')`, uuid.New(), f.tenant); err != nil {
		t.Fatal(err)
	}
	automatic := func(target string) error {
		return shareddatabase.WithTenantTx(context.Background(), f.raw, f.tenant, func(tx *sql.Tx) error {
			return dispatchguard.AuthorizeAutomaticScan(tx, sensordispatch.Payload{TenantID: f.tenant.String(), Targets: []string{target}, Protocols: []string{"TLS"}, Ports: []int{443}, Options: map[string]interface{}{"origin": "auto_scan"}})
		})
	}
	if err := automatic("93.184.216.34"); !errors.Is(err, dispatchguard.ErrDenied) {
		t.Fatalf("automatic scan under a private-typed 0.0.0.0/0: err=%v, want ErrDenied", err)
	}
	if _, err := f.raw.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,network_type,is_active) VALUES($1,$2,'private /24','cidr','93.184.216.0/24','production','private',true)`, uuid.New(), f.tenant); err != nil {
		t.Fatal(err)
	}
	if err := automatic("93.184.216.34"); err != nil {
		t.Fatalf("automatic scan inside a narrow declared segment refused: %v", err)
	}

	// The other polarity: a /8 (IPv4) and a /16 (IPv6) are claims of ownership.
	seed("declared", "93.0.0.0/8")
	seed("declared", "2606::/16")
	if _, err := f.svc.CreateJob(f.tenant.String(), user, req); err != nil {
		t.Fatalf("targets inside declared /8 and /16 segments needed confirmation: %v", err)
	}
}

// TestIntegration_LoweredJobBoundStopsQueuedWork (review N2): the job records
// its external-address total, and the processor re-checks it against the
// operator's CURRENT job bound.
func TestIntegration_LoweredJobBoundStopsQueuedWork(t *testing.T) {
	t.Setenv(dispatchguard.EnvExternalTargetsEnabled, "true")
	f := newDispatchFixture(t)
	scanner := &recordingScanner{}
	f.jp.portScanner = scanner
	job, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
		Targets: []string{"93.184.216.0/28"}, Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "auto", ExternalTargetsConfirmed: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var total int
	if err := f.raw.QueryRow(`SELECT (metadata->'external_targets'->>'total_addresses')::int FROM discovery_jobs WHERE id=$1`, job.ID).Scan(&total); err != nil || total != 16 {
		t.Fatalf("recorded total = %d (err %v), want 16", total, err)
	}
	target := f.onlyTarget(t, job.ID)

	t.Setenv(dispatchguard.EnvExternalJobMaxAddresses, "8")
	if err := f.jp.processTarget(job, &target, nil); !errors.Is(err, dispatchguard.ErrDenied) {
		t.Fatalf("job bound lowered to 8 after queueing a 16-address job: err=%v, want ErrDenied", err)
	}
	if len(scanner.addresses) != 0 {
		t.Fatalf("scanner reached %d address(es) over the operator's current bound", len(scanner.addresses))
	}

	t.Setenv(dispatchguard.EnvExternalJobMaxAddresses, "16")
	if _, err := f.raw.Exec(`UPDATE discovery_targets SET status='pending' WHERE job_id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.jp.processTarget(job, &target, nil); err != nil {
		t.Fatalf("at the bound: %v", err)
	}
	if len(scanner.addresses) != 16 {
		t.Fatalf("scanner reached %d address(es), want the 16 confirmed", len(scanner.addresses))
	}
}
