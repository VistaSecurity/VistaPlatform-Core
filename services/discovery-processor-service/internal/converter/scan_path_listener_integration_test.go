package converter

// One listener, two scan paths, one crypto configuration ( WP4) — hop 1
// of 2.
//
// When the platform's callers moved from the legacy protocols × ports jobs to
// planned jobs on the shared engine, a host the legacy path had scanned is
// re-scanned by the planned path from the same kind of executor. Inventory
// keys crypto configurations on (asset, endpoint, protocol, the component
// fingerprint, discovery_method), so any difference in those inputs between
// the two rows records a SECOND configuration instead of updating the first.
//
// This hop builds, for one TLS and one SSH listener and each executor (tenant
// sensor, platform), the sensor_discoveries row each path writes and runs the
// REAL converter over it:
//
//   - planned, sensor: the engine output stored through the real
//     jobunits.RecordSensorBatch into a real sensor_discoveries table, read
//     back as the processor reads it;
//   - planned, platform: the same output through the real jobunits.Commit, as
//     cluster-sensor-service's work-unit executor stores it;
//   - legacy, platform: the legacy platform path's metadata — the same
//     jobunits.TLSProbeMetadata / SSHProbeMetadata inside the same
//     MirrorMetadata;
//   - legacy, sensor: the sensor-manager envelope (StoreDiscoveries) around the
//     raw_metadata the sensor's legacy executor built from the same
//     ProbeResult.
//
// Both legacy executors were deleted in WP5, so the two legacy rows are
// hand-built from what those executors wrote (the parity harness held them to
// the real ones field by field until then). They still matter: rows they
// stored are in every upgraded database, and a sensor without scan_plan_v1
// keeps running its own legacy executor through the 4.5 line, so a re-scan
// on the engine must update those configurations rather than add new ones.
//
// The converted findings are normalised (ids and times replaced by fixed
// placeholders) and pinned in a golden file that hop 2 —
// inventory-service's TestIntegration_ScanPathListener_OneConfigurationPerListener
// — ingests through the REAL ingest path, asserting one configuration per
// listener. Regenerate with UPDATE_GOLDEN=1.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/jobunits"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// ScanPathListenerGolden is the hand-off file hop 2 reads.
const scanPathListenerGolden = "../../../../shared/jobunits/testdata/scan_path_listener/converted_findings.golden.json"

const (
	scanPathAddr     = "10.0.0.30"
	placeholderJob   = "{{job}}"
	placeholderSens  = "{{sensor}}"
	placeholderID    = "{{discovery_id}}"
	placeholderTime  = "{{timestamp}}"
	scanPathTLSPort  = 8443
	scanPathSSHPort  = 2222
	scanPathCertDays = 3650
)

// scanPathProbeResults are what the shared prober measures on the two
// listeners — the same ProbeResult whichever path ran it.
func scanPathProbeResults() (tlsRes, sshRes *shareddisc.ProbeResult) {
	notBefore := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	leaf := certificates.CertificateInfo{
		SubjectDN: "CN=listener.example.test", IssuerDN: "CN=Example Test CA", SerialNumber: "1001",
		NotBefore: notBefore, NotAfter: notBefore.AddDate(0, 0, scanPathCertDays),
		FingerprintSHA256: strings.Repeat("ab", 32), FingerprintSHA1: strings.Repeat("cd", 20),
		KeyAlgorithm: "RSA", KeySize: 2048, SignatureAlg: "SHA256-RSA", ChainOrder: 0,
		SubjectAlternativeNames: []string{"listener.example.test"},
	}
	tlsRes = &shareddisc.ProbeResult{
		Protocol: "TLS", Port: scanPathTLSPort, Confidence: 0,
		TLSVersions:    []string{"TLS 1.3", "TLS 1.2"},
		SelectedCipher: "TLS_AES_128_GCM_SHA256", ALPN: []string{""},
		Certificates:         []certificates.CertificateInfo{leaf},
		CertValidationStatus: "untrusted_ca",
		Metadata: map[string]interface{}{
			"tls_version_raw": 772, "cipher_suite_raw": 4865, "negotiated_protocol": "", "tls_fingerprint": "772-4865",
			"server_requests_client_cert": false, "tls_key_exchange_group": "X25519", "key_exchange_key_size": 253,
			"cert_has_sct": false, "cert_is_ev": false, "cert_known_bad_ca": false,
		},
	}
	sshRes = &shareddisc.ProbeResult{
		Protocol: "SSH", Port: scanPathSSHPort,
		SSHBanner: "SSH-2.0-OpenSSH_9.6", SSHProtocolVersion: "SSH-2.0", SSHSoftwareVersion: "OpenSSH_9.6",
		SSHHostKeyType: "ssh-ed25519", SSHHostKeyFingerprint: "SHA256:" + strings.Repeat("A", 43), SSHKeyTypes: []string{"ssh-ed25519"},
		SSHKexAlgorithm: "curve25519-sha256", SSHHostKeyAlgorithm: "ssh-ed25519",
		SSHEncryptionAlgC2S: "chacha20-poly1305@openssh.com", SSHEncryptionAlgS2C: "chacha20-poly1305@openssh.com",
		SSHMACAlgC2S: "umac-128-etm@openssh.com", SSHMACAlgS2C: "umac-128-etm@openssh.com", SSHCompressionAlg: "none",
		SSHServerKexAlgorithms: []string{"curve25519-sha256", "diffie-hellman-group14-sha256"},
	}
	sshRes.Metadata = map[string]interface{}{
		"ssh_protocol_version": sshRes.SSHProtocolVersion, "ssh_software_version": sshRes.SSHSoftwareVersion,
		"ssh_kex_algorithm": sshRes.SSHKexAlgorithm, "ssh_host_key_algorithm": sshRes.SSHHostKeyAlgorithm,
		"ssh_encryption_alg_c2s": sshRes.SSHEncryptionAlgC2S, "ssh_encryption_alg_s2c": sshRes.SSHEncryptionAlgS2C,
		"ssh_mac_alg_c2s": sshRes.SSHMACAlgC2S, "ssh_mac_alg_s2c": sshRes.SSHMACAlgS2C, "ssh_compression_alg": sshRes.SSHCompressionAlg,
		"ssh_kex_algorithms_server": sshRes.SSHServerKexAlgorithms,
	}
	return tlsRes, sshRes
}

// scanPathUnitOutput is the engine's output for the host: both listeners open
// and identified.
func scanPathUnitOutput() shareddisc.UnitOutput {
	tlsRes, sshRes := scanPathProbeResults()
	a := netip.MustParseAddr(scanPathAddr)
	return shareddisc.UnitOutput{
		Host: shareddisc.HostScan{Addr: a, Liveness: shareddisc.LivenessUp, LivenessEvidence: "tcp-open:2222", PortsRequested: 2,
			Open: []int{scanPathSSHPort, scanPathTLSPort}, OpenCount: 2},
		TCP: []shareddisc.Observation{
			{Addr: a, Port: scanPathSSHPort, Transport: "tcp", State: "open", Protocol: "SSH", Identified: true, Result: sshRes},
			{Addr: a, Port: scanPathTLSPort, Transport: "tcp", State: "open", Protocol: "TLS", Identified: true, Result: tlsRes},
		},
	}
}

// legacySensorRow is the row sensor-manager's StoreDiscoveries writes for the
// legacy sensor's result on one listener: the envelope keys, with the sensor's
// discoveryForFinding metadata (sensor/internal/discovery/job_results.go)
// nested under raw_metadata.
func legacySensorRow(res *shareddisc.ProbeResult, jobID string) (string, map[string]interface{}) {
	raw := map[string]interface{}{}
	// The typed DiscoveryFinding fields under their JSON names (probeResultToFinding).
	typed := map[string]interface{}{
		"tls_versions": res.TLSVersions, "selected_cipher": res.SelectedCipher, "supported_ciphers": res.SupportedCiphers,
		"alpn": res.ALPN, "cert_validation_status": res.CertValidationStatus, "cert_validation_error": res.CertValidationError,
		"ssh_banner": res.SSHBanner, "ssh_key_types": res.SSHKeyTypes, "ssh_host_key_type": res.SSHHostKeyType,
		"ssh_host_key_fingerprint": res.SSHHostKeyFingerprint, "ssh_protocol_version": res.SSHProtocolVersion,
		"ssh_software_version": res.SSHSoftwareVersion, "ssh_kex_algorithm": res.SSHKexAlgorithm,
		"ssh_host_key_algorithm": res.SSHHostKeyAlgorithm, "ssh_encryption_alg_c2s": res.SSHEncryptionAlgC2S,
		"ssh_encryption_alg_s2c": res.SSHEncryptionAlgS2C, "ssh_mac_alg_c2s": res.SSHMACAlgC2S, "ssh_mac_alg_s2c": res.SSHMACAlgS2C,
		"ssh_compression_alg": res.SSHCompressionAlg, "ssh_kex_algorithms_server": res.SSHServerKexAlgorithms,
	}
	for k, v := range typed {
		// encoding/json drops omitempty strings and nil slices.
		switch x := v.(type) {
		case string:
			if x == "" && k != "selected_cipher" {
				continue
			}
		case []string:
			if x == nil {
				continue
			}
		}
		raw[k] = v
	}
	for k, v := range res.Metadata {
		raw[k] = v
	}
	keySize := 0
	if len(res.Certificates) > 0 {
		certs := make([]map[string]interface{}, 0, len(res.Certificates))
		for _, c := range res.Certificates {
			certs = append(certs, jobunits.CertInfoToMap(c))
		}
		raw["certificates"] = certs
		keySize = res.Certificates[0].KeySize
	}
	raw["cipher_suite"] = res.SelectedCipher
	version := ""
	if len(res.TLSVersions) > 0 {
		raw["version"] = res.TLSVersions[0]
		version = res.TLSVersions[0]
	} else if res.SSHProtocolVersion != "" {
		version = res.SSHProtocolVersion
	}
	raw[sensordispatch.MetadataJobIDKey] = jobID
	raw["discovery_source"] = sensordispatch.DiscoverySourceActiveScan
	raw["probe_timestamp"] = placeholderTime
	return cryptoparse.NormalizeProtocol(res.Protocol), map[string]interface{}{
		"source_ip": "", "version": version, "cipher_suite": res.SelectedCipher, "key_size": keySize,
		"discovery_method": sensordispatch.DiscoveryMethodActive, "raw_metadata": raw, "service_hints": nil,
	}
}

// ScanPathListenerCase is one listener × executor in the golden file.
type ScanPathListenerCase struct {
	Listener string         `json:"listener"`
	Executor string         `json:"executor"`
	Legacy   *IngestFinding `json:"legacy"`
	Planned  *IngestFinding `json:"planned"`
}

func TestIntegration_ScanPathListener_ConvertedFindings(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := raw.Exec(q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	sensor := uuid.New()
	exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,reported_capabilities) VALUES($1,$2,'edge','linux','test-v1','datacenter_host','active',now(),ARRAY['scan_plan_v1'])`, sensor, tenant)
	var platform uuid.UUID
	if err := raw.QueryRow(`SELECT id FROM sensors WHERE tenant_id=$1 AND profile='discovery' AND 'system'=ANY(tags)`, tenant).Scan(&platform); err != nil {
		t.Fatalf("platform discovery sensor: %v", err)
	}
	meta, _ := json.Marshal(map[string]any{shareddisc.ScanPlanMetadataKey: map[string]any{"depth": "custom"}, "options": map[string]any{"origin": "auto_scan", "active_scan": true}})

	plannedJob := func(onSensor bool) (string, jobunits.Unit) {
		jobID := uuid.New()
		if onSensor {
			exec(`INSERT INTO discovery_jobs(id,tenant_id,execution_mode,status,requested_sensor_ids,assigned_sensor_id,dispatched_at,metadata) VALUES($1,$2,'sensors',$3,ARRAY[$4::text],$4::uuid,now(),$5::jsonb)`,
				jobID, tenant, sensordispatch.StatusAwaitingSensor, sensor.String(), string(meta))
		} else {
			exec(`INSERT INTO discovery_jobs(id,tenant_id,execution_mode,status,started_at,metadata) VALUES($1,$2,'platform','running',now(),$3::jsonb)`, jobID, tenant, string(meta))
		}
		u := jobunits.Unit{JobID: jobID.String(), TenantID: tenant.String(), TargetInput: scanPathAddr, Address: scanPathAddr}
		if err := raw.QueryRow(`INSERT INTO discovery_targets(job_id,tenant_id,input,protocols,ports) VALUES($1,$2,$3,'{}',ARRAY[2222,8443]) RETURNING id`, jobID, tenant, scanPathAddr).Scan(&u.TargetID); err != nil {
			t.Fatal(err)
		}
		status := "running"
		if onSensor {
			status = "pending"
		}
		if err := raw.QueryRow(`INSERT INTO discovery_job_units(tenant_id,job_id,target_id,address,attempts,status) VALUES($1,$2,$3,$4,1,$5) RETURNING id`,
			tenant, jobID, u.TargetID, scanPathAddr, status).Scan(&u.ID); err != nil {
			t.Fatal(err)
		}
		return jobID.String(), u
	}

	// Planned, sensor: the tenant sensor's report.
	sensorJob, sensorUnit := plannedJob(true)
	resp, err := jobunits.RecordSensorBatch(ctx, raw, tenant, sensor, uuid.MustParse(sensorJob),
		sensordispatch.UnitBatch{Units: []sensordispatch.UnitResult{sensordispatch.NewUnitResult(sensorUnit.TargetID, sensorUnit.Address, 1, scanPathUnitOutput())}})
	if err != nil || resp.Accepted != 1 {
		t.Fatalf("sensor report = %+v %v", resp, err)
	}
	// Planned, platform: the work-unit executor's commit.
	platformJob, platformUnit := plannedJob(false)
	if err := shareddatabase.WithTenantTx(ctx, raw, tenant, func(tx *sql.Tx) error {
		return jobunits.Commit(tx, platformUnit, scanPathUnitOutput(), jobunits.CommitOptions{From: "running", Attempt: 1, ActiveScan: true,
			MirrorSensorID: func(jobunits.Tx) (string, error) { return platform.String(), nil }})
	}); err != nil {
		t.Fatalf("platform commit: %v", err)
	}

	mirrored := func(jobID string, port int) *models.SensorDiscovery {
		t.Helper()
		var sd models.SensorDiscovery
		if err := raw.QueryRow(`SELECT id,sensor_id,batch_id,protocol,host(dest_ip),port,confidence,metadata FROM sensor_discoveries WHERE tenant_id=$1 AND batch_id=$2 AND port=$3`,
			tenant, jobID, port).Scan(&sd.ID, &sd.SensorID, &sd.BatchID, &sd.Protocol, &sd.DestIP, &sd.Port, &sd.Confidence, &sd.Metadata); err != nil {
			t.Fatalf("mirrored row for job %s port %d: %v", jobID, port, err)
		}
		return &sd
	}
	row := func(protocol string, port int, metadata map[string]interface{}) *models.SensorDiscovery {
		blob, err := json.Marshal(metadata)
		if err != nil {
			t.Fatal(err)
		}
		return &models.SensorDiscovery{ID: uuid.New(), SensorID: sensor, BatchID: "legacy", Protocol: protocol, DestIP: scanPathAddr, Port: port, Metadata: blob}
	}
	convert := func(sd *models.SensorDiscovery) *IngestFinding {
		t.Helper()
		f, err := NewSensorDiscoveryConverter().ToIngestFinding(sd)
		if err != nil {
			t.Fatal(err)
		}
		return normaliseScanPathFinding(f)
	}

	tlsRes, sshRes := scanPathProbeResults()
	var cases []ScanPathListenerCase
	for _, l := range []struct {
		name string
		res  *shareddisc.ProbeResult
	}{{"tls", tlsRes}, {"ssh", sshRes}} {
		proto, envelope := legacySensorRow(l.res, "legacy-job")
		legacySensor := row(proto, l.res.Port, envelope)
		cases = append(cases, ScanPathListenerCase{Listener: l.name, Executor: "sensor",
			Legacy: convert(legacySensor), Planned: convert(mirrored(sensorJob, l.res.Port))})

		data := jobunits.ProbeResultData(l.res) // what tls_prober.go / ssh_prober.go return
		legacyPlatform := row(cryptoparse.NormalizeProtocol(l.res.Protocol), l.res.Port, jobunits.MirrorMetadata(data, true, "legacy-job"))
		legacyPlatform.SensorID = platform
		cases = append(cases, ScanPathListenerCase{Listener: l.name, Executor: "platform",
			Legacy: convert(legacyPlatform), Planned: convert(mirrored(platformJob, l.res.Port))})
	}

	// The inputs inventory keys a configuration on, compared here so a
	// difference is named at this hop; hop 2 proves the whole key.
	for _, c := range cases {
		lk, pk := scanPathKeyInputs(c.Legacy), scanPathKeyInputs(c.Planned)
		if lk != pk {
			t.Errorf("%s via %s: dedup inputs differ\n legacy:  %s\n planned: %s", c.Listener, c.Executor, lk, pk)
		}
	}

	got, err := json.MarshalIndent(map[string]any{"cases": cases}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(scanPathListenerGolden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(scanPathListenerGolden, got, 0o644); err != nil { //nolint:gosec // test golden, not a secret
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(scanPathListenerGolden)
	if err != nil {
		t.Fatalf("read golden (regenerate with UPDATE_GOLDEN=1): %v", err)
	}
	if string(want) != string(got) {
		t.Fatalf("converted findings differ from %s — hop 2 ingests that file, so regenerate it with UPDATE_GOLDEN=1 and review the diff:\n%s", scanPathListenerGolden, got)
	}
}

// normaliseScanPathFinding replaces what differs run to run (ids, times, the
// job) with placeholders hop 2 fills in.
func normaliseScanPathFinding(f *IngestFinding) *IngestFinding {
	if f.SourceSensorID != nil {
		s := placeholderSens
		f.SourceSensorID = &s
	}
	for _, k := range []string{"sensor_id"} {
		if _, ok := f.RawData[k]; ok {
			f.RawData[k] = placeholderSens
		}
	}
	for _, k := range []string{"discovery_id"} {
		f.RawData[k] = placeholderID
	}
	for _, k := range []string{"batch_id", sensordispatch.MetadataJobIDKey} {
		if _, ok := f.RawData[k]; ok {
			f.RawData[k] = placeholderJob
		}
	}
	for _, k := range []string{"timestamp", "probe_timestamp"} {
		if _, ok := f.RawData[k]; ok {
			f.RawData[k] = placeholderTime
		}
	}
	return f
}

func scanPathKeyInputs(f *IngestFinding) string {
	// An empty string is folded into <nil>: the legacy envelope writes
	// cipher_suite "" on every SSH row (sensor-empty-cipher-on-ssh), and hop 2
	// shows inventory records that as the same configuration (the planned
	// row's absent value is a component-subset of it).
	s := func(p *string) string {
		if p == nil || *p == "" {
			return "<nil>"
		}
		return *p
	}
	i := func(p *int) string {
		if p == nil {
			return "<nil>"
		}
		b, _ := json.Marshal(*p)
		return string(b)
	}
	method, _ := f.RawData["discovery_method"].(string)
	source, _ := f.RawData["source"].(string)
	return strings.Join([]string{"protocol=" + f.Protocol, "port=" + i(f.Port), "version=" + s(f.ProtocolVersion), "cipher=" + s(f.CipherSuite),
		"kex=" + s(f.KeyExchangeAlgorithm), "key_size=" + i(f.KeySize), "hash=" + s(f.HashAlgorithm), "method=" + method, "source=" + source}, " ")
}
