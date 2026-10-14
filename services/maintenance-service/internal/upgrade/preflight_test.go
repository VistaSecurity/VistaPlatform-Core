package upgrade

import (
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/backups"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/capabilities"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

var testNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// passingPreflight passes every check; each test breaks one thing.
func passingPreflight() (*Preflight, *fakeVerifier) {
	v := &fakeVerifier{}
	return &Preflight{
		Capabilities: fakeDetector{caps: helmManaged},
		Tags:         fakeTags{tags: []string{"v4.4.0", "4.5.0", "4.6.0", "latest", "sha256-abc.sig"}},
		ChartSource:  upgradeTestSource,
		RunningChart: "4.5.0",
		Verifier:     v,
		Releases:     fakeReleases{hist: []Release{{Revision: 2, ChartVersion: "4.5.0", Status: HelmDeployed, Config: map[string]any{}}}},
		Schema:       fakeSchema{v: "4.5.0"},
		Runs:         fakeRunning{},
		Backups:      &fakeBackups{available: true, recent: &backups.Backup{ID: uuid.New(), CreatedAt: testNow.Add(-2 * time.Hour), Status: backups.StatusReady}},
		Now:          func() time.Time { return testNow },
	}, v
}

func checkOf(t *testing.T, r Result, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %s check in %+v", name, r.Checks)
	return Check{}
}

func TestPreflight_AllPass(t *testing.T) {
	p, v := passingPreflight()
	r := p.Run(context.Background(), "v4.6.0", Options{})
	if !r.OK || r.Version != "4.6.0" || r.CurrentVersion != "4.5.0" {
		t.Fatalf("result %+v", r)
	}
	var names []string
	for _, c := range r.Checks {
		names = append(names, c.Name)
		if c.Status != CheckPass {
			t.Errorf("%s = %s: %s", c.Name, c.Status, c.Detail)
		}
	}
	want := []string{CheckCapabilities, CheckVersion, CheckSignature, CheckValueOverrides, CheckSingleNode, CheckSchema, CheckNoRunning, CheckRecentBackup}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("checks %v, want %v (every check, in order)", names, want)
	}
	if !reflect.DeepEqual(v.calls(), []string{"ghcr.io/vistasecurity/vistaplatform:4.6.0"}) {
		t.Fatalf("verified %v", v.calls())
	}
}

// (a)
func TestPreflight_Capabilities(t *testing.T) {
	for _, tc := range []struct {
		caps capabilities.Capabilities
		want string
	}{
		{capabilities.Capabilities{HelmManaged: true, GitOps: true, Reason: capabilities.ReasonGitOps}, "GitOps"},
		{capabilities.Capabilities{Reason: capabilities.ReasonNotHelmManaged}, "No Helm release"},
		{capabilities.Capabilities{Reason: capabilities.ReasonNotKubernetes}, "not running on Kubernetes"},
		{capabilities.Capabilities{Reason: capabilities.ReasonClusterAPIUnavailable}, "Kubernetes API"},
	} {
		p, _ := passingPreflight()
		p.Capabilities = fakeDetector{caps: tc.caps}
		r := p.Run(context.Background(), "4.6.0", Options{})
		c := checkOf(t, r, CheckCapabilities)
		if r.OK || c.Status != CheckFail || !strings.Contains(c.Detail, tc.want) {
			t.Errorf("%s: ok=%v %+v", tc.caps.Reason, r.OK, c)
		}
	}
}

// (b)
func TestPreflight_Version(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		tags          fakeTags
		want          string
	}{
		{"not published", "4.9.0", fakeTags{tags: []string{"4.6.0"}}, "not published"},
		{"same version", "4.5.0", fakeTags{tags: []string{"4.5.0"}}, "not newer"},
		{"older version", "4.4.0", fakeTags{tags: []string{"v4.4.0"}}, "not newer"},
		{"not semver", "latest", fakeTags{tags: []string{"latest"}}, "not a release version"},
		{"registry down", "4.6.0", fakeTags{err: errors.New("registry request https://ghcr.io/v2/ returned HTTP 503")}, "HTTP 503"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, v := passingPreflight()
			p.Tags = tc.tags
			r := p.Run(context.Background(), tc.version, Options{})
			c := checkOf(t, r, CheckVersion)
			if r.OK || c.Status != CheckFail || !strings.Contains(c.Detail, tc.want) {
				t.Fatalf("ok=%v %+v", r.OK, c)
			}
			// A version that cannot be installed is not sent to cosign.
			if sig := checkOf(t, r, CheckSignature); sig.Status != CheckFail || len(v.calls()) != 0 {
				t.Fatalf("signature %+v, verify calls %v", sig, v.calls())
			}
		})
	}
	p, _ := passingPreflight()
	p.Tags = nil
	if c := checkOf(t, p.Run(context.Background(), "4.6.0", Options{}), CheckVersion); c.Status != CheckFail {
		t.Fatalf("no chart source: %+v", c)
	}
}

// (c)
func TestPreflight_Signature(t *testing.T) {
	p, v := passingPreflight()
	v.err = errors.New("cosign verify of ghcr.io/vistasecurity/vistaplatform:4.6.0 failed: none of the expected identities matched")
	r := p.Run(context.Background(), "4.6.0", Options{})
	if c := checkOf(t, r, CheckSignature); r.OK || c.Status != CheckFail || !strings.Contains(c.Detail, "identities matched") {
		t.Fatalf("mismatch: ok=%v %+v", r.OK, c)
	}

	p, v = passingPreflight()
	p.SkipSignature = true
	r = p.Run(context.Background(), "4.6.0", Options{})
	if c := checkOf(t, r, CheckSignature); !r.OK || c.Status != CheckWarn || len(v.calls()) != 0 {
		t.Fatalf("skip: ok=%v %+v calls %v", r.OK, c, v.calls())
	}

	p, v = passingPreflight()
	r = p.Run(context.Background(), "4.6.0", Options{DeferSignature: true})
	if c := checkOf(t, r, CheckSignature); c.Status != CheckPass || len(v.calls()) != 0 {
		t.Fatalf("defer: %+v calls %v", c, v.calls())
	}

	p, _ = passingPreflight()
	p.Verifier = nil
	if c := checkOf(t, p.Run(context.Background(), "4.6.0", Options{}), CheckSignature); c.Status != CheckFail {
		t.Fatalf("no verifier must fail closed: %+v", c)
	}
	p, _ = passingPreflight()
	p.Verifier = Cosign{}
	if c := checkOf(t, p.Run(context.Background(), "4.6.0", Options{}), CheckSignature); c.Status != CheckFail || !strings.Contains(c.Detail, "identity") {
		t.Fatalf("no identity must fail closed: %+v", c)
	}
}

// (d) — through the REAL release Secret decoding, from a fixture encoded the
// way Helm stores it.
func TestPreflight_ValueOverridesFromTheReleaseSecret(t *testing.T) {
	cfg := map[string]any{
		"image": map[string]any{"tag": "v4.5.0-hotfix1", "registry": "harbor.example"},
		"backends": map[string]any{
			"auth-service":      map[string]any{"image": map[string]any{"tag": "v4.5.0-hotfix2"}},
			"inventory-service": map[string]any{"image": map[string]any{"digest": "sha256:abc"}},
			"cbom-service":      map[string]any{"image": map[string]any{"digest": ""}}, // an un-pin, not a pin
			"audit-service":     map[string]any{"replicas": 2},
		},
		"frontend": map[string]any{"webUi": map[string]any{"image": map[string]any{"tag": "v4.5.0-hotfix3"}}},
	}
	client := fake.NewClientset(
		releaseSecret(t, 1, "4.4.0", HelmSuperseded, map[string]any{}, ""),
		releaseSecret(t, 2, "4.5.0", HelmDeployed, cfg, ""),
	)
	p, _ := passingPreflight()
	p.Releases = SecretReleases{Client: client, Namespace: upgradeTestNS, ReleaseName: upgradeTestRelease}
	r := p.Run(context.Background(), "4.6.0", Options{})
	c := checkOf(t, r, CheckValueOverrides)
	if !r.OK || c.Status != CheckWarn {
		t.Fatalf("ok=%v %+v", r.OK, c)
	}
	for _, want := range []string{"image.tag=v4.5.0-hotfix1", "backends.auth-service.image.tag=v4.5.0-hotfix2",
		"backends.inventory-service.image.digest", "frontend.webUi.image.tag=v4.5.0-hotfix3"} {
		if !strings.Contains(c.Detail, want) {
			t.Errorf("detail lacks %q: %s", want, c.Detail)
		}
	}
	if strings.Contains(c.Detail, "cbom-service") || strings.Contains(c.Detail, "audit-service") {
		t.Errorf("detail names a non-pin: %s", c.Detail)
	}

	// Only the LATEST revision's values count.
	client = fake.NewClientset(
		releaseSecret(t, 1, "4.4.0", HelmSuperseded, cfg, ""),
		releaseSecret(t, 2, "4.5.0", HelmDeployed, map[string]any{"tls": map[string]any{"dnsName": "x"}}, ""),
	)
	p.Releases = SecretReleases{Client: client, Namespace: upgradeTestNS, ReleaseName: upgradeTestRelease}
	if c := checkOf(t, p.Run(context.Background(), "4.6.0", Options{}), CheckValueOverrides); c.Status != CheckPass {
		t.Fatalf("clean latest revision: %+v", c)
	}

	p.Releases = fakeReleases{err: errors.New("forbidden")}
	if c := checkOf(t, p.Run(context.Background(), "4.6.0", Options{}), CheckValueOverrides); c.Status != CheckWarn {
		t.Fatalf("unreadable: %+v", c)
	}
}

const twoDeployments = `---
# Source: vistaplatform/templates/backend/deployments.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-service
spec:
  strategy:
    type: RollingUpdate
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pcap-processor
spec:
  strategy:
    type: Recreate
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inventory-service
spec: {}
---
apiVersion: v1
kind: Service
metadata:
  name: auth-service
`

// (e)
func TestPreflight_SingleNode(t *testing.T) {
	p, _ := passingPreflight()
	p.SingleNode = true
	p.Releases = fakeReleases{hist: []Release{{Revision: 2, Status: HelmDeployed, Manifest: twoDeployments}}}
	r := p.Run(context.Background(), "4.6.0", Options{})
	c := checkOf(t, r, CheckSingleNode)
	if !r.OK || c.Status != CheckWarn || !strings.Contains(c.Detail, "auth-service, inventory-service") || strings.Contains(c.Detail, "pcap-processor") {
		t.Fatalf("ok=%v %+v", r.OK, c)
	}
	p.SingleNode = false
	if c := checkOf(t, p.Run(context.Background(), "4.6.0", Options{}), CheckSingleNode); c.Status != CheckPass {
		t.Fatalf("multi-node: %+v", c)
	}
}

// (f)
func TestPreflight_Schema(t *testing.T) {
	for _, tc := range []struct {
		schema fakeSchema
		status string
	}{
		{fakeSchema{v: "4.5.0"}, CheckPass},
		{fakeSchema{v: "4.4.0"}, CheckWarn},
		{fakeSchema{v: ""}, CheckWarn},
		{fakeSchema{err: errors.New("permission denied for table schema_migration_status")}, CheckWarn},
	} {
		p, _ := passingPreflight()
		p.Schema = tc.schema
		r := p.Run(context.Background(), "4.6.0", Options{})
		if c := checkOf(t, r, CheckSchema); c.Status != tc.status || !r.OK {
			t.Errorf("%+v: %+v ok=%v", tc.schema, c, r.OK)
		}
	}
}

// (g)
func TestPreflight_RunInProgress(t *testing.T) {
	p, _ := passingPreflight()
	p.Runs = fakeRunning{list: []runs.Run{{Kind: runs.KindBackup, Status: runs.StatusRunning}}}
	r := p.Run(context.Background(), "4.6.0", Options{})
	if c := checkOf(t, r, CheckNoRunning); r.OK || c.Status != CheckFail || !strings.Contains(c.Detail, "backup run") {
		t.Fatalf("ok=%v %+v", r.OK, c)
	}
	p.Runs = fakeRunning{err: errors.New("db down")}
	if c := checkOf(t, p.Run(context.Background(), "4.6.0", Options{}), CheckNoRunning); c.Status != CheckFail {
		t.Fatalf("unreadable runs must fail: %+v", c)
	}
}

// (h)
func TestPreflight_RecentBackup(t *testing.T) {
	p, _ := passingPreflight()
	p.Backups = &fakeBackups{available: true}
	r := p.Run(context.Background(), "4.6.0", Options{})
	if c := checkOf(t, r, CheckRecentBackup); !r.OK || c.Status != CheckWarn || !strings.Contains(c.Detail, "take a backup first") {
		t.Fatalf("no recent: ok=%v %+v", r.OK, c)
	}
	p.Backups = &fakeBackups{available: false}
	if c := checkOf(t, p.Run(context.Background(), "4.6.0", Options{}), CheckRecentBackup); c.Status != CheckWarn || !strings.Contains(c.Detail, "not configured") {
		t.Fatalf("no storage: %+v", c)
	}
}

func TestDecodeRelease_RealHelmEncoding(t *testing.T) {
	sec := releaseSecret(t, 7, "4.5.0", HelmDeployed, map[string]any{"image": map[string]any{"tag": "x"}}, "kind: Service\n")
	rel, err := DecodeRelease(sec.Data["release"])
	if err != nil {
		t.Fatal(err)
	}
	if rel.Revision != 7 || rel.ChartVersion != "4.5.0" || rel.AppVersion != "4.5.0" || rel.Status != HelmDeployed ||
		rel.Manifest != "kind: Service\n" || rel.Updated.IsZero() || str(dig(rel.Config, "image", "tag")) != "x" {
		t.Fatalf("decoded %+v", rel)
	}
	// Plain (un-gzipped) JSON is accepted; garbage is an error.
	plain := base64.StdEncoding.EncodeToString([]byte(`{"version":3,"info":{"status":"failed"},"chart":{"metadata":{"version":"4.6.0"}}}`))
	if rel, err := DecodeRelease([]byte(plain)); err != nil || rel.Revision != 3 || rel.Status != HelmFailed {
		t.Fatalf("plain: %+v %v", rel, err)
	}
	for _, bad := range []string{"!!not base64!!", base64.StdEncoding.EncodeToString([]byte{0x1f, 0x8b, 0, 0}), base64.StdEncoding.EncodeToString([]byte("not json"))} {
		if _, err := DecodeRelease([]byte(bad)); err == nil {
			t.Errorf("decoded %q", bad)
		}
	}
}

func TestSecretReleases_HistoryAndRollbackCandidate(t *testing.T) {
	other := releaseSecret(t, 1, "1.0.0", HelmDeployed, nil, "")
	other.Name = "sh.helm.release.v1.vista.v2.v1" // a release called "vista.v2"
	other.Labels["name"] = "vista.v2"
	client := fake.NewClientset(
		releaseSecret(t, 1, "4.4.0", HelmSuperseded, nil, ""),
		releaseSecret(t, 2, "4.5.0", HelmDeployed, nil, ""),
		releaseSecret(t, 3, "4.6.0", HelmFailed, nil, ""),
		other,
		&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "unrelated", Namespace: upgradeTestNS}},
	)
	hist, err := SecretReleases{Client: client, Namespace: upgradeTestNS, ReleaseName: upgradeTestRelease}.History(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var revs []int
	for _, r := range hist {
		revs = append(revs, r.Revision)
	}
	if !reflect.DeepEqual(revs, []int{3, 2, 1}) {
		t.Fatalf("revisions %v", revs)
	}
	// After a failed upgrade the previous revision is still `deployed`.
	if c := RollbackCandidate(hist); c == nil || c.Revision != 2 || c.ChartVersion != "4.5.0" {
		t.Fatalf("candidate %+v", c)
	}
	// After a successful one it is `superseded`.
	hist[0].Status, hist[1].Status = HelmDeployed, HelmSuperseded
	if c := RollbackCandidate(hist); c == nil || c.Revision != 2 {
		t.Fatalf("candidate after success %+v", c)
	}
	if c := RollbackCandidate(hist[:1]); c != nil {
		t.Fatalf("one revision has no candidate: %+v", c)
	}
	if _, err := (SecretReleases{Client: fake.NewClientset(), Namespace: upgradeTestNS, ReleaseName: upgradeTestRelease}).History(context.Background()); !errors.Is(err, ErrNoRelease) {
		t.Fatalf("empty: %v", err)
	}
}

func TestChartRef(t *testing.T) {
	if ref, err := ChartRef("oci://registry.example:5000/charts/vistaplatform", "4.6.0"); err != nil || ref != "registry.example:5000/charts/vistaplatform:4.6.0" {
		t.Fatalf("%q %v", ref, err)
	}
	if _, err := ChartRef("https://example/chart", "4.6.0"); err == nil {
		t.Fatal("accepted a non-oci source")
	}
}
