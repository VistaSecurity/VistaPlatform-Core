package capabilities

import (
	"context"
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const (
	ns      = "vista"
	release = "vista"
	podName = "vista-maintenance-service-abc"
)

func helmSecret(name string, labels map[string]string) *corev1.Secret {
	l := map[string]string{"owner": "helm", "name": release, "status": "deployed"}
	for k, v := range labels {
		l[k] = v
	}
	return &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns, Labels: l}, Type: "helm.sh/release.v1"}
}

func pod(labels map[string]string) *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: podName, Namespace: ns, Labels: labels}}
}

func settings() Settings {
	return Settings{ReleaseName: release, Namespace: ns, PodName: podName, BackupsEnabled: true}
}

func detect(t *testing.T, s Settings, objs ...runtime.Object) Capabilities {
	t.Helper()
	return NewKubernetes(fake.NewSimpleClientset(objs...), s).Detect(context.Background())
}

func TestNotKubernetes_EverythingOff(t *testing.T) {
	got := NotKubernetes{}.Detect(context.Background())
	want := Capabilities{Reason: ReasonNotKubernetes}
	if got != want {
		t.Fatalf("NotKubernetes = %+v, want %+v", got, want)
	}
}

func TestHelmManaged_UpdatesOffered(t *testing.T) {
	got := detect(t, settings(), helmSecret("sh.helm.release.v1.vista.v3", nil), pod(nil))
	want := Capabilities{HelmManaged: true, Backups: true, Updates: true}
	if got != want {
		t.Fatalf("helm-managed install = %+v, want %+v", got, want)
	}
}

func TestNoReleaseSecret_NotHelmManaged(t *testing.T) {
	// Argo CD renders with `helm template` and leaves no release Secret.
	got := detect(t, settings(), pod(nil))
	if got.HelmManaged || got.Updates || got.Reason != ReasonNotHelmManaged {
		t.Fatalf("no release Secret = %+v, want helm_managed=false updates=false reason=%s", got, ReasonNotHelmManaged)
	}
	if !got.Backups {
		t.Fatalf("backups depend on storage, not on Helm: %+v", got)
	}
}

func TestOtherReleasesSecretsDoNotCount(t *testing.T) {
	cases := []string{
		"sh.helm.release.v1.vista-other.v1", // a different release
		"sh.helm.release.v1.vista.v2.v1",    // release "vista.v2"
		"sh.helm.release.v1.vista.vx",       // not a revision
		"vista.v1",                          // not a Helm storage name
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			got := detect(t, settings(), helmSecret(name, nil))
			if got.HelmManaged {
				t.Fatalf("Secret %q made release %q helm-managed: %+v", name, release, got)
			}
		})
	}
}

func TestSecretWithoutHelmOwnerLabelIsIgnored(t *testing.T) {
	sec := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "sh.helm.release.v1.vista.v1", Namespace: ns}}
	if got := detect(t, settings(), sec); got.HelmManaged {
		t.Fatalf("an unlabelled lookalike Secret counted as Helm storage: %+v", got)
	}
}

func TestGitOpsLabels(t *testing.T) {
	for _, label := range GitOpsLabels {
		t.Run("secret/"+label, func(t *testing.T) {
			got := detect(t, settings(), helmSecret("sh.helm.release.v1.vista.v1", map[string]string{label: "x"}), pod(nil))
			assertGitOps(t, got)
		})
		t.Run("pod/"+label, func(t *testing.T) {
			got := detect(t, settings(), helmSecret("sh.helm.release.v1.vista.v1", nil), pod(map[string]string{label: "x"}))
			assertGitOps(t, got)
		})
	}
}

func assertGitOps(t *testing.T, got Capabilities) {
	t.Helper()
	want := Capabilities{HelmManaged: true, GitOps: true, Backups: true, Updates: false, Reason: ReasonGitOps}
	if got != want {
		t.Fatalf("GitOps-owned install = %+v, want %+v", got, want)
	}
}

func TestReleaseUnknown(t *testing.T) {
	s := settings()
	s.ReleaseName = ""
	got := detect(t, s, helmSecret("sh.helm.release.v1.vista.v1", nil))
	if got != (Capabilities{Reason: ReasonReleaseUnknown}) {
		t.Fatalf("no release name = %+v", got)
	}
}

func TestClusterAPIErrorFailsClosed(t *testing.T) {
	client := fake.NewSimpleClientset(helmSecret("sh.helm.release.v1.vista.v1", nil))
	client.PrependReactor("list", "secrets", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("secrets is forbidden")
	})
	got := NewKubernetes(client, settings()).Detect(context.Background())
	if got != (Capabilities{Reason: ReasonClusterAPIUnavailable}) {
		t.Fatalf("API error = %+v, want everything off with reason %s", got, ReasonClusterAPIUnavailable)
	}
}

func TestPodReadErrorDoesNotWithholdUpdates(t *testing.T) {
	client := fake.NewSimpleClientset(helmSecret("sh.helm.release.v1.vista.v1", nil))
	client.PrependReactor("get", "pods", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("pods is forbidden")
	})
	got := NewKubernetes(client, settings()).Detect(context.Background())
	if !got.Updates {
		t.Fatalf("pod read error withheld updates: %+v", got)
	}
}

func TestBackupsFollowTheChartSetting(t *testing.T) {
	s := settings()
	s.BackupsEnabled = false
	if got := detect(t, s, helmSecret("sh.helm.release.v1.vista.v1", nil)); got.Backups {
		t.Fatalf("backups offered with maintenance.backups.enabled=false: %+v", got)
	}
}

// The detector reads only what the chart's maintenance-service Role grants:
// secrets list and pods get. A new API call here needs a new Role rule, and
// scripts/test-chart-maintenance-rbac.mjs pins that list.
func TestDetectorStaysInsideTheRole(t *testing.T) {
	client := fake.NewSimpleClientset(helmSecret("sh.helm.release.v1.vista.v1", nil), pod(nil))
	NewKubernetes(client, settings()).Detect(context.Background())
	allowed := map[string]bool{"list/secrets": true, "get/pods": true}
	for _, a := range client.Actions() {
		key := a.GetVerb() + "/" + a.GetResource().Resource
		if !allowed[key] {
			t.Errorf("detector made %s, which the maintenance-service Role does not grant", key)
		}
		if a.GetNamespace() != ns {
			t.Errorf("detector made %s outside namespace %q (%q)", key, ns, a.GetNamespace())
		}
	}
}
