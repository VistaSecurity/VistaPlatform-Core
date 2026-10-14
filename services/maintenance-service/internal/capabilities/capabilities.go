// Package capabilities decides which maintenance operations this install
// supports: whether Helm manages it, whether a GitOps controller owns it, and
// therefore whether the console may offer backups and updates.
//
// The admin console never guesses. It renders whatever Capabilities says, and
// every "unavailable" state on the Maintenance pages carries the Reason below
// in plain language (spec platform-maintenance.md §1).
package capabilities

import (
	"context"
	"errors"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Reasons the console renders. An empty Reason means updates are available.
const (
	// ReasonNotKubernetes: no in-cluster configuration (Docker Compose, a
	// developer laptop). Compose is evaluation only; nothing is offered.
	ReasonNotKubernetes = "not_kubernetes"
	// ReasonNotHelmManaged: in a cluster, but no Helm release Secret for this
	// release exists — the chart was rendered with `helm template` and applied
	// by something else (Argo CD does exactly this).
	ReasonNotHelmManaged = "not_helm_managed"
	// ReasonGitOps: Helm manages the release, but a GitOps controller owns it.
	// An in-product `helm upgrade` would be reverted on the controller's next
	// sync, so the console points the operator at their values repository.
	ReasonGitOps = "gitops"
	// ReasonClusterAPIUnavailable: in a cluster, but the Kubernetes API could
	// not answer (RBAC missing, API server unreachable). Fail closed.
	ReasonClusterAPIUnavailable = "cluster_api_unavailable"
	// ReasonReleaseUnknown: in a cluster, but HELM_RELEASE_NAME or
	// POD_NAMESPACE was not rendered into the pod, so there is nothing to look
	// up. Only a hand-edited Deployment reaches this.
	ReasonReleaseUnknown = "release_unknown"
)

// GitOpsLabels are the labels whose presence on the release Secret or on this
// pod means a GitOps controller owns the install.
var GitOpsLabels = []string{
	"argocd.argoproj.io/instance",
	"kustomize.toolkit.fluxcd.io/name",
	"helm.toolkit.fluxcd.io/name",
}

// helmReleaseSecretPrefix is the name prefix of the Secrets Helm 3 stores a
// release's revisions in: sh.helm.release.v1.<release>.v<revision>.
const helmReleaseSecretPrefix = "sh.helm.release.v1."

// Capabilities is the `capabilities` object of GET /admin/maintenance/status.
type Capabilities struct {
	HelmManaged bool   `json:"helm_managed"`
	GitOps      bool   `json:"gitops"`
	Backups     bool   `json:"backups"`
	Updates     bool   `json:"updates"`
	Reason      string `json:"reason"`
}

// Release is the `release` object of GET /admin/maintenance/status.
type Release struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Detector answers the capability question. The Kubernetes implementation is
// NewKubernetes; NotKubernetes is what a process outside a cluster gets.
type Detector interface {
	Detect(ctx context.Context) Capabilities
}

// Settings are the inputs the chart renders into the pod's environment.
type Settings struct {
	ReleaseName string // HELM_RELEASE_NAME
	Namespace   string // POD_NAMESPACE (downward API)
	PodName     string // POD_NAME (downward API); empty skips the pod-label check
	// BackupsEnabled is MAINTENANCE_BACKUPS_ENABLED == "true": the chart
	// rendered the backups PVC (maintenance.backups.enabled).
	BackupsEnabled bool
}

// NotKubernetes is the detector for a process with no in-cluster
// configuration: every capability false, reason not_kubernetes.
type NotKubernetes struct{}

// Detect implements Detector.
func (NotKubernetes) Detect(context.Context) Capabilities {
	return Capabilities{Reason: ReasonNotKubernetes}
}

// Kubernetes detects capabilities through the Kubernetes API with the
// service's own namespace-scoped ServiceAccount. It reads only what the chart's
// maintenance-service Role grants: Secrets (list) and Pods (get).
type Kubernetes struct {
	client   kubernetes.Interface
	settings Settings
}

// NewKubernetes builds a detector over any clientset — the real one in
// production, k8s.io/client-go/kubernetes/fake in tests.
func NewKubernetes(client kubernetes.Interface, settings Settings) *Kubernetes {
	return &Kubernetes{client: client, settings: settings}
}

// FromEnvironment returns the Kubernetes detector when the process runs in a
// cluster (in-cluster config resolves), and NotKubernetes otherwise.
func FromEnvironment(settings Settings) (Detector, error) {
	cfg, err := rest.InClusterConfig()
	if errors.Is(err, rest.ErrNotInCluster) {
		return NotKubernetes{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("capabilities: in-cluster config: %w", err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("capabilities: build clientset: %w", err)
	}
	return NewKubernetes(client, settings), nil
}

// Detect implements Detector.
//
//   - helm_managed: a Secret named sh.helm.release.v1.<release>.v* exists in
//     the namespace.
//   - gitops: that Secret, or this pod, carries one of GitOpsLabels. The pod
//     stands in for "this pod's Deployment" because the service's Role grants
//     no read on Deployments (the chart test pins the verb list), and the
//     GitOps controllers that do not leave a Helm release Secret behind at all
//     (Argo CD renders with `helm template`) are already caught by
//     helm_managed=false.
//   - updates: helm_managed && !gitops.
//   - backups: the chart rendered backup storage (MAINTENANCE_BACKUPS_ENABLED)
//     and the API answered.
func (k *Kubernetes) Detect(ctx context.Context) Capabilities {
	s := k.settings
	// Backups run as Jobs through the same API, so they are offered only once
	// the API has answered.
	var caps Capabilities
	if s.ReleaseName == "" || s.Namespace == "" {
		caps.Reason = ReasonReleaseUnknown
		return caps
	}

	// Helm labels its storage Secrets owner=helm; the selector keeps the list
	// to those (a namespace can hold hundreds of Secrets), and the name prefix
	// is the actual rule.
	secrets, err := k.client.CoreV1().Secrets(s.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm",
	})
	if err != nil {
		caps.Reason = ReasonClusterAPIUnavailable
		return caps
	}
	caps.Backups = s.BackupsEnabled
	prefix := helmReleaseSecretPrefix + s.ReleaseName + ".v"
	for i := range secrets.Items {
		sec := &secrets.Items[i]
		if !isRevisionSuffix(strings.TrimPrefix(sec.Name, prefix)) || !strings.HasPrefix(sec.Name, prefix) {
			continue
		}
		caps.HelmManaged = true
		if hasGitOpsLabel(sec.Labels) {
			caps.GitOps = true
		}
	}

	if !caps.GitOps && s.PodName != "" {
		pod, err := k.client.CoreV1().Pods(s.Namespace).Get(ctx, s.PodName, metav1.GetOptions{})
		if err == nil && hasGitOpsLabel(pod.Labels) {
			caps.GitOps = true
		}
		// A failed pod read is not a reason to withhold updates the release
		// Secret already proved are Helm's: the Secret is the authority, the
		// pod only adds a second place to find a GitOps label.
	}

	caps.Updates = caps.HelmManaged && !caps.GitOps
	switch {
	case caps.GitOps:
		caps.Reason = ReasonGitOps
	case !caps.HelmManaged:
		caps.Reason = ReasonNotHelmManaged
	}
	return caps
}

// isRevisionSuffix reports whether rev is a Helm revision number. Release
// names may contain dots, so without it release "vista" would claim the
// Secrets of a release called "vista.v2".
func isRevisionSuffix(rev string) bool {
	if rev == "" {
		return false
	}
	for _, r := range rev {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func hasGitOpsLabel(labels map[string]string) bool {
	for _, l := range GitOpsLabels {
		if _, ok := labels[l]; ok {
			return true
		}
	}
	return false
}
