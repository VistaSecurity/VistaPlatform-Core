package backups

import (
	"context"
	"fmt"
	"sort"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// secretsList is secrets.yaml: a Kubernetes List an operator applies into the
// restore namespace with `kubectl apply -n <ns> -f secrets.yaml` BEFORE
// installing the chart. Each Secret keeps its labels and annotations — the
// Helm ownership metadata (app.kubernetes.io/managed-by, meta.helm.sh/*) is
// what lets `helm install` of the same release name adopt it, and the chart's
// lookup-and-preserve templates then keep the restored values instead of
// generating new ones. Server-side identity (uid, resourceVersion,
// managedFields, ownerReferences, namespace) is dropped.
type secretsList struct {
	APIVersion string          `json:"apiVersion"`
	Kind       string          `json:"kind"`
	Items      []corev1.Secret `json:"items"`
}

// dropAnnotations are annotations that must not travel to a new cluster.
var dropAnnotations = []string{"kubectl.kubernetes.io/last-applied-configuration"}

// readSecrets reads the named Secrets and renders secrets.yaml. A Secret that
// does not exist (jwt-signing on an install with jwtSigning.enabled=false) is
// skipped and absent from the returned names. Any other read error fails the
// backup: a bundle that silently lacks the master key would restore into
// undecryptable credentials.
func readSecrets(ctx context.Context, client kubernetes.Interface, namespace string, names []string) ([]byte, []string, error) {
	list := secretsList{APIVersion: "v1", Kind: "List", Items: []corev1.Secret{}}
	var included []string
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		sec, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read Secret %s: %w", name, err)
		}
		out := corev1.Secret{
			TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Secret"},
			ObjectMeta: metav1.ObjectMeta{
				Name:        sec.Name,
				Labels:      sec.Labels,
				Annotations: map[string]string{},
			},
			Type: sec.Type,
			Data: sec.Data,
		}
		for k, v := range sec.Annotations {
			out.Annotations[k] = v
		}
		for _, k := range dropAnnotations {
			delete(out.Annotations, k)
		}
		if len(out.Annotations) == 0 {
			out.Annotations = nil
		}
		list.Items = append(list.Items, out)
		included = append(included, sec.Name)
	}
	sort.Strings(included)
	raw, err := yaml.Marshal(list)
	if err != nil {
		return nil, nil, err
	}
	return raw, included, nil
}
