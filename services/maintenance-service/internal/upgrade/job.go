package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// UpdateJobTemplateFile is the key of the chart's update-Job ConfigMap
// (templates/maintenance/update-job-configmap.yaml) and the file name under
// its mount.
const UpdateJobTemplateFile = "update-job.yaml"

// The variables the service sets on the Job's container; the template carries
// each with an empty value. They are the ONLY things the service changes:
// image, ServiceAccount, release, namespace, chart source, timeout, registry
// credential and security context are all the chart's, rendered by Helm, so
// the Job carries everything it needs from creation — which matters, because
// the Job replaces the service that created it.
const (
	EnvAction   = "MAINTENANCE_ACTION" // upgrade | rollback
	EnvVersion  = "TARGET_VERSION"     // upgrade: the chart version
	EnvRevision = "ROLLBACK_REVISION"  // rollback: the Helm revision
)

// Job actions, which are also the name of the Job's step in the run.
const (
	ActionUpgrade  = "upgrade"
	ActionRollback = "rollback"
)

// UpdaterServiceAccount is the account the Job runs helm as.
const UpdaterServiceAccount = "vistaplatform-updater"

// LoadUpdateJobTemplate reads and checks the chart-rendered update Job.
func LoadUpdateJobTemplate(dir string) (*batchv1.Job, error) {
	raw, err := os.ReadFile(filepath.Join(dir, UpdateJobTemplateFile))
	if err != nil {
		return nil, fmt.Errorf("upgrade: read the update Job template: %w", err)
	}
	var job batchv1.Job
	if err := yaml.UnmarshalStrict(raw, &job); err != nil {
		return nil, fmt.Errorf("upgrade: parse the update Job template: %w", err)
	}
	spec := job.Spec.Template.Spec
	switch {
	case job.Kind != "Job" || len(spec.Containers) == 0:
		return nil, fmt.Errorf("upgrade: the update Job template is not a Job with a container")
	case spec.ServiceAccountName != UpdaterServiceAccount:
		return nil, fmt.Errorf("upgrade: the update Job template must run as %s, not %q", UpdaterServiceAccount, spec.ServiceAccountName)
	}
	for _, name := range []string{EnvAction, EnvVersion, EnvRevision} {
		if !hasEnv(spec.Containers, name) {
			return nil, fmt.Errorf("upgrade: the update Job template's containers carry no %s variable", name)
		}
	}
	return &job, nil
}

func hasEnv(cs []corev1.Container, name string) bool {
	for _, c := range cs {
		for _, e := range c.Env {
			if e.Name == name {
				return true
			}
		}
	}
	return false
}

// UpdateJobName is short (it ends up in pod names and label values) and
// unique per run.
func UpdateJobName(action string, runID uuid.UUID) string {
	return "maintenance-" + action + "-" + strings.ReplaceAll(runID.String(), "-", "")[:12]
}

// BuildUpdateJob instantiates the template for one run.
func BuildUpdateJob(tmpl *batchv1.Job, runID uuid.UUID, action, version string, revision int) *batchv1.Job {
	job := tmpl.DeepCopy()
	job.Name = UpdateJobName(action, runID)
	job.GenerateName = ""
	rev := ""
	if revision > 0 {
		rev = strconv.Itoa(revision)
	}
	set := map[string]string{EnvAction: action, EnvVersion: version, EnvRevision: rev}
	for i := range job.Spec.Template.Spec.Containers {
		c := &job.Spec.Template.Spec.Containers[i]
		for j := range c.Env {
			if v, ok := set[c.Env[j].Name]; ok {
				c.Env[j].Value = v
				c.Env[j].ValueFrom = nil
			}
		}
	}
	return job
}
