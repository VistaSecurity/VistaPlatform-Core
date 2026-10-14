package backups

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

// EnvBackupID is the variable the service sets on the Job's containers; the
// template carries it with an empty value. It is the ONLY thing the service
// changes in the pod — everything else (image, database connection, volume,
// security context) is the chart's, rendered by Helm, so the Job cannot drift
// from what the chart would do and the service never edits YAML.
const EnvBackupID = "BACKUP_ID"

// LoadJobTemplate reads the chart-rendered backup Job (the
// <release>-maintenance-jobs ConfigMap, mounted into the pod). It is read on
// every backup, so a `helm upgrade` that changes it applies to the next backup
// once the kubelet has refreshed the mount.
func LoadJobTemplate(dir string) (*batchv1.Job, error) {
	raw, err := os.ReadFile(filepath.Join(dir, JobTemplateFile))
	if err != nil {
		return nil, fmt.Errorf("backups: read the Job template: %w", err)
	}
	var job batchv1.Job
	if err := yaml.UnmarshalStrict(raw, &job); err != nil {
		return nil, fmt.Errorf("backups: parse the Job template: %w", err)
	}
	if job.Kind != "Job" || len(job.Spec.Template.Spec.Containers) == 0 {
		return nil, fmt.Errorf("backups: the Job template is not a Job with a container")
	}
	if !hasEnv(job.Spec.Template.Spec.Containers, EnvBackupID) {
		return nil, fmt.Errorf("backups: the Job template's containers carry no %s variable", EnvBackupID)
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

// JobName is the backup Job's name: short (a Job name ends up in its pods'
// names and a label value, both bounded) and unique per backup.
func JobName(backupID uuid.UUID) string {
	return "maintenance-backup-" + strings.ReplaceAll(backupID.String(), "-", "")[:12]
}

// BuildJob instantiates the template for one backup: its name, and BACKUP_ID.
func BuildJob(tmpl *batchv1.Job, backupID uuid.UUID) *batchv1.Job {
	job := tmpl.DeepCopy()
	job.Name = JobName(backupID)
	job.GenerateName = ""
	if job.Labels == nil {
		job.Labels = map[string]string{}
	}
	job.Labels["vistasecurity.io/maintenance-backup"] = backupID.String()
	for i := range job.Spec.Template.Spec.Containers {
		c := &job.Spec.Template.Spec.Containers[i]
		for j := range c.Env {
			if c.Env[j].Name == EnvBackupID {
				c.Env[j].Value = backupID.String()
				c.Env[j].ValueFrom = nil
			}
		}
	}
	return job
}
