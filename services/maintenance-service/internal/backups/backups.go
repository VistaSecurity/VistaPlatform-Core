// Package backups is platform backups (spec platform-maintenance.md §3
// "Backup", WP3): a `backup` run whose Kubernetes Job runs `pg_dump -Fc` of
// the platform database into the backups volume, after which this service —
// which mounts the same volume — writes the manifest, packs the bundle (a tar,
// or an encrypted bundle when the install's Secrets are included, D2), prunes
// to the retention count, and serves downloads.
//
// Collect posture, never key material, applies with one deliberate exception
// the operator opts into: with include_secrets the bundle carries the chart's
// Secrets (the encryption master key among them), because without that key a
// restored database holds credentials nothing can decrypt. That bundle exists
// only encrypted under the operator's passphrase; the Secrets are streamed
// straight into the encrypted tar and never written to disk in the clear, and
// the passphrase is held in memory only for the length of the run.
package backups

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// Backup statuses (platform_backups.status).
const (
	StatusRunning = "running"
	StatusReady   = "ready"
	StatusFailed  = "failed"
	StatusDeleted = "deleted"
)

// Step names of a backup run.
const (
	StepDump      = "dump"      // the Job: pg_dump -Fc into the volume
	StepPackage   = "package"   // the service: manifest + bundle (+ encryption)
	StepRetention = "retention" // the service: prune beyond the retention count
)

// Files in a backup's directory on the volume.
const (
	FileDump          = "database.dump"
	FilePgDumpVersion = "pg_dump.version"
	FileSchema        = "schema.json"
	FileManifest      = "manifest.json"
	FileSecrets       = "secrets.yaml"
	FileBundleTar     = "bundle.tar"
	FileBundleEnc     = "bundle.enc"
	// JobTemplateFile is the key of the chart's Job-template ConfigMap, and the
	// file name under its mount.
	JobTemplateFile = "backup-job.yaml"
)

// Contents is platform_backups.contents.
type Contents struct {
	Database bool `json:"database"`
	Secrets  bool `json:"secrets"`
	// CBOMSigningKey: the CBOM artifact signing key Secret is in the bundle
	// (only with Secrets, and only when MAINTENANCE_SECRET_CBOM_SIGNING names
	// the Secret cbom-service signs with and it was found). Known once the
	// backup is ready.
	CBOMSigningKey bool `json:"cbom_signing_key"`
}

// Backup is one row of platform_backups.
type Backup struct {
	ID        uuid.UUID  `json:"id"`
	RunID     *uuid.UUID `json:"run_id"`
	CreatedAt time.Time  `json:"created_at"`
	SizeBytes *int64     `json:"size_bytes"`
	Contents  Contents   `json:"contents"`
	Encrypted bool       `json:"encrypted"`
	Manifest  *Manifest  `json:"manifest"`
	Status    string     `json:"status"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
	// FilePath is relative to the backups volume. Not served: the download
	// route is the only way to the file.
	FilePath string `json:"-"`
}

var (
	// ErrNotFound: no backup with that id.
	ErrNotFound = errors.New("backups: backup not found")
	// ErrUnavailable: this install has no backup storage or no cluster API.
	ErrUnavailable = errors.New("backups: backups are not available in this deployment")
	// ErrNotReady: the backup is not ready to download.
	ErrNotReady = errors.New("backups: backup is not ready")
	// ErrBackupRunning: a running backup cannot be deleted.
	ErrBackupRunning = errors.New("backups: backup is still running")
)

// SecretNames are the four chart Secrets a backup with include_secrets
// carries, as the chart named them (rendered into the pod's environment).
type SecretNames struct {
	Install    string // vistaplatform.installSecretName
	Platform   string // vistaplatform.platformSecretName (platform.existingSecretName when set)
	JWTSigning string // vistaplatform.jwtSigningSecretName
	Generated  string // vistaplatform.generatedSecretName
	// CBOMSigning is vistaplatform.cbomSigningSecretName — the Secret
	// cbom-service signs with, chart-managed or cbomSigning.existingSecretName
	// (MAINTENANCE_SECRET_CBOM_SIGNING); empty skips it.
	CBOMSigning string
}

func (s SecretNames) list() []string {
	var out []string
	for _, n := range []string{s.Install, s.Platform, s.JWTSigning, s.Generated, s.CBOMSigning} {
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}
