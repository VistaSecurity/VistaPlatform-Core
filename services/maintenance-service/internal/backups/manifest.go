package backups

import (
	"encoding/json"
	"strings"
	"time"
)

// ManifestFormatVersion is manifest.json's format_version.
const ManifestFormatVersion = 1

// Manifest is manifest.json, and platform_backups.manifest. It describes the
// bundle; it never carries key material (the Secrets' NAMES are listed, their
// contents are only in the encrypted bundle).
type Manifest struct {
	FormatVersion int       `json:"format_version"`
	BackupID      string    `json:"backup_id"`
	CreatedAt     time.Time `json:"created_at"`
	AppVersion    string    `json:"app_version"`
	ChartVersion  string    `json:"chart_version"`
	// Schema is the newest public.schema_migration_status row — schema hash
	// plus the app/chart version that wrote it — as the backup Job read it.
	// null when the table is absent (an install whose schema is not applied by
	// the chart's Job).
	Schema      json.RawMessage `json:"schema"`
	Edition     string          `json:"edition"`
	ChartSource string          `json:"chart_source"`
	InstallID   string          `json:"install_id,omitempty"`
	Release     ManifestRelease `json:"release"`
	Database    ManifestDB      `json:"database"`
	Contents    Contents        `json:"contents"`
	// Secrets names the Secrets in secrets.yaml (empty without include_secrets).
	Secrets       []string `json:"secrets"`
	Encrypted     bool     `json:"encrypted"`
	PgDumpVersion string   `json:"pg_dump_version"`
}

// ManifestRelease is the Helm release the backup was taken from.
type ManifestRelease struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// ManifestDB says where the database credential lives, so a restore knows
// which Secret key to recreate. External = datastores.postgres.enabled=false.
type ManifestDB struct {
	External         bool   `json:"external"`
	CredentialSecret string `json:"credential_secret,omitempty"`
	CredentialKey    string `json:"credential_key,omitempty"`
}

// EditionFromChartSource names the image line a chart source belongs to:
// "core" for the public Core chart (ghcr.io/vistasecurity), "commercial" for
// the Enterprise/MSP line (docker.io/vistasecurity), "unknown" for a mirror
// (whose chart_source is recorded verbatim beside it).
func EditionFromChartSource(src string) string {
	s := strings.TrimPrefix(strings.ToLower(src), "oci://")
	switch {
	case strings.HasPrefix(s, "ghcr.io/vistasecurity/"):
		return "core"
	case strings.HasPrefix(s, "docker.io/vistasecurity/"), strings.HasPrefix(s, "registry-1.docker.io/vistasecurity/"):
		return "commercial"
	}
	return "unknown"
}
