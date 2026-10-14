package upgrade

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// helmReleasePrefix is the name prefix of Helm 3's storage Secrets:
// sh.helm.release.v1.<release>.v<revision>.
const helmReleasePrefix = "sh.helm.release.v1."

// maxReleaseBytes bounds one decoded release (the rendered manifest is the
// bulk of it; this chart's is well under 2 MiB).
const maxReleaseBytes = 32 << 20

// gzipMagic is the first two bytes of a gzip stream. Helm gzips the release
// JSON before base64-encoding it into the Secret's `release` key.
var gzipMagic = []byte{0x1f, 0x8b}

// Release is one revision of the Helm release, as decoded from its Secret.
type Release struct {
	Revision     int       `json:"revision"`
	ChartVersion string    `json:"chart_version"`
	AppVersion   string    `json:"app_version"`
	Status       string    `json:"status"`
	Updated      time.Time `json:"updated"`
	Description  string    `json:"description,omitempty"`

	// Config is the user-supplied values of this revision (what
	// --reset-then-reuse-values carries forward). Never served: values can hold
	// secrets.
	Config map[string]any `json:"-"`
	// Manifest is the rendered manifest of this revision. Never served.
	Manifest string `json:"-"`
}

// helmRelease is the subset of Helm's release JSON this package reads.
type helmRelease struct {
	Name      string         `json:"name"`
	Version   int            `json:"version"`
	Namespace string         `json:"namespace"`
	Config    map[string]any `json:"config"`
	Manifest  string         `json:"manifest"`
	Info      struct {
		LastDeployed time.Time `json:"last_deployed"`
		Status       string    `json:"status"`
		Description  string    `json:"description"`
	} `json:"info"`
	Chart struct {
		Metadata struct {
			Version    string `json:"version"`
			AppVersion string `json:"appVersion"`
		} `json:"metadata"`
	} `json:"chart"`
}

// DecodeRelease decodes the `release` key of a Helm 3 release Secret: base64,
// then gzip (Helm always gzips; a plain JSON payload is accepted too), then
// JSON. The Secret's data as client-go returns it — already one base64 layer
// removed by the API — is the input.
func DecodeRelease(data []byte) (Release, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return Release{}, fmt.Errorf("release payload is not base64: %w", err)
	}
	if bytes.HasPrefix(raw, gzipMagic) {
		zr, err := gzip.NewReader(bytes.NewReader(raw))
		if err != nil {
			return Release{}, fmt.Errorf("release payload is not gzip: %w", err)
		}
		raw, err = io.ReadAll(io.LimitReader(zr, maxReleaseBytes+1))
		if err != nil {
			return Release{}, fmt.Errorf("release payload: %w", err)
		}
		if len(raw) > maxReleaseBytes {
			return Release{}, errors.New("release payload is larger than this service reads")
		}
	}
	var hr helmRelease
	if err := json.Unmarshal(raw, &hr); err != nil {
		return Release{}, fmt.Errorf("release payload is not a Helm release: %w", err)
	}
	return Release{
		Revision:     hr.Version,
		ChartVersion: hr.Chart.Metadata.Version,
		AppVersion:   hr.Chart.Metadata.AppVersion,
		Status:       hr.Info.Status,
		Updated:      hr.Info.LastDeployed.UTC(),
		Description:  hr.Info.Description,
		Config:       hr.Config,
		Manifest:     hr.Manifest,
	}, nil
}

// ReleaseReader reads the Helm history of this install's release.
type ReleaseReader interface {
	// History returns every stored revision, newest first.
	History(ctx context.Context) ([]Release, error)
}

// SecretReleases reads the history from the release Secrets with the
// service's own ServiceAccount (secrets get/list).
type SecretReleases struct {
	Client      kubernetes.Interface
	Namespace   string
	ReleaseName string
}

// ErrNoRelease: no release Secret for this release exists.
var ErrNoRelease = errors.New("upgrade: no Helm release found for this install")

// History implements ReleaseReader.
func (s SecretReleases) History(ctx context.Context) ([]Release, error) {
	if s.Client == nil || s.ReleaseName == "" {
		return nil, ErrNoRelease
	}
	list, err := s.Client.CoreV1().Secrets(s.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm,name=" + s.ReleaseName,
	})
	if err != nil {
		return nil, fmt.Errorf("upgrade: list release Secrets: %w", err)
	}
	prefix := helmReleasePrefix + s.ReleaseName + ".v"
	var out []Release
	for i := range list.Items {
		sec := &list.Items[i]
		rev, ok := strings.CutPrefix(sec.Name, prefix)
		if !ok {
			continue
		}
		n, err := strconv.Atoi(rev)
		if err != nil || n <= 0 {
			continue
		}
		rel, err := DecodeRelease(sec.Data["release"])
		if err != nil {
			return nil, fmt.Errorf("upgrade: decode %s: %w", sec.Name, err)
		}
		if rel.Revision == 0 {
			rel.Revision = n
		}
		out = append(out, rel)
	}
	if len(out) == 0 {
		return nil, ErrNoRelease
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Revision > out[j].Revision })
	return out, nil
}

// Helm release statuses this package reasons about.
const (
	HelmDeployed   = "deployed"
	HelmSuperseded = "superseded"
	HelmFailed     = "failed"
)

// RollbackCandidate is the revision "Roll back to <previous>" offers: the
// newest revision below the latest that was deployed and is not the latest —
// after a failed upgrade the previous revision is still `deployed`, after a
// successful one it is `superseded`. nil when there is none.
func RollbackCandidate(history []Release) *Release {
	if len(history) < 2 {
		return nil
	}
	latest := history[0].Revision
	for i := range history {
		r := history[i]
		if r.Revision < latest && (r.Status == HelmDeployed || r.Status == HelmSuperseded) {
			return &r
		}
	}
	return nil
}
