package updates

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ErrDisabled means the operator turned the update check off
// (maintenance.updateCheck.enabled=false); a manual check would be an outbound
// call they asked not to make.
var ErrDisabled = errors.New("the update check is disabled for this install")

// View is the body of GET /admin/updates: the stored row plus the two derived
// answers the console needs.
type View struct {
	Status
	// UpdateAvailable is computed at read time from the stored latest version
	// and the version this pod runs, so the banner disappears the moment an
	// update lands, without waiting for the next check.
	UpdateAvailable bool `json:"update_available"`
	CheckEnabled    bool `json:"check_enabled"`
}

// Service is what the HTTP handlers call.
type Service struct {
	Checker        *Checker
	Store          Store
	Enabled        bool
	RunningVersion string
}

// Read returns the stored row and the derived fields.
func (s *Service) Read(ctx context.Context) (View, error) {
	st, err := s.Store.Get(ctx)
	if err != nil {
		return View{}, err
	}
	return s.view(st), nil
}

// Check runs a check now.
func (s *Service) Check(ctx context.Context) (View, error) {
	if !s.Enabled {
		return View{}, ErrDisabled
	}
	st, err := s.Checker.Run(ctx)
	if err != nil {
		return View{}, err
	}
	return s.view(st), nil
}

func (s *Service) view(st Status) View {
	v := View{Status: st, CheckEnabled: s.Enabled}
	if st.PrereleasesSeen == nil {
		v.PrereleasesSeen = []string{}
	}
	if st.LatestVersion != nil {
		v.UpdateAvailable = Newer(*st.LatestVersion, s.RunningVersion)
	}
	return v
}

// SecretReader returns one Secret's .dockerconfigjson payload.
type SecretReader func(ctx context.Context, name string) ([]byte, error)

// RegistryTags is the production TagSource: it resolves the pull credential
// afresh on every listing (a rotated pull secret needs no restart) and lists
// the chart source's tags.
type RegistryTags struct {
	Source         Source
	PullSecretName string
	ReadSecret     SecretReader
	Log            logrus.FieldLogger
}

// ListTags implements TagSource.
func (r RegistryTags) ListTags(ctx context.Context) ([]string, error) {
	var creds Credentials
	if r.PullSecretName != "" && r.ReadSecret != nil {
		raw, err := r.ReadSecret(ctx, r.PullSecretName)
		if err == nil {
			var ok bool
			creds, ok, err = CredentialsFromDockerConfig(raw, r.Source.Registry)
			if err == nil && !ok {
				r.log().Debugf("pull secret %s has no credentials for %s; checking anonymously", r.PullSecretName, r.Source.Registry)
			}
		}
		if err != nil {
			// Not fatal: a public registry needs no credential, and a private
			// one answers 401, which the row then reports with its URL.
			r.log().WithError(err).Warnf("update check: pull secret %s unusable; checking anonymously", r.PullSecretName)
			creds = Credentials{}
		}
	}
	return NewLister(r.Source, creds).ListTags(ctx)
}

func (r RegistryTags) log() logrus.FieldLogger {
	if r.Log != nil {
		return r.Log
	}
	return logrus.StandardLogger()
}

// Env names (rendered by the chart from maintenance.updateCheck.* and
// image.pullSecrets).
const (
	EnvChartSource   = "MAINTENANCE_CHART_SOURCE"
	EnvEnabled       = "MAINTENANCE_UPDATE_CHECK_ENABLED"
	EnvInterval      = "MAINTENANCE_UPDATE_CHECK_INTERVAL"
	EnvPrereleases   = "MAINTENANCE_UPDATE_INCLUDE_PRERELEASES"
	EnvPullSecret    = "MAINTENANCE_PULL_SECRET_NAME"
	EnvNotesBaseURL  = "MAINTENANCE_NOTES_BASE_URL"
	defaultInterval  = 24 * time.Hour
	minInterval      = time.Minute
	defaultStartWait = 30 * time.Second
)

// EnvSettings are the update-check settings read from the environment.
type EnvSettings struct {
	Enabled            bool
	Interval           time.Duration
	IncludePrereleases bool
	ChartSource        string
	PullSecretName     string
	NotesBaseURL       string
	// Warnings are problems with the configuration that fell back to a default.
	Warnings []string
}

// SettingsFromEnv reads the settings. The check is on unless explicitly
// "false", matching the chart default; a bad interval falls back to 24h with a
// warning rather than stopping the service.
func SettingsFromEnv(getenv func(string) string) EnvSettings {
	if getenv == nil {
		getenv = os.Getenv
	}
	s := EnvSettings{
		Enabled:            !strings.EqualFold(strings.TrimSpace(getenv(EnvEnabled)), "false"),
		IncludePrereleases: strings.EqualFold(strings.TrimSpace(getenv(EnvPrereleases)), "true"),
		ChartSource:        strings.TrimSpace(getenv(EnvChartSource)),
		PullSecretName:     strings.TrimSpace(getenv(EnvPullSecret)),
		NotesBaseURL:       strings.TrimSpace(getenv(EnvNotesBaseURL)),
		Interval:           defaultInterval,
	}
	if raw := strings.TrimSpace(getenv(EnvInterval)); raw != "" {
		d, err := time.ParseDuration(raw)
		switch {
		case err != nil:
			s.Warnings = append(s.Warnings, EnvInterval+"="+raw+" is not a Go duration; using 24h")
		case d < minInterval:
			s.Warnings = append(s.Warnings, EnvInterval+"="+raw+" is below the 1m minimum; using 24h")
		default:
			s.Interval = d
		}
	}
	return s
}

// failingTags is the TagSource of an install whose chart source does not
// parse: every check records why in the row, where the console shows it,
// instead of the service refusing to start.
type failingTags struct{ err error }

func (f failingTags) ListTags(context.Context) ([]string, error) { return nil, f.err }

// NewService assembles the production service from settings. An unusable chart
// source does not stop the service: each check records the parse error in the
// status row.
func NewService(settings EnvSettings, running string, store Store, locker Locker, read SecretReader, log logrus.FieldLogger) *Service {
	src, err := ParseSource(settings.ChartSource)
	var tags TagSource = RegistryTags{Source: src, PullSecretName: settings.PullSecretName, ReadSecret: read, Log: log}
	if err != nil {
		tags = failingTags{err: err}
	}
	checker := &Checker{
		Tags:   tags,
		Store:  store,
		Locker: locker,
		Log:    log,
		Config: Config{
			Source:             src,
			SourceLabel:        sourceLabel(src, err, settings.ChartSource),
			RunningVersion:     running,
			IncludePrereleases: settings.IncludePrereleases,
			NotesBaseURL:       settings.NotesBaseURL,
			Interval:           settings.Interval,
			StartDelay:         defaultStartWait,
		},
	}
	return &Service{Checker: checker, Store: store, Enabled: settings.Enabled, RunningVersion: running}
}

func sourceLabel(_ Source, parseErr error, raw string) string {
	if parseErr == nil {
		return ""
	}
	if raw == "" {
		return "(not configured)"
	}
	return raw
}
