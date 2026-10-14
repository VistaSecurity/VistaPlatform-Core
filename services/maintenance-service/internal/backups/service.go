package backups

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/bundlecrypt"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

// Config is the backup feature's per-install configuration, rendered into the
// pod's environment by the chart (ConfigFromEnv).
type Config struct {
	Enabled         bool   // MAINTENANCE_BACKUPS_ENABLED
	Root            string // MAINTENANCE_BACKUPS_PATH: the backups volume's mount
	Retention       int    // MAINTENANCE_BACKUPS_RETENTION: keep the newest N ready backups; <= 0 keeps all
	JobTemplateDir  string // MAINTENANCE_JOB_TEMPLATE_DIR: the Job-template ConfigMap's mount
	JobTemplateName string // MAINTENANCE_JOB_TEMPLATE_CONFIGMAP (named in errors and logs)
	Namespace       string // POD_NAMESPACE
	ReleaseName     string // HELM_RELEASE_NAME
	AppVersion      string // CHART_APP_VERSION
	ChartVersion    string // CHART_VERSION
	ChartSource     string // MAINTENANCE_CHART_SOURCE
	Secrets         SecretNames
	DB              ManifestDB
	// Params is the bundle encryption cost; zero means bundlecrypt.DefaultParams.
	Params bundlecrypt.Params
}

// Steps of a backup run.
var runSteps = []runs.StepDef{
	{Name: StepDump, Executor: runs.ExecutorJob},
	{Name: StepPackage, Executor: runs.ExecutorService},
	{Name: StepRetention, Executor: runs.ExecutorService},
}

// CreateOptions is what an operator chose in the Create backup dialog.
type CreateOptions struct {
	IncludeSecrets bool
	Passphrase     string
}

// Validation errors the handler maps to 400s.
var (
	ErrPassphraseRequired       = errors.New("a passphrase is required when the backup includes the encryption keys and install secrets")
	ErrPassphraseTooShort       = fmt.Errorf("the passphrase must be at least %d characters", bundlecrypt.MinPassphraseLen)
	ErrPassphraseWithoutSecrets = errors.New("a passphrase is only used when the backup includes the encryption keys and install secrets")
)

// Validate checks CreateOptions (D2: never key material without a passphrase).
func (o CreateOptions) Validate() error {
	switch {
	case o.IncludeSecrets && o.Passphrase == "":
		return ErrPassphraseRequired
	case o.IncludeSecrets && len([]rune(o.Passphrase)) < bundlecrypt.MinPassphraseLen:
		return ErrPassphraseTooShort
	case !o.IncludeSecrets && o.Passphrase != "":
		return ErrPassphraseWithoutSecrets
	}
	return nil
}

// Service runs backups. It is the runs.Finalizer for KindBackup.
type Service struct {
	cfg    Config
	store  Store
	runner *runs.Runner
	client kubernetes.Interface
	log    logrus.FieldLogger
	now    func() time.Time

	mu      sync.Mutex
	pending map[uuid.UUID][]byte // run id -> passphrase, for the run's lifetime only
}

// NewService builds the service and registers it as the backup Finalizer.
// client may be nil (not in a cluster): Available then reports false.
func NewService(cfg Config, store Store, runner *runs.Runner, client kubernetes.Interface, log logrus.FieldLogger) *Service {
	if log == nil {
		log = logrus.StandardLogger()
	}
	s := &Service{cfg: cfg, store: store, runner: runner, client: client, log: log, now: time.Now, pending: map[uuid.UUID][]byte{}}
	if runner != nil {
		runner.Register(runs.KindBackup, s)
	}
	return s
}

// Available reports whether this install can take a backup: storage, the
// Job template and the cluster API are all there.
func (s *Service) Available() bool {
	return s.cfg.Enabled && s.cfg.Root != "" && s.cfg.JobTemplateDir != "" && s.client != nil && s.runner != nil && s.store != nil
}

// Create starts a backup run. ErrUnavailable, a validation error, or
// runs.ErrRunInProgress are the expected failures.
func (s *Service) Create(ctx context.Context, startedBy *uuid.UUID, opts CreateOptions) (Backup, runs.Run, error) {
	if !s.Available() {
		return Backup{}, runs.Run{}, ErrUnavailable
	}
	if err := opts.Validate(); err != nil {
		return Backup{}, runs.Run{}, err
	}
	tmpl, err := LoadJobTemplate(s.cfg.JobTemplateDir)
	if err != nil {
		s.log.WithError(err).WithField("configmap", s.cfg.JobTemplateName).Error("backups: Job template unusable")
		return Backup{}, runs.Run{}, ErrUnavailable
	}
	run, err := s.runner.Begin(ctx, runs.KindBackup, startedBy, s.cfg.AppVersion, "", runSteps)
	if err != nil {
		return Backup{}, runs.Run{}, err
	}
	b := Backup{
		ID:        uuid.New(),
		RunID:     &run.ID,
		CreatedAt: s.now().UTC(),
		Contents:  Contents{Database: true, Secrets: opts.IncludeSecrets},
		Encrypted: opts.IncludeSecrets,
		Status:    StatusRunning,
	}
	b.FilePath = b.ID.String()
	if err := s.store.Insert(ctx, b); err != nil {
		s.runner.Abandon(ctx, run, fmt.Errorf("record the backup: %w", err))
		return Backup{}, runs.Run{}, err
	}
	if opts.IncludeSecrets {
		s.mu.Lock()
		s.pending[run.ID] = []byte(opts.Passphrase)
		s.mu.Unlock()
	}
	if err := s.runner.Launch(ctx, run, BuildJob(tmpl, b.ID)); err != nil {
		return Backup{}, runs.Run{}, err
	}
	run.JobName = JobName(b.ID)
	return b, run, nil
}

func (s *Service) takePassphrase(runID uuid.UUID) []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := s.pending[runID]
	delete(s.pending, runID)
	return p
}

// dir is a backup's directory, refusing any path that escapes the volume (a
// file_path is read back from the database; it is not trusted to stay inside).
func (s *Service) dir(b Backup) (string, error) {
	return s.within(b.ID.String())
}

func (s *Service) within(rel string) (string, error) {
	root := filepath.Clean(s.cfg.Root)
	p := filepath.Clean(filepath.Join(root, rel))
	if r, err := filepath.Rel(root, p); err != nil || r == "." || strings.HasPrefix(r, "..") {
		return "", fmt.Errorf("backups: path %q escapes the backups volume", rel)
	}
	return p, nil
}

func (s *Service) removeFiles(b Backup) error {
	d, err := s.dir(b)
	if err != nil {
		return err
	}
	return os.RemoveAll(d)
}

// Finalize implements runs.Finalizer: package the dump, then prune.
func (s *Service) Finalize(ctx context.Context, run runs.Run, outcome runs.JobOutcome, p *runs.Progress) error {
	passphrase := s.takePassphrase(run.ID)
	b, err := s.store.GetByRun(ctx, run.ID)
	if errors.Is(err, ErrNotFound) {
		return nil // the run failed before its backup row was written
	}
	if err != nil {
		return fmt.Errorf("read the backup record: %w", err)
	}
	fail := func(cause error) error {
		if err := s.store.MarkFailed(ctx, b.ID); err != nil {
			s.log.WithError(err).WithField("backup_id", b.ID).Warn("backups: mark failed")
		}
		if err := s.removeFiles(b); err != nil {
			s.log.WithError(err).WithField("backup_id", b.ID).Warn("backups: remove a failed backup's files")
		}
		return cause
	}
	if !outcome.Succeeded {
		return fail(nil)
	}
	p.Start(StepPackage)
	if b.Contents.Secrets && len(passphrase) == 0 {
		err := errors.New("the passphrase is held only in memory for the length of a backup, and the maintenance service restarted while this one ran; create the backup again")
		p.Fail(StepPackage, err)
		return fail(err)
	}
	res, m, err := s.pack(ctx, b, passphrase)
	if err != nil {
		p.Fail(StepPackage, err)
		return fail(fmt.Errorf("package the backup: %w", err))
	}
	if err := s.store.MarkReady(ctx, b.ID, res.Size, m, filepath.Join(b.ID.String(), res.Name)); err != nil {
		p.Fail(StepPackage, err)
		return fail(fmt.Errorf("record the backup: %w", err))
	}
	p.Succeed(StepPackage)

	p.Start(StepRetention)
	if err := s.prune(ctx); err != nil {
		p.Fail(StepRetention, err)
		return fmt.Errorf("the backup is ready, but removing backups beyond the retention count failed: %w", err)
	}
	p.Succeed(StepRetention)
	return nil
}

func (s *Service) pack(ctx context.Context, b Backup, passphrase []byte) (PackResult, Manifest, error) {
	d, err := s.dir(b)
	if err != nil {
		return PackResult{}, Manifest{}, err
	}
	m := Manifest{
		FormatVersion: ManifestFormatVersion,
		BackupID:      b.ID.String(),
		CreatedAt:     b.CreatedAt.UTC(),
		AppVersion:    s.cfg.AppVersion,
		ChartVersion:  s.cfg.ChartVersion,
		Schema:        ReadSchemaRow(d),
		Edition:       EditionFromChartSource(s.cfg.ChartSource),
		ChartSource:   s.cfg.ChartSource,
		Release:       ManifestRelease{Name: s.cfg.ReleaseName, Namespace: s.cfg.Namespace},
		Database:      s.cfg.DB,
		Contents:      b.Contents,
		Secrets:       []string{},
		Encrypted:     b.Encrypted,
		PgDumpVersion: ReadDumpVersion(d),
	}
	m.InstallID = s.installID(ctx)
	var secretsYAML []byte
	if b.Contents.Secrets {
		raw, names, err := readSecrets(ctx, s.client, s.cfg.Namespace, s.cfg.Secrets.list())
		if err != nil {
			return PackResult{}, Manifest{}, err
		}
		secretsYAML, m.Secrets = raw, names
		for _, n := range names {
			if s.cfg.Secrets.CBOMSigning != "" && n == s.cfg.Secrets.CBOMSigning {
				m.Contents.CBOMSigningKey = true
			}
		}
	}
	res, err := Pack(PackInput{Dir: d, Manifest: m, Secrets: secretsYAML, Passphrase: passphrase, Params: s.cfg.Params, Now: s.now()})
	return res, m, err
}

// installID reads install-id from the install Secret: the identity a restore
// is checked against. Best effort — a missing Secret leaves it out.
func (s *Service) installID(ctx context.Context) string {
	if s.client == nil || s.cfg.Secrets.Install == "" {
		return ""
	}
	sec, err := s.client.CoreV1().Secrets(s.cfg.Namespace).Get(ctx, s.cfg.Secrets.Install, metaGet)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(sec.Data["install-id"]))
}

// prune removes ready backups beyond the retention count, oldest first.
func (s *Service) prune(ctx context.Context) error {
	if s.cfg.Retention <= 0 {
		return nil
	}
	old, err := s.store.ReadyBeyond(ctx, s.cfg.Retention)
	if err != nil {
		return err
	}
	var errs []error
	for _, b := range old {
		if err := s.removeFiles(b); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := s.store.MarkDeleted(ctx, b.ID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// List returns the backups not deleted, newest first.
func (s *Service) List(ctx context.Context) ([]Backup, error) {
	if s.store == nil {
		return []Backup{}, nil
	}
	return s.store.List(ctx)
}

// Delete removes a backup's files and marks it deleted. Deleting a deleted
// backup is a no-op; a running one cannot be deleted.
func (s *Service) Delete(ctx context.Context, id uuid.UUID) (Backup, error) {
	if s.store == nil {
		return Backup{}, ErrNotFound
	}
	b, err := s.store.Get(ctx, id)
	if err != nil {
		return Backup{}, err
	}
	switch b.Status {
	case StatusDeleted:
		return b, nil
	case StatusRunning:
		return b, ErrBackupRunning
	}
	if err := s.removeFiles(b); err != nil {
		return b, err
	}
	return b, s.store.MarkDeleted(ctx, id)
}

// Download is an open backup file and how to name it.
type Download struct {
	File     *os.File
	Size     int64
	Filename string
	Backup   Backup
}

// Open opens a ready backup for download. The caller closes File.
func (s *Service) Open(ctx context.Context, id uuid.UUID) (Download, error) {
	if s.store == nil {
		return Download{}, ErrNotFound
	}
	b, err := s.store.Get(ctx, id)
	if err != nil {
		return Download{}, err
	}
	if b.Status != StatusReady || b.FilePath == "" {
		return Download{}, ErrNotReady
	}
	p, err := s.within(b.FilePath)
	if err != nil {
		return Download{}, err
	}
	f, err := os.Open(p)
	if err != nil {
		return Download{}, fmt.Errorf("open backup file: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return Download{}, err
	}
	return Download{File: f, Size: st.Size(), Filename: DownloadFilename(b), Backup: b}, nil
}

var unsafeFilenameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// DownloadFilename is vista-platform-backup-<created_at>-<version>.tar|.enc.
func DownloadFilename(b Backup) string {
	version := "unknown"
	if b.Manifest != nil && b.Manifest.AppVersion != "" {
		version = b.Manifest.AppVersion
	}
	version = strings.Trim(unsafeFilenameChars.ReplaceAllString(version, "_"), "._-")
	if version == "" {
		version = "unknown"
	}
	ext := ".tar"
	if b.Encrypted || strings.HasSuffix(b.FilePath, FileBundleEnc) {
		ext = ".enc"
	}
	return fmt.Sprintf("vista-platform-backup-%s-%s%s", b.CreatedAt.UTC().Format("20060102-150405"), version, ext)
}

var metaGet = metav1.GetOptions{}
