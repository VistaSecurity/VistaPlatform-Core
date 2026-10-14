// Package upgrade is the one-click update and rollback (spec
// platform-maintenance.md §3 "Update", WP4): pre-flight, the `update` run —
// backup first (D4), verify the chart's signature, `helm upgrade` in a Job
// running as the vistaplatform-updater ServiceAccount, smoke — the `rollback`
// run, and the Helm release history the console offers a rollback from.
//
// The updater updates itself. `helm upgrade` replaces this service's own pod
// mid-run, so the helm step is a Kubernetes Job carrying everything it needs
// from creation, and the run is settled by whichever process sees the Job
// end: usually the NEW pod, through the Runner's reconcile-on-start, which
// then runs the smoke step (this package's Finalizer).
package upgrade

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/backups"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

// Step names.
const (
	StepBackup   = "backup"
	StepVerify   = "verify"
	StepUpgrade  = ActionUpgrade
	StepRollback = ActionRollback
	StepSmoke    = "smoke"
)

// Step details (runs.Step.Detail).
const (
	DetailSkippedByOperator      = "skipped_by_operator"
	DetailSkippedByConfiguration = "skipped_by_configuration"
)

var updateSteps = []runs.StepDef{
	{Name: StepBackup, Executor: runs.ExecutorService},
	{Name: StepVerify, Executor: runs.ExecutorService},
	{Name: StepUpgrade, Executor: runs.ExecutorJob},
	{Name: StepSmoke, Executor: runs.ExecutorService},
}

var rollbackSteps = []runs.StepDef{
	{Name: StepRollback, Executor: runs.ExecutorJob},
	{Name: StepSmoke, Executor: runs.ExecutorService},
}

// Config is the per-install configuration the chart renders into the pod.
type Config struct {
	Namespace    string // POD_NAMESPACE
	ReleaseName  string // HELM_RELEASE_NAME
	ChartSource  string // MAINTENANCE_CHART_SOURCE
	RunningChart string // CHART_VERSION
	// JobTemplateDir is MAINTENANCE_UPDATE_JOB_TEMPLATE_DIR, the mount of the
	// update-Job ConfigMap (MAINTENANCE_UPDATE_JOB_TEMPLATE_CONFIGMAP).
	JobTemplateDir  string
	JobTemplateName string
	// SkipSignature is MAINTENANCE_SKIP_SIGNATURE_VERIFY.
	SkipSignature bool
}

// BackupTaker is the backup feature as the update run uses it.
type BackupTaker interface {
	Available() bool
	TakeForRun(ctx context.Context, runID uuid.UUID) (backups.ForRunResult, error)
	FailRunningForRun(ctx context.Context, runID uuid.UUID)
}

// Audit event types (spec §2).
const (
	EventUpdateStarted   = "maintenance.update.started"
	EventUpdateSucceeded = "maintenance.update.succeeded"
	EventUpdateFailed    = "maintenance.update.failed"
	EventRolledBack      = "maintenance.update.rolled_back"
)

// RunEvent is one activity-trail entry about an update or rollback run. The
// start is recorded from the request; the outcome from whichever process
// settles the run, which may be a later pod with no request in hand.
type RunEvent struct {
	EventType string
	Run       runs.Run
	Success   bool
	// Phase is "started" or "finished".
	Phase   string
	Message string
}

// Auditor records RunEvents. cmd/ provides the shared-audit implementation.
type Auditor interface {
	RecordRun(ctx context.Context, ev RunEvent)
}

type nopAuditor struct{}

func (nopAuditor) RecordRun(context.Context, RunEvent) {}

// Errors the handlers map to statuses.
var (
	// ErrUnavailable: no cluster, no run store or no update Job template (503).
	ErrUnavailable = errors.New("upgrade: updates are not available in this deployment")
	// ErrBackupUnavailable: the update must back up first and this install has
	// no backup storage (422; the operator ticks "I have my own backup").
	ErrBackupUnavailable = errors.New("backup storage is not configured for this install, so the update cannot take its backup first; take your own backup and confirm it")
	// ErrInvalidRevision: the rollback target is not a revision Helm can roll back to (422).
	ErrInvalidRevision = errors.New("upgrade: not a revision this release can roll back to")
	// ErrNotUpdatable: capabilities.updates is false (422).
	ErrNotUpdatable = errors.New("upgrade: this install cannot be changed from the console")
)

// PreflightFailedError carries the failing pre-flight (422).
type PreflightFailedError struct{ Result Result }

func (e *PreflightFailedError) Error() string {
	return fmt.Sprintf("pre-flight failed: %v", e.Result.Failed())
}

// Service starts and settles update and rollback runs.
type Service struct {
	cfg       Config
	runner    *runs.Runner
	runStore  runs.Store
	preflight *Preflight
	backups   BackupTaker
	verifier  Verifier
	releases  ReleaseReader
	smoke     Smoker
	audit     Auditor
	log       logrus.FieldLogger
}

// Deps are the Service's collaborators.
type Deps struct {
	Runner    *runs.Runner // nil outside a cluster
	RunStore  runs.Store
	Preflight *Preflight
	Backups   BackupTaker
	Verifier  Verifier
	Releases  ReleaseReader
	Smoke     Smoker
	Audit     Auditor
	Log       logrus.FieldLogger
}

// NewService builds the service and registers it as the Finalizer for update
// and rollback runs — call before the Runner reconciles.
func NewService(cfg Config, d Deps) *Service {
	if d.Log == nil {
		d.Log = logrus.StandardLogger()
	}
	if d.Audit == nil {
		d.Audit = nopAuditor{}
	}
	s := &Service{cfg: cfg, runner: d.Runner, runStore: d.RunStore, preflight: d.Preflight, backups: d.Backups,
		verifier: d.Verifier, releases: d.Releases, smoke: d.Smoke, audit: d.Audit, log: d.Log}
	if d.Runner != nil {
		d.Runner.Register(runs.KindUpdate, s)
		d.Runner.Register(runs.KindRollback, s)
	}
	return s
}

// Available reports whether runs can be started here.
func (s *Service) Available() bool {
	return s.runner != nil && s.runStore != nil && s.cfg.JobTemplateDir != ""
}

// Preflight runs pre-flight for version.
func (s *Service) Preflight(ctx context.Context, version string) Result {
	return s.preflight.Run(ctx, version, Options{})
}

// History is the Helm release history, newest first.
func (s *Service) History(ctx context.Context) ([]Release, error) {
	if s.releases == nil {
		return nil, ErrNoRelease
	}
	return s.releases.History(ctx)
}

func (s *Service) anyRunning(ctx context.Context) error {
	running, err := s.runStore.ListRunning(ctx)
	if err != nil {
		return fmt.Errorf("upgrade: list running runs: %w", err)
	}
	if len(running) > 0 {
		return runs.ErrRunInProgress
	}
	return nil
}

// StartUpdate starts an update run to version. Expected errors:
// ErrUnavailable, runs.ErrRunInProgress, *PreflightFailedError,
// ErrBackupUnavailable.
func (s *Service) StartUpdate(ctx context.Context, startedBy *uuid.UUID, version string, skipBackup bool) (runs.Run, Result, error) {
	if !s.Available() {
		return runs.Run{}, Result{}, ErrUnavailable
	}
	tmpl, err := LoadUpdateJobTemplate(s.cfg.JobTemplateDir)
	if err != nil {
		s.log.WithError(err).WithField("configmap", s.cfg.JobTemplateName).Error("upgrade: update Job template unusable")
		return runs.Run{}, Result{}, ErrUnavailable
	}
	if err := s.anyRunning(ctx); err != nil {
		return runs.Run{}, Result{}, err
	}
	res := s.preflight.Run(ctx, version, Options{DeferSignature: true})
	if !res.OK {
		return runs.Run{}, res, &PreflightFailedError{Result: res}
	}
	if !skipBackup && (s.backups == nil || !s.backups.Available()) {
		return runs.Run{}, res, ErrBackupUnavailable
	}
	target := res.Version
	run, err := s.runner.Begin(ctx, runs.KindUpdate, startedBy, s.cfg.RunningChart, target, updateSteps)
	if err != nil {
		return runs.Run{}, res, err
	}
	s.audit.RecordRun(ctx, RunEvent{EventType: EventUpdateStarted, Run: run, Success: true, Phase: "started"})
	s.runner.Start(run, func(ctx context.Context, p *runs.Progress) (*batchv1.Job, error) {
		return s.prepareUpdate(ctx, run, p, tmpl, target, skipBackup)
	})
	return run, res, nil
}

func (s *Service) prepareUpdate(ctx context.Context, run runs.Run, p *runs.Progress, tmpl *batchv1.Job, target string, skipBackup bool) (*batchv1.Job, error) {
	if skipBackup {
		p.Skip(StepBackup)
		p.Note(StepBackup, DetailSkippedByOperator, "Skipped: the operator confirmed they have their own backup.")
	} else {
		p.Start(StepBackup)
		res, err := s.backups.TakeForRun(ctx, run.ID)
		if err != nil {
			p.Note(StepBackup, "", res.LogTail)
			p.Fail(StepBackup, err)
			return nil, fmt.Errorf("the backup before the update failed, so nothing was changed: %w", err)
		}
		size := int64(0)
		if res.Backup.SizeBytes != nil {
			size = *res.Backup.SizeBytes
		}
		p.Note(StepBackup, "", fmt.Sprintf("Backup %s is ready (%d bytes, database only). Download it from Backups.", res.Backup.ID, size))
		p.Succeed(StepBackup)
	}

	if s.cfg.SkipSignature {
		p.Skip(StepVerify)
		p.Note(StepVerify, DetailSkippedByConfiguration, "Skipped: signature verification is turned off for this install (maintenance.updates.skipSignatureVerify).")
	} else {
		p.Start(StepVerify)
		if err := VerifyChart(ctx, s.verifier, s.cfg.ChartSource, target); err != nil {
			p.Fail(StepVerify, err)
			return nil, fmt.Errorf("the chart's signature could not be verified, so nothing was changed: %w", err)
		}
		ref, _ := ChartRef(s.cfg.ChartSource, target)
		p.Note(StepVerify, "", "Verified "+ref+" against the release signing identity.")
		p.Succeed(StepVerify)
	}
	return BuildUpdateJob(tmpl, run.ID, ActionUpgrade, target, 0), nil
}

// StartRollback starts a rollback run to revision. Expected errors:
// ErrUnavailable, runs.ErrRunInProgress, ErrNotUpdatable, ErrInvalidRevision.
func (s *Service) StartRollback(ctx context.Context, startedBy *uuid.UUID, revision int) (runs.Run, error) {
	if !s.Available() {
		return runs.Run{}, ErrUnavailable
	}
	tmpl, err := LoadUpdateJobTemplate(s.cfg.JobTemplateDir)
	if err != nil {
		s.log.WithError(err).WithField("configmap", s.cfg.JobTemplateName).Error("upgrade: update Job template unusable")
		return runs.Run{}, ErrUnavailable
	}
	if err := s.anyRunning(ctx); err != nil {
		return runs.Run{}, err
	}
	if c := s.preflight.checkCapabilities(ctx); c.Status != CheckPass {
		return runs.Run{}, fmt.Errorf("%w: %s", ErrNotUpdatable, c.Detail)
	}
	history, err := s.History(ctx)
	if err != nil {
		return runs.Run{}, fmt.Errorf("%w: the release history could not be read: %v", ErrInvalidRevision, err)
	}
	var target *Release
	for i := range history {
		if history[i].Revision == revision {
			target = &history[i]
		}
	}
	switch {
	case target == nil:
		return runs.Run{}, fmt.Errorf("%w: revision %d is not in the release history", ErrInvalidRevision, revision)
	case revision == history[0].Revision:
		return runs.Run{}, fmt.Errorf("%w: revision %d is the current revision", ErrInvalidRevision, revision)
	case target.Status != HelmDeployed && target.Status != HelmSuperseded:
		return runs.Run{}, fmt.Errorf("%w: revision %d is %s, not a revision that ran", ErrInvalidRevision, revision, target.Status)
	}
	run, err := s.runner.Begin(ctx, runs.KindRollback, startedBy, s.cfg.RunningChart, target.ChartVersion, rollbackSteps)
	if err != nil {
		return runs.Run{}, err
	}
	s.audit.RecordRun(ctx, RunEvent{EventType: EventRolledBack, Run: run, Success: true, Phase: "started",
		Message: fmt.Sprintf("roll back to revision %d (chart %s)", revision, target.ChartVersion)})
	job := BuildUpdateJob(tmpl, run.ID, ActionRollback, "", revision)
	if err := s.runner.Launch(ctx, run, job); err != nil {
		return runs.Run{}, err
	}
	run.JobName = job.Name
	return run, nil
}

// Finalize implements runs.Finalizer for update and rollback runs: after the
// helm Job succeeded, the smoke step; after anything failed, cleanup.
func (s *Service) Finalize(ctx context.Context, run runs.Run, outcome runs.JobOutcome, p *runs.Progress) error {
	failEvent := EventUpdateFailed
	okEvent := EventUpdateSucceeded
	if run.Kind == runs.KindRollback {
		failEvent, okEvent = EventRolledBack, EventRolledBack
	}
	if !outcome.Succeeded {
		if run.Kind == runs.KindUpdate && s.backups != nil {
			s.backups.FailRunningForRun(ctx, run.ID)
		}
		s.audit.RecordRun(ctx, RunEvent{EventType: failEvent, Run: run, Success: false, Phase: "finished", Message: outcome.Reason})
		return nil
	}
	p.Start(StepSmoke)
	if s.smoke == nil {
		err := errors.New("no smoke check is configured")
		p.Fail(StepSmoke, err)
		s.audit.RecordRun(ctx, RunEvent{EventType: failEvent, Run: run, Success: false, Phase: "finished", Message: err.Error()})
		return err
	}
	if err := s.smoke.Smoke(ctx, run.ToVersion); err != nil {
		p.Fail(StepSmoke, err)
		msg := "helm finished, but the smoke check failed: " + err.Error()
		s.audit.RecordRun(ctx, RunEvent{EventType: failEvent, Run: run, Success: false, Phase: "finished", Message: msg})
		return errors.New(msg)
	}
	p.Note(StepSmoke, "", "Every service reports "+run.ToVersion+".")
	p.Succeed(StepSmoke)
	s.audit.RecordRun(ctx, RunEvent{EventType: okEvent, Run: run, Success: true, Phase: "finished"})
	return nil
}

// SQLSchema reads schema_migration_status.
type SQLSchema struct{ DB *sql.DB }

// LatestChartVersion implements SchemaReader.
func (q SQLSchema) LatestChartVersion(ctx context.Context) (string, error) {
	if q.DB == nil {
		return "", errors.New("no database")
	}
	var v sql.NullString
	err := q.DB.QueryRowContext(ctx,
		`SELECT chart_version FROM public.schema_migration_status ORDER BY applied_at DESC LIMIT 1`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v.String, nil
}
