package backups

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

// ErrForRunFailed wraps why a backup taken as a step of another run failed.
var ErrForRunFailed = errors.New("backups: the backup failed")

// ForRunResult is what a backup taken as a step of another run produced.
type ForRunResult struct {
	Backup Backup
	// LogTail is the last lines the pg_dump Job printed (on failure, the why).
	LogTail string
}

// forRunPoll is how often TakeForRun reads its Job. A var so tests shorten it.
var forRunPoll = 3 * time.Second

// TakeForRun takes a DATABASE-ONLY backup as a step of another run — the
// update run's mandatory first step (spec D4) — and waits for it. It is the
// same backup a `backup` run takes (the chart's pg_dump Job template, the same
// manifest, bundle, retention and platform_backups row, whose run_id is the
// calling run), but it does not open a run of its own: only one run may be
// running, and that is the update.
//
// No Secrets and no passphrase: the update run is started from a dialog that
// asks for neither, and an unencrypted bundle must never carry key material
// (D2). An operator who wants the keys in the pre-update backup takes one from
// Backups first and ticks "I have my own backup".
func (s *Service) TakeForRun(ctx context.Context, runID uuid.UUID) (ForRunResult, error) {
	if !s.Available() {
		return ForRunResult{}, ErrUnavailable
	}
	tmpl, err := LoadJobTemplate(s.cfg.JobTemplateDir)
	if err != nil {
		return ForRunResult{}, fmt.Errorf("%w: the backup Job template is unusable: %v", ErrForRunFailed, err)
	}
	b := Backup{
		ID:        uuid.New(),
		RunID:     &runID,
		CreatedAt: s.now().UTC(),
		Contents:  Contents{Database: true},
		Status:    StatusRunning,
	}
	b.FilePath = b.ID.String()
	if err := s.store.Insert(ctx, b); err != nil {
		return ForRunResult{}, fmt.Errorf("%w: record the backup: %v", ErrForRunFailed, err)
	}
	fail := func(cause error, tail string) (ForRunResult, error) {
		// A fresh context: the caller's may be what ended.
		cctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.store.MarkFailed(cctx, b.ID); err != nil {
			s.log.WithError(err).WithField("backup_id", b.ID).Warn("backups: mark failed")
		}
		if err := s.removeFiles(b); err != nil {
			s.log.WithError(err).WithField("backup_id", b.ID).Warn("backups: remove a failed backup's files")
		}
		return ForRunResult{Backup: b, LogTail: tail}, fmt.Errorf("%w: %v", ErrForRunFailed, cause)
	}

	job := BuildJob(tmpl, b.ID)
	job.Namespace = s.cfg.Namespace
	job.Labels[runs.LabelRunID] = runID.String()
	if job.Spec.Template.Labels == nil {
		job.Spec.Template.Labels = map[string]string{}
	}
	job.Spec.Template.Labels[runs.LabelRunID] = runID.String()
	jobs := s.client.BatchV1().Jobs(s.cfg.Namespace)
	if _, err := jobs.Create(ctx, job, metav1.CreateOptions{}); err != nil {
		return fail(fmt.Errorf("could not create the backup Job: %w", err), "")
	}
	defer func() {
		bg := metav1.DeletePropagationBackground
		dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := jobs.Delete(dctx, job.Name, metav1.DeleteOptions{PropagationPolicy: &bg}); err != nil && !apierrors.IsNotFound(err) {
			s.log.WithError(err).WithField("job", job.Name).Warn("backups: delete the pre-update backup Job")
		}
	}()

	for {
		cur, err := jobs.Get(ctx, job.Name, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			return fail(fmt.Errorf("the backup Job %s no longer exists", job.Name), "")
		case err != nil:
			if ctx.Err() != nil {
				return fail(ctx.Err(), "")
			}
		default:
			if done, ok, reason := jobDone(cur); done {
				if !ok {
					return fail(errors.New(reason), s.jobLogTail(ctx, job.Name))
				}
				return s.finishForRun(ctx, b, fail)
			}
		}
		select {
		case <-ctx.Done():
			return fail(ctx.Err(), "")
		case <-time.After(forRunPoll):
		}
	}
}

func (s *Service) finishForRun(ctx context.Context, b Backup, fail func(error, string) (ForRunResult, error)) (ForRunResult, error) {
	res, m, err := s.pack(ctx, b, nil)
	if err != nil {
		return fail(fmt.Errorf("package the backup: %w", err), "")
	}
	rel := filepath.Join(b.ID.String(), res.Name)
	if err := s.store.MarkReady(ctx, b.ID, res.Size, m, rel); err != nil {
		return fail(fmt.Errorf("record the backup: %w", err), "")
	}
	size := res.Size
	b.Status, b.SizeBytes, b.Manifest, b.FilePath = StatusReady, &size, &m, rel
	if err := s.prune(ctx); err != nil {
		// The backup the update needs exists; a retention failure must not
		// block the update. It is logged and the next backup prunes again.
		s.log.WithError(err).Warn("backups: retention after the pre-update backup failed")
	}
	return ForRunResult{Backup: b}, nil
}

// FailRunningForRun marks any backup of runID still `running` failed — the
// cleanup when an update run is settled by a restarted service while its
// backup step was in flight.
func (s *Service) FailRunningForRun(ctx context.Context, runID uuid.UUID) {
	if s.store == nil {
		return
	}
	b, err := s.store.GetByRun(ctx, runID)
	if err != nil || b.Status != StatusRunning {
		return
	}
	if err := s.store.MarkFailed(ctx, b.ID); err != nil {
		s.log.WithError(err).WithField("backup_id", b.ID).Warn("backups: mark an interrupted pre-update backup failed")
	}
	_ = s.removeFiles(b)
}

// RecentReady reports the newest ready backup created at or after since.
func (s *Service) RecentReady(ctx context.Context, since time.Time) (*Backup, error) {
	list, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].Status == StatusReady && !list[i].CreatedAt.Before(since) {
			return &list[i], nil
		}
	}
	return nil, nil
}

func jobDone(job *batchv1.Job) (done, succeeded bool, reason string) {
	for _, c := range job.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			return true, true, ""
		case batchv1.JobFailed:
			reason = strings.TrimSpace(strings.Trim(c.Reason+": "+c.Message, ": "))
			if reason == "" {
				reason = "the backup Job failed"
			}
			return true, false, "the backup Job failed: " + reason
		}
	}
	return false, false, ""
}

// jobLogTail is the last lines of the newest pod of a Job. Best effort.
func (s *Service) jobLogTail(ctx context.Context, jobName string) string {
	pods, err := s.client.CoreV1().Pods(s.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "job-name=" + jobName})
	if err != nil || len(pods.Items) == 0 {
		return ""
	}
	sort.Slice(pods.Items, func(i, j int) bool {
		return pods.Items[j].CreationTimestamp.Before(&pods.Items[i].CreationTimestamp)
	})
	tail := int64(50)
	limit := int64(64 << 10)
	raw, err := s.client.CoreV1().Pods(s.cfg.Namespace).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{TailLines: &tail, LimitBytes: &limit}).Do(ctx).Raw()
	if err != nil {
		return ""
	}
	var keep []string
	for _, l := range strings.Split(strings.TrimRight(string(raw), "\n"), "\n") {
		if !strings.HasPrefix(l, runs.StepMarker+" ") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}
