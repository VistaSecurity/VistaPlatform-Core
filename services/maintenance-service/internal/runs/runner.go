package runs

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// StepMarker is how a Job reports its steps: a line
//
//	VISTA_STEP <name> <running|succeeded|failed|skipped>
//
// on its standard output. Marker lines are kept out of the log tail.
const StepMarker = "VISTA_STEP"

// JobOutcome is how the Job ended, as the Runner saw it.
type JobOutcome struct {
	Succeeded bool
	// Reason says why the Job failed (or why its end is unknown); empty on success.
	Reason string
	// Reconciled: the run was picked up by Reconcile after the service
	// restarted, so anything held only in the previous process's memory for
	// this run (a backup passphrase, say) is gone.
	Reconciled bool
}

// Finalizer runs a kind's service-side steps once its Job has ended, and
// cleans up after a failed Job. A returned error fails the run with that
// message. On a failed Job the run fails with the Job's reason whatever
// Finalize returns.
type Finalizer interface {
	Finalize(ctx context.Context, run Run, outcome JobOutcome, p *Progress) error
}

// Config tunes the Runner.
type Config struct {
	Namespace string
	// PollInterval is how often a running Job is read. Default 3s.
	PollInterval time.Duration
	// LogTailLines is how many trailing lines are fetched from the Job pod's
	// log per poll. Default 200.
	LogTailLines int64
	// MaxLogTailBytes bounds the tail stored on a step. Default 8 KiB.
	MaxLogTailBytes int
	// KeepFinishedJobs leaves settled Jobs in the cluster. Default false: the
	// Job is deleted (with its pod) once its run is settled — the run row is
	// the record, and the next backup must not trip over the last one's Job.
	KeepFinishedJobs bool
}

func (c Config) withDefaults() Config {
	if c.PollInterval <= 0 {
		c.PollInterval = 3 * time.Second
	}
	if c.LogTailLines <= 0 {
		c.LogTailLines = 200
	}
	if c.MaxLogTailBytes <= 0 {
		c.MaxLogTailBytes = 8 << 10
	}
	return c
}

// Runner launches, follows and settles runs. Safe for concurrent use.
type Runner struct {
	store      Store
	client     kubernetes.Interface
	cfg        Config
	log        logrus.FieldLogger
	finalizers map[Kind]Finalizer

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu       sync.Mutex
	watching map[uuid.UUID]bool
}

// NewRunner builds a Runner. client may be a fake clientset in tests.
func NewRunner(store Store, client kubernetes.Interface, cfg Config, log logrus.FieldLogger) *Runner {
	if log == nil {
		log = logrus.StandardLogger()
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{
		store: store, client: client, cfg: cfg.withDefaults(), log: log,
		finalizers: map[Kind]Finalizer{}, ctx: ctx, cancel: cancel, watching: map[uuid.UUID]bool{},
	}
}

// Register sets the Finalizer for a kind. Call before Reconcile.
func (r *Runner) Register(kind Kind, f Finalizer) { r.finalizers[kind] = f }

// Store is the Runner's store (read paths use it directly).
func (r *Runner) Store() Store { return r.store }

// Begin records a new running run with its declared steps, all pending. It
// returns ErrRunInProgress when another run is running. The caller then
// Launches it (or Abandons it if it cannot build the Job).
func (r *Runner) Begin(ctx context.Context, kind Kind, startedBy *uuid.UUID, fromVersion, toVersion string, steps []StepDef) (Run, error) {
	run := Run{ID: uuid.New(), Kind: kind, StartedBy: startedBy, FromVersion: fromVersion, ToVersion: toVersion}
	for _, s := range steps {
		run.Steps = append(run.Steps, Step{Name: s.Name, Executor: s.Executor, Status: StepPending})
	}
	return r.store.Create(ctx, run)
}

// Abandon settles a begun run that never got a Job.
func (r *Runner) Abandon(ctx context.Context, run Run, cause error) {
	st := newRunState(run)
	r.finish(ctx, st, JobOutcome{Reason: cause.Error()})
}

// Launch creates the run's Job and follows it in the background. job.Name
// must be set; the Runner labels it with the run id and puts it in the
// Runner's namespace. If the Job cannot be created the run is settled failed
// and the error returned.
func (r *Runner) Launch(ctx context.Context, run Run, job *batchv1.Job) error {
	if job.Name == "" {
		err := errors.New("runs: job has no name")
		r.Abandon(ctx, run, err)
		return err
	}
	job.Namespace = r.cfg.Namespace
	if job.Labels == nil {
		job.Labels = map[string]string{}
	}
	job.Labels[LabelRunID] = run.ID.String()
	if job.Spec.Template.Labels == nil {
		job.Spec.Template.Labels = map[string]string{}
	}
	job.Spec.Template.Labels[LabelRunID] = run.ID.String()

	// The name goes on the row BEFORE the Job exists: a restart between the
	// two then finds a row naming a Job that is not there and settles it,
	// rather than a Job no row names.
	if err := r.store.SetJobName(ctx, run.ID, job.Name); err != nil {
		r.Abandon(ctx, run, fmt.Errorf("record the Job name: %w", err))
		return err
	}
	run.JobName = job.Name
	if _, err := r.client.BatchV1().Jobs(r.cfg.Namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		r.Abandon(ctx, run, fmt.Errorf("could not create the Job: %w", err))
		return err
	}
	r.follow(run, false)
	return nil
}

// PrepareFunc runs a run's service-side steps that come BEFORE its Job (the
// update run's backup and signature verification), reporting them through p,
// and returns the Job to launch. An error fails the run with its message; the
// function marks its own failed step (p.Fail) so the error lands on it.
type PrepareFunc func(ctx context.Context, p *Progress) (*batchv1.Job, error)

// Start runs prepare in the background and then Launches the Job it returns,
// for a run begun with Begin. The work is tracked like a followed Job: Stop
// waits for it and a stopping Runner abandons it without settling the row —
// the next process's Reconcile fails it ("restarted before this run's Job was
// created"), because a half-done preparation cannot be resumed.
func (r *Runner) Start(run Run, prepare PrepareFunc) {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		st := newRunState(run)
		p := &Progress{r: r, st: st}
		job, err := prepare(r.ctx, p)
		if r.ctx.Err() != nil {
			return
		}
		if err != nil {
			r.finish(r.ctx, st, JobOutcome{Reason: err.Error()})
			return
		}
		st.mu.Lock()
		cur := st.run
		cur.Steps = cloneSteps(st.run.Steps)
		st.mu.Unlock()
		if err := r.Launch(r.ctx, cur, job); err != nil {
			r.log.WithError(err).WithField("run_id", run.ID).Warn("runs: launch after preparation")
		}
	}()
}

// Reconcile settles or resumes every run left `running` — call once on boot,
// after registering finalizers. A run whose Job has ended is settled from the
// Job's status; one whose Job still runs is followed again; one whose Job is
// gone, or never got one, is failed with the reason.
func (r *Runner) Reconcile(ctx context.Context) error {
	running, err := r.store.ListRunning(ctx)
	if err != nil {
		return fmt.Errorf("runs: reconcile: %w", err)
	}
	for _, run := range running {
		if run.JobName == "" {
			r.log.WithField("run_id", run.ID).Warn("runs: reconcile: run never got a Job; failing it")
			r.finish(ctx, newRunState(run), JobOutcome{Reason: "the maintenance service restarted before this run's Job was created", Reconciled: true})
			continue
		}
		r.log.WithFields(logrus.Fields{"run_id": run.ID, "job": run.JobName}).Info("runs: reconcile: resuming run")
		r.follow(run, true)
	}
	return nil
}

// Wait blocks until every followed run has settled (tests use it).
func (r *Runner) Wait() { r.wg.Wait() }

// Stop stops following runs. Runs still going stay `running` in the database;
// the next process's Reconcile picks them up.
func (r *Runner) Stop() {
	r.cancel()
	r.wg.Wait()
}

// runState is a followed run's in-memory steps.
type runState struct {
	mu  sync.Mutex
	run Run
}

// newRunState copies the run's steps: the state is mutated by its own
// goroutine and must not share a backing array with the caller's copy.
func newRunState(run Run) *runState {
	run.Steps = cloneSteps(run.Steps)
	return &runState{run: run}
}

func (r *Runner) follow(run Run, reconciled bool) {
	r.mu.Lock()
	if r.watching[run.ID] {
		r.mu.Unlock()
		return
	}
	r.watching[run.ID] = true
	r.mu.Unlock()

	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		defer func() {
			r.mu.Lock()
			delete(r.watching, run.ID)
			r.mu.Unlock()
		}()
		r.watch(newRunState(run), reconciled)
	}()
}

func (r *Runner) watch(st *runState, reconciled bool) {
	ctx := r.ctx
	jobs := r.client.BatchV1().Jobs(r.cfg.Namespace)
	log := r.log.WithFields(logrus.Fields{"run_id": st.run.ID, "job": st.run.JobName})
	for {
		job, err := jobs.Get(ctx, st.run.JobName, metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			r.finish(ctx, st, JobOutcome{Reason: fmt.Sprintf("the Job %s no longer exists", st.run.JobName), Reconciled: reconciled})
			return
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			log.WithError(err).Warn("runs: read Job; retrying")
		default:
			r.refreshFromLog(ctx, st)
			if done, ok, reason := jobFinished(job); done {
				r.finish(ctx, st, JobOutcome{Succeeded: ok, Reason: reason, Reconciled: reconciled})
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.cfg.PollInterval):
		}
	}
}

// jobFinished reads the Job's terminal condition.
func jobFinished(job *batchv1.Job) (done, succeeded bool, reason string) {
	for _, c := range job.Status.Conditions {
		if c.Status != corev1.ConditionTrue {
			continue
		}
		switch c.Type {
		case batchv1.JobComplete:
			return true, true, ""
		case batchv1.JobFailed:
			reason = strings.TrimSpace(strings.Join(nonEmpty(c.Reason, c.Message), ": "))
			if reason == "" {
				reason = "the Job failed"
			}
			return true, false, reason
		}
	}
	return false, false, ""
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, v := range s {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// refreshFromLog reads the newest pod of the Job, applies its step markers
// and stores the log tail on the step it belongs to. Best effort: a pod not
// yet scheduled has no log, and a log read failure only costs the tail.
func (r *Runner) refreshFromLog(ctx context.Context, st *runState) {
	pods, err := r.client.CoreV1().Pods(r.cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: "job-name=" + st.run.JobName})
	if err != nil || len(pods.Items) == 0 {
		return
	}
	sort.Slice(pods.Items, func(i, j int) bool {
		return pods.Items[j].CreationTimestamp.Before(&pods.Items[i].CreationTimestamp)
	})
	tail := r.cfg.LogTailLines
	limit := int64(r.cfg.MaxLogTailBytes) * 8
	raw, err := r.client.CoreV1().Pods(r.cfg.Namespace).GetLogs(pods.Items[0].Name, &corev1.PodLogOptions{TailLines: &tail, LimitBytes: &limit}).Do(ctx).Raw()
	if err != nil {
		return
	}
	st.mu.Lock()
	changed := applyLog(&st.run, string(raw), r.cfg.MaxLogTailBytes, time.Now().UTC())
	steps := cloneSteps(st.run.Steps)
	st.mu.Unlock()
	if changed {
		if err := r.store.UpdateSteps(ctx, st.run.ID, steps); err != nil {
			r.log.WithError(err).WithField("run_id", st.run.ID).Warn("runs: persist steps")
		}
	}
}

// applyLog applies a log read to the run's Job steps: markers move statuses
// (never backwards — a marker scrolled out of the tail cannot undo a state),
// and the non-marker lines become the tail of the Job step currently running
// (or, before any marker, the first unfinished Job step). Reports a change.
func applyLog(run *Run, log string, maxBytes int, now time.Time) bool {
	changed := false
	var plain []string
	current := -1
	sc := bufio.NewScanner(strings.NewReader(log))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if fields := strings.Fields(line); len(fields) == 3 && fields[0] == StepMarker {
			if i := stepIndex(run.Steps, fields[1], ExecutorJob); i >= 0 {
				if moveStep(&run.Steps[i], fields[2], now) {
					changed = true
				}
				current = i
			}
			continue
		}
		plain = append(plain, line)
	}
	if current < 0 || isTerminal(run.Steps[current].Status) && run.Steps[current].Status != StepFailed {
		for i := range run.Steps {
			if run.Steps[i].Executor == ExecutorJob && run.Steps[i].Status == StepRunning {
				current = i
				break
			}
		}
	}
	if current < 0 {
		for i := range run.Steps {
			if run.Steps[i].Executor == ExecutorJob && !isTerminal(run.Steps[i].Status) {
				current = i
				break
			}
		}
	}
	if current >= 0 {
		t := boundTail(strings.Join(plain, "\n"), maxBytes)
		if run.Steps[current].LogTail != t {
			run.Steps[current].LogTail = t
			changed = true
		}
	}
	return changed
}

var stepRank = map[string]int{StepPending: 0, StepRunning: 1, StepSucceeded: 2, StepFailed: 2, StepSkipped: 2}

func moveStep(s *Step, to string, now time.Time) bool {
	rank, ok := stepRank[to]
	if !ok || to == StepPending || rank <= stepRank[s.Status] {
		return false
	}
	if s.StartedAt == nil {
		t := now
		s.StartedAt = &t
	}
	if rank == 2 && s.FinishedAt == nil {
		t := now
		s.FinishedAt = &t
	}
	s.Status = to
	return true
}

func isTerminal(status string) bool { return stepRank[status] == 2 }

func stepIndex(steps []Step, name, executor string) int {
	for i := range steps {
		if steps[i].Name == name && (executor == "" || steps[i].Executor == executor) {
			return i
		}
	}
	return -1
}

// boundTail keeps the last maxBytes of s, cut at a line start.
func boundTail(s string, maxBytes int) string {
	s = strings.TrimRight(s, "\n")
	if len(s) <= maxBytes {
		return s
	}
	s = s[len(s)-maxBytes:]
	if i := strings.IndexByte(s, '\n'); i >= 0 && i < len(s)-1 {
		s = s[i+1:]
	}
	return s
}

func cloneSteps(s []Step) []Step { return append([]Step(nil), s...) }

// finish settles a run: the Job steps from the outcome, then the kind's
// Finalizer for the service steps, then the row. Uses a fresh context so a
// Stop mid-finish still records the result.
func (r *Runner) finish(_ context.Context, st *runState, outcome JobOutcome) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	now := time.Now().UTC()

	st.mu.Lock()
	failedOne := false
	for i := range st.run.Steps {
		s := &st.run.Steps[i]
		if s.Executor != ExecutorJob || isTerminal(s.Status) {
			if s.Status == StepFailed {
				failedOne = true
				if s.Error == "" && !outcome.Succeeded {
					s.Error = outcome.Reason
				}
			}
			continue
		}
		switch {
		case outcome.Succeeded:
			moveStep(s, StepSucceeded, now)
		case !failedOne:
			moveStep(s, StepFailed, now)
			s.Error = outcome.Reason
			failedOne = true
		default:
			moveStep(s, StepSkipped, now)
		}
	}
	run := st.run
	run.Steps = cloneSteps(st.run.Steps)
	st.mu.Unlock()

	p := &Progress{r: r, st: st}
	var ferr error
	if f := r.finalizers[run.Kind]; f != nil {
		ferr = f.Finalize(ctx, run, outcome, p)
	}

	status, msg := StatusSucceeded, ""
	switch {
	case !outcome.Succeeded:
		status, msg = StatusFailed, outcome.Reason
	case ferr != nil:
		status, msg = StatusFailed, ferr.Error()
	}

	st.mu.Lock()
	for i := range st.run.Steps {
		if status == StatusFailed && !isTerminal(st.run.Steps[i].Status) {
			moveStep(&st.run.Steps[i], StepSkipped, now)
		}
	}
	steps := cloneSteps(st.run.Steps)
	st.mu.Unlock()

	if err := r.store.Finish(ctx, run.ID, status, steps, msg); err != nil {
		r.log.WithError(err).WithField("run_id", run.ID).Error("runs: settle run")
	}
	r.log.WithFields(logrus.Fields{"run_id": run.ID, "kind": run.Kind, "status": status, "reconciled": outcome.Reconciled}).Info("runs: run settled")

	if run.JobName != "" && !r.cfg.KeepFinishedJobs {
		bg := metav1.DeletePropagationBackground
		if err := r.client.BatchV1().Jobs(r.cfg.Namespace).Delete(ctx, run.JobName, metav1.DeleteOptions{PropagationPolicy: &bg}); err != nil && !apierrors.IsNotFound(err) {
			r.log.WithError(err).WithField("job", run.JobName).Warn("runs: delete finished Job")
		}
	}
}

// Progress lets a Finalizer report the service-side steps it runs.
type Progress struct {
	r  *Runner
	st *runState
}

func (p *Progress) update(name, to, errMsg string) {
	p.st.mu.Lock()
	i := stepIndex(p.st.run.Steps, name, "")
	if i < 0 {
		p.st.mu.Unlock()
		return
	}
	moveStep(&p.st.run.Steps[i], to, time.Now().UTC())
	if errMsg != "" {
		p.st.run.Steps[i].Error = errMsg
	}
	steps := cloneSteps(p.st.run.Steps)
	id := p.st.run.ID
	p.st.mu.Unlock()
	if err := p.r.store.UpdateSteps(context.Background(), id, steps); err != nil {
		p.r.log.WithError(err).WithField("run_id", id).Warn("runs: persist steps")
	}
}

// Start marks a step running.
func (p *Progress) Start(name string) { p.update(name, StepRunning, "") }

// Succeed marks a step succeeded.
func (p *Progress) Succeed(name string) { p.update(name, StepSucceeded, "") }

// Fail marks a step failed with the error's message.
func (p *Progress) Fail(name string, err error) {
	msg := "failed"
	if err != nil {
		msg = err.Error()
	}
	p.update(name, StepFailed, msg)
}

// Skip marks a step skipped.
func (p *Progress) Skip(name string) { p.update(name, StepSkipped, "") }

// Note sets a step's Detail and log tail (either may be empty to leave it).
func (p *Progress) Note(name, detail, logTail string) {
	p.st.mu.Lock()
	i := stepIndex(p.st.run.Steps, name, "")
	if i < 0 {
		p.st.mu.Unlock()
		return
	}
	if detail != "" {
		p.st.run.Steps[i].Detail = detail
	}
	if logTail != "" {
		p.st.run.Steps[i].LogTail = boundTail(logTail, p.r.cfg.MaxLogTailBytes)
	}
	steps := cloneSteps(p.st.run.Steps)
	id := p.st.run.ID
	p.st.mu.Unlock()
	if err := p.r.store.UpdateSteps(context.Background(), id, steps); err != nil {
		p.r.log.WithError(err).WithField("run_id", id).Warn("runs: persist steps")
	}
}

// Run is the run as this Progress last recorded it.
func (p *Progress) Run() Run {
	p.st.mu.Lock()
	defer p.st.mu.Unlock()
	r := p.st.run
	r.Steps = cloneSteps(p.st.run.Steps)
	return r
}
