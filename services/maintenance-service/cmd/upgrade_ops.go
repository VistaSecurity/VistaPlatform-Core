package main

import (
	"context"
	"database/sql"
	"os"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/backups"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/capabilities"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/updates"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/upgrade"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/versions"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

// upgradeInputs are what the update and rollback runs (WP4) need from the
// rest of main(): the capability detector the status route uses, the update
// check's tag source (pre-flight's "does the version exist"), the version
// aggregator (the smoke step) and the audit middleware for run outcomes that
// are settled with no request in hand.
type upgradeInputs struct {
	Detector   capabilities.Detector
	Tags       updates.TagSource
	Versions   versions.Source
	SingleNode bool
	AuditMW    *auditmiddleware.Middleware
	// PullSecret reads the registry credential cosign uses; nil = anonymous.
	PullSecret updates.SecretReader
	// TrustEnv is the trust bundle's environment for subprocesses
	// (SSL_CERT_FILE); nil without EXTRA_TRUSTED_CA_PATH.
	TrustEnv []string
}

// upgradeConfigFromEnv reads what the chart renders into the pod.
func upgradeConfigFromEnv() upgrade.Config {
	return upgrade.Config{
		Namespace:       os.Getenv("POD_NAMESPACE"),
		ReleaseName:     os.Getenv("HELM_RELEASE_NAME"),
		ChartSource:     os.Getenv(updates.EnvChartSource),
		RunningChart:    version.Get().Chart,
		JobTemplateDir:  os.Getenv("MAINTENANCE_UPDATE_JOB_TEMPLATE_DIR"),
		JobTemplateName: os.Getenv("MAINTENANCE_UPDATE_JOB_TEMPLATE_CONFIGMAP"),
		SkipSignature:   os.Getenv("MAINTENANCE_SKIP_SIGNATURE_VERIFY") == "true",
	}
}

// newUpgradeService wires the update/rollback service. It registers itself as
// the Finalizer for update and rollback runs, so it must be built before the
// Runner reconciles.
func newUpgradeService(cfg upgrade.Config, db *sql.DB, client kubernetes.Interface, runner *runs.Runner, runStore runs.Store,
	bk *backups.Service, in upgradeInputs, log logrus.FieldLogger) *upgrade.Service {
	pullSecret := os.Getenv(updates.EnvPullSecret)
	verifier := upgrade.Cosign{
		IdentityRegexp: os.Getenv("MAINTENANCE_VERIFICATION_IDENTITY_REGEXP"),
		ExtraEnv:       in.TrustEnv,
		DockerConfig: func(ctx context.Context) []byte {
			if pullSecret == "" || in.PullSecret == nil {
				return nil
			}
			raw, err := in.PullSecret(ctx, pullSecret)
			if err != nil {
				log.WithError(err).Warn("upgrade: pull secret unreadable; verifying anonymously")
				return nil
			}
			return raw
		},
	}
	var releases upgrade.ReleaseReader
	if client != nil {
		releases = upgrade.SecretReleases{Client: client, Namespace: cfg.Namespace, ReleaseName: cfg.ReleaseName}
	}
	var bt upgrade.BackupTaker
	var bf upgrade.BackupFinder
	if bk != nil {
		bt, bf = bk, bk
	}
	var rr upgrade.RunningRuns
	if runStore != nil {
		rr = runStore
	}
	pf := &upgrade.Preflight{
		Capabilities:  in.Detector,
		Tags:          in.Tags,
		ChartSource:   cfg.ChartSource,
		RunningChart:  cfg.RunningChart,
		Verifier:      verifier,
		SkipSignature: cfg.SkipSignature,
		Releases:      releases,
		SingleNode:    in.SingleNode,
		Schema:        upgrade.SQLSchema{DB: db},
		Runs:          rr,
		Backups:       bf,
	}
	return upgrade.NewService(cfg, upgrade.Deps{
		Runner:    runner,
		RunStore:  runStore,
		Preflight: pf,
		Backups:   bt,
		Verifier:  verifier,
		Releases:  releases,
		Smoke:     upgrade.VersionSmoke{Source: in.Versions},
		Audit:     runAuditor{mw: in.AuditMW},
		Log:       log,
	})
}

// runAuditor records update/rollback run events through the shared audit
// middleware — the same trail attachAuditLogging writes the request-level
// entries to — attributed to the platform user who started the run.
type runAuditor struct{ mw *auditmiddleware.Middleware }

func (a runAuditor) RecordRun(ctx context.Context, ev upgrade.RunEvent) {
	if a.mw == nil {
		return
	}
	rt := "platform_maintenance_run"
	rid := ev.Run.ID
	entry := &auditmiddleware.ActivityLogRequest{
		EventType:     ev.EventType,
		EventCategory: auditmiddleware.EventCategorySystem,
		Action:        string(ev.Run.Kind),
		UserType:      "platform",
		UserID:        ev.Run.StartedBy,
		ResourceType:  &rt,
		ResourceID:    &rid,
		Success:       ev.Success,
		Metadata: map[string]any{
			"phase": ev.Phase, "from_version": ev.Run.FromVersion, "to_version": ev.Run.ToVersion,
		},
	}
	if ev.Message != "" {
		entry.Metadata["message"] = ev.Message
		if !ev.Success {
			msg := ev.Message
			entry.ErrorMessage = &msg
		}
	}
	_ = a.mw.LogActivity(ctx, entry)
}
