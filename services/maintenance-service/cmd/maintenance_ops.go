package main

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/backups"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/upgrade"
)

// maintenanceOps is the run machinery and the backup feature main() serves
// (WP3), and the update and rollback runs (WP4) on the same Runner.
type maintenanceOps struct {
	runner   *runs.Runner // nil outside Kubernetes: nothing to launch a Job on
	runStore runs.Store
	backups  *backups.Handlers
	upgrade  *upgrade.Handlers
}

// Stop stops following runs; any still going are reconciled by the next boot.
func (o *maintenanceOps) Stop() {
	if o != nil && o.runner != nil {
		o.runner.Stop()
	}
}

// backupsConfigFromEnv reads what the chart renders into the pod.
func backupsConfigFromEnv() backups.Config {
	retention, err := strconv.Atoi(os.Getenv("MAINTENANCE_BACKUPS_RETENTION"))
	if err != nil {
		retention = 5
	}
	return backups.Config{
		Enabled:         os.Getenv("MAINTENANCE_BACKUPS_ENABLED") == "true",
		Root:            os.Getenv("MAINTENANCE_BACKUPS_PATH"),
		Retention:       retention,
		JobTemplateDir:  os.Getenv("MAINTENANCE_JOB_TEMPLATE_DIR"),
		JobTemplateName: os.Getenv("MAINTENANCE_JOB_TEMPLATE_CONFIGMAP"),
		Namespace:       os.Getenv("POD_NAMESPACE"),
		ReleaseName:     os.Getenv("HELM_RELEASE_NAME"),
		AppVersion:      os.Getenv("CHART_APP_VERSION"),
		ChartVersion:    os.Getenv("CHART_VERSION"),
		ChartSource:     os.Getenv("MAINTENANCE_CHART_SOURCE"),
		Secrets: backups.SecretNames{
			Install:    os.Getenv("MAINTENANCE_SECRET_INSTALL"),
			Platform:   os.Getenv("MAINTENANCE_SECRET_PLATFORM"),
			JWTSigning: os.Getenv("MAINTENANCE_SECRET_JWT_SIGNING"),
			Generated:  os.Getenv("MAINTENANCE_SECRET_GENERATED"),
			// The Secret cbom-service signs with (chart-managed or existing*); unset when it has none.
			CBOMSigning: os.Getenv("MAINTENANCE_SECRET_CBOM_SIGNING"),
		},
		DB: backups.ManifestDB{
			External:         os.Getenv("MAINTENANCE_DB_EXTERNAL") == "true",
			CredentialSecret: os.Getenv("MAINTENANCE_DB_SECRET_NAME"),
			CredentialKey:    os.Getenv("MAINTENANCE_DB_SECRET_KEY"),
		},
	}
}

// inClusterClient is the service's own ServiceAccount clientset, or nil
// outside a cluster.
func inClusterClient() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if errors.Is(err, rest.ErrNotInCluster) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

// newMaintenanceOps wires the run store, the Runner (when there is a cluster)
// and the backup feature, and reconciles runs left `running` by a previous
// process — the restart-survival WP4's update run depends on.
func newMaintenanceOps(db *sql.DB, client kubernetes.Interface, cfg backups.Config, auditor backups.Auditor, up upgradeInputs, log logrus.FieldLogger) *maintenanceOps {
	if log == nil {
		log = logrus.StandardLogger()
	}
	var runStore runs.Store
	if db != nil {
		runStore = runs.SQLStore{DB: db}
	}
	var backupStore backups.Store
	if db != nil {
		backupStore = backups.SQLStore{DB: db}
	}
	ops := &maintenanceOps{runStore: runStore}
	if client != nil && runStore != nil {
		ops.runner = runs.NewRunner(runStore, client, runs.Config{Namespace: cfg.Namespace}, log)
	}
	svc := backups.NewService(cfg, backupStore, ops.runner, client, log)
	ops.backups = backups.NewHandlers(svc, auditor, log)
	// The update and rollback runs (WP4) register their Finalizer on the same
	// Runner BEFORE it reconciles: an update Job that finished while this
	// process was starting — the normal case, since the update replaces this
	// pod — is settled here, and its smoke step runs.
	var upSvc *upgrade.Service
	if db != nil {
		upSvc = newUpgradeService(upgradeConfigFromEnv(), db, client, ops.runner, runStore, svc, up, log)
	}
	ops.upgrade = upgrade.NewHandlers(upSvc, log)
	if ops.runner != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := ops.runner.Reconcile(ctx); err != nil {
			log.WithError(err).Error("maintenance runs: reconcile on start failed; runs left running will be settled on the next start")
		}
	}
	return ops
}
