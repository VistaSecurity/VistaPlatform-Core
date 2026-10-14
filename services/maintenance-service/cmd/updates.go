package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/updates"
	"github.com/vistasecurity/vistaplatform/shared/version"
)

// dockerConfigKey is the data key of a kubernetes.io/dockerconfigjson Secret.
const dockerConfigKey = ".dockerconfigjson"

// newUpdateService assembles the update-check service from the environment the
// chart renders (MAINTENANCE_UPDATE_CHECK_*, MAINTENANCE_CHART_SOURCE,
// MAINTENANCE_PULL_SECRET_NAME) and starts the scheduler when the check is on
// and a chart source is configured. Only one replica runs a given check — the
// advisory lock inside Checker.Run — so every replica can start the scheduler.
func newUpdateService(ctx context.Context, db *sql.DB, namespace string, log logrus.FieldLogger) *updates.Service {
	settings := updates.SettingsFromEnv(os.Getenv)
	for _, w := range settings.Warnings {
		log.Warn("updates: " + w)
	}
	svc := updates.NewService(settings, version.Get().Chart,
		updates.PGStore{DB: db}, updates.PGLocker{DB: db}, pullSecretReader(namespace, log), log)

	switch {
	case !settings.Enabled:
		log.Info("updates: the periodic update check is disabled (MAINTENANCE_UPDATE_CHECK_ENABLED=false)")
	case settings.ChartSource == "":
		log.Info("updates: no chart source configured (MAINTENANCE_CHART_SOURCE); the periodic update check is not started")
	default:
		svc.Checker.Start(ctx)
		log.WithFields(logrus.Fields{"source": settings.ChartSource, "interval": settings.Interval.String(), "prereleases": settings.IncludePrereleases}).
			Info("updates: periodic update check scheduled")
	}
	return svc
}

// pullSecretReader reads a dockerconfigjson Secret through the service's own
// namespace-scoped ServiceAccount (the Role grants secrets get/list). Outside a
// cluster it returns nil and the check goes anonymous.
func pullSecretReader(namespace string, log logrus.FieldLogger) updates.SecretReader {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		if !errors.Is(err, rest.ErrNotInCluster) {
			log.WithError(err).Warn("updates: in-cluster config unavailable; registry pull credentials will not be read")
		}
		return nil
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.WithError(err).Warn("updates: could not build a Kubernetes client; registry pull credentials will not be read")
		return nil
	}
	return func(ctx context.Context, name string) ([]byte, error) {
		sec, err := client.CoreV1().Secrets(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("read pull secret %s: %w", name, err)
		}
		raw, ok := sec.Data[dockerConfigKey]
		if !ok {
			return nil, fmt.Errorf("pull secret %s has no %s key", name, dockerConfigKey)
		}
		return raw, nil
	}
}
