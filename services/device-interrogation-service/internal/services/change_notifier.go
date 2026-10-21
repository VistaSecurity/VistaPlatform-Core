package services

import (
	"context"
	"sync/atomic"

	"github.com/vistasecurity/vistaplatform/shared/dcim/changenotify"
)

// This service writes DCIM tables directly in one place: cloud enumeration
// (and its retained-context replay) ensures the cloud account's site and its
// regions' locations (shared/cloudaccount → shared/dcim/sites) and mirrors an
// account + region as a cluster (shared/identity/postgres MirrorCloudCluster),
// recording each through shared/dcim/changes. The change notifier lives where
// the writer lives, so those changes raise `object_changed` like
// inventory-service's: cmd/main.go installs one notifier here, and the run
// entry points open a unit around their work (ChangeUnit).

var changeNotifier atomic.Pointer[changenotify.Notifier]

// SetChangeNotifier installs the process's change notifier. cmd/main.go calls
// it once, before any worker starts; nil uninstalls it (tests).
func SetChangeNotifier(n *changenotify.Notifier) { changeNotifier.Store(n) }

// ChangeNotifier is the installed notifier, or nil.
func ChangeNotifier() *changenotify.Notifier { return changeNotifier.Load() }

// ChangeUnit runs fn as one change-notification unit under the installed
// notifier: what fn records is raised once it has committed. Without a
// notifier, or inside an enclosing unit, fn simply runs.
func ChangeUnit(ctx context.Context, fn func(context.Context) error) error {
	return ChangeNotifier().Unit(ctx, fn)
}
