package main

import (
	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/backups"
)

// backupsTestOps is the router tests' maintenanceOps: no database, no cluster
// — backups report unavailable, lists are empty — so the gate tests drive the
// REAL backup handlers without any dependency answering for them.
func backupsTestOps() *maintenanceOps {
	return newMaintenanceOps(nil, nil, backups.Config{}, nil, upgradeInputs{}, nil)
}
