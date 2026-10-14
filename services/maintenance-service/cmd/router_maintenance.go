package main

import (
	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/runs"
)

// mountBackupRoutes mounts the backup and run-history routes (WP3) on the
// authenticated admin group. Reads are under platform.health; every write —
// and the download, which exports the whole database — under
// platform.maintenance.
func mountBackupRoutes(admin *gin.RouterGroup, read, write gin.HandlerFunc, ops *maintenanceOps) {
	admin.GET("/backups", read, ops.backups.List)
	admin.POST("/backups", write, ops.backups.Create)
	admin.GET("/backups/:id/download", write, ops.backups.Download)
	admin.DELETE("/backups/:id", write, ops.backups.Delete)

	admin.GET("/runs", read, runs.ListHandler(ops.runStore))
	admin.GET("/runs/:id", read, runs.GetHandler(ops.runStore))
}

// mountUpgradeRoutes mounts the update, rollback and release-history routes
// (WP4). Pre-flight, the update and the rollback change the cluster and are
// under platform.maintenance; the history is a read under platform.health.
func mountUpgradeRoutes(admin *gin.RouterGroup, read, write gin.HandlerFunc, ops *maintenanceOps) {
	admin.POST("/updates/preflight", write, ops.upgrade.Preflight)
	admin.POST("/updates", write, ops.upgrade.StartUpdate)
	admin.POST("/rollbacks", write, ops.upgrade.StartRollback)
	admin.GET("/releases", read, ops.upgrade.Releases)
}
