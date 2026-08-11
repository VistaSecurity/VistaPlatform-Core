package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// editionHooks are the extension points the Enterprise build fills in.
//
// The zero value is the Core edition: every hook nil, meaning the CMDB / ITSM
// *sync* routes are never mounted and no external connector is linked into the
// binary. That is a supported product configuration, not a degraded one — Core
// keeps the entire asset/CMDB data model and every internal CMDB capability:
// infrastructure assets, crypto configurations, certificates, keys, libraries,
// the inventory lenses, discovery ingestion, lifecycle, bulk/spreadsheet
// import, and the whole v1 + v2 inventory API. A Core install has a full
// internal CMDB; it simply cannot push it to, or pull it from, ServiceNow,
// Device42, SolarWinds, or Oomnitza.
//
// The Enterprise build supplies real implementations from cmd/edition_ee.go,
// which is guarded by `//go:build ee` and imports
// services/inventory-service/ee/. Neither that file nor the ee/ tree exists in
// the open-source repository, so a Core checkout cannot accidentally link
// Enterprise code — there is nothing to link. See
// docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5.
//
// Hooks are wired at process start (init) rather than resolved per request:
// this boundary decides which *code* is present, while shared/entitlements
// decides which *tenant* may use it. Both gates apply in an Enterprise build —
// the mounted routes still carry their settings.update / assets.manage RBAC
// checks, exactly as they did before the carve.
type editionHooks struct {
	// RegisterCMDBSyncRoutes constructs the CMDB sync service and mounts the
	// external-integration endpoints (profiles CRUD, test-connection, push
	// sync, inbound pull, sync-job history) on the authenticated /api/v2
	// group, gating them itself. Nil in Core, so those routes simply do not
	// exist.
	//
	// It takes Core's *services.AssetService: the dependency direction is
	// Enterprise → Core, so inbound-pull asset creation and the crypto-posture
	// write-back both reuse Core's asset paths rather than duplicating them.
	RegisterCMDBSyncRoutes func(
		apiv2 *gin.RouterGroup,
		db *database.DB,
		rawDB *sql.DB,
		assetService *services.AssetService,
		encryptionMasterKey string,
	)
}

// hooks is the active edition. Core leaves it zero; the Enterprise build
// replaces it from an init() in cmd/edition_ee.go.
var hooks editionHooks

// edition reports the build's edition for startup logging, so an operator can
// tell from the first log line which binary is running.
func edition() string {
	if hooks.RegisterCMDBSyncRoutes == nil {
		return "core"
	}
	return "enterprise"
}
