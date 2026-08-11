package main

import (
	"database/sql"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/cbom-service/internal/cbom"
	sharedstorage "github.com/vistasecurity/vistaplatform/shared/storage"
)

// editionHooks are the extension points the Enterprise build fills in.
//
// The zero value is the Core edition: every hook nil, meaning artifacts are
// generated unsigned and unattested, the comparison routes are never mounted,
// and downloads serve the canonical CycloneDX form only. That is a supported
// product configuration, not a degraded one — Core's promise is generation and
// CycloneDX export, CycloneDX being the CBOM standard itself.
//
// The Enterprise build supplies real implementations from cmd/edition_ee.go,
// which is guarded by `//go:build ee` and imports services/cbom-service/ee/.
// Neither that file nor the ee/ tree exists in the open-source repository, so
// a Core checkout cannot accidentally link Enterprise code — there is nothing
// to link. See docsv4/internal/operations/OPEN_SOURCE_CARVE_TRACKER.md §5.5.
//
// Hooks are wired at process start (init) rather than resolved per request:
// this boundary decides which *code* is present, while shared/entitlements
// decides which *tenant* may use it. Both gates apply in an Enterprise build.
type editionHooks struct {
	// NewSigner returns the artifact signer, or nil to generate unsigned.
	// The error is advisory (e.g. missing secret) and is logged, not fatal.
	NewSigner func() (cbom.Signer, error)

	// NewAttestationBuilder returns the compliance-attestation builder, or
	// nil to generate artifacts without an attestation layer.
	NewAttestationBuilder func(db *sql.DB) cbom.AttestationBuilder

	// RegisterComparisonRoutes mounts the artifact comparison/drift
	// endpoints. Nil in Core, so those routes simply do not exist.
	RegisterComparisonRoutes func(api *gin.RouterGroup, repo *cbom.Repository, storage sharedstorage.ArtifactStorageService)

	// NewArtifactFormatter returns the renderer for the alternate download
	// formats (SPDX, PDF), or nil to serve CycloneDX only. Unlike the hooks
	// above, absence is user-visible: Core's /download answers 402 for
	// spdx/pdf rather than degrading the response.
	NewArtifactFormatter func() cbom.ArtifactFormatter
}

// hooks is the active edition. Core leaves it zero; the Enterprise build
// replaces it from an init() in cmd/edition_ee.go.
var hooks editionHooks

// edition reports the build's edition for startup logging, so an operator can
// tell from the first log line which binary is running.
func edition() string {
	if hooks.NewSigner == nil && hooks.RegisterComparisonRoutes == nil {
		return "core"
	}
	return "enterprise"
}
