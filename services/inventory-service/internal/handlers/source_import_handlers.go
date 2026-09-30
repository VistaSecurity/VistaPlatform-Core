package handlers

// The internal source-import surface (platform ADR-0002 D3).
//
// A connector that pulls from a system of record runs OUTSIDE this service and
// writes the inventory only through these routes. They exist for services,
// never for people:
//
//   - They are mounted on their own group behind RequireSignedServiceCall,
//     which admits an HMAC-signed service call (INTERNAL_AUTH_SECRET) and
//     nothing else. A tenant or platform token is refused, not merely
//     unprivileged — there is no JWT fallback on this group.
//   - The tenant is REQUIRED and comes from the signed X-Tenant-ID header, so
//     every call names exactly one tenant and cannot be re-pointed at another
//     without breaking the signature. Every write then runs tenant-scoped
//     under RLS (services/source_import.go).
//   - The /inventory-service/internal/ prefix is denied at the edge on every
//     host (standards/service-registry.yaml internal_prefixes): no browser and
//     no customer integration calls these, so publishing them buys nothing.
//
// Under the service mesh they are served on the mTLS listener like every other
// route, so a caller also presents the platform client certificate.

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// RequireSignedServiceCall admits an HMAC-signed service-to-service call that
// names one tenant in its signed X-Tenant-ID header, and refuses everything
// else with 401.
//
// It deliberately does not share JWTMiddleware's internal-call branch: that one
// falls through to token authentication when the signature is absent, which is
// right for routes people also use and wrong for routes only services may. An
// empty secret refuses every request — fail closed, never open.
func RequireSignedServiceCall(internalSecret string) gin.HandlerFunc {
	var verifier *serviceauth.Verifier
	if strings.TrimSpace(internalSecret) != "" {
		verifier = serviceauth.NewVerifier(internalSecret)
	}
	return func(c *gin.Context) {
		if verifier == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Internal auth not configured"})
			return
		}
		if !verifier.Verify(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "A signed service call is required"})
			return
		}
		tenantID, err := uuid.Parse(strings.TrimSpace(c.GetHeader(serviceauth.HeaderTenantID)))
		if err != nil || tenantID == uuid.Nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID must name the tenant this call writes for"})
			return
		}
		c.Set("isInternalCall", true)
		c.Set("userID", "system")
		c.Set("tenantID", tenantID)
		c.Next()
	}
}

// sourceImporter is the service behind the internal source routes. An
// interface so the contract test can drive the real handlers and assert their
// bodies against the spec without a database; production passes
// *services.SourceImportService.
type sourceImporter interface {
	UpsertSegments(ctx context.Context, tenantID uuid.UUID, items []services.SourceSegment) ([]services.SourceSegmentResult, error)
	Admission(ctx context.Context, tenantID uuid.UUID, count int) (services.SourceAdmission, error)
	ResolveAssets(ctx context.Context, tenantID uuid.UUID, source identity.Source, items []services.SourceAssetItem) []services.SourceAssetResult
	ClassKeyExists(ctx context.Context, tenantID uuid.UUID, key string) (bool, error)
	HardwareAssets(ctx context.Context, tenantID uuid.UUID, after uuid.UUID, limit int) ([]services.SourceHardwareAsset, error)
	AttachLinks(ctx context.Context, tenantID uuid.UUID, source identity.Source, items []services.SourceLink) ([]services.SourceItemResult, error)
	RecordPresence(ctx context.Context, tenantID uuid.UUID, source identity.Source, platform string, items []services.SourcePresence) ([]services.SourceItemResult, error)
	RecordRun(ctx context.Context, tenantID uuid.UUID, source identity.Source, runID uuid.UUID, items []services.SourceRunItem) ([]services.SourceItemResult, error)
	ArchiveRunAssets(ctx context.Context, tenantID uuid.UUID, source identity.Source, runID uuid.UUID, actor uuid.UUID, reason string, ids []uuid.UUID) ([]services.SourceUndoResult, error)
	SetScanConsent(ctx context.Context, tenantID uuid.UUID, source identity.Source, allow bool, actor uuid.UUID) (services.SourceScanConsent, error)
}

// SourceImportHandler serves the internal source routes.
type SourceImportHandler struct {
	svc sourceImporter
}

// NewSourceImportHandler wires the handler.
func NewSourceImportHandler(svc *services.SourceImportService) *SourceImportHandler {
	if svc == nil {
		return &SourceImportHandler{}
	}
	return &SourceImportHandler{svc: svc}
}

// newSourceImportHandlerWith is the injectable form the contract test uses.
func newSourceImportHandlerWith(svc sourceImporter) *SourceImportHandler {
	return &SourceImportHandler{svc: svc}
}

// signedTenant is the tenant RequireSignedServiceCall put on the context.
func signedTenant(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get("tenantID")
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	id, ok := v.(uuid.UUID)
	if !ok || id == uuid.Nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Tenant ID not found"})
		return uuid.Nil, false
	}
	return id, true
}

// sourceSegmentsRequest is the body of POST /internal/sources/segments.
type sourceSegmentsRequest struct {
	Segments []services.SourceSegment `json:"segments"`
}

// UpsertSegments — POST /inventory-service/internal/sources/segments
func (h *SourceImportHandler) UpsertSegments(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req sourceSegmentsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(req.Segments) == 0 || len(req.Segments) > services.MaxSourceBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "segments must hold between 1 and " + strconv.Itoa(services.MaxSourceBatch) + " items"})
		return
	}
	results, err := h.svc.UpsertSegments(c.Request.Context(), tenantID, req.Segments)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

// sourceAdmissionRequest is the body of POST /internal/sources/assets/admission.
type sourceAdmissionRequest struct {
	Count int `json:"count"`
}

// AssetAdmission — POST /inventory-service/internal/sources/assets/admission
//
// A check that cannot be answered is a 500 carrying `stage` (policy / limit),
// so the caller can say which half failed. It never answers "allowed" for a
// check it could not make.
func (h *SourceImportHandler) AssetAdmission(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req sourceAdmissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Count < 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "count must not be negative"})
		return
	}
	adm, err := h.svc.Admission(c.Request.Context(), tenantID, req.Count)
	if err != nil {
		stage := "policy"
		if errors.Is(err, services.ErrAssetLimit) {
			stage = "limit"
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "stage": stage})
		return
	}
	c.JSON(http.StatusOK, adm)
}

// sourceIdentifier is one identifier on a source asset.
type sourceIdentifier struct {
	Kind  string  `json:"kind"`
	Value string  `json:"value"`
	Scope *string `json:"scope,omitempty"`
}

// sourceAssetWire is one asset observation on the wire.
//
// An ALLOWLIST of the AssetInput fields a source may state, not AssetInput
// itself: a connector maps its vendor's model onto these and nothing else
// reaches the inventory (ADR-0002 D10 "pull is allowlist-only"). Approval
// status is not among them — it is always the tenant's policy's answer.
//
// Description through support_group and operating_system joined at M3: they
// are the canonical asset fields a CMDB mapping may pull (cmdbmap's asset:
// vocabulary). The operating system is a class attribute, so it is taken as
// one named field rather than as a free attributes map.
type sourceAssetWire struct {
	ClassKey             string                 `json:"class_key"`
	Identifiers          []sourceIdentifier     `json:"identifiers,omitempty"`
	DisplayName          *string                `json:"display_name,omitempty"`
	Hostname             *string                `json:"hostname,omitempty"`
	IPAddress            *string                `json:"ip_address,omitempty"`
	Description          *string                `json:"description,omitempty"`
	Environment          *string                `json:"environment,omitempty"`
	BusinessUnit         *string                `json:"business_unit,omitempty"`
	OwnerEmail           *string                `json:"owner_email,omitempty"`
	SupportGroup         *string                `json:"support_group,omitempty"`
	OperatingSystem      *string                `json:"operating_system,omitempty"`
	Site                 *string                `json:"site,omitempty"`
	Region               *string                `json:"region,omitempty"`
	Tags                 map[string]interface{} `json:"tags,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
	ObservationReceiptID string                 `json:"observation_receipt_id,omitempty"`
	ObservedAt           *time.Time             `json:"observed_at,omitempty"`
	Facts                []services.SourceFact  `json:"facts,omitempty"`
	ClaimDiscoverySource string                 `json:"claim_discovery_source,omitempty"`
}

func (w sourceAssetWire) item() services.SourceAssetItem {
	in := models.AssetInput{
		ClassKey:             w.ClassKey,
		DisplayName:          w.DisplayName,
		Hostname:             w.Hostname,
		IPAddress:            w.IPAddress,
		Description:          w.Description,
		Environment:          w.Environment,
		BusinessUnit:         w.BusinessUnit,
		OwnerEmail:           w.OwnerEmail,
		SupportGroup:         w.SupportGroup,
		Site:                 w.Site,
		Region:               w.Region,
		Tags:                 w.Tags,
		Metadata:             w.Metadata,
		ObservationReceiptID: w.ObservationReceiptID,
	}
	if w.ObservedAt != nil {
		in.ObservationTime = w.ObservedAt.UTC()
	}
	if w.OperatingSystem != nil && strings.TrimSpace(*w.OperatingSystem) != "" {
		in.Attributes = map[string]interface{}{"operating_system": strings.TrimSpace(*w.OperatingSystem)}
	}
	for _, id := range w.Identifiers {
		in.Identifiers = append(in.Identifiers, models.AssetIdentifierInput{Kind: id.Kind, Value: id.Value, Scope: id.Scope})
	}
	return services.SourceAssetItem{Input: in, Facts: w.Facts, ClaimDiscoverySource: w.ClaimDiscoverySource}
}

// sourceWire is the provenance a request's items carry.
type sourceWire struct {
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
}

// importedSource reads a request's source and refuses anything but an imported
// one. A system of record's data is IMPORTED — the one source kind an external
// connector states. Measured, declared and inferred belong to sensors, to
// people and to models, and a connector that could claim them could pass its
// data off as something it is not.
func importedSource(c *gin.Context, w sourceWire) (identity.Source, bool) {
	source := identity.Source{Kind: identity.SourceKind(strings.TrimSpace(w.Kind)), Ref: strings.TrimSpace(w.Ref)}
	if source.Kind != identity.SourceImported || !source.Valid() {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source must be {kind: imported, ref: <producer>:<id>}"})
		return identity.Source{}, false
	}
	return source, true
}

// sourceAssetsRequest is the body of POST /internal/sources/assets.
type sourceAssetsRequest struct {
	Source sourceWire        `json:"source"`
	Assets []sourceAssetWire `json:"assets"`
}

// ResolveAssets — POST /inventory-service/internal/sources/assets
func (h *SourceImportHandler) ResolveAssets(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req sourceAssetsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	source, ok := importedSource(c, req.Source)
	if !ok {
		return
	}
	if len(req.Assets) == 0 || len(req.Assets) > services.MaxSourceBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "assets must hold between 1 and " + strconv.Itoa(services.MaxSourceBatch) + " items"})
		return
	}
	items := make([]services.SourceAssetItem, 0, len(req.Assets))
	for _, w := range req.Assets {
		items = append(items, w.item())
	}
	c.JSON(http.StatusOK, gin.H{"results": h.svc.ResolveAssets(c.Request.Context(), tenantID, source, items)})
}

// sourceLinksRequest is the body of POST /internal/sources/assets/links.
type sourceLinksRequest struct {
	Source sourceWire            `json:"source"`
	Links  []services.SourceLink `json:"links"`
}

// AttachLinks — POST /inventory-service/internal/sources/assets/links
//
// A source attaches its own scoped record id to an asset it wrote to (the
// CMDB push's echo link, D11 item 3). Per-item results; an item naming an
// asset that is not this tenant's is `not_found`.
func (h *SourceImportHandler) AttachLinks(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req sourceLinksRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	source, ok := importedSource(c, req.Source)
	if !ok {
		return
	}
	if len(req.Links) == 0 || len(req.Links) > services.MaxSourceBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "links must hold between 1 and " + strconv.Itoa(services.MaxSourceBatch) + " items"})
		return
	}
	results, err := h.svc.AttachLinks(c.Request.Context(), tenantID, source, req.Links)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

// sourcePresenceRequest is the body of POST /internal/sources/assets/presence.
type sourcePresenceRequest struct {
	Source   sourceWire                `json:"source"`
	Platform string                    `json:"platform"`
	Items    []services.SourcePresence `json:"items"`
}

// RecordPresence — POST /inventory-service/internal/sources/assets/presence
//
// A source records that an asset is absent from it (retired or no longer
// listed) or present again, on the asset's timeline. The asset itself is not
// changed (D11 item 2).
func (h *SourceImportHandler) RecordPresence(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req sourcePresenceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	source, ok := importedSource(c, req.Source)
	if !ok {
		return
	}
	if len(req.Items) == 0 || len(req.Items) > services.MaxSourceBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "items must hold between 1 and " + strconv.Itoa(services.MaxSourceBatch) + " items"})
		return
	}
	platform := strings.TrimSpace(req.Platform)
	if len(platform) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "platform is longer than 64 characters"})
		return
	}
	results, err := h.svc.RecordPresence(c.Request.Context(), tenantID, source, platform, req.Items)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

// sourceRunRequest is the body of POST /internal/sources/assets/runs.
type sourceRunRequest struct {
	Source sourceWire               `json:"source"`
	RunID  uuid.UUID                `json:"run_id"`
	Items  []services.SourceRunItem `json:"items"`
}

// RecordRun — POST /inventory-service/internal/sources/assets/runs
//
// A source tags the assets one of its runs created or wrote to with the run's
// id, on each asset's timeline (platform ADR-0002 D11 item 6). Per-item
// results; an item naming an asset that is not this tenant's is `not_found`.
func (h *SourceImportHandler) RecordRun(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req sourceRunRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	source, ok := importedSource(c, req.Source)
	if !ok {
		return
	}
	if req.RunID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "run_id is required"})
		return
	}
	if len(req.Items) == 0 || len(req.Items) > services.MaxSourceBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "items must hold between 1 and " + strconv.Itoa(services.MaxSourceBatch) + " items"})
		return
	}
	results, err := h.svc.RecordRun(c.Request.Context(), tenantID, source, req.RunID, req.Items)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

// sourceUndoRequest is the body of POST /internal/sources/assets/archive.
type sourceUndoRequest struct {
	Source   sourceWire  `json:"source"`
	RunID    uuid.UUID   `json:"run_id"`
	ActorID  *uuid.UUID  `json:"actor_user_id,omitempty"`
	Reason   string      `json:"reason"`
	AssetIDs []uuid.UUID `json:"asset_ids"`
}

// ArchiveRunAssets — POST /inventory-service/internal/sources/assets/archive
//
// Undo of a source run on the inventory side: archives (never deletes) the
// named assets THAT RUN created, and keeps — with the reason — any it did not
// create, any another source has also reported, and any merged away. The
// actor is the person who asked for the undo, recorded on the archive.
func (h *SourceImportHandler) ArchiveRunAssets(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req sourceUndoRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	source, ok := importedSource(c, req.Source)
	if !ok {
		return
	}
	if req.RunID == uuid.Nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "run_id is required"})
		return
	}
	if len(req.AssetIDs) == 0 || len(req.AssetIDs) > services.MaxSourceBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "asset_ids must hold between 1 and " + strconv.Itoa(services.MaxSourceBatch) + " items"})
		return
	}
	actor := uuid.Nil
	if req.ActorID != nil {
		actor = *req.ActorID
	}
	results, err := h.svc.ArchiveRunAssets(c.Request.Context(), tenantID, source, req.RunID, actor, strings.TrimSpace(req.Reason), req.AssetIDs)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"results": results})
}

// sourceScanConsentRequest is the body of PUT /internal/sources/scan-consent.
type sourceScanConsentRequest struct {
	Source          sourceWire `json:"source"`
	AllowActiveScan *bool      `json:"allow_active_scan"`
	ActorID         *uuid.UUID `json:"actor_user_id,omitempty"`
}

// SetScanConsent — PUT /inventory-service/internal/sources/scan-consent
//
// Records whether assets known only from this imported source may be actively
// scanned by AUTOMATIC scanning (platform ADR-0002 D10). allow_active_scan is
// required — an omitted value is refused rather than read as false or true.
func (h *SourceImportHandler) SetScanConsent(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	var req sourceScanConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	source, ok := importedSource(c, req.Source)
	if !ok {
		return
	}
	if req.AllowActiveScan == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "allow_active_scan is required"})
		return
	}
	if len(source.Ref) > 200 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source.ref is longer than 200 characters"})
		return
	}
	actor := uuid.Nil
	if req.ActorID != nil {
		actor = *req.ActorID
	}
	out, err := h.svc.SetScanConsent(c.Request.Context(), tenantID, source, *req.AllowActiveScan, actor)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, out)
}

// ClassExists — GET /inventory-service/internal/sources/asset-classes/:key
func (h *SourceImportHandler) ClassExists(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	key := c.Param("key")
	exists, err := h.svc.ClassKeyExists(c.Request.Context(), tenantID, key)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not check the asset class"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"key": key, "exists": exists})
}

// HardwareAssets — GET /inventory-service/internal/sources/hardware-assets?after=&limit=
func (h *SourceImportHandler) HardwareAssets(c *gin.Context) {
	tenantID, ok := signedTenant(c)
	if !ok {
		return
	}
	after := uuid.Nil
	if raw := strings.TrimSpace(c.Query("after")); raw != "" {
		id, err := uuid.Parse(raw)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "after must be an asset id"})
			return
		}
		after = id
	}
	limit := services.MaxSourceHardwarePage
	if raw := c.Query("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > services.MaxSourceHardwarePage {
			c.JSON(http.StatusBadRequest, gin.H{"error": "limit must be between 1 and " + strconv.Itoa(services.MaxSourceHardwarePage)})
			return
		}
		limit = n
	}
	assets, err := h.svc.HardwareAssets(c.Request.Context(), tenantID, after, limit)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not read the inventory"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"assets": assets, "more": len(assets) == limit})
}

// RegisterSourceImportRoutes mounts the internal source routes on internal,
// which must be a group carrying RequireSignedServiceCall. Paths are written in
// full so the spec-route guard, which scans for a method call followed by a
// string literal, can see them.
func RegisterSourceImportRoutes(internal *gin.RouterGroup, h *SourceImportHandler) {
	internal.POST("/inventory-service/internal/sources/segments", h.UpsertSegments)
	internal.POST("/inventory-service/internal/sources/assets/admission", h.AssetAdmission)
	internal.POST("/inventory-service/internal/sources/assets", h.ResolveAssets)
	internal.POST("/inventory-service/internal/sources/assets/links", h.AttachLinks)
	internal.POST("/inventory-service/internal/sources/assets/presence", h.RecordPresence)
	internal.POST("/inventory-service/internal/sources/assets/runs", h.RecordRun)
	internal.POST("/inventory-service/internal/sources/assets/archive", h.ArchiveRunAssets)
	internal.PUT("/inventory-service/internal/sources/scan-consent", h.SetScanConsent)
	internal.GET("/inventory-service/internal/sources/asset-classes/:key", h.ClassExists)
	internal.GET("/inventory-service/internal/sources/hardware-assets", h.HardwareAssets)
}
