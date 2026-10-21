package handlers

// HTTP surface of virtualisation (DCIM BUILD_PLAN row 4.2), under
// /api/v2/inventory-service/virtualization:
//
//	GET    /{object}                        virtualization.read    list (filters, q, limit, offset)
//	POST   /{object}                        virtualization.manage  create
//	GET    /{object}/{id}                   virtualization.read
//	PATCH  /{object}/{id}                   virtualization.manage  a platform cluster type answers 403 read_only
//	DELETE /{object}/{id}                   virtualization.manage
//	GET    /clusters/{id}/hosts             virtualization.read    the cluster's hosts
//	POST   /clusters/{id}/hosts             virtualization.manage  {"asset_id"} — a hypervisor or hardware joins
//	DELETE /clusters/{id}/hosts/{asset_id}  virtualization.manage
//	GET    /clusters/{id}/vms               virtualization.read    the cluster's VMs with vCPU / memory / disk
//	GET    /assets/{id}/virtualization      virtualization.read    the asset page's VM / hypervisor card
//	PATCH  /assets/{id}/virtualization      virtualization.manage  a VM's cluster_id, vcpus, memory_mb, disk_mb
//
// {object} is cluster-types, cluster-groups, clusters, virtual-disks. Envelope
// and error codes are IPAM's (ipam_handlers.go). Gates are mounted with the
// routes (cmd/virtualization_routes.go).

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// VirtualizationStore is what the handlers need; services.VirtualizationService
// implements it.
type VirtualizationStore interface {
	List(ctx context.Context, tenant uuid.UUID, route string, p services.IPAMListParams) ([]json.RawMessage, int, error)
	Get(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) (json.RawMessage, error)
	Create(ctx context.Context, tenant uuid.UUID, route string, body []byte) (json.RawMessage, error)
	Update(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID, body []byte) (json.RawMessage, error)
	Delete(ctx context.Context, tenant uuid.UUID, route string, id uuid.UUID) error
	ClusterHosts(ctx context.Context, tenant, cluster uuid.UUID) ([]services.ClusterMember, error)
	AddClusterHost(ctx context.Context, tenant, cluster, asset uuid.UUID) ([]services.ClusterMember, error)
	RemoveClusterHost(ctx context.Context, tenant, cluster, asset uuid.UUID) error
	ClusterVMs(ctx context.Context, tenant, cluster uuid.UUID) ([]services.ClusterMember, error)
	AssetVirtualization(ctx context.Context, tenant, asset uuid.UUID) (*services.AssetVirtualization, error)
	UpdateAssetVirtualization(ctx context.Context, tenant, asset uuid.UUID, patch services.VirtualizationPatch) (*services.AssetVirtualization, error)
}

// VirtualizationHandler serves the virtualisation routes. The object CRUD is
// the catalogue handler's over another store.
type VirtualizationHandler struct {
	*CatalogueHandler
	store VirtualizationStore
}

// NewVirtualizationHandler returns the handler over store.
func NewVirtualizationHandler(store VirtualizationStore) *VirtualizationHandler {
	return &VirtualizationHandler{CatalogueHandler: &CatalogueHandler{store: virtCRUD{store}}, store: store}
}

// virtCRUD adapts the store to the catalogue handler's CRUD half; the template
// and hardware methods are never routed here.
type virtCRUD struct{ VirtualizationStore }

func (virtCRUD) ImportDeviceTypes(context.Context, uuid.UUID, []byte) ([]services.ImportedDeviceType, error) {
	return nil, services.ErrIPAMNotFound
}
func (virtCRUD) ListTemplates(context.Context, uuid.UUID, services.TemplateParent, string, services.IPAMListParams) ([]json.RawMessage, int, error) {
	return nil, 0, services.ErrIPAMNotFound
}
func (virtCRUD) GetTemplate(context.Context, uuid.UUID, services.TemplateParent, string, uuid.UUID) (json.RawMessage, error) {
	return nil, services.ErrIPAMNotFound
}
func (virtCRUD) CreateTemplate(context.Context, uuid.UUID, services.TemplateParent, string, []byte) (json.RawMessage, error) {
	return nil, services.ErrIPAMNotFound
}
func (virtCRUD) UpdateTemplate(context.Context, uuid.UUID, services.TemplateParent, string, uuid.UUID, []byte) (json.RawMessage, error) {
	return nil, services.ErrIPAMNotFound
}
func (virtCRUD) DeleteTemplate(context.Context, uuid.UUID, services.TemplateParent, string, uuid.UUID) error {
	return services.ErrIPAMNotFound
}
func (virtCRUD) Hardware(context.Context, uuid.UUID, uuid.UUID) (*services.AssetHardware, error) {
	return nil, services.ErrIPAMNotFound
}
func (virtCRUD) UpdateHardware(context.Context, uuid.UUID, uuid.UUID, services.HardwarePatch) (*services.AssetHardware, error) {
	return nil, services.ErrIPAMNotFound
}
func (virtCRUD) ApplyDeviceType(context.Context, uuid.UUID, uuid.UUID, uuid.UUID) (*services.ApplyDeviceTypeResult, error) {
	return nil, services.ErrIPAMNotFound
}
func (virtCRUD) EOLCatalogueEntries(context.Context, uuid.UUID, string, string, int) ([]services.EOLCatalogueRef, error) {
	return nil, services.ErrIPAMNotFound
}

// ClusterHosts is GET /clusters/{id}/hosts.
func (h *VirtualizationHandler) ClusterHosts(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	rows, err := h.store.ClusterHosts(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// AddClusterHost is POST /clusters/{id}/hosts {"asset_id": "…"}.
func (h *VirtualizationHandler) AddClusterHost(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	body, ok := ipamBody(c)
	if !ok {
		return
	}
	var req struct {
		AssetID string `json:"asset_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "body must be a JSON object")
		return
	}
	asset, err := uuid.Parse(req.AssetID)
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "asset_id must be a UUID.")
		return
	}
	rows, err := h.store.AddClusterHost(c.Request.Context(), tenant, id, asset)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// RemoveClusterHost is DELETE /clusters/{id}/hosts/{asset_id}.
func (h *VirtualizationHandler) RemoveClusterHost(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	asset, err := uuid.Parse(c.Param("asset_id"))
	if err != nil {
		ipamError(c, http.StatusBadRequest, "invalid_id", "asset_id must be a UUID.")
		return
	}
	if err := h.store.RemoveClusterHost(c.Request.Context(), tenant, id, asset); err != nil {
		ipamStoreError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ClusterVMs is GET /clusters/{id}/vms.
func (h *VirtualizationHandler) ClusterVMs(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	rows, err := h.store.ClusterVMs(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rows})
}

// AssetVirtualization is GET /assets/{id}/virtualization.
func (h *VirtualizationHandler) AssetVirtualization(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	v, err := h.store.AssetVirtualization(c.Request.Context(), tenant, id)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": v})
}

// UpdateAssetVirtualization is PATCH /assets/{id}/virtualization.
func (h *VirtualizationHandler) UpdateAssetVirtualization(c *gin.Context) {
	tenant, ok := ipamTenant(c)
	if !ok {
		return
	}
	id, ok := ipamID(c)
	if !ok {
		return
	}
	body, ok := ipamBody(c)
	if !ok {
		return
	}
	var patch services.VirtualizationPatch
	if err := json.Unmarshal(body, &patch); err != nil || patch == nil {
		ipamError(c, http.StatusBadRequest, "invalid_request", "body must be a JSON object")
		return
	}
	v, err := h.store.UpdateAssetVirtualization(c.Request.Context(), tenant, id, patch)
	if err != nil {
		ipamStoreError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": v})
}
