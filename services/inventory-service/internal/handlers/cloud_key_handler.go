package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	sharedmw "github.com/vistasecurity/vistaplatform/shared/middleware"
)

// cloudKeyStore is the narrow persistence surface the cloud-key intake needs.
// *services.AssetService satisfies it; tests pass a recorder.
type cloudKeyStore interface {
	UpsertCloudKeys(tenantID uuid.UUID, records []services.CloudKeyRecord) (int, error)
}

// CloudKeyHandler ingests cloud KMS keys into the first-class key inventory.
type CloudKeyHandler struct {
	store cloudKeyStore
}

func NewCloudKeyHandler(store cloudKeyStore) *CloudKeyHandler {
	return &CloudKeyHandler{store: store}
}

// cloudKeyIngestRequest is the wire shape: a batch of keys as the PROVIDER
// describes them. The mapping onto inventory's own vocabulary happens here, in
// the service that owns the `keys` table — never on the discovery side.
type cloudKeyIngestRequest struct {
	Keys []services.CloudKeyRecord `json:"keys"`
}

// IngestCloudKeys — POST /inventory-service/keys/cloud.
//
// INTERNAL ONLY. device-interrogation-service calls it after a cloud KMS
// discovery, so that discovered keys land in the same `keys` table the
// Inventory → Keys lens reads instead of only in the parallel `kms_keys`
// table, whose sole reader is an experimental endpoint no UI calls.
//
// Same transport rule as the agent-host approval route: the handler refuses
// anything that is not an HMAC-verified service call, and no tenant permission
// gates it because an internal call carries no user. The tenant comes from the
// X-Tenant-ID header the auth middleware honours for verified internal calls.
//
// Not in the OpenAPI contract; no browser calls it. A tenant user sees the
// result at Inventory → Keys.
func (h *CloudKeyHandler) IngestCloudKeys(c *gin.Context) {
	if !sharedmw.IsInternalCall(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "cloud key ingest is an internal service call"})
		return
	}
	tenantIDVal, exists := c.Get("tenantID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "tenant not found"})
		return
	}
	tenantID, ok := tenantIDVal.(uuid.UUID)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid tenant id"})
		return
	}

	var req cloudKeyIngestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if len(req.Keys) == 0 {
		// Nothing to do is not a failure — a region with no keys is a normal
		// discovery result.
		c.JSON(http.StatusOK, gin.H{"written": 0})
		return
	}

	written, err := h.store.UpsertCloudKeys(tenantID, req.Keys)
	if err != nil {
		// Partial success is reported honestly: `written` is what landed, and
		// the status says the batch did not complete.
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to ingest cloud keys", "written": written})
		return
	}
	c.JSON(http.StatusOK, gin.H{"written": written})
}
