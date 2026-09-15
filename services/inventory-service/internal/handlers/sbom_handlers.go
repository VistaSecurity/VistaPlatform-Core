package handlers

// The SBOM upload surface (workstream 2.6b) and the two software reads it
// feeds: an asset's Software tab and the tenant software catalogue.

import (
	"context"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/sbom"
)

// sbomIngester is the narrow slice of SBOMIngestService this handler uses.
// Narrow on purpose: the contract tests build the handler with a stub and no
// database, and a wide interface would make the stub declare methods these
// paths never call — which is how a stub stops resembling the thing it stands
// in for.
type sbomIngester interface {
	Ingest(ctx context.Context, tenantID, assetID, actorUserID uuid.UUID, filename string, r io.Reader) (*services.SBOMIngestResult, error)
	ListAssetSoftware(ctx context.Context, tenantID, assetID uuid.UUID, q, status, sortKey string, limit, offset int) ([]services.SoftwareInstallRow, int, error)
	ListProducts(ctx context.Context, tenantID uuid.UUID, q, sortKey string, limit, offset int) ([]services.SoftwareProductRow, int, error)
}

// SBOMHandler serves the upload endpoints and the software reads.
type SBOMHandler struct {
	ingest sbomIngester
}

func NewSBOMHandler(ingest sbomIngester) *SBOMHandler {
	return &SBOMHandler{ingest: ingest}
}

// maxSBOMUpload is the request-body ceiling, and it is deliberately
// sbom.MaxDocumentBytes and not a number of its own.
//
// The parser refuses a document over 32 MiB rather than truncating it. If the
// handler allowed more, a 40 MiB upload would be read fully into memory and
// then refused, which is the worst of both; if it allowed less, the parser's
// documented cap would be a lie the user hits a different error before
// reaching. One number, imported.
//
// A multipart request carries a little more than the document (the part
// headers, the boundary), so the ceiling is the cap plus a small envelope
// allowance rather than the cap exactly — otherwise a document of exactly the
// documented maximum would be refused by the transport.
const maxSBOMUpload = int64(sbom.MaxDocumentBytes) + (1 << 16)

// UploadAssetSBOM handles POST /infrastructure-assets/:id/sbom.
func (h *SBOMHandler) UploadAssetSBOM(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	assetID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid asset ID"})
		return
	}
	h.ingestInto(c, tenantID, assetID, userID)
}

// UploadSBOM handles POST /sbom — an upload with no target asset, which creates
// or matches one from the document's subject.
func (h *SBOMHandler) UploadSBOM(c *gin.Context) {
	tenantID, userID, ok := tenantAndUser(c)
	if !ok {
		return
	}
	h.ingestInto(c, tenantID, uuid.Nil, userID)
}

func (h *SBOMHandler) ingestInto(c *gin.Context, tenantID, assetID, userID uuid.UUID) {
	body, filename, ok := sbomBody(c)
	if !ok {
		return
	}
	defer func() { _ = body.Close() }()

	result, err := h.ingest.Ingest(c.Request.Context(), tenantID, assetID, userID, filename, body)
	if err != nil {
		writeSBOMError(c, err)
		return
	}
	// 201: the upload created rows. It answers 201 even when every product
	// already existed, because the ingest itself — the history entry, the
	// refreshed install set, the fact — is new every time.
	c.JSON(http.StatusCreated, result)
}

// sbomBody returns the document bytes from either shape of request.
//
// Both are accepted because both are what people have: a browser posts a file
// input as multipart, and `curl -X POST --data-binary @sbom.json -H
// 'Content-Type: application/json'` from a build pipeline posts the raw
// document. Refusing the second would mean the CI integration this feature
// exists for needs a multipart encoder to say one thing.
//
// The FORMAT is never taken from the filename or the Content-Type. sbom.Parse
// detects CycloneDX or SPDX from the document's own declaration, because both
// of those are supplied by whoever is uploading and neither is evidence.
func sbomBody(c *gin.Context) (io.ReadCloser, string, bool) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxSBOMUpload)

	mediaType, _, err := mime.ParseMediaType(c.GetHeader("Content-Type"))
	if err == nil && strings.HasPrefix(mediaType, "multipart/") {
		file, header, ferr := c.Request.FormFile("file")
		if ferr != nil {
			// An over-cap multipart upload fails HERE, not in the parser: the
			// MaxBytesReader above trips while FormFile is still reading the
			// envelope, so FormFile reports an error and the document never
			// reaches sbom.Parse. Answering the generic 400 would tell a user
			// whose form was perfectly well-formed that it had no `file` part,
			// and multipart is the BROWSER's shape — the upload page's own.
			//
			// The raw-body path does not need this: sbom.Parse reads at most
			// MaxDocumentBytes+1 itself and returns a LimitError, which is
			// below the transport ceiling, so the MaxBytesReader never trips
			// first. It is the multipart envelope that pushes past it.
			if isRequestBodyTooLarge(ferr) {
				writeSBOMTooLarge(c)
				return nil, "", false
			}
			c.JSON(http.StatusBadRequest, gin.H{
				"error":   "No document uploaded",
				"message": "expected a multipart form with a `file` part holding the CycloneDX or SPDX JSON",
			})
			return nil, "", false
		}
		name := ""
		if header != nil {
			name = header.Filename
		}
		return file, name, true
	}

	// A raw body. `filename` is a query parameter here rather than guessed,
	// because the only honest alternative is to have none.
	return c.Request.Body, c.Query("filename"), true
}

// writeSBOMError maps an ingest failure onto a status.
//
// Every refusal the parser can produce is reachable through errors.Is, which is
// what lets this map them without matching on message text. A LimitError
// carries the observed value and the cap, so its message is handed through
// verbatim: "43,000 components, limit 100,000" is something a user can act on
// and "too big" is not.
func writeSBOMError(c *gin.Context, err error) {
	var limitErr *sbom.LimitError
	switch {
	// FIRST, ahead of every parser branch. readCapped wraps whatever io.ReadAll
	// returns in ErrMalformed, so a MaxBytesReader ceiling reached DURING the
	// parse arrives here already looking like a malformed document — and the
	// ErrMalformed branch below would answer 400 "Could not read this document"
	// for a document that is merely too big. "The body exceeded the transport
	// ceiling" is the more specific fact and has to be tested for first.
	//
	// It does not fire today on the raw path, because the parser's own
	// MaxDocumentBytes+1 read stops below the transport ceiling. That is a
	// property of two constants, not of this mapping: narrow the envelope
	// allowance and the misleading 400 appears, which is how it was found.
	case isRequestBodyTooLarge(err):
		writeSBOMTooLarge(c)

	case errors.Is(err, services.ErrSBOMAssetNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})

	case errors.As(err, &limitErr):
		// 413 for bytes, 422 for components: one is a transport limit the
		// client could in principle chunk around, the other is a statement
		// about the content.
		status := http.StatusRequestEntityTooLarge
		if limitErr.Limit != "bytes" {
			status = http.StatusUnprocessableEntity
		}
		c.JSON(status, gin.H{"error": "Document too large", "message": err.Error()})

	case errors.Is(err, sbom.ErrUnsupportedEncoding),
		errors.Is(err, sbom.ErrUnsupportedSpecVersion),
		errors.Is(err, sbom.ErrUnknownFormat),
		errors.Is(err, sbom.ErrMalformed):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not read this document", "message": err.Error()})

	case errors.Is(err, services.ErrSBOMSubjectNotAnAsset):
		// 422: the document is well-formed and we read it. The answer is that
		// its subject is not something an asset can be created from, and the
		// message names the remedy.
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Cannot create an asset from this document", "message": err.Error()})

	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to ingest the document"})
	}
}

// isRequestBodyTooLarge reports whether err is the MaxBytesReader ceiling.
//
// The typed check is the real one — net/http returns *http.MaxBytesError — and
// the string check is kept beside it because the error travels through
// multipart and gin, either of which may wrap it in something that does not
// implement Unwrap. Matching on text alone is what this codebase keeps warning
// about; matching on text only as a FALLBACK to the typed test is the part that
// makes it safe.
func isRequestBodyTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return true
	}
	return err != nil && strings.Contains(err.Error(), "http: request body too large")
}

// writeSBOMTooLarge answers 413 with the cap named in the body.
//
// One place, because the ceiling is reachable from two — the parser's own
// LimitError on a raw body, and the transport's MaxBytesReader on a multipart
// envelope — and a user who hits either should read the same number.
func writeSBOMTooLarge(c *gin.Context) {
	c.JSON(http.StatusRequestEntityTooLarge, gin.H{
		"error":   "Document too large",
		"message": "the upload exceeds the " + strconv.Itoa(sbom.MaxDocumentBytes>>20) + " MiB limit",
	})
}

// GetAssetSoftware handles GET /infrastructure-assets/:id/software.
func (h *SBOMHandler) GetAssetSoftware(c *gin.Context) {
	tenantID, assetID, ok := tenantAndAsset(c)
	if !ok {
		return
	}
	limit, offset := softwarePaging(c)
	sortKey := c.Query("sort")
	rows, total, err := h.ingest.ListAssetSoftware(
		c.Request.Context(), tenantID, assetID, c.Query("q"), c.Query("status"), sortKey, limit, offset)
	if err != nil {
		if strings.HasPrefix(err.Error(), "unknown sort") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sort", "message": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve software"})
		return
	}
	// An empty array is a REAL answer and is not a 404 — an asset nobody has
	// enumerated software on has none recorded, which is different from the
	// asset not existing. `sw.package_count` is the fact that distinguishes
	// "none found" from "never looked"; this list does not pretend to.
	c.JSON(http.StatusOK, gin.H{"software": rows, "total": total, "limit": limit, "offset": offset})
}

// GetSoftwareProducts handles GET /software/products — the tenant catalogue.
func (h *SBOMHandler) GetSoftwareProducts(c *gin.Context) {
	tenantID, ok := tenantFromContext(c)
	if !ok {
		return
	}
	limit, offset := softwarePaging(c)
	rows, total, err := h.ingest.ListProducts(c.Request.Context(), tenantID, c.Query("q"), c.Query("sort"), limit, offset)
	if err != nil {
		if strings.HasPrefix(err.Error(), "unknown sort") {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sort", "message": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve software products"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"products": rows, "total": total, "limit": limit, "offset": offset})
}

// softwarePaging clamps limit and offset. A limit of 0 or a garbage value falls
// back to the default rather than returning everything: an asset with 40,000
// components would otherwise be one response.
func softwarePaging(c *gin.Context) (limit, offset int) {
	limit = 50
	if v, err := strconv.Atoi(c.Query("limit")); err == nil && v > 0 {
		limit = v
	}
	if limit > 500 {
		limit = 500
	}
	if v, err := strconv.Atoi(c.Query("offset")); err == nil && v > 0 {
		offset = v
	}
	return limit, offset
}
