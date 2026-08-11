package cbom

import (
	"context"
	"fmt"
	"io"

	"github.com/google/uuid"
	sharedstorage "github.com/vistasecurity/vistaplatform/shared/storage"
)

// cbomStorageReadCapFallback bounds an object-stored CBOM read when no explicit
// per-artifact-type max is configured, so a malformed/oversized object can't
// OOM the pod. 256 MB matches the documented CBOM default.
const cbomStorageReadCapFallback = 256 * 1024 * 1024

// ReadStoredBytes streams an object-stored CBOM artifact's canonical bytes into
// memory, capped at the configured CBOM max file size (falling back to 256 MB).
// Used by the download (SPDX/PDF), verify, and diff paths for S3-backed
// artifacts, where the bytes are needed server-side rather than as a URL.
func ReadStoredBytes(ctx context.Context, store sharedstorage.ArtifactStorageService, key string, tenantID *uuid.UUID) ([]byte, error) {
	if store == nil {
		return nil, fmt.Errorf("storage not configured")
	}
	maxBytes := int64(cbomStorageReadCapFallback)
	if cfg, err := store.GetArtifactConfig(sharedstorage.ArtifactTypeCBOM); err == nil && cfg != nil && cfg.MaxFileSizeMB > 0 {
		maxBytes = cfg.GetMaxFileSize()
	}
	rc, err := store.Stream(ctx, sharedstorage.ArtifactTypeCBOM, key, tenantID)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rc.Close() }()
	// Read one byte past the cap so we can detect (and reject) overflow.
	data, err := io.ReadAll(io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read stored artifact: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("stored CBOM artifact exceeds max size of %d bytes", maxBytes)
	}
	return data, nil
}
