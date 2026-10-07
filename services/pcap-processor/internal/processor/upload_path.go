package processor

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

// errPathOutsideUploadRoot is returned for a job whose file path is not inside
// the tenant's own upload directory.
var errPathOutsideUploadRoot = errors.New("capture path is outside the tenant's upload directory")

// resolveUploadPath confines the file path a NATS job names to
// <uploadRoot>/<tenantID>/, the directory sensor-manager writes that tenant's
// uploads into, and returns the path the processor must open and delete.
//
// pcap-processor opens and then REMOVES whatever path the message carries. The
// message is trusted input from the platform's own publisher, but a consumer
// that deletes an arbitrary path on a forged or corrupted message is one NATS
// credential away from deleting any file the pod can write, or from reading
// another tenant's capture into this tenant's inventory. So the path is judged
// here, before anything is opened:
//
//   - it must be absolute (the publisher always writes an absolute path);
//   - after filepath.Clean (which resolves any ".." segments) it must still lie
//     under the upload root's <tenantID> directory, so neither "../../etc/passwd"
//     nor another tenant's directory nor the root itself passes;
//   - where the file exists, symlinks are resolved and the RESOLVED location
//     must lie under the (resolved) tenant directory too, and must be a regular
//     file, so a symlink planted in the directory cannot lead out of it and a
//     device or FIFO is never opened;
//   - the caller then opens and removes the returned, resolved path rather than
//     the original string, so a symlink swapped in after the check does not
//     redirect the operation.
//
// A path that does not exist yet passes the lexical check and fails later when
// it is opened, which keeps the existing "unopenable capture" handling.
func resolveUploadPath(uploadRoot string, tenantID uuid.UUID, raw string) (string, error) {
	if strings.TrimSpace(uploadRoot) == "" {
		return "", errors.New("pcap upload root is not configured")
	}
	if raw == "" || strings.ContainsRune(raw, 0) {
		return "", fmt.Errorf("%w: empty or malformed path", errPathOutsideUploadRoot)
	}
	if !filepath.IsAbs(raw) {
		return "", fmt.Errorf("%w: path is not absolute", errPathOutsideUploadRoot)
	}
	rootAbs, err := filepath.Abs(uploadRoot)
	if err != nil {
		return "", fmt.Errorf("resolve upload root: %w", err)
	}
	tenantDir := filepath.Join(rootAbs, tenantID.String())
	cleaned := filepath.Clean(raw)
	if !isStrictlyInside(tenantDir, cleaned) {
		return "", errPathOutsideUploadRoot
	}

	resolved, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cleaned, nil
		}
		return "", fmt.Errorf("resolve capture path: %w", err)
	}
	resolvedTenantDir, err := filepath.EvalSymlinks(tenantDir)
	if err != nil {
		// The file resolved but its tenant directory did not: nothing sane.
		return "", fmt.Errorf("resolve tenant upload directory: %w", err)
	}
	if !isStrictlyInside(resolvedTenantDir, resolved) {
		return "", errPathOutsideUploadRoot
	}
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat capture: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%w: not a regular file", errPathOutsideUploadRoot)
	}
	return resolved, nil
}

// isStrictlyInside reports whether path lies below dir, and is not dir
// itself (which is not a capture file).
func isStrictlyInside(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
