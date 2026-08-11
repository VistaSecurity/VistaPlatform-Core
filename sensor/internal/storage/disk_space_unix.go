//go:build !windows

package storage

import (
	"fmt"
	"syscall"
)

// checkDiskSpace returns an error if available disk space at path is below minFreeMB.
// On failure to stat, it fails open (allows the write).
func checkDiskSpace(path string, minFreeMB int64) error {
	if minFreeMB <= 0 {
		return nil
	}
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return nil // fail open
	}
	available := int64(stat.Bavail) * int64(stat.Bsize)
	required := minFreeMB * 1024 * 1024
	if available < required {
		return fmt.Errorf("insufficient disk space: %d MB available, need %d MB free", available/(1024*1024), minFreeMB)
	}
	return nil
}
