//go:build windows

package storage

// checkDiskSpace is a no-op on Windows (syscall.Statfs not available).
func checkDiskSpace(path string, minFreeMB int64) error {
	return nil
}
