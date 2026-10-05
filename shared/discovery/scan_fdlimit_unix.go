//go:build unix

package discovery

import "syscall"

// processFDLimit reads the soft RLIMIT_NOFILE. Go raises the soft limit to
// the hard limit at start-up, so this is the limit the process actually has.
func processFDLimit() (uint64, bool) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		// Unreadable: assume the traditional default rather than "unlimited".
		return 1024, true
	}
	// The conversion is a no-op on Linux and macOS; Rlimit.Cur is int64 on
	// some BSDs.
	return uint64(rl.Cur), true
}
