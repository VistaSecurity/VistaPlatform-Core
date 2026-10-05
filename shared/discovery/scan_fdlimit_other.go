//go:build !unix

package discovery

// processFDLimit: no per-process descriptor rlimit on this platform (Windows
// sockets are bounded by memory and the ephemeral port range instead), so the
// connection gate uses a fixed budget.
func processFDLimit() (uint64, bool) { return 0, false }
