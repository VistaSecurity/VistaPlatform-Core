package atomicfile

import (
	"sync"
	"time"
)

// Retry runs fn up to attempts times, sleeping delay (doubling) between
// failures, and returns nil on the first success or the last error. It is for
// persisting credentials the platform has already committed to: a transient
// failure (a brief disk-full, an antivirus lock on Windows) should not turn
// into a lockout.
func Retry(attempts int, delay time.Duration, fn func() error) error {
	var err error
	for i := 0; i < attempts; i++ {
		if err = fn(); err == nil {
			return nil
		}
		if i < attempts-1 && delay > 0 {
			time.Sleep(delay)
			delay *= 2
		}
	}
	return err
}

// Pending records that rotated credentials are held in memory only because
// persisting them failed. The owner re-checks it on every heartbeat so the
// condition is reported loudly and repeatedly, and retried, until it clears.
type Pending struct {
	mu  sync.Mutex
	err error
}

// Set marks the credentials as unpersisted with the failure that caused it.
func (p *Pending) Set(err error) {
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
}

// Clear marks the credentials as safely on disk.
func (p *Pending) Clear() {
	p.mu.Lock()
	p.err = nil
	p.mu.Unlock()
}

// Err returns the failure, or nil when nothing is pending.
func (p *Pending) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}
