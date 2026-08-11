package main

import (
	"strings"
	"sync"
)

// logRingBuffer keeps the most recent log lines in memory so the export_logs
// command can return them to the platform console. It implements io.Writer so
// it can be tee'd onto the standard logger's output alongside stderr.
type logRingBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
}

func newLogRingBuffer(max int) *logRingBuffer {
	return &logRingBuffer{max: max}
}

// Write appends each log line, evicting the oldest beyond the cap.
func (b *logRingBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		if line == "" {
			continue
		}
		b.lines = append(b.lines, line)
	}
	if len(b.lines) > b.max {
		b.lines = b.lines[len(b.lines)-b.max:]
	}
	return len(p), nil
}

// tail returns the last n lines (all of them if n <= 0 or exceeds the buffer).
func (b *logRingBuffer) tail(n int) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if n <= 0 || n > len(b.lines) {
		n = len(b.lines)
	}
	out := make([]string, n)
	copy(out, b.lines[len(b.lines)-n:])
	return out
}

// logRing is the process-wide recent-log buffer wired into the standard logger
// in main().
var logRing = newLogRingBuffer(1000)
