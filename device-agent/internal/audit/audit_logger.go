package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditEvent represents a single auditable action
type AuditEvent struct {
	Timestamp  time.Time              `json:"timestamp"`
	EventType  string                 `json:"event_type"`
	DeviceID   string                 `json:"device_id,omitempty"`
	DeviceAddr string                 `json:"device_addr,omitempty"`
	Action     string                 `json:"action"`
	Result     string                 `json:"result"` // "success", "failure", "error"
	Details    map[string]interface{} `json:"details,omitempty"`
	ErrorMsg   string                 `json:"error,omitempty"`
}

// AuditLogger writes audit events to a local log file
type AuditLogger struct {
	mu       sync.Mutex
	file     *os.File
	filePath string
}

// NewAuditLogger creates a new AuditLogger writing to dataDir/audit.log
func NewAuditLogger(dataDir string) (*AuditLogger, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create audit log directory: %w", err)
	}
	path := filepath.Join(dataDir, "device-agent-audit.log")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	return &AuditLogger{file: f, filePath: path}, nil
}

// Log records an audit event
func (al *AuditLogger) Log(event AuditEvent) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}
	data, err := json.Marshal(event)
	if err != nil {
		return
	}
	al.mu.Lock()
	defer al.mu.Unlock()
	al.file.Write(data)
	al.file.Write([]byte("\n"))
	al.file.Sync() // fsync so audit events survive a process crash
}

// LogInterrogation is a convenience method for device interrogation events
func (al *AuditLogger) LogInterrogation(deviceID, deviceAddr, protocol, result string, details map[string]interface{}, err error) {
	event := AuditEvent{
		Timestamp:  time.Now(),
		EventType:  "interrogation",
		DeviceID:   deviceID,
		DeviceAddr: deviceAddr,
		Action:     "interrogate_" + protocol,
		Result:     result,
		Details:    details,
	}
	if err != nil {
		event.ErrorMsg = err.Error()
	}
	al.Log(event)
}

// Close flushes and closes the audit log
func (al *AuditLogger) Close() error {
	al.mu.Lock()
	defer al.mu.Unlock()
	return al.file.Close()
}

// GetPath returns the audit log file path
func (al *AuditLogger) GetPath() string {
	return al.filePath
}
