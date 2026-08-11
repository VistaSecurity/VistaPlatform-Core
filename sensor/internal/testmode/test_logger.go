package testmode

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TestLogger handles logging to rotating files in test mode
type TestLogger struct {
	filePath    string
	maxSize     int64
	currentSize int64
	mu          sync.Mutex
	file        *os.File
}

// LogEntry represents a log entry in test mode
type LogEntry struct {
	Timestamp  time.Time              `json:"timestamp"`
	Type       string                 `json:"type"`
	Message    string                 `json:"message"`
	Data       map[string]interface{} `json:"data,omitempty"`
	SensorID   string                 `json:"sensor_id,omitempty"`
	Interface  string                 `json:"interface,omitempty"`
	SourceIP   string                 `json:"source_ip,omitempty"`
	DestIP     string                 `json:"dest_ip,omitempty"`
	Port       int                    `json:"port,omitempty"`
	Protocol   string                 `json:"protocol,omitempty"`
	Confidence float64                `json:"confidence,omitempty"`
}

// NewTestLogger creates a new test logger with file rotation
func NewTestLogger(dataPath string) (*TestLogger, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}

	filePath := filepath.Join(dataPath, "test-discoveries.log")

	// Check if file exists and get its size
	var currentSize int64
	if info, err := os.Stat(filePath); err == nil {
		currentSize = info.Size()
	}

	return &TestLogger{
		filePath:    filePath,
		maxSize:     10 * 1024 * 1024, // 10MB
		currentSize: currentSize,
	}, nil
}

// LogDiscovery logs a discovery in test mode
func (tl *TestLogger) LogDiscovery(discovery interface{}) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Type:      "discovery",
		Message:   "Cryptographic implementation discovered",
		Data:      make(map[string]interface{}),
	}

	// Convert discovery to map for logging
	if discoveryMap, ok := discovery.(map[string]interface{}); ok {
		for k, v := range discoveryMap {
			entry.Data[k] = v
		}
	} else {
		// Try to marshal and unmarshal to get a map
		if data, err := json.Marshal(discovery); err == nil {
			json.Unmarshal(data, &entry.Data)
		}
	}

	return tl.writeEntry(entry)
}

// LogHeartbeat logs a heartbeat in test mode
func (tl *TestLogger) LogHeartbeat(heartbeat interface{}) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Type:      "heartbeat",
		Message:   "Sensor heartbeat",
		Data:      make(map[string]interface{}),
	}

	// Convert heartbeat to map for logging
	if heartbeatMap, ok := heartbeat.(map[string]interface{}); ok {
		for k, v := range heartbeatMap {
			entry.Data[k] = v
		}
	} else {
		// Try to marshal and unmarshal to get a map
		if data, err := json.Marshal(heartbeat); err == nil {
			json.Unmarshal(data, &entry.Data)
		}
	}

	return tl.writeEntry(entry)
}

// LogError logs an error in test mode
func (tl *TestLogger) LogError(err error, context string) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Type:      "error",
		Message:   fmt.Sprintf("Error in %s: %v", context, err),
		Data: map[string]interface{}{
			"error":   err.Error(),
			"context": context,
		},
	}

	return tl.writeEntry(entry)
}

// LogInfo logs general information in test mode
func (tl *TestLogger) LogInfo(message string, data map[string]interface{}) error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	entry := LogEntry{
		Timestamp: time.Now(),
		Type:      "info",
		Message:   message,
		Data:      data,
	}

	return tl.writeEntry(entry)
}

// writeEntry writes a log entry to the file with rotation
func (tl *TestLogger) writeEntry(entry LogEntry) error {
	// Check if we need to rotate the file
	if tl.currentSize >= tl.maxSize {
		if err := tl.rotateFile(); err != nil {
			return fmt.Errorf("failed to rotate log file: %v", err)
		}
	}

	// Open file if not already open
	if tl.file == nil {
		file, err := os.OpenFile(tl.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("failed to open log file: %v", err)
		}
		tl.file = file
	}

	// Marshal entry to JSON
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal log entry: %v", err)
	}

	// Write entry with newline
	line := string(data) + "\n"
	n, err := tl.file.WriteString(line)
	if err != nil {
		return fmt.Errorf("failed to write log entry: %v", err)
	}

	// Update current size
	tl.currentSize += int64(n)

	return nil
}

// rotateFile rotates the log file when it reaches max size
func (tl *TestLogger) rotateFile() error {
	// Close current file
	if tl.file != nil {
		tl.file.Close()
		tl.file = nil
	}

	// Create backup filename with timestamp
	backupPath := fmt.Sprintf("%s.%d", tl.filePath, time.Now().Unix())

	// Rename current file to backup
	if err := os.Rename(tl.filePath, backupPath); err != nil {
		return fmt.Errorf("failed to rename log file: %v", err)
	}

	// Reset current size
	tl.currentSize = 0

	// Clean up old backup files (keep only the 5 most recent)
	tl.cleanupOldBackups()

	return nil
}

// cleanupOldBackups removes old backup files, keeping only the 5 most recent
func (tl *TestLogger) cleanupOldBackups() {
	dir := filepath.Dir(tl.filePath)
	baseName := filepath.Base(tl.filePath)

	// Find all backup files
	files, err := filepath.Glob(filepath.Join(dir, baseName+".*"))
	if err != nil {
		return
	}

	// If we have more than 5 backup files, remove the oldest ones
	if len(files) > 5 {
		// Sort by modification time (oldest first)
		for i := 0; i < len(files)-5; i++ {
			os.Remove(files[i])
		}
	}
}

// Close closes the test logger
func (tl *TestLogger) Close() error {
	tl.mu.Lock()
	defer tl.mu.Unlock()

	if tl.file != nil {
		return tl.file.Close()
	}
	return nil
}

// GetLogPath returns the path to the current log file
func (tl *TestLogger) GetLogPath() string {
	return tl.filePath
}

// GetLogSize returns the current size of the log file
func (tl *TestLogger) GetLogSize() int64 {
	tl.mu.Lock()
	defer tl.mu.Unlock()
	return tl.currentSize
}
