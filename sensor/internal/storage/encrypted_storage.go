package storage

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
)

// EncryptedStorage handles encrypted storage of discovery data
type EncryptedStorage struct {
	config        *config.Config
	encryptionKey []byte
	aead          cipher.AEAD
	mu            sync.RWMutex
	currentFile   *os.File
	fileSize      int64
	discoveries   []*models.CryptoDiscovery
}

// NewEncryptedStorage creates a new encrypted storage instance
func NewEncryptedStorage(cfg *config.Config) (*EncryptedStorage, error) {
	// Generate or load encryption key.
	// The key is stored in KeyPath (not DataPath) so that discovery ciphertext
	// and the key are not co-located.
	key, err := getOrGenerateKey(cfg.Storage.EncryptionKey, cfg.Storage.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get encryption key: %v", err)
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// Create GCM mode
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Ensure data directory exists
	if err := os.MkdirAll(cfg.Storage.DataPath, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %v", err)
	}

	es := &EncryptedStorage{
		config:        cfg,
		encryptionKey: key,
		aead:          aead,
		discoveries:   make([]*models.CryptoDiscovery, 0),
	}

	// Open current file
	if err := es.openCurrentFile(); err != nil {
		return nil, fmt.Errorf("failed to open current file: %v", err)
	}

	return es, nil
}

// StoreDiscovery stores a discovery record
func (es *EncryptedStorage) StoreDiscovery(discovery *models.CryptoDiscovery) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	// Add to in-memory buffer
	es.discoveries = append(es.discoveries, discovery)

	// Check if we need to rotate file
	if es.fileSize >= es.config.Storage.RotationSize {
		if err := es.rotateFile(); err != nil {
			return fmt.Errorf("failed to rotate file: %v", err)
		}
	}

	// Write discovery to current file
	return es.writeDiscovery(discovery)
}

// StoreDiscoveries stores multiple discovery records
func (es *EncryptedStorage) StoreDiscoveries(discoveries []*models.CryptoDiscovery) error {
	es.mu.Lock()
	defer es.mu.Unlock()

	// Add to in-memory buffer
	es.discoveries = append(es.discoveries, discoveries...)

	// Check if we need to rotate file
	if es.fileSize >= es.config.Storage.RotationSize {
		if err := es.rotateFile(); err != nil {
			return fmt.Errorf("failed to rotate file: %v", err)
		}
	}

	// Write discoveries to current file
	for _, discovery := range discoveries {
		if err := es.writeDiscovery(discovery); err != nil {
			return fmt.Errorf("failed to write discovery: %v", err)
		}
	}

	return nil
}

// GetDiscoveries returns all stored discoveries
func (es *EncryptedStorage) GetDiscoveries() ([]*models.CryptoDiscovery, error) {
	es.mu.RLock()
	defer es.mu.RUnlock()

	// Return in-memory discoveries
	result := make([]*models.CryptoDiscovery, len(es.discoveries))
	copy(result, es.discoveries)

	return result, nil
}

// ExportDiscoveries exports discoveries for air-gapped transfer
func (es *EncryptedStorage) ExportDiscoveries() ([]byte, error) {
	es.mu.RLock()
	defer es.mu.RUnlock()

	// Create export structure
	export := struct {
		SensorID    string                    `json:"sensor_id"`
		Timestamp   time.Time                 `json:"timestamp"`
		Discoveries []*models.CryptoDiscovery `json:"discoveries"`
		Count       int                       `json:"count"`
	}{
		SensorID:    es.config.SensorID,
		Timestamp:   time.Now(),
		Discoveries: es.discoveries,
		Count:       len(es.discoveries),
	}

	// Marshal to JSON
	jsonData, err := json.Marshal(export)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal export: %v", err)
	}

	// Encrypt the data
	encryptedData, err := es.encryptData(jsonData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt export: %v", err)
	}

	return encryptedData, nil
}

// Cleanup removes old files based on retention policy
func (es *EncryptedStorage) Cleanup() error {
	es.mu.Lock()
	defer es.mu.Unlock()

	// Get list of files in data directory
	files, err := filepath.Glob(filepath.Join(es.config.Storage.DataPath, "discoveries_*.enc"))
	if err != nil {
		return fmt.Errorf("failed to list files: %v", err)
	}

	// Calculate cutoff time
	cutoffTime := time.Now().Add(-time.Duration(es.config.Storage.RetentionDays) * 24 * time.Hour)

	// Remove old files
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue
		}

		if info.ModTime().Before(cutoffTime) {
			if err := os.Remove(file); err != nil {
				fmt.Printf("Warning: Failed to remove old file %s: %v\n", file, err)
			}
		}
	}

	return nil
}

// Close closes the storage
func (es *EncryptedStorage) Close() error {
	es.mu.Lock()
	defer es.mu.Unlock()

	if es.currentFile != nil {
		return es.currentFile.Close()
	}

	return nil
}

// openCurrentFile opens the current discovery file
func (es *EncryptedStorage) openCurrentFile() error {
	filename := fmt.Sprintf("discoveries_%s.enc", time.Now().Format("20060102_150405"))
	filepath := filepath.Join(es.config.Storage.DataPath, filename)

	file, err := os.OpenFile(filepath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}

	es.currentFile = file
	es.fileSize = 0

	return nil
}

// rotateFile rotates to a new file
func (es *EncryptedStorage) rotateFile() error {
	// Close current file
	if es.currentFile != nil {
		es.currentFile.Close()
	}

	// Open new file
	return es.openCurrentFile()
}

// writeDiscovery writes a discovery to the current file
func (es *EncryptedStorage) writeDiscovery(discovery *models.CryptoDiscovery) error {
	// Check disk space before writing
	if err := checkDiskSpace(es.config.Storage.DataPath, es.config.Storage.MinFreeSpaceMB); err != nil {
		return fmt.Errorf("disk space check failed: %v", err)
	}

	jsonData, err := json.Marshal(discovery)
	if err != nil {
		return fmt.Errorf("failed to marshal discovery: %v", err)
	}

	// Optionally compress before encrypting
	dataToEncrypt := jsonData
	if es.config.Storage.EnableCompression {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(jsonData); err != nil {
			return fmt.Errorf("failed to compress discovery: %v", err)
		}
		if err := gz.Close(); err != nil {
			return fmt.Errorf("failed to finalize compression: %v", err)
		}
		// Prefix with 'Z' to indicate compressed
		dataToEncrypt = append([]byte{'Z'}, buf.Bytes()...)
	}

	encryptedData, err := es.encryptData(dataToEncrypt)
	if err != nil {
		return fmt.Errorf("failed to encrypt discovery: %v", err)
	}

	_, err = es.currentFile.Write(encryptedData)
	if err != nil {
		return fmt.Errorf("failed to write to file: %v", err)
	}
	_, err = es.currentFile.Write([]byte("\n"))
	if err != nil {
		return fmt.Errorf("failed to write separator: %v", err)
	}

	es.fileSize += int64(len(encryptedData) + 1)
	return nil
}

// IsFull returns true if the in-memory discovery buffer exceeds 5000 entries,
// signaling to callers that they should slow down discovery emission.
func (es *EncryptedStorage) IsFull() bool {
	es.mu.RLock()
	defer es.mu.RUnlock()
	return len(es.discoveries) > 5000
}

// encryptData encrypts data using AES-GCM
func (es *EncryptedStorage) encryptData(data []byte) ([]byte, error) {
	// Generate random nonce
	nonce := make([]byte, es.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt data
	ciphertext := es.aead.Seal(nonce, nonce, data, nil)

	return ciphertext, nil
}

// decryptData decrypts data using AES-GCM. If the plaintext was stored with
// compression (prefix 'Z' + gzip), it is decompressed before return.
func (es *EncryptedStorage) decryptData(encryptedData []byte) ([]byte, error) {
	// Extract nonce
	nonceSize := es.aead.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("encrypted data too short")
	}

	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	// Decrypt data
	plaintext, err := es.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	// Decompress if stored with compression marker (matches writeDiscovery)
	if len(plaintext) > 0 && plaintext[0] == 'Z' {
		gzr, err := gzip.NewReader(bytes.NewReader(plaintext[1:]))
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %v", err)
		}
		decompressed, err := io.ReadAll(gzr)
		gzr.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to decompress: %v", err)
		}
		return decompressed, nil
	}

	return plaintext, nil
}

// getOrGenerateKey resolves the AES-256 encryption key from (in priority order):
//  1. keyString from config — must be a 64-character hex string (32 bytes) or a
//     raw 16/24/32-byte ASCII string.  Hex is preferred; raw bytes are accepted
//     as a fallback so existing deployments are not broken.
//  2. A key file at keyDir/encryption.key (loaded from a previous run).
//  3. A freshly generated 32-byte random key, persisted to keyDir/encryption.key.
//
// keyDir is intentionally separate from the data directory so the ciphertext
// and the key are not co-located.
func getOrGenerateKey(keyString, keyDir string) ([]byte, error) {
	if keyString != "" {
		// Prefer hex-encoded key (64 hex chars = 32 bytes = AES-256)
		if decoded, err := hex.DecodeString(keyString); err == nil {
			if err := validateAESKeyLength(decoded); err != nil {
				return nil, fmt.Errorf("hex-decoded encryption key invalid: %w", err)
			}
			return decoded, nil
		}
		// Fall back to treating the string as raw bytes
		raw := []byte(keyString)
		if err := validateAESKeyLength(raw); err != nil {
			return nil, fmt.Errorf("encryption key invalid (provide a 64-char hex string for AES-256): %w", err)
		}
		return raw, nil
	}

	// Try to load existing key from key directory (separate from data directory)
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory %s: %v", keyDir, err)
	}
	keyPath := filepath.Join(keyDir, "encryption.key")
	if keyData, err := os.ReadFile(keyPath); err == nil {
		if err := validateAESKeyLength(keyData); err == nil {
			return keyData, nil
		}
		// Key file exists but is malformed — generate a new one
	}

	// Generate new 256-bit key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate encryption key: %v", err)
	}

	// Persist key with owner-only permissions
	if err := os.WriteFile(keyPath, key, 0600); err != nil {
		return nil, fmt.Errorf("failed to save encryption key to %s: %v", keyPath, err)
	}

	return key, nil
}

// validateAESKeyLength returns an error if key is not a valid AES key length
// (16 bytes = AES-128, 24 bytes = AES-192, 32 bytes = AES-256).
func validateAESKeyLength(key []byte) error {
	switch len(key) {
	case 16, 24, 32:
		return nil
	default:
		return fmt.Errorf("invalid AES key length %d (must be 16, 24, or 32 bytes)", len(key))
	}
}
