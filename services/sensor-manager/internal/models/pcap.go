package models

import (
	"time"

	"github.com/google/uuid"
)

// PcapUploadJob represents a PCAP file upload and processing job
type PcapUploadJob struct {
	ID                  uuid.UUID              `json:"id" db:"id"`
	TenantID            uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	UploadedBy          uuid.UUID              `json:"uploaded_by" db:"uploaded_by"`
	OriginalFilename    string                 `json:"original_filename" db:"original_filename"`
	FileSizeBytes       int64                  `json:"file_size_bytes" db:"file_size_bytes"`
	FilePath            *string                `json:"-" db:"file_path"`
	Status              string                 `json:"status" db:"status"`
	DiscoveryCount      int                    `json:"discovery_count" db:"discovery_count"`
	PacketCount         int64                  `json:"packet_count" db:"packet_count"`
	ProtocolsFound      map[string]int         `json:"protocols_found" db:"protocols_found"`
	CaptureTimeRange    map[string]interface{} `json:"capture_time_range" db:"capture_time_range"`
	ErrorMessage        *string                `json:"error_message,omitempty" db:"error_message"`
	ProcessingStartedAt *time.Time             `json:"processing_started_at,omitempty" db:"processing_started_at"`
	CreatedAt           time.Time              `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at" db:"updated_at"`
	CompletedAt         *time.Time             `json:"completed_at,omitempty" db:"completed_at"`
}

// PcapJobResultUpdate contains fields that the pcap-processor sends back
type PcapJobResultUpdate struct {
	Status           string                 `json:"status" binding:"required"`
	DiscoveryCount   *int                   `json:"discovery_count,omitempty"`
	PacketCount      *int64                 `json:"packet_count,omitempty"`
	ProtocolsFound   map[string]int         `json:"protocols_found,omitempty"`
	CaptureTimeRange map[string]interface{} `json:"capture_time_range,omitempty"`
	ErrorMessage     *string                `json:"error_message,omitempty"`
}
