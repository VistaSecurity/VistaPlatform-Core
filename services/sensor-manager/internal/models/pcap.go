package models

import (
	"time"

	"github.com/google/uuid"
)

// PcapUploadJob represents a PCAP file upload and processing job
type PcapUploadJob struct {
	ID               uuid.UUID              `json:"id" db:"id"`
	TenantID         uuid.UUID              `json:"tenant_id" db:"tenant_id"`
	UploadedBy       uuid.UUID              `json:"uploaded_by" db:"uploaded_by"`
	OriginalFilename string                 `json:"original_filename" db:"original_filename"`
	FileSizeBytes    int64                  `json:"file_size_bytes" db:"file_size_bytes"`
	FilePath         *string                `json:"-" db:"file_path"`
	Status           string                 `json:"status" db:"status"`
	DiscoveryCount   int                    `json:"discovery_count" db:"discovery_count"`
	PacketCount      int64                  `json:"packet_count" db:"packet_count"`
	ProtocolsFound   map[string]int         `json:"protocols_found" db:"protocols_found"`
	CaptureTimeRange map[string]interface{} `json:"capture_time_range" db:"capture_time_range"`
	ErrorMessage     *string                `json:"error_message,omitempty" db:"error_message"`
	// TruncatedPacketCount counts packets the capture recorded shorter than
	// they were on the wire (its snapshot length cut them off). The upload page
	// warns when it is non-zero: a truncated packet's TLS handshake and
	// certificates cannot be read, so the job completes with less than the
	// capture appeared to hold.
	TruncatedPacketCount int64 `json:"truncated_packet_count" db:"truncated_packet_count"`
	// SnapshotLength is the most bytes the capture kept per packet; nil when
	// the job has not been processed or the file did not say.
	SnapshotLength      *int       `json:"snapshot_length,omitempty" db:"snapshot_length"`
	ProcessingStartedAt *time.Time `json:"processing_started_at,omitempty" db:"processing_started_at"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
	CompletedAt         *time.Time `json:"completed_at,omitempty" db:"completed_at"`
}

// PcapJobResultUpdate contains fields that the pcap-processor sends back
type PcapJobResultUpdate struct {
	Status               string                 `json:"status" binding:"required"`
	DiscoveryCount       *int                   `json:"discovery_count,omitempty"`
	PacketCount          *int64                 `json:"packet_count,omitempty"`
	ProtocolsFound       map[string]int         `json:"protocols_found,omitempty"`
	CaptureTimeRange     map[string]interface{} `json:"capture_time_range,omitempty"`
	ErrorMessage         *string                `json:"error_message,omitempty"`
	TruncatedPacketCount *int64                 `json:"truncated_packet_count,omitempty"`
	SnapshotLength       *int                   `json:"snapshot_length,omitempty"`
}
