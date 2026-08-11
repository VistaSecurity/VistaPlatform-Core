package models

import "github.com/google/uuid"

// BulkRowStatus is the outcome of importing a single spreadsheet row.
type BulkRowStatus string

const (
	BulkRowCreated          BulkRowStatus = "created"
	BulkRowSkippedDuplicate BulkRowStatus = "skipped_duplicate"
	BulkRowError            BulkRowStatus = "error"
)

// BulkRowResult is the per-row outcome of a bulk import. Index is the 0-based
// position of the row in the submitted batch, so the UI can line each result
// up against the row the user uploaded.
type BulkRowResult struct {
	Index  int           `json:"index"`
	Status BulkRowStatus `json:"status"`
	ID     *uuid.UUID    `json:"id,omitempty"`
	Reason string        `json:"reason,omitempty"`
}

// BulkImportResult is the aggregate response for a bulk import. Partial success
// is the norm: one bad row never rolls back the rest of the batch.
type BulkImportResult struct {
	Created int             `json:"created"`
	Skipped int             `json:"skipped"`
	Failed  int             `json:"failed"`
	Results []BulkRowResult `json:"results"`
}

// NewBulkImportResult returns a result sized for the given batch length.
func NewBulkImportResult(n int) *BulkImportResult {
	return &BulkImportResult{Results: make([]BulkRowResult, 0, n)}
}

// Add records one row's outcome and bumps the matching aggregate counter.
func (r *BulkImportResult) Add(index int, status BulkRowStatus, id *uuid.UUID, reason string) {
	r.Results = append(r.Results, BulkRowResult{Index: index, Status: status, ID: id, Reason: reason})
	switch status {
	case BulkRowCreated:
		r.Created++
	case BulkRowSkippedDuplicate:
		r.Skipped++
	case BulkRowError:
		r.Failed++
	}
}

// AssetBulkImportRequest is the body for POST .../infrastructure-assets/bulk.
type AssetBulkImportRequest struct {
	Rows []AssetInput `json:"rows" binding:"required"`
}

// NetworkSegmentBulkImportRequest is the body for POST .../network-segments/bulk.
type NetworkSegmentBulkImportRequest struct {
	Rows []NetworkSegmentInput `json:"rows" binding:"required"`
}
