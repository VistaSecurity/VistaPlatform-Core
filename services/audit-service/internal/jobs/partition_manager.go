package jobs

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"
)

// PartitionManager handles automatic partition creation for activity_logs.
//
// RLS: every method here is partition DDL / catalog maintenance (CREATE/DROP
// partition, pg_class + audit.partition_info introspection), not tenant row
// access. It carries no tenant context and runs as the schema owner, not the
// tenant-scoped app role — there is nothing to wrap in WithTenantTx (Phase 4).
type PartitionManager struct {
	db       *sql.DB
	interval time.Duration
	logger   *log.Logger
}

// NewPartitionManager creates a new partition manager
func NewPartitionManager(db *sql.DB) *PartitionManager {
	return &PartitionManager{
		db:       db,
		interval: 7 * 24 * time.Hour, // Run weekly
		logger:   log.New(log.Writer(), "[PartitionManager] ", log.LstdFlags),
	}
}

// Start begins the partition management process
func (pm *PartitionManager) Start(ctx context.Context) {
	pm.logger.Printf("Starting partition manager (interval: %v)", pm.interval)

	// Run immediately on start
	pm.ensurePartitions(ctx)

	ticker := time.NewTicker(pm.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			pm.logger.Println("Stopping partition manager")
			return
		case <-ticker.C:
			pm.ensurePartitions(ctx)
		}
	}
}

// ensurePartitions ensures future partitions exist
func (pm *PartitionManager) ensurePartitions(ctx context.Context) {
	pm.logger.Println("Checking for partition maintenance")

	// Check if partitioning is enabled (table exists with partitions)
	var isPartitioned bool
	err := pm.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM pg_class c
			JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname = 'audit'
			  AND c.relname = 'activity_logs'
			  AND c.relkind = 'p'
		)
	`).Scan(&isPartitioned)

	if err != nil {
		pm.logger.Printf("ERROR: Failed to check partition status: %v", err)
		return
	}

	if !isPartitioned {
		pm.logger.Println("Table is not partitioned, skipping partition management")
		return
	}

	// Create partitions for the next 3 months
	pm.createFuturePartitions(ctx, 3)
}

// createFuturePartitions creates partitions for future months
func (pm *PartitionManager) createFuturePartitions(ctx context.Context, monthsAhead int) {
	now := time.Now()

	for i := 0; i <= monthsAhead; i++ {
		targetDate := now.AddDate(0, i, 0)
		year := targetDate.Year()
		month := int(targetDate.Month())

		partitionName, err := pm.createPartition(ctx, year, month)
		if err != nil {
			pm.logger.Printf("ERROR: Failed to create partition for %d-%02d: %v", year, month, err)
			continue
		}

		if partitionName != "" {
			pm.logger.Printf("Created partition: %s", partitionName)
		}
	}
}

// createPartition creates a single monthly partition
func (pm *PartitionManager) createPartition(ctx context.Context, year, month int) (string, error) {
	var partitionName sql.NullString

	err := pm.db.QueryRowContext(ctx, `
		SELECT audit.create_activity_logs_partition($1, $2)
	`, year, month).Scan(&partitionName)

	if err != nil {
		return "", fmt.Errorf("failed to create partition: %w", err)
	}

	if partitionName.Valid {
		return partitionName.String, nil
	}

	return "", nil // Partition already exists
}

// GetPartitionInfo returns information about current partitions
func (pm *PartitionManager) GetPartitionInfo(ctx context.Context) ([]PartitionInfo, error) {
	rows, err := pm.db.QueryContext(ctx, `
		SELECT
			partition_name,
			partition_bounds,
			partition_size,
			COALESCE(row_count, 0) as row_count
		FROM audit.partition_info
		ORDER BY partition_name
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query partition info: %w", err)
	}
	defer rows.Close()

	var partitions []PartitionInfo
	for rows.Next() {
		var p PartitionInfo
		if err := rows.Scan(&p.Name, &p.Bounds, &p.Size, &p.RowCount); err != nil {
			return nil, fmt.Errorf("failed to scan partition info: %w", err)
		}
		partitions = append(partitions, p)
	}

	return partitions, rows.Err()
}

// PartitionInfo represents information about a partition
type PartitionInfo struct {
	Name     string `json:"name"`
	Bounds   string `json:"bounds"`
	Size     string `json:"size"`
	RowCount int64  `json:"row_count"`
}

// DropOldPartitions drops partitions older than the specified retention period
// This should be called after data has been archived to S3
func (pm *PartitionManager) DropOldPartitions(ctx context.Context, retentionDays int) ([]string, error) {
	cutoffDate := time.Now().AddDate(0, 0, -retentionDays)
	cutoffYear := cutoffDate.Year()
	cutoffMonth := int(cutoffDate.Month())

	pm.logger.Printf("Dropping partitions older than %d-%02d", cutoffYear, cutoffMonth)

	rows, err := pm.db.QueryContext(ctx, `
		SELECT c.relname
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'audit'
		  AND c.relname LIKE 'activity_logs_y%'
		  AND c.relname < $1
		ORDER BY c.relname
	`, fmt.Sprintf("activity_logs_y%dm%02d", cutoffYear, cutoffMonth))

	if err != nil {
		return nil, fmt.Errorf("failed to query old partitions: %w", err)
	}
	defer rows.Close()

	var droppedPartitions []string
	for rows.Next() {
		var partitionName string
		if err := rows.Scan(&partitionName); err != nil {
			return droppedPartitions, fmt.Errorf("failed to scan partition name: %w", err)
		}

		// Drop the partition
		_, err := pm.db.ExecContext(ctx, fmt.Sprintf("DROP TABLE IF EXISTS audit.%s", partitionName))
		if err != nil {
			pm.logger.Printf("ERROR: Failed to drop partition %s: %v", partitionName, err)
			continue
		}

		pm.logger.Printf("Dropped partition: %s", partitionName)
		droppedPartitions = append(droppedPartitions, partitionName)
	}

	return droppedPartitions, rows.Err()
}
