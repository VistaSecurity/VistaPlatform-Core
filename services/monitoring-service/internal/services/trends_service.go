package services

import (
	"database/sql"
	"time"
)

// TrendPoint represents a single point in a historical trend
type TrendPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Value     *float64  `json:"value"`
	Status    string    `json:"status"`
}

// GetHistoricalTrends retrieves historical metrics for trend analysis
func (s *MetricsService) GetHistoricalTrends(serviceName, metricType string, windowDuration int, startTime, endTime time.Time) ([]TrendPoint, error) {
	// Determine which column to query
	var column string
	switch metricType {
	case "latency_p50":
		column = "latency_p50"
	case "latency_p95":
		column = "latency_p95"
	case "latency_p99":
		column = "latency_p99"
	case "error_rate":
		column = "error_rate"
	case "throughput":
		column = "throughput"
	default:
		column = "latency_p95" // Default
	}

	var query string
	var rows *sql.Rows
	var err error

	if serviceName != "" {
		query = `
			SELECT 
				window_start as timestamp,
				` + column + ` as value,
				status
			FROM platform_metrics_snapshots
			WHERE service_name = $1 
				AND window_duration = $2
				AND window_start >= $3 
				AND window_start <= $4
				AND ` + column + ` IS NOT NULL
			ORDER BY window_start ASC
		`
		rows, err = s.db.Query(query, serviceName, windowDuration, startTime, endTime)
	} else {
		// Aggregate across all services
		query = `
			SELECT 
				window_start as timestamp,
				AVG(` + column + `) as value,
				MIN(status) as status
			FROM platform_metrics_snapshots
			WHERE window_duration = $1
				AND window_start >= $2 
				AND window_start <= $3
				AND ` + column + ` IS NOT NULL
			GROUP BY window_start
			ORDER BY window_start ASC
		`
		rows, err = s.db.Query(query, windowDuration, startTime, endTime)
	}

	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var trends []TrendPoint
	for rows.Next() {
		var point TrendPoint
		var value sql.NullFloat64
		var status string

		err := rows.Scan(&point.Timestamp, &value, &status)
		if err != nil {
			continue
		}

		if value.Valid {
			point.Value = &value.Float64
		}
		point.Status = status

		trends = append(trends, point)
	}

	return trends, nil
}
