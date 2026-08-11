---
render_macros: false
---

# Compliance Engine Event Processing Alerts

This document describes the alert thresholds and monitoring configuration for the compliance-engine event processing system.

## Overview

The compliance-engine processes events from the NATS event bus to generate and update compliance findings in real-time. Monitoring these metrics is critical for ensuring the system is operating correctly and findings are being generated as expected.

## Metrics Endpoint

The compliance-engine exposes metrics at:
- `GET /metrics` - Full metrics snapshot
- `GET /metrics/health` - Quick health check based on metrics

**Note:** These endpoints do not require authentication and are intended for monitoring-service scraping.

## Key Metrics

### Event Processing Metrics

- **events_processed**: Total number of events processed
- **events_processed_success**: Number of successfully processed events
- **events_processed_error**: Number of failed event processing attempts
- **events_processed_by_type**: Breakdown by event type (asset.changed, asset.deleted, certificate.changed, bulk.asset.changed)
- **processing_latency_avg_ms**: Average processing latency in milliseconds
- **processing_latency_max_ms**: Maximum processing latency in milliseconds
- **error_rate_percent**: Error rate as a percentage (0-100)

### Finding Metrics

- **findings_upserted**: Total number of findings created or updated
- **findings_created**: Number of new findings created
- **findings_updated**: Number of existing findings updated
- **findings_marked_inactive**: Number of findings marked as inactive
- **resurfaced_findings**: Number of findings that resurfaced (INACTIVE → ACTIVE)
- **state_transitions**: Map of state transitions (e.g., "ACTIVE->INACTIVE", "INACTIVE->ACTIVE")

### NATS Connection Metrics

- **nats_connection_status**: Current connection status ("connected", "disconnected", "reconnecting")
- **nats_reconnect_count**: Number of times NATS connection was re-established

### Error Metrics

- **processing_errors**: Total number of processing errors
- **error_by_type**: Breakdown of errors by type (timeout, connection, database, nats, not_found, other)

## Recommended Alert Thresholds

Configure these alert thresholds in the monitoring-service using the alerting API:

### 1. High Event Processing Latency

**Metric:** `processing_latency_avg_ms`  
**Threshold:** > 5000 ms (5 seconds)  
**Severity:** Warning  
**Description:** Average event processing latency exceeds 5 seconds, indicating potential performance issues.

**Configuration:**
```json
{
  "service_name": "compliance-engine",
  "metric_type": "response_time",
  "metric_name": "processing_latency_avg_ms",
  "warning_threshold": 5000,
  "critical_threshold": 10000,
  "enabled": true
}
```

### 2. High Error Rate

**Metric:** `error_rate_percent`  
**Threshold:** > 1%  
**Severity:** Critical  
**Description:** More than 1% of events are failing to process, indicating a systemic issue.

**Configuration:**
```json
{
  "service_name": "compliance-engine",
  "metric_type": "error_rate",
  "metric_name": "error_rate_percent",
  "warning_threshold": 0.5,
  "critical_threshold": 1.0,
  "enabled": true
}
```

### 3. NATS Connection Failure

**Metric:** `nats_connection_status`  
**Threshold:** != "connected"  
**Severity:** Critical  
**Description:** NATS connection is not healthy, events cannot be processed.

**Configuration:**
This requires a custom alert check that queries the metrics endpoint and checks the `nats_connection_status` field.

### 4. No Events Processed Recently

**Metric:** `last_event_processed_at`  
**Threshold:** > 10 minutes (if events_processed > 0)  
**Severity:** Warning  
**Description:** No events have been processed in the last 10 minutes, but the service has processed events before. This may indicate events are not being published or the subscriber is not receiving them.

**Configuration:**
This requires a custom alert check that compares `last_event_processed_at` timestamp with current time.

### 5. High Finding Generation Errors

**Metric:** `error_by_type` (database errors)  
**Threshold:** > 5 errors in last 5 minutes  
**Severity:** Warning  
**Description:** Database errors are occurring during finding generation, indicating potential database connectivity or query issues.

**Configuration:**
This requires monitoring the `error_by_type` map and tracking database errors over time.

## Alert Configuration via API

Use the monitoring-service alerting API to configure these thresholds:

```bash
# Create alert threshold
curl -X POST http://localhost:8080/api/v1/monitoring-service/alerting/thresholds \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "compliance-engine",
    "metric_type": "response_time",
    "metric_name": "processing_latency_avg_ms",
    "warning_threshold": 5000,
    "critical_threshold": 10000,
    "enabled": true
  }'
```

## Monitoring Dashboard

The metrics endpoint provides all necessary data for building monitoring dashboards. Key visualizations to include:

1. **Event Processing Rate**: Line chart showing events processed per minute
2. **Error Rate Trend**: Line chart showing error rate over time
3. **Latency Distribution**: Histogram of processing latencies
4. **Finding Generation Rate**: Bar chart showing findings created/updated per hour
5. **State Transitions**: Pie chart showing distribution of state transitions
6. **NATS Connection Status**: Status indicator with connection history

## Troubleshooting

### High Latency

- Check database query performance
- Review control evaluation logic
- Verify NATS message queue depth
- Check for resource constraints (CPU, memory)

### High Error Rate

- Review error logs for specific error types
- Check database connectivity
- Verify NATS connection stability
- Review event payload format

### NATS Connection Issues

- Verify NATS service is running
- Check network connectivity
- Review NATS authentication credentials
- Check for NATS server logs

### No Events Processed

- Verify inventory-service is publishing events
- Check NATS subscription status
- Review event subscriber logs
- Verify event topics are correct

## Integration with Monitoring Service

The monitoring-service should scrape metrics from the compliance-engine `/metrics` endpoint periodically (recommended: every 30 seconds). The metrics are stored in InfluxDB and can be queried for alerting and dashboards.

**Scraping Configuration:**
```yaml
services:
  compliance-engine:
    metrics_endpoint: "http://compliance-engine:8080/metrics"
    scrape_interval: 30s
    timeout: 5s
```

## Best Practices

1. **Monitor Continuously**: Set up continuous monitoring, not just alerting
2. **Trend Analysis**: Track metrics over time to identify patterns
3. **Baseline Establishment**: Establish baseline metrics during normal operation
4. **Alert Fatigue Prevention**: Use appropriate thresholds to avoid false positives
5. **Automated Response**: Consider automated remediation for common issues (e.g., NATS reconnection)

## Future Enhancements

- Dead letter queue for failed events
- Event replay capability
- More granular error categorization
- Performance profiling integration
- Real-time metrics streaming
