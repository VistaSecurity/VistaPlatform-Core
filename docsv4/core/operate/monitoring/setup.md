---
render_macros: false
---

# System Monitoring & Alerting Guide
## Comprehensive Platform Monitoring and Alert Management

**Last Updated**: 2026-04-18  
**Version**: 1.0  
**Audience**: Platform Administrators

---

## 📋 Overview

Vista Platform includes comprehensive system monitoring and alerting capabilities that provide real-time visibility into platform health, performance metrics, and automated alert notifications. This guide covers all monitoring features, alert configuration, and notification setup.

---

## 🎯 Key Features

### Real-Time Monitoring
- **Service Health Dashboard**: Live status of all platform services
- **Historical Trends**: Performance metrics over time (latency, error rates, throughput)
- **Alert History**: Timeline of triggered alerts and their resolution

### Configurable Alerting
- **Custom Thresholds**: Set warning and critical thresholds for any metric
- **Multi-Metric Support**: Monitor latency (P50, P95, P99), error rates, throughput, CPU, memory
- **Service-Specific**: Configure alerts for specific services or platform-wide

### Multi-Channel Notifications
- **Slack Integration**: Receive alerts in Slack channels
- **Webhook Notifications**: Custom webhook endpoints for any integration
- **PagerDuty Integration**: Critical alert escalation
- **Email Notifications**: Email alerts (production integration ready)
- **In-App Notifications**: Dashboard alerts

---

## 📊 Monitoring Dashboard

### Accessing the System Health pages

Navigate to **System Health** in the admin console's left rail to access the
platform monitoring dashboard — its three sub-pages are **Services** (backend
status and latency), **Gateway** (API gateway routing health), and **Alerts**
(alert history and thresholds). See the [Platform Admin Guide → System Health](../platform-admin-guide.md#system-health)
for the current tour of those pages.

### Dashboard Sections

#### 1. Services

The default sub-page. An overall-status banner ("All systems operational" or a
count of services needing attention), four stat tiles pulled from the
monitoring-service's aggregate metrics (**Healthy**, **Degraded**, **Down**,
**Avg latency**), and a table of every reporting service with its status,
message, and response time. There is no per-service uptime percentage and no
Core/Platform/Infra grouping — the underlying API doesn't return that shape.

#### 2. Gateway

A read-only view of the API gateway's routers and services, proxied from
Traefik's own API. Shows router/service counts and per-router/per-service
status. There is no historical chart on this page.

#### 3. Alerts

Alert history (triggered alerts and their status) and the configured alert
thresholds, both read-only in the console today — creating or editing a
threshold is done via the API (below), not a form on this page. The page also
surfaces platform-track stateful alerts (e.g. `service_down`,
`tenant_health_degraded`) and active maintenance windows, since notification
delivery is suppressed during a window.

---

## 🚨 Alert Configuration

### Default Alert Thresholds

The system comes with pre-configured alert thresholds:

1. **High Response Time**
   - Warning: 500ms
   - Critical: 1000ms
   - Severity: High

2. **High Error Rate**
   - Warning: 1%
   - Critical: 5%
   - Severity: Critical

3. **Low Uptime**
   - Warning: 99%
   - Critical: 95%
   - Severity: Critical

4. **High CPU Usage**
   - Warning: 80%
   - Critical: 90%
   - Severity: Medium

5. **High Memory Usage**
   - Warning: 85%
   - Critical: 95%
   - Severity: Medium

### Creating Custom Alert Thresholds

Alert thresholds can be configured via the API or directly in the database.

#### API Endpoints

**Create Alert Threshold**
```bash
POST /api/v1/monitoring-service/alerting/thresholds
Content-Type: application/json

{
  "threshold_name": "high_api_latency",
  "metric_type": "response_time",
  "service_name": "api-gateway",  # Optional: null for platform-wide
  "warning_threshold": 200.0,
  "critical_threshold": 500.0,
  "severity": "high",
  "enabled": true,
  "notify_email": false,
  "notify_slack": true,
  "notify_webhook": false,
  "notify_in_app": true,
  "comparison_operator": "gt",  # gt, gte, lt, lte, eq
  "duration_minutes": 5,  # Alert must exceed threshold for this duration
  "description": "Alert when API gateway latency exceeds thresholds"
}
```

**Update Alert Threshold**
```bash
PUT /api/v1/monitoring-service/alerting/thresholds/{id}
Content-Type: application/json

{
  "warning_threshold": 250.0,
  "critical_threshold": 600.0,
  "enabled": true
}
```

**List Alert Thresholds**
```bash
GET /api/v1/monitoring-service/alerting/thresholds?enabled=true&service_name=api-gateway
```

**Delete Alert Threshold**
```bash
DELETE /api/v1/monitoring-service/alerting/thresholds/{id}
```

#### Threshold Configuration Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `threshold_name` | string | Yes | Unique name for the threshold |
| `metric_type` | string | Yes | One of: `response_time`, `error_rate`, `cpu_usage`, `memory_usage`, `uptime`, `throughput` |
| `service_name` | string | Optional | Service name (null = platform-wide) |
| `warning_threshold` | float | Optional | Warning level threshold |
| `critical_threshold` | float | Optional | Critical level threshold |
| `severity` | string | Yes | `low`, `medium`, `high`, `critical` |
| `enabled` | boolean | Yes | Whether threshold is active |
| `notify_email` | boolean | Yes | Enable email notifications |
| `notify_slack` | boolean | Yes | Enable Slack notifications |
| `notify_webhook` | boolean | Yes | Enable webhook notifications |
| `notify_in_app` | boolean | Yes | Enable in-app notifications |
| `comparison_operator` | string | Yes | `gt`, `gte`, `lt`, `lte`, `eq` |
| `duration_minutes` | integer | Yes | Duration threshold must be exceeded (prevents spam) |
| `description` | string | Optional | Human-readable description |

### Alert Evaluation

The `AlertEvaluator` background job runs every 5 minutes to:
1. Check all enabled alert thresholds
2. Compare current metrics against thresholds
3. Trigger alerts if thresholds are exceeded
4. Send notifications via configured channels
5. Record alert history

**Alert Suppression**: Alerts are suppressed if triggered within the `duration_minutes` window to prevent alert spam.

---

## 📈 Historical Trend Analysis

### Accessing Historical Trends

Historical trends are available via API and displayed in the dashboard charts.

#### API Endpoint

```bash
GET /api/v1/monitoring-service/trends?metric_type=latency_p95&window=1h&service_name=api-gateway&start=2026-04-18T00:00:00Z&end=2026-04-18T23:59:59Z
```

**Query Parameters**:
- `metric_type`: One of `latency_p50`, `latency_p95`, `latency_p99`, `error_rate`, `throughput`
- `window`: Aggregation window - `1m`, `1h`, or `1d`
- `service_name`: Optional - filter by specific service
- `start`: ISO 8601 timestamp (default: 24 hours ago)
- `end`: ISO 8601 timestamp (default: now)

#### Response Format

```json
{
  "service_name": "api-gateway",
  "metric_type": "latency_p95",
  "window": "1h",
  "start_time": "2026-04-18T00:00:00Z",
  "end_time": "2026-04-18T23:59:59Z",
  "trends": [
    {
      "timestamp": "2026-04-18T00:00:00Z",
      "value": 245.5,
      "status": "healthy"
    },
    {
      "timestamp": "2026-04-18T01:00:00Z",
      "value": 312.8,
      "status": "healthy"
    }
  ],
  "count": 24
}
```

### Trend Analysis Use Cases

1. **Performance Degradation Detection**: Identify gradual increases in latency
2. **Error Rate Spikes**: Track error rates over time to identify patterns
3. **Capacity Planning**: Analyze throughput trends for resource planning
4. **Post-Incident Analysis**: Review historical metrics around incidents

---

## 🔔 Notification Setup

> **Note**: The platform now uses a unified notification service. For comprehensive notification setup, see [Notification Provider Integration Guide](../operations/notification-providers.md).

### Legacy Notification Channels

The following sections document the legacy notification system. For new deployments, use the unified notification service instead.

### Slack Integration

1. **Create Slack Webhook**:
   - Go to your Slack workspace settings
   - Navigate to Apps → Incoming Webhooks
   - Create a new webhook for your channel
   - Copy the webhook URL

2. **Create Notification Channel** (via database):
   ```sql
   INSERT INTO monitoring_notification_channels (
     channel_name,
     channel_type,
     config,
     enabled
   ) VALUES (
     'Production Alerts',
     'slack',
     '{"webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"}'::jsonb,
     true
   );
   ```

3. **Enable Slack Notifications**:
   - Set `notify_slack: true` in your alert thresholds
   - Alerts will be sent as formatted Slack messages with severity colors

### Webhook Integration

1. **Create Notification Channel**:
   ```sql
   INSERT INTO monitoring_notification_channels (
     channel_name,
     channel_type,
     config,
     enabled
   ) VALUES (
     'Custom Webhook',
     'webhook',
     '{
       "url": "https://your-webhook-endpoint.com/alerts",
       "headers": {
         "Authorization": "Bearer YOUR_TOKEN",
         "X-Custom-Header": "value"
       }
     }'::jsonb,
     true
   );
   ```

2. **Webhook Payload Format**:
   ```json
   {
     "alert": {
       "threshold_name": "high_response_time",
       "service_name": "api-gateway",
       "metric_type": "response_time",
       "severity": "critical",
       "threshold": 500.0,
       "actual_value": 850.5,
       "message": "high_response_time exceeded threshold: 500.00 (actual: 850.50)",
       "timestamp": "2026-04-18T12:00:00Z",
       "metadata": {
         "comparison_operator": "gt",
         "service_status": "degraded"
       }
     },
     "channel": {
       "name": "Custom Webhook",
       "type": "webhook"
     },
     "timestamp": 1736856000
   }
   ```

### Legacy: PagerDuty Integration (Deprecated)

> **Deprecated**: Use the unified notification service instead. This section is kept for reference only.

1. **Create PagerDuty Integration Key**:
   - Log into PagerDuty
   - Create a new integration (Events API v2)
   - Copy the integration key

2. **Create Notification Channel**:
   ```sql
   INSERT INTO monitoring_notification_channels (
     channel_name,
     channel_type,
     config,
     enabled
   ) VALUES (
     'PagerDuty Critical',
     'pagerduty',
     '{"integration_key": "YOUR_PAGERDUTY_KEY"}'::jsonb,
     true
   );
   ```

3. **Enable PagerDuty Notifications**:
   - Configure alert thresholds with `notify_pagerduty: true`
   - Critical alerts will trigger PagerDuty incidents

### Unified: Email Notifications

Email notifications use the unified notification service. See [Notification Provider Integration Guide](../operations/notification-providers.md) for:
- Gmail setup (development/testing)
- SendGrid setup (recommended for production)
- AWS SES setup (production)
- Office 365 setup
- Tenant email configuration

**Legacy Email Configuration (Deprecated):**

> **Deprecated**: The following describes the legacy email system. New deployments should use the unified notification service.

Email notifications are now fully implemented with a hybrid approach:

**Platform Default Configuration:**
- Configured via `platform_settings` table (`email_config` setting)
- Used by all tenants unless they configure their own SMTP
- SMTP credentials stored encrypted in database

**Tenant Override (Optional):**
- Tenants can configure their own SMTP in `tenant_admin_settings.config.email_config`
- Set `use_platform_default: false` and provide SMTP credentials
- SMTP passwords encrypted using `ENCRYPTION_MASTER_KEY`

**Configuration:**
- Platform admins configure default SMTP via Admin UI or database
- Tenant admins can override via Tenant Settings (if enabled)
- Resolution: tenant override → platform default → environment variables

**Implementation:**
- Uses `shared/email` package with tenant-aware configuration
- Supports multiple recipients per notification channel
- Error handling: logs failures but doesn't block other notification channels

---

## 📝 Alert History

### Viewing Alert History

**API Endpoint**:
```bash
GET /api/v1/monitoring-service/alerting/history?service_name=api-gateway&status=active&limit=50&offset=0
```

**Query Parameters**:
- `service_name`: Optional - filter by service
- `status`: Optional - `active`, `acknowledged`, `resolved`, `suppressed`
- `limit`: Number of results (default: 50, max: 500)
- `offset`: Pagination offset

**Response Format**:
```json
{
  "alerts": [
    {
      "id": "uuid",
      "threshold_id": "uuid",
      "threshold_name": "high_response_time",
      "metric_type": "response_time",
      "service_name": "api-gateway",
      "threshold_value": 500.0,
      "actual_value": 850.5,
      "severity": "critical",
      "status": "active",
      "message": "high_response_time exceeded threshold...",
      "triggered_at": "2026-04-18T12:00:00Z",
      "acknowledged_at": null,
      "resolved_at": null
    }
  ],
  "count": 150,
  "limit": 50,
  "offset": 0
}
```

### Alert States

- **active**: Alert is currently active (threshold exceeded)
- **acknowledged**: Alert has been acknowledged by an administrator
- **resolved**: Alert has been resolved (threshold no longer exceeded)
- **suppressed**: Alert has been manually suppressed

---

## 🔧 Configuration

### Environment Variables

The monitoring service uses standard environment variables. Alert evaluation interval can be configured:

```bash
# Alert evaluation interval (default: 5 minutes)
ALERT_EVALUATION_INTERVAL=5m
```

### Database Tables

**monitoring_alert_thresholds**: Stores alert threshold configurations  
**monitoring_alert_history**: Stores triggered alerts  
**monitoring_notification_channels**: Stores notification channel configurations

See database migration `23-monitoring-alerting-schema.sql` for full schema details.

---

## 🛠️ Troubleshooting

### Alerts Not Triggering

1. **Check Threshold Status**: Ensure thresholds are `enabled: true`
2. **Verify Metrics**: Check that metrics are being collected for the service
3. **Review Evaluation Logs**: Check monitoring service logs for evaluation errors
4. **Duration Window**: Ensure threshold has been exceeded for `duration_minutes`

### Notifications Not Sending

1. **Verify Channel Configuration**: Check `monitoring_notification_channels` table
2. **Test Channel**: Use API to send test notification
3. **Check Channel Status**: Ensure channel is `enabled: true`
4. **Review Logs**: Check monitoring service logs for notification errors
5. **Network Connectivity**: Verify webhook endpoints are accessible

### Charts Not Displaying Data

1. **Time Range**: Ensure selected time range has data
2. **Service Filter**: Check if service filter is excluding all services
3. **Metric Type**: Verify metric type is being collected
4. **API Response**: Check browser network tab for API errors

---

## 📚 Related Documentation

- [Platform Integrations Setup](../configuration/platform-integrations.md)
- [Secrets Management](../security/secrets-management.md)

---

## 🆘 Support

For issues or questions:
- Check monitoring service logs
- Review alert history in the dashboard
- Contact platform administration team
