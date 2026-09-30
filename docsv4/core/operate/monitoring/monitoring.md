---
render_macros: false
---

# Production Monitoring & Alerting Setup

This document provides instructions for setting up monitoring and alerting for Vista Platform in production environments.

## Overview

The platform includes built-in monitoring capabilities through the `monitoring-service`, which collects metrics, tracks service health, and provides alerting. This guide covers:

- Service health monitoring
- Metrics collection and aggregation
- Alerting configuration
- Integration with external monitoring tools (CloudWatch, Grafana)
- Dashboard setup

## Built-in Monitoring Service

### Service Health Endpoints

All services expose health check endpoints:

```bash
# API Gateway health
curl https://api.example.com/api/v1/health

# Individual service health
curl https://api.example.com/api/v1/auth-service/health
curl https://api.example.com/api/v1/inventory-service/health
curl https://api.example.com/api/v1/monitoring-service/health
```

### Platform Metrics API

The monitoring service provides platform-wide metrics.

> **What `$TOKEN` is.** In this guide `$TOKEN` is a **signed-in session access
> token** — the short-lived access token issued when a user signs in
> (`POST /api/v1/auth-service/auth/login`; the web UI holds the same token in its
> `access_token` cookie). It carries that user's role, so the calls below work
> only for a user whose role allows them. A **personal API token**
> (My Profile → API Tokens, `qvpat_…`) is *not* accepted here: those work only
> with the MCP server.

```bash
# Platform summary
curl -H "Authorization: Bearer $TOKEN" \
  https://api.example.com/api/v1/monitoring-service/platform/summary

# Service-specific metrics
curl -H "Authorization: Bearer $TOKEN" \
  https://api.example.com/api/v1/monitoring-service/platform/services/auth-service

# Historical trends
curl -H "Authorization: Bearer $TOKEN" \
  https://api.example.com/api/v1/monitoring-service/platform/trends?period=24h
```

## Alerting Configuration

### Setting Up Alert Thresholds

Alert thresholds are configured via the admin UI or API:

```bash
# Create alert threshold via API
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "auth-service",
    "metric_name": "error_rate",
    "threshold_value": 0.05,
    "comparison": "greater_than",
    "severity": "high"
  }' \
  https://api.example.com/api/v1/monitoring-service/alerts/thresholds
```

### Notification Channels

monitoring-service does not deliver notifications itself. Threshold alerts and
security-incident notices are published to the notification service, which
applies the **platform** notification channels and routing rules — the same
delivery path as every other platform alert (service down, tenant health, and so
on).

Configure delivery in the admin console under **Settings → Notification
Delivery**: add a channel (in-app, email, Slack, webhook, PagerDuty), then a
routing rule that sends the severities you care about to it. A fresh install
already has a default pack: an in-app channel and an email channel to the
`super_admin` platform users, with rules for critical/high alerts and for
everything else. Per-channel setup (Slack app, PagerDuty routing key, SMTP) is in
the [Notification Provider Integration Guide](../operations/notification-providers.md);
the **Test** button on a channel reports why a delivery failed.

monitoring-service exposes no notification-channel API.

## AWS CloudWatch Integration

### Setting Up CloudWatch Logs

1. **Configure AWS IAM Role**
   - Create IAM role with `logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents` permissions
   - Attach role to EC2 instance or ECS task

2. **Install CloudWatch Agent** (if using EC2)
   ```bash
   wget https://s3.amazonaws.com/amazoncloudwatch-agent/amazon_linux/amd64/latest/amazon-cloudwatch-agent.rpm
   sudo rpm -U ./amazon-cloudwatch-agent.rpm
   ```

3. **Configure Agent**
   ```bash
   sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
     -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
   ```

### CloudWatch Metrics

The platform can send custom metrics to CloudWatch:

```bash
# Set environment variable to enable CloudWatch metrics
export CLOUDWATCH_ENABLED=true
export AWS_REGION=us-east-1
```

### CloudWatch Dashboards

Create CloudWatch dashboards to visualize:

- API Gateway request rates and errors
- Service health status
- Database connection pool usage
- Resource tracker costs
- Authentication success/failure rates

## Grafana Integration

### Setting Up Grafana Data Source

1. **Install Grafana** (if not using container)
   ```bash
   docker run -d -p 3001:3000 \
     -e GF_SECURITY_ADMIN_PASSWORD=admin \
     grafana/grafana:latest
   ```

2. **Add InfluxDB Data Source**
   - URL: `http://influxdb:8086`
   - Database: `metrics`
   - User: `admin`
   - Password: `adminpass123` (change in production)

3. **Import Platform Dashboards**
   - Service Health Dashboard
   - Resource Usage Dashboard
   - Cost Tracking Dashboard
   - Authentication Metrics Dashboard

### Grafana Alert Rules

Configure Grafana alert rules for:

- Service downtime (health check failures)
- High error rates (>5% of requests)
- Database connection pool exhaustion
- High memory usage (>80%)
- Cost anomalies (unusual AWS spending)

## Key Metrics to Monitor

### Service-Level Metrics

- **Request Rate**: Requests per second per service
- **Error Rate**: Percentage of failed requests
- **Response Time**: P50, P95, P99 latencies
- **Active Connections**: Database and Redis connections
- **Memory Usage**: Per-service memory consumption
- **CPU Usage**: Per-service CPU utilization

### Platform-Level Metrics

- **Total Tenants**: Active tenant count
- **Total Users**: Active user count
- **API Gateway Throughput**: Total requests through gateway
- **Cost Tracking**: Platform-wide AWS cost synchronization. Per-tenant compute cost is not currently measured — it reports as "not measured" pending a per-tenant attribution model, rather than an estimated figure.
- **Health Scores**: Tenant health scores and trends

### Database Metrics

- **Connection Pool**: Active/idle connections
- **Query Performance**: Slow query count
- **Replication Lag**: If using read replicas
- **Disk Usage**: Database storage utilization

## Alerting Best Practices

### Critical Alerts (Immediate Response)

- Service health check failures
- Database connection failures
- Authentication service failures
- API Gateway 5xx errors >1%

### Warning Alerts (Monitor Closely)

- Error rate >5% for any service
- Response time P95 >1 second
- Memory usage >80%
- Database connection pool >80% utilized

### Info Alerts (Track Trends)

- Cost anomalies (>20% increase)
- Tenant health score drops
- Unusual API usage patterns

## Monitoring Checklist

- [ ] Configure alert thresholds for all critical services
- [ ] Set up notification channels (Slack, email, PagerDuty)
- [ ] Create CloudWatch dashboards or Grafana dashboards
- [ ] Set up log aggregation (CloudWatch Logs or ELK)
- [ ] Configure health check monitoring
- [ ] Set up cost monitoring alerts
- [ ] Test alert notifications
- [ ] Document on-call procedures
- [ ] Set up incident response workflows

## Troubleshooting

### Services Not Reporting Metrics

1. Check monitoring-service is running:
   ```bash
   docker compose ps monitoring-service
   ```

2. Verify database connectivity:
   ```bash
   docker compose exec monitoring-service \
     psql -U crypto_user -d crypto_inventory -c "SELECT 1"
   ```

3. Check service logs:
   ```bash
   docker compose logs monitoring-service | tail -50
   ```

### Alerts Not Firing

1. Verify alert thresholds are configured:
   ```bash
   curl -H "Authorization: Bearer $TOKEN" \
     https://api.example.com/api/v1/monitoring-service/alerts/thresholds
   ```

2. Check the platform notification channels and routing rules are enabled
   (admin console → **Settings → Notification Delivery**) and look at its
   delivery history for the alert.

3. Review alert evaluator job logs:
   ```bash
   docker compose logs monitoring-service | grep -i alert
   ```

## Related Documentation

- [Production Deployment Checklist](../deployment/production-checklist.md)
- [Log Management](./log-management.md)
- AWS Cost Explorer Setup
