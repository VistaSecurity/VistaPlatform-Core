---
render_macros: false
---

# Notification Provider Integration Guide

This guide provides step-by-step instructions for integrating third-party notification providers with the unified notification service.

## Overview

The unified notification service supports multiple notification channels:
- **Slack** - Team collaboration and alerts
- **Email** - SMTP-based email delivery
- **Webhook** - Custom HTTP endpoints
- **PagerDuty** - Incident management
- **SMS** - Text messaging (placeholder for future implementation)
- **In-App** - Platform notification center

## Slack Integration

### Prerequisites

- Slack workspace with admin permissions
- Access to Slack App Management

### Step 1: Create Slack Incoming Webhook

1. **Navigate to Slack Apps**:
   - Go to https://api.slack.com/apps
   - Sign in to your workspace

2. **Create New App**:
   - Click "Create New App"
   - Choose "From scratch"
   - Enter app name (e.g., "Crypto Inventory Alerts")
   - Select your workspace
   - Click "Create App"

3. **Enable Incoming Webhooks**:
   - In the app settings, navigate to "Incoming Webhooks"
   - Toggle "Activate Incoming Webhooks" to ON

4. **Create Webhook**:
   - Click "Add New Webhook to Workspace"
   - Select the channel where alerts should be posted
   - Click "Allow"
   - Copy the webhook URL (format: `https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX`)

### Step 2: Configure in Platform

#### For Platform Administrators

1. Navigate to **Operations** → **Notifications & Alerts** → **Channels**
2. Click **Add Channel**
3. Configure:
   - **Channel Name**: "Platform Alerts" (or descriptive name)
   - **Channel Type**: Slack
   - **Webhook URL**: Paste the webhook URL from Step 1
   - **Channel** (optional): Override default channel (e.g., `#alerts`)
   - **Enabled**: ✓
4. Click **Test** to verify connectivity
5. Click **Create**

#### For Tenant Administrators

1. Navigate to **Settings** → **Notifications** → **Channels**
2. Click **Add Channel**
3. Configure as above
4. Test and save

### Step 3: Create Notification Rules

After creating the channel, create rules to route alerts:

1. Navigate to **Notifications** → **Rules**
2. Click **Add Rule**
3. Configure:
   - **Rule Name**: "Critical Alerts to Slack"
   - **Alert Source**: Select source (monitoring, discovery, etc.)
   - **Channels**: Select your Slack channel
   - **Severity Filter**: Select severities (e.g., critical, high)
   - **Frequency**: Immediate
4. Enable and save

### Message Format

Slack notifications are sent as formatted message blocks:

```json
{
  "text": "[high] high_response_time",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*high_response_time*\nService response time exceeded threshold"
      }
    },
    {
      "type": "section",
      "fields": [
        {
          "type": "mrkdwn",
          "text": "*Source:*\nmonitoring"
        },
        {
          "type": "mrkdwn",
          "text": "*Severity:*\nhigh"
        }
      ]
    }
  ]
}
```

### Troubleshooting

**Webhook not working:**
- Verify webhook URL is correct
- Check Slack app has "Incoming Webhooks" enabled
- Ensure channel still exists and app has access
- Test webhook manually: `curl -X POST -H 'Content-type: application/json' --data '{"text":"Test"}' <webhook-url>`

**Messages not appearing:**
- Check channel permissions
- Verify rule is enabled and matches alert criteria
- Review notification history for delivery status

## Email Provider Integration

### Prerequisites

- SMTP server access (Gmail, SendGrid, AWS SES, etc.)
- SMTP credentials (username/password or API key)

### Step 1: Choose Email Provider

#### Option A: Gmail (Development/Testing)

**Limitations:**
- Requires "Less secure app access" or App Password
- Daily sending limits apply
- Not recommended for production

**Setup:**
1. Enable 2-factor authentication
2. Generate App Password: https://myaccount.google.com/apppasswords
3. Use App Password as SMTP password

**SMTP Settings:**
- Host: `smtp.gmail.com`
- Port: `587` (TLS) or `465` (SSL)
- Username: Your Gmail address
- Password: App Password

#### Option B: SendGrid (Recommended for Production)

**Setup:**
1. Create SendGrid account: https://sendgrid.com
2. Verify sender identity (domain or single sender)
3. Create API key: Settings → API Keys → Create API Key
4. Use API key as SMTP password

**SMTP Settings:**
- Host: `smtp.sendgrid.net`
- Port: `587`
- Username: `apikey`
- Password: Your SendGrid API key

#### Option C: AWS SES (Production)

**Setup:**
1. Verify email address or domain in AWS SES
2. Move out of sandbox mode (if needed)
3. Create SMTP credentials: AWS Console → SES → SMTP Settings

**SMTP Settings:**
- Host: `email-smtp.<region>.amazonaws.com`
- Port: `587` (TLS) or `465` (SSL)
- Username: SMTP username from AWS
- Password: SMTP password from AWS

#### Option D: Microsoft 365 / Office 365

**SMTP Settings:**
- Host: `smtp.office365.com`
- Port: `587`
- Username: Your Office 365 email
- Password: Your Office 365 password (or App Password if MFA enabled)

### Step 2: Configure Platform Email (Platform Admins)

1. Navigate to **Platform Administration** → **Platform Settings** → **Email Configuration**
2. Configure SMTP settings:
   - **SMTP Host**: Your provider's SMTP host
   - **SMTP Port**: `587` (TLS) or `465` (SSL)
   - **SMTP Username**: Your SMTP username
   - **SMTP Password**: Your SMTP password (encrypted in database)
   - **From Email**: Verified sender address
   - **From Name**: Display name (e.g., "Crypto Inventory Platform")
3. Test configuration
4. Save settings

### Step 3: Configure Tenant Email Channel

1. Navigate to **Settings** → **Notifications** → **Channels**
2. Click **Add Channel**
3. Configure:
   - **Channel Name**: "Email Alerts"
   - **Channel Type**: Email
   - **Recipients**: Enter email addresses (one per line)
   - **Enabled**: ✓
4. Click **Test** to send test email
5. Click **Create**

**Note:** Tenant email channels use platform SMTP configuration by default. Tenants can configure their own SMTP in tenant settings if needed.

### Step 4: Email Configuration Best Practices

**Security:**
- Use App Passwords or API keys instead of account passwords
- Enable encryption (TLS/SSL)
- Store passwords encrypted in database (automatic)

**Reliability:**
- Use production-grade providers (SendGrid, AWS SES) for production
- Configure SPF, DKIM, and DMARC records for domain
- Monitor bounce rates and delivery status

**Testing:**
- Always test email channels after configuration
- Verify emails arrive in inbox (not spam)
- Check email formatting and content

### Troubleshooting

**Emails not sending:**
- Verify SMTP credentials are correct
- Check SMTP port (587 for TLS, 465 for SSL)
- Ensure sender email is verified
- Review service logs for SMTP errors

**Emails going to spam:**
- Configure SPF record: `v=spf1 include:sendgrid.net ~all` (for SendGrid)
- Configure DKIM (provider-specific)
- Configure DMARC policy
- Use verified domain instead of single email

**Rate limiting:**
- Gmail: 500 emails/day (free), 2000/day (Workspace)
- SendGrid: Based on plan (100/day free, unlimited paid)
- AWS SES: Starts in sandbox (200/day), request production access

## Webhook Integration

### Overview

Webhooks allow integration with custom monitoring systems, ticketing systems, or internal tools.

### Step 1: Prepare Webhook Endpoint

Your webhook endpoint should:
- Accept POST requests
- Handle JSON payloads
- Return 2xx status codes for success
- Be accessible from the platform (public or VPN)

**Example endpoint (Node.js):**
```javascript
app.post('/webhook/alerts', (req, res) => {
  const alert = req.body;
  console.log('Received alert:', alert);
  
  // Process alert (save to database, create ticket, etc.)
  
  res.status(200).json({ received: true });
});
```

### Step 2: Configure Webhook Channel

1. Navigate to **Notifications** → **Channels**
2. Click **Add Channel**
3. Configure:
   - **Channel Name**: "Custom Webhook"
   - **Channel Type**: Webhook
   - **URL**: Your webhook endpoint URL
   - **Headers** (optional): Custom HTTP headers
   - **Authentication** (optional):
     - **Type**: Bearer or Basic
     - **Token/Credentials**: Authentication details
   - **Enabled**: ✓
4. Click **Test** to send test notification
5. Click **Create**

### Step 3: Webhook Payload Format

Webhooks receive notifications in this format:

```json
{
  "alert_source": "monitoring",
  "alert_type": "high_response_time",
  "severity": "high",
  "message": "Service response time exceeded threshold",
  "timestamp": "2026-04-19T12:45:00Z",
  "metadata": {
    "service_name": "api-gateway",
    "threshold_value": 1000,
    "actual_value": 1500
  }
}
```

### Step 4: Authentication Options

**Bearer Token:**
```json
{
  "auth": {
    "type": "bearer",
    "token": "your-api-token"
  }
}
```

**Basic Auth:**
```json
{
  "auth": {
    "type": "basic",
    "username": "webhook-user",
    "password": "webhook-password"
  }
}
```

### Troubleshooting

**Webhook not receiving requests:**
- Verify URL is correct and accessible
- Check firewall/security group rules
- Test endpoint manually: `curl -X POST -H 'Content-Type: application/json' -d '{"test":true}' <webhook-url>`

**Authentication failures:**
- Verify credentials are correct
- Check token expiration
- Ensure endpoint accepts your auth method

**Timeout errors:**
- Ensure endpoint responds quickly (< 10 seconds)
- Consider async processing for long operations

## PagerDuty Integration

### Prerequisites

- PagerDuty account
- Admin access to create integrations

### Step 1: Create PagerDuty Integration

1. **Log into PagerDuty**
2. **Navigate to Services**:
   - Go to Services → Your Service
   - Or create a new service

3. **Add Integration**:
   - Click "Integrations" tab
   - Click "New Integration"
   - Select "Events API v2"
   - Enter integration name (e.g., "Crypto Inventory Platform")
   - Click "Add Integration"

4. **Copy Integration Key**:
   - Copy the Integration Key (format: alphanumeric string)
   - Keep this secure

### Step 2: Configure in Platform

1. Navigate to **Notifications** → **Channels**
2. Click **Add Channel**
3. Configure:
   - **Channel Name**: "PagerDuty Critical"
   - **Channel Type**: PagerDuty
   - **Integration Key**: Paste the integration key from Step 1
   - **Enabled**: ✓
4. Click **Test** to create a test incident
5. Click **Create**

### Step 3: Severity Mapping

PagerDuty severity mapping:
- `critical` → PagerDuty "critical"
- `high` → PagerDuty "error"
- `medium` → PagerDuty "warning"
- `low` → PagerDuty "info"
- `info` → PagerDuty "info"

### Step 4: Create Rules for Critical Alerts

1. Navigate to **Notifications** → **Rules**
2. Create rule:
   - **Rule Name**: "Critical to PagerDuty"
   - **Alert Source**: Select source
   - **Channels**: Select PagerDuty channel
   - **Severity Filter**: Select "critical" and "high"
   - **Frequency**: Immediate
3. Enable and save

### Troubleshooting

**Incidents not creating:**
- Verify integration key is correct
- Check PagerDuty service is active
- Review PagerDuty event log
- Ensure rule matches alert criteria

**Wrong severity:**
- Check severity mapping in delivery service
- Verify alert severity in notification request

## SMS Integration (Placeholder)

SMS integration is planned for future implementation. When available, configuration will follow similar patterns to other channels.

**Planned Providers:**
- Twilio
- AWS SNS
- Other SMS gateways

## Best Practices

### Channel Management

1. **Naming Convention**: Use descriptive names (e.g., "Production Slack", "Ops Email")
2. **Testing**: Always test channels after creation or changes
3. **Monitoring**: Review notification history regularly
4. **Redundancy**: Configure multiple channels for critical alerts

### Rule Configuration

1. **Priority**: Set higher priority for critical alert rules
2. **Severity Filtering**: Use severity filters to reduce noise
3. **Frequency**: Use digest mode for non-critical alerts
4. **Testing**: Test rules with sample alerts

### Security

1. **Credentials**: Store all credentials encrypted
2. **Access Control**: Limit channel management to authorized users
3. **Audit**: Review notification history for security events
4. **Rotation**: Rotate API keys and passwords regularly

## Related Documentation

- [Platform Admin Guide](../platform-admin-guide.md)
- [Tenant Admin Guide](../../guides/tenant-admin-guide.md)
