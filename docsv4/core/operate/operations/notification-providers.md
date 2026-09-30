---
render_macros: false
---

# Notification Provider Integration Guide

This guide provides step-by-step instructions for integrating third-party notification providers with the unified notification service.

## Overview

The unified notification service supports multiple notification channels:
- **Slack** - Team collaboration and alerts
- **Email** - SMTP-based email delivery
- **Webhook** - Custom HTTP endpoints (signed, with an idempotency key)
- **PagerDuty** - Incident management
- **In-App** - Platform notification center

There is no SMS channel, and **Microsoft Teams is not a supported channel** — see
[Microsoft Teams](#microsoft-teams) below.

### What the Test button tells you

**Test** sends a real test notification through the connection and reports the
real outcome. When it fails, the reason is shown — for example *"Address not
allowed: the destination is a private, loopback or otherwise internal address"*,
*"The receiving service says the endpoint does not exist (HTTP 404)"*, *"The
destination did not respond in time"* or *"Email delivery isn't configured by the
platform operator."* Reasons never include the connection's URL, tokens or
headers, so it is safe to screenshot them into a ticket; the technical detail is in
the notification service's log. The same reason appears in **Delivery History**
(hover the channels cell of a failed row).

A **PagerDuty** test opens a throwaway incident and resolves it immediately, so it
does not leave anything open or page anyone for longer than the resolve takes.

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
   - Enter app name (e.g., "Vista Platform Alerts")
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

1. Navigate to **Settings → Notification Delivery** in the admin console
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

1. Navigate to **Settings → Integrations** in the tenant app
2. Click **Add Channel**
3. Configure as above
4. Test and save

### Step 3: Create Notification Rules

After creating the channel, create rules to route alerts. For a tenant
administrator, rules are under **Settings → Notifications & Alerts → Routing
Rules**; for a platform administrator, routing rules live alongside channels on
**Settings → Notification Delivery**.

1. Click **Add Rule**
2. Configure:
   - **Rule Name**: "Critical Alerts to Slack"
   - **Alert Source**: Select source (monitoring, discovery, etc.)
   - **Channels**: Select your Slack channel
   - **Severity Filter**: Select severities (e.g., critical, high)
   - **Frequency**: Immediate
3. Enable and save

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

1. Navigate to **Settings → Email** in the admin console
2. Configure SMTP settings:
   - **SMTP Host**: Your provider's SMTP host
   - **SMTP Port**: `587` (TLS) or `465` (SSL)
   - **SMTP Username**: Your SMTP username
   - **SMTP Password**: Your SMTP password (encrypted in database)
   - **From Email**: Verified sender address
   - **From Name**: Display name (e.g., "Vista Platform")
3. Test configuration
4. Save settings

### Step 3: Configure Tenant Email Channel

1. Navigate to **Settings → Integrations** in the tenant app
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

**"Email delivery isn't configured by the platform operator":**
No SMTP host is set anywhere the platform looks — not in **Settings → Email**, not
as a tenant override, and not through the `SMTP_HOST` environment variable. Email
channels then fail immediately and are **not retried** (retrying cannot help), and
the tenant's email connection card carries the same notice. Configure SMTP (Step 2
above) and the channels start working with no other change. In a local
compose development stack, set `SMTP_HOST` (for example to a mail catcher) for the
notification service.

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

1. Navigate to **Settings → Integrations** (tenant app) or **Settings →
   Notification Delivery** (admin console)
2. Click **Add Channel**
3. Configure:
   - **Channel Name**: "Custom Webhook"
   - **Channel Type**: Generic webhook
   - **URL**: Your webhook endpoint URL
   - **Authentication**: **None**, **Bearer token**, **Basic** (username +
     password) or **Custom header** (one header name and value)
   - **Signing secret** (optional): leave blank and Vista generates one
   - **Enabled**: ✓
4. Click **Add connection**. If Vista generated a signing secret it is shown
   **once** — copy it into your receiver now.
5. Click **Test** on the connection card to send a test notification.

Every credential you enter (token, password, header value, signing secret) is
encrypted at rest and **write-only**: the console never shows it again, only a
masked form such as `••••wxyz`. Editing a connection and leaving a credential
blank keeps the stored value; entering a new one replaces it.

### Step 3: Webhook Payload Format

Webhooks receive notifications in this format:

```json
{
  "event_id": "6f1c1c0e-3b0a-4c2e-9b1e-0a1b2c3d4e5f",
  "alert_source": "monitoring",
  "alert_type": "high_response_time",
  "severity": "high",
  "title": "High response time",
  "message": "Service response time exceeded threshold",
  "timestamp": "2026-04-19T12:45:00Z",
  "metadata": {
    "service_name": "api-gateway",
    "threshold_value": 1000,
    "actual_value": 1500
  }
}
```

### Step 4: Verify the signature and de-duplicate

Every delivery carries three headers:

| Header | Meaning |
|---|---|
| `X-Vista-Event-Id` | A stable id for this notification. **Identical on every retry** of the same notification, so use it as your idempotency key and ignore a repeat. |
| `X-Vista-Timestamp` | Unix time (seconds) when the request was sent. |
| `X-Vista-Signature` | `sha256=` followed by the hex HMAC-SHA256 of `timestamp + "." + body`, keyed with the channel's signing secret. Present when the channel has a signing secret. |

To verify: recompute the HMAC over the timestamp, a literal `.`, and the **raw
request body bytes** (before any JSON parsing), compare it to the header in
constant time, and reject requests whose timestamp is more than a few minutes
old to defeat replay.

```python
import hashlib, hmac, time

def verify(secret: str, headers: dict, raw_body: bytes, tolerance: int = 300) -> bool:
    timestamp = headers["X-Vista-Timestamp"]
    if abs(time.time() - int(timestamp)) > tolerance:
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), timestamp.encode() + b"." + raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, headers["X-Vista-Signature"])
```

```javascript
const crypto = require('crypto');

function verify(secret, headers, rawBody, toleranceSeconds = 300) {
  const timestamp = headers['x-vista-timestamp'];
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > toleranceSeconds) return false;
  const expected = 'sha256=' + crypto
    .createHmac('sha256', secret)
    .update(`${timestamp}.`)
    .update(rawBody)
    .digest('hex');
  const given = Buffer.from(headers['x-vista-signature'] || '');
  const want = Buffer.from(expected);
  return given.length === want.length && crypto.timingSafeEqual(given, want);
}
```

**Rotating the secret:** open the connection, enter a new **Signing secret**
(or click **Generate** and copy the value), and save. Update your receiver at
the same time — deliveries are signed with the new secret from the moment you
save. A connection created before signing existed has no secret until you enter
one.

**Retries:** a delivery that fails with a temporary error (a timeout, a 5xx, a 429)
is retried with backoff and carries the **same** `X-Vista-Event-Id`. A 4xx other
than 408, 425 and 429 is treated as permanent and is not retried.

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
   - Enter integration name (e.g., "Vista Platform")
   - Click "Add Integration"

4. **Copy Integration Key**:
   - Copy the Integration Key (format: alphanumeric string)
   - Keep this secure

### Step 2: Configure in Platform

1. Navigate to **Settings → Integrations** (tenant app) or **Settings →
   Notification Delivery** (admin console)
2. Click **Add Channel**
3. Configure:
   - **Channel Name**: "PagerDuty Critical"
   - **Channel Type**: PagerDuty
   - **Integration Key**: Paste the integration key from Step 1
   - **Enabled**: ✓
4. Click **Test** — this opens a throwaway incident and resolves it straight
   away, so nothing is left open
5. Click **Create**

### Step 3: Incident identity (dedup) and auto-resolve

Every event carries a `dedup_key` derived from the alert, so PagerDuty treats one
alert as one incident:

- the alert opening, and any later **escalation** of the same alert, update the
  **same** incident (`dedup_key` = `vista-alert-<alert id>`);
- when the platform observes the condition clear and auto-resolves the alert, it
  sends a **resolve** event with the same key, closing the incident;
- a notification that is not a stateful alert (for example a discovery job
  result) gets its own key from its event id, which is stable across retries — so
  a retried delivery never opens a second incident.

Note that the auto-resolve notice is an *info*-severity notification. A routing
rule whose **Severity Filter** is only "critical" and "high" will not route it, so
the incident would stay open until you resolve it in PagerDuty. If you want
automatic resolution, include **info** in the severity filter of the rule that
feeds PagerDuty, or add a second rule for PagerDuty limited to auto-resolve
notices.

### Step 4: Severity Mapping

PagerDuty severity mapping:
- `critical` → PagerDuty "critical"
- `high` → PagerDuty "error"
- `medium` → PagerDuty "warning"
- `low` → PagerDuty "info"
- `info` → PagerDuty "info"

### Step 5: Create Rules for Critical Alerts

1. Navigate to **Settings → Notifications & Alerts → Routing Rules** (tenant
   app) or **Settings → Notification Delivery** (admin console)
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

## Microsoft Teams

**Microsoft Teams is not a supported channel.** There is no Teams option in
**Add connection**, and a Teams *Workflows* (or legacy Office 365 connector) URL
pasted into a **Generic webhook** connection will **not post anything**: Teams
expects an Adaptive Card payload, and a generic webhook sends the alert JSON
described above. The delivery can look successful on Vista's side while nothing
appears in the Teams channel. To reach Teams today, point a Generic webhook at a
small relay that turns the alert JSON into an Adaptive Card and posts it.

## SMS

There is no SMS channel. It is not offered in either console.

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
