# Audit Logging User Guide

**Version:** 1.0  
**Last Updated:** 2026-09-12

This guide provides comprehensive information about audit logging, activity monitoring, and security investigation workflows in the Vista Platform.

---

## Table of Contents

1. [Overview](#overview)
2. [Understanding Event Types](#understanding-event-types)
3. [Event Categories](#event-categories)
4. [Compliance Tagging System](#compliance-tagging-system)
5. [Activity Log Management](#activity-log-management)
6. [Security Investigation Workflows](#security-investigation-workflows)
7. [Compliance Reporting Workflows](#compliance-reporting-workflows)
8. [Best Practices](#best-practices)

---

## Overview

The audit logging system captures every action performed in the platform, providing:
- **Complete Audit Trail**: Every action logged with full context
- **Compliance Support**: Automatic tagging for compliance frameworks
- **Security Monitoring**: Real-time detection of suspicious activity
- **Troubleshooting**: Detailed logs for debugging issues

### What is Logged

Every logged event includes:
- **Who**: User ID, email, and user type (tenant/platform/service)
- **What**: Event type, action, and resource affected
- **When**: Precise timestamp
- **Where**: IP address and user agent
- **How**: Success/failure status and error details
- **Why**: Request ID for tracing through system
- **Context**: Old values, new values, and changed fields

---

## Understanding Event Types

Event types follow a consistent naming pattern: `{resource}.{action}`

### Common Event Types

#### Asset Events
- `asset.created`: New asset added
- `asset.updated`: Asset modified
- `asset.deleted`: Asset removed
- `asset.discovered`: Asset found by discovery
- `asset.approved`: Discovery approval granted

#### User Events
- `user.login`: Successful authentication
- `user.login.failed`: Authentication failure
- `user.logout`: User logged out
- `user.created`: New user added
- `user.updated`: User modified
- `user.deleted`: User removed
- `user.password.changed`: Password updated
- `user.mfa.enabled`: MFA activated
- `user.mfa.disabled`: MFA deactivated

#### Compliance Events
- `compliance.assessment.created`: New assessment started
- `compliance.assessment.completed`: Assessment finished
- `compliance.finding.created`: New finding detected
- `compliance.finding.resolved`: Finding addressed
- `compliance.finding.suppressed`: Finding suppressed
- `compliance.control.passed`: Control validation succeeded
- `compliance.control.failed`: Control validation failed

#### System Events
- `system.config.updated`: System configuration changed
- `system.integration.created`: Integration added
- `system.integration.deleted`: Integration removed
- `system.backup.completed`: Backup successful
- `system.backup.failed`: Backup failed

#### Discovery Events
- `discovery.job.started`: Discovery scan began
- `discovery.job.completed`: Discovery scan finished
- `discovery.job.failed`: Discovery scan failed
- `device.interrogated`: Device scanned
- `cloud.sync.completed`: Cloud sync finished

---

## Event Categories

Every event carries one category. It is matched by the Audit page's search box
and by the export endpoint's `event_category` filter. These are the categories
the platform records:

| Category | Covers |
|----------|--------|
| `authentication` | Login, logout, token refresh, API tokens, SSO and OAuth flows |
| `user` | User lifecycle, roles and permissions, profile and preference changes |
| `tenant` | Tenant lifecycle and tenant-level health |
| `asset` | Infrastructure assets, crypto configurations, keys, findings, asset approval |
| `certificate` | Certificate upload, deletion, chain building, expiry and revocation |
| `discovery` | Sensors and discovery agents, discovery jobs, device interrogation, PCAP intake |
| `compliance` | Framework activation, control evaluation, compliance findings, tickets |
| `report` | CBOM artifacts, comparisons and scopes |
| `config` | Tenant and platform settings changes |
| `data` | Data access and export, including access through the MCP server |
| `job` | Background job lifecycle |
| `system` | Platform operation: monitoring, notifications, resource tracking, the audit trail itself |

Every request the platform serves is recorded under the category of the
service that served it — a request to the inventory service is `asset`, to a
discovery service `discovery`, and so on — with a few resource-level
exceptions (certificates are always `certificate`, tenant lifecycle is always
`tenant`, settings are always `config`, and sign-in is always
`authentication`). Handlers that record a richer event of their own name the
category directly.

### Upgrading

Before this categorization existed, every request the platform's request
logger recorded (as opposed to a specific handler naming its own event) was
filed under `system`, with an event type of the form
`system.<service>.<action>` — for example `system.inventory-service.create`
instead of `asset.assets.create`. **Rows written before the upgrade are not
rewritten** — they keep the category and event type they were recorded with.
If you have an alert rule or a SIEM filter that matches on
`event_category = system` or on the `system.<service>.<action>` event-type
shape, it will continue to match only the old rows; new activity moves to the
categories in the table above and needs a filter written against those
instead.

---

## Compliance Tagging System

Events are automatically tagged with relevant compliance frameworks to simplify compliance reporting.

### Supported Frameworks

**SOC2 (soc2)**
- User authentication events
- Access control changes
- System configuration changes
- Backup and recovery events
- Security monitoring events

**ISO 27001 (iso27001)**
- Information security events
- Asset management events
- Access control events
- Incident management events
- Audit trail events

**GDPR (gdpr)**
- Personal data access
- Data modification events
- Data deletion events
- Consent management
- Data export events

**HIPAA (hipaa)**
- PHI access events
- Security events
- Configuration changes
- User management
- Audit logging

**PCI DSS (pci_dss)**
- Card data access
- Security events
- Network configuration
- Access control
- Audit mechanisms

### Using Compliance Tags

**Filtering by Framework**

Compliance tags are not one of the three controls on the Audit page. To pull the
events carrying a given tag, use the audit API's `compliance_tag` filter (see
[Getting events out](#getting-events-out)) with one of `soc2`, `iso27001`,
`gdpr`, `hipaa`, `pci_dss`.

**Generating Compliance Reports**
1. Select framework
2. All tagged events included automatically
3. Generate on demand (running them on a schedule is an Enterprise capability)

---

## Activity Log Management

### Viewing Logs

Open the **profile chip** at the bottom of the left rail → **Organization
Settings** → **Audit**. Reading the trail needs the **audit read** permission:
Tenant Administrator, Security Administrator and Viewer have it by default;
Billing Admin and API User do not.

Events are listed newest first, with four columns:

| Column | What it shows |
|---|---|
| **Actor** | The member's email, or *System* for platform-initiated events. |
| **Action** | What was done. A failed attempt is marked *· failed* and shown in red. |
| **Target** | The resource type and id, falling back to the event category. |
| **When** | How long ago it happened. |

Three controls narrow the list:

- a **search** box, matching across actor, action, event type, event category,
  resource type and resource id;
- an **actor** selector, built from the actors present in the loaded events;
- a **window** — last 24 hours, last 7 days, or last 30 days (the default).

**The controls narrow what is already on screen, not what is fetched.** The page
loads the most recent events and tells you how many of the total it is showing
("Showing the 100 most recent of 4,812 events"). On a busy trail, a 30-day
window can therefore show less than 30 days' worth. To reach further back, use
the API below.

There is **no advanced query builder** and **no saved queries** on this page.

### Getting events out

**There is no export control on the Audit page in this release.** The audit
service exposes an export endpoint instead, which you can call with a personal
API token (**My Profile → API Tokens**):

```
GET /api/v1/audit-service/activity-logs/export?format=csv
GET /api/v1/audit-service/activity-logs/export?format=json
```

`format` accepts `csv` or `json` and defaults to `json`. A tenant user's request
is always scoped to their own organization, whatever else is passed.

The same request accepts filters, which is how you reach further back than the
page can show:

| Parameter | Notes |
|---|---|
| `start_date`, `end_date` | RFC 3339 timestamps. The usual way to bound an export. |
| `event_type`, `event_category`, `action` | Repeatable — pass the parameter more than once for several values. |
| `user_id`, `user_type` | Narrow to one member, or to human vs. system actors. |
| `resource_type`, `resource_id` | Narrow to one kind of resource, or one resource. |
| `compliance_tag` | Repeatable. `soc2`, `iso27001`, `gdpr`, `hipaa`, `pci_dss`. |
| `success` | `true` or `false` — failures only, or successes only. |

**One request returns at most 10,000 events.** Bound long periods with
`start_date` / `end_date` and pull them in chunks rather than asking for a year
at once.

**The two formats do not carry the same detail.** CSV is a flat fourteen-column
table — id, occurred at, tenant id, user id, user type, user email, event type,
event category, action, resource type, resource id, success, error message,
compliance tags. **JSON carries the whole record**, including the fields CSV has
no column for: `changed_fields`, `old_values`, `new_values`, `ip_address` and
`user_agent`. If you are investigating *what changed* rather than *what
happened*, ask for JSON.


### Searching Logs

Use the page's search box for a quick look — it matches a substring against the
actor, action, event type, event category, resource type and resource id of the
events already loaded. Examples:

- a member's email address
- an event type such as `asset.created`
- a resource id you are tracing

For anything the box cannot express — a precise time window, a compliance tag, a
success/failure split, or more history than the page holds — use the export
endpoint's filters above.

---

## Security Investigation Workflows

### Investigating Failed Logins

**Scenario**: Multiple failed login attempts detected

1. **Initial Investigation**
   - Open **Settings → Audit**
   - Search for `user.login.failed`
   - Narrow the window to the period in question
   - Look for patterns (same user, time clustering). Source addresses are not a
     column on the page — pull a JSON export if you need them

2. **Identify Affected Accounts**
   - Note user emails with failures
   - Check if multiple users affected (broader attack)
   - Check if single user (credential issue)

3. **Check for Success After Failures**
   - After identifying time window, search for `user.login`
   - Check if successful login follows failures
   - Potential compromise if login succeeds after many failures

4. **Correlate with Other Events**
   - Search for user activity after successful login
   - Look for unusual actions (bulk deletions, config changes)
   - Check IP address changes

5. **Take Action**
   - Reset compromised passwords
   - Enable/require MFA
   - Block suspicious IP addresses
   - Create alert rule to prevent future incidents

### Investigating Unauthorized Access

**Scenario**: Suspected unauthorized resource access

1. **Resource Audit Trail**
   - Navigate to the resource
   - Click **View Audit Trail**
   - Review all access and modifications
   - Note users who accessed resource

2. **User Activity Review**
   - For each suspicious user:
   - View user activity timeline
   - Check authentication events
   - Review all actions in time window

3. **Pattern Analysis**
   - Look for unusual access patterns
   - Check access times (after hours?)
   - Review IP addresses (unusual locations?)
   - Check user agent (automated tools?)

4. **Correlation**
   - Did user access other sensitive resources?
   - Were changes made after access?
   - Are compliance tags affected?

5. **Response**
   - Revoke access if unauthorized
   - Document findings
   - Update access controls
   - Create alert rule for similar patterns

### Investigating Data Modifications

**Scenario**: Unexpected data changes detected

1. **Initial Review**
   - Open **Settings → Audit**
   - Search for the resource type, or for `updated` / `deleted`
   - Identify when changes occurred

2. **Change Details**
   - The page shows *that* something changed, not *what* changed. For the field
     detail, take a **JSON export** bounded to the window you identified
   - Review **changed_fields**, and compare **old_values** with **new_values**
   - Check who made changes

3. **Context Gathering**
   - View user activity timeline
   - Check what led to changes
   - Review surrounding actions
   - Check if part of normal workflow

4. **Impact Assessment**
   - What data was affected?
   - Are compliance requirements impacted?
   - Do changes violate policies?
   - Were proper approvals obtained?

5. **Remediation**
   - Revert changes if unauthorized
   - Contact user if unclear
   - Update approval workflows
   - Add safeguards to prevent recurrence

---

## Compliance Reporting Workflows

### SOC2 Audit Preparation

1. **Define Scope**
   - Determine audit period (typically 12 months)
   - Identify relevant event types
   - List specific compliance requirements

2. **Pull the events**
   - Call the export endpoint with `compliance_tag=soc2` and `start_date` /
     `end_date` set to the audit period (see
     [Getting events out](#getting-events-out))
   - A twelve-month period will exceed the 10,000-event cap; pull it month by
     month and keep each response

3. **Evidence Collection**
   - Repeat the export for access-control and authentication events
     (`event_category=authentication`)
   - Collect configuration-change events the same way
   - Keep the raw responses: they are the evidence, and re-pulling later gives a
     different window

4. **Analysis**
   - Review for anomalies
   - Document any incidents
   - Verify controls functioning
   - Prepare explanations for auditors

5. **Reporting**
   - Generate the framework report and deliver it to the compliance team
   - Maintain historical reports — the platform keeps the trail, not your
     assembled evidence packages

### GDPR Compliance Reporting

1. **Data Access Logging**
   - Export with `compliance_tag=gdpr`, or `event_category=data` for access and
     export events specifically
   - Document access purposes

2. **Data Subject Requests**
   - For everything the platform holds *about* one member, use **Settings →
     People & Access → Members → Export this member's data** — it is built for
     exactly this request and states inside what it leaves out. See
     [Tenant Admin Guide → People & Access](./tenant-admin-guide.md#people--access)
   - For that member's activity specifically, export with their `user_id`

3. **Data Retention**
   - Configure retention policies
   - Set GDPR-compliant periods (730 days)
   - Document retention decisions
   - Implement automated deletion

4. **Regular Reporting**
   - Take the export monthly — there is no console control that does it for you
   - Review data access patterns
   - Monitor for unauthorized access
   - Report to Data Protection Officer

### HIPAA Audit Trail

1. **Required Events**
   - All PHI access events
   - User authentication
   - Configuration changes
   - Security incidents
   - System access

2. **Retention Requirements**
   - Configure 7-year retention (2555 days)
   - Use HIPAA retention policy template
   - Ensure logs tamper-proof
   - Maintain backup copies

3. **Audit Trail Review**
   - Filter by `hipaa` compliance tag
   - Review monthly
   - Document review completion
   - Report exceptions

4. **Incident Response**
   - Create alert rules for suspicious PHI access
   - Document all security incidents
   - Generate incident reports
   - Maintain incident log

---

## Best Practices

### Regular Monitoring

**Daily**
- Review the alert inbox under **Remediation → Alerts**
- Check for failed authentication attempts
- Monitor critical resource changes

**Weekly**
- Review activity log summary
- Check compliance gaps
- Analyze access patterns
- Update alert rules as needed

**Monthly**
- Generate compliance reports
- Review retention policies
- Update notification rules

### Alert Configuration

**Start Simple**
- Begin with critical events only
- Add rules gradually
- Test each rule thoroughly
- Adjust cooldown periods based on frequency

**Reduce Noise**
- Set appropriate thresholds
- Use cooldown periods effectively
- Combine similar alerts
- Filter out expected events

**Tune Continuously**
- Review triggered alerts weekly
- Disable rules that fire too often
- Add rules for new threats
- Update actions as team changes

### Security Investigation

**Be Thorough**
- Don't stop at first finding
- Correlate multiple data points
- Check for related activity
- Document all findings

**Act Quickly**
- Investigate alerts within 24 hours
- Respond to security events immediately
- Document response actions
- Follow up on remediation

**Learn and Improve**
- Review past incidents
- Update alert rules
- Improve detection capability
- Share lessons learned

### Compliance Management

**Proactive Approach**
- Review compliance tags quarterly
- Update retention policies annually
- Take a test export before you need a real one, so you find out about the
  10,000-event cap on your own schedule rather than an auditor's
- Maintain audit readiness

**Documentation**
- Document all compliance processes
- Maintain evidence files
- Keep audit reports organized
- Version control policies

**Automation**
- Script the export endpoint against a personal API token rather than repeating
  the pull by hand — the console has no scheduler for it
- Configure retention policies so the trail still holds the period you will be
  asked about

---

**Last Updated:** 2026-09-16
