# Audit Logging User Guide

**Version:** 1.0  
**Last Updated:** 2026-02-02

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

Events are grouped into logical categories for easier filtering and analysis.

### Security
Events related to authentication, authorization, and security:
- Login attempts (success/failure)
- Password changes
- MFA changes
- Permission changes
- API key operations
- SSO events

### Asset
Events related to asset lifecycle:
- Asset CRUD operations
- Asset discovery
- Asset classification changes
- Certificate operations
- Key management

### Compliance
Events related to compliance and risk:
- Assessment operations
- Finding lifecycle
- Control evaluations
- Report generation
- Framework changes

### System
Platform-level events:
- Configuration changes
- Integration management
- Backup operations
- Service health events
- Performance events

### User
User management events:
- User lifecycle
- Role assignments
- Profile updates
- Preference changes

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
1. Navigate to Activity Logs
2. Click **Advanced Query**
3. Select compliance tags
4. Choose frameworks: soc2, iso27001, gdpr, hipaa, pci_dss
5. Run query

**Generating Compliance Reports**
1. Select framework
2. All tagged events included automatically
3. Generate on demand (running them on a schedule is an Enterprise capability)

---

## Activity Log Management

### Viewing Logs

**Basic Viewing**
1. Navigate to **Settings → Activity Logs**
2. Logs displayed in reverse chronological order
3. Use date range filter to focus on specific period
4. Default: Last 7 days

**Filtering Logs**
- **Date Range**: Select preset or custom range
- **Event Type**: Pick specific event types
- **Event Category**: Filter by category
- **Status**: Success or failure only
- **Search**: Free-text search across all fields

**Advanced Filtering**
1. Click **Advanced Query** button
2. Add multiple filter conditions
3. Combine with AND/OR logic
4. Save query for reuse
5. Export filtered results

### Searching Logs

**Quick Search**
Use the search box for simple queries:
- User email: `john@example.com`
- Resource ID: `asset-12345`
- Event type: `asset.created`
- IP address: `192.168.1.1`

**Advanced Search**
Build complex queries with multiple criteria:
1. Event types: Select multiple types
2. Users: Filter by specific users
3. Resources: Filter by resource type or ID
4. Compliance: Filter by compliance tags
5. Date ranges: Precise time windows

### Exporting Logs

**CSV Export**
1. Apply desired filters
2. Click **Export → CSV**
3. Opens in spreadsheet software
4. Good for manual analysis
5. Contains all visible columns

**JSON Export**
1. Apply desired filters
2. Click **Export → JSON**
3. Machine-readable format
4. Good for programmatic processing
5. Includes all metadata

**Export Tips**
- Export filters are applied
- Large exports may take time
- Maximum 10,000 events per export
- Use date ranges to limit size
- Schedule reports for regular exports

---

## Security Investigation Workflows

### Investigating Failed Logins

**Scenario**: Multiple failed login attempts detected

1. **Initial Investigation**
   - Navigate to Activity Logs
   - Filter by event type: `user.login.failed`
   - Set date range to recent period
   - Look for patterns (same user, same IP, time clustering)

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
   - Navigate to Activity Logs
   - Filter by event type: `*.updated` or `*.deleted`
   - Focus on relevant resource types
   - Identify when changes occurred

2. **Change Details**
   - Click on log entry
   - Review **changed_fields**
   - Compare **old_values** vs **new_values**
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

2. **Generate Activity Report**
   - Navigate to Activity Logs
   - Click Advanced Query
   - Select compliance tag: `soc2`
   - Set date range to audit period
   - Export as CSV or JSON

3. **Evidence Collection**
   - Filter for access control events
   - Export user authentication logs
   - Collect configuration change logs
   - Gather backup and recovery events

4. **Analysis**
   - Review for anomalies
   - Document any incidents
   - Verify controls functioning
   - Prepare explanations for auditors

5. **Reporting**
   - Generate the framework report and deliver it to the compliance team
   - Maintain historical reports

### GDPR Compliance Reporting

1. **Data Access Logging**
   - Filter for events with `gdpr` tag
   - Focus on personal data access
   - Export user data access logs
   - Document access purposes

2. **Data Subject Requests**
   - Search for specific user activity
   - Generate user activity timeline
   - Export complete user history
   - Include all personal data access

3. **Data Retention**
   - Configure retention policies
   - Set GDPR-compliant periods (730 days)
   - Document retention decisions
   - Implement automated deletion

4. **Regular Reporting**
   - Schedule monthly GDPR reports
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
- Review Alerts Dashboard
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
- Test report generation regularly
- Maintain audit readiness

**Documentation**
- Document all compliance processes
- Maintain evidence files
- Keep audit reports organized
- Version control policies

**Automation**
- Set up automatic exports
- Configure retention policies
- Automate evidence collection

---

**Last Updated:** 2026-02-02
