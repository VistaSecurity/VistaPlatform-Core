package audit

// AuditMetadata provides rich context for audit log entries
type AuditMetadata struct {
	ResourceName     string                 `json:"resource_name"`     // Human-readable name
	RelatedResources []RelatedResource      `json:"related_resources"` // Linked resources
	BusinessContext  string                 `json:"business_context"`  // Why action taken
	ChangeSummary    string                 `json:"change_summary"`    // Human-readable summary
	AdditionalData   map[string]interface{} `json:"additional_data"`   // Service-specific data
}

// RelatedResource represents a resource linked to the audit event
type RelatedResource struct {
	Type string `json:"type"` // e.g., "asset", "certificate", "finding"
	ID   string `json:"id"`   // UUID
	Name string `json:"name"` // Human-readable name
}

// Standard event categories
const (
	EventCategoryAsset       = "asset"
	EventCategoryCertificate = "certificate"
	EventCategoryUser        = "user"
	EventCategoryAuth        = "authentication"
	EventCategoryCompliance  = "compliance"
	EventCategoryReport      = "report"
	EventCategoryDiscovery   = "discovery"
	EventCategorySensor      = "sensor"
	EventCategoryConfig      = "configuration"
	EventCategorySystem      = "system"
	EventCategoryData        = "data"
)

// Standard event types by category
const (
	// Asset events
	EventTypeAssetCreated  = "asset.created"
	EventTypeAssetUpdated  = "asset.updated"
	EventTypeAssetDeleted  = "asset.deleted"
	EventTypeAssetApproved = "asset.approved"
	EventTypeAssetDenied   = "asset.denied"
	EventTypeAssetExported = "asset.exported"

	// Certificate events
	EventTypeCertificateUploaded   = "certificate.uploaded"
	EventTypeCertificateDeleted    = "certificate.deleted"
	EventTypeCertificateChainBuilt = "certificate.chain_built"
	EventTypeCertificateExpiring   = "certificate.expiring"
	EventTypeCertificateRevoked    = "certificate.revoked"

	// User events
	EventTypeUserCreated         = "user.created"
	EventTypeUserUpdated         = "user.updated"
	EventTypeUserDeleted         = "user.deleted"
	EventTypeUserLogin           = "user.login"
	EventTypeUserLoginFailed     = "user.login.failed"
	EventTypeUserLogout          = "user.logout"
	EventTypeUserPasswordChanged = "user.password.changed"

	// Role/Permission events (tenant-scoped)
	EventTypeRoleAssigned      = "role.assigned"
	EventTypeRoleRevoked       = "role.revoked"
	EventTypePermissionGranted = "permission.granted"
	EventTypePermissionRevoked = "permission.revoked"

	// Compliance events
	EventTypeComplianceAssessmentStarted   = "compliance.assessment.started"
	EventTypeComplianceAssessmentCompleted = "compliance.assessment.completed"
	EventTypeOverrideCreated               = "override.created"
	EventTypeOverrideApproved              = "override.approved"
	EventTypeOverrideRejected              = "override.rejected"
	EventTypeFindingAssigned               = "finding.assigned"
	EventTypeFindingStatusChanged          = "finding.status_changed"
	EventTypeTicketCreated                 = "ticket.created"
	EventTypeTicketUpdated                 = "ticket.updated"
	EventTypeTicketClosed                  = "ticket.closed"

	// Report events
	EventTypeReportGenerated          = "report.generated"
	EventTypeReportDownloaded         = "report.downloaded"
	EventTypeReportTemplateCustomized = "report_template.customized"
	EventTypeScheduledReportCreated   = "scheduled_report.created"
	EventTypeScheduledReportModified  = "scheduled_report.modified"
	EventTypeScheduledReportDeleted   = "scheduled_report.deleted"

	// Discovery events
	EventTypeDiscoveryJobCreated   = "discovery.job.created"
	EventTypeDiscoveryJobCompleted = "discovery.job.completed"
	EventTypeDiscoveryJobFailed    = "discovery.job.failed"

	// Sensor events
	EventTypeSensorRegistered    = "sensor.registered"
	EventTypeSensorConfigChanged = "sensor.config_changed"
	EventTypeSensorDeactivated   = "sensor.deactivated"
	EventTypeSensorHealthCheck   = "sensor.health_check"

	// Network space events (legacy)
	EventTypeNetworkSpaceCreated     = "network_space.created"
	EventTypeNetworkSpaceAssetTagged = "network_space.asset_tagged"

	// Network segment events
	EventTypeNetworkSegmentCreated     = "network_segment.created"
	EventTypeNetworkSegmentUpdated     = "network_segment.updated"
	EventTypeNetworkSegmentDeleted     = "network_segment.deleted"
	EventTypeNetworkSegmentAssetTagged = "network_segment.asset_tagged"

	// System events
	EventTypeSystemConfigChanged = "system.config.changed"
	EventTypeSecurityAlert       = "security.alert"
	EventTypeIncidentCreated     = "incident.created"
)

// ComplianceFrameworks that may apply to events
var ComplianceFrameworks = map[string][]string{
	"asset":          {"soc2", "iso27001", "hipaa", "pci_dss"},
	"certificate":    {"soc2", "iso27001", "pci_dss"},
	"user":           {"soc2", "iso27001", "gdpr", "hipaa"},
	"authentication": {"soc2", "iso27001", "gdpr", "hipaa", "pci_dss"},
	"compliance":     {"soc2", "iso27001", "gdpr", "hipaa", "pci_dss"},
	"data":           {"soc2", "iso27001", "gdpr", "hipaa", "pci_dss"},
	"report":         {"soc2", "iso27001"},
}
