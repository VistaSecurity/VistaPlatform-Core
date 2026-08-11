package services

import (
	"fmt"
	"strings"
)

// RemediationTemplateService generates contextual remediation text from templates.
type RemediationTemplateService struct{}

// NewRemediationTemplateService returns a new template service.
func NewRemediationTemplateService() *RemediationTemplateService {
	return &RemediationTemplateService{}
}

// TemplateDef holds a template string and its placeholders.
type TemplateDef struct {
	FindingType string
	Severity    string
	Template    string
}

var defaultTemplates = []TemplateDef{
	{"expiring_cert", "high", "Renew certificate {cert_cn} on {server_name} ({ip}:{port}) at {location} / {environment}. Service: {service_name}. Current expiry: {expiry_date}."},
	{"expiring_cert", "critical", "URGENT: Replace expired certificate {cert_cn} on {server_name} ({ip}:{port}) at {location} / {environment}. Expired: {expiry_date}."},
	{"expired_cert", "critical", "URGENT: Replace expired certificate {cert_cn} on {server_name} ({ip}:{port}) at {location} / {environment}. Expired: {expiry_date}."},
	{"weak_cipher", "high", "Update cipher suite configuration for {service_name} on {server_name} ({ip}:{port}) at {location} / {environment}. Current: {cipher_suite}. Remove weak ciphers and enable AEAD suites."},
	{"weak_cipher", "medium", "Update cipher suite configuration for {service_name} on {server_name} ({ip}:{port}) at {location} / {environment}. Current: {cipher_suite}."},
	{"deprecated_protocol", "medium", "Disable {protocol_version} on {service_name} on {server_name} ({ip}:{port}) at {location} / {environment}. Minimum recommended: TLS 1.2."},
	{"weak_key_exchange", "medium", "Update key exchange configuration for {service_name} on {server_name} ({ip}:{port}) at {location} / {environment}. Current: {key_exchange}. Upgrade to ECDHE with >= 256-bit curves."},
	{"small_key_size", "medium", "Regenerate keys for {service_name} on {server_name} ({ip}:{port}) at {location} / {environment}. Current key size: {key_size} bits. Minimum recommended: 2048 for RSA, 256 for ECDSA."},
}

// GetTemplates returns all available remediation templates (finding_type, severity, template, placeholders).
func (s *RemediationTemplateService) GetTemplates() []map[string]interface{} {
	out := make([]map[string]interface{}, 0, len(defaultTemplates))
	seen := make(map[string]bool)
	for _, t := range defaultTemplates {
		key := t.FindingType + ":" + t.Severity
		if seen[key] {
			continue
		}
		seen[key] = true
		placeholders := extractPlaceholders(t.Template)
		out = append(out, map[string]interface{}{
			"finding_type": t.FindingType,
			"severity":     t.Severity,
			"template":     t.Template,
			"placeholders": placeholders,
		})
	}
	return out
}

func extractPlaceholders(tpl string) []string {
	var list []string
	seen := make(map[string]bool)
	for {
		i := strings.Index(tpl, "{")
		if i < 0 {
			break
		}
		j := strings.Index(tpl[i:], "}")
		if j < 0 {
			break
		}
		j += i
		name := tpl[i+1 : j]
		if !seen[name] {
			seen[name] = true
			list = append(list, name)
		}
		tpl = tpl[j+1:]
	}
	return list
}

// GenerateRemediationText fills a template with the given placeholders.
// placeholders is a map of placeholder name -> value (e.g. cert_cn, server_name, ip, port, location, environment, service_name, expiry_date, cipher_suite, protocol_version, key_exchange, key_size).
func (s *RemediationTemplateService) GenerateRemediationText(findingType, severity string, placeholders map[string]string) string {
	for _, t := range defaultTemplates {
		if t.FindingType == findingType && t.Severity == severity {
			return s.fillTemplate(t.Template, placeholders)
		}
	}
	// Fallback: use first matching finding_type
	for _, t := range defaultTemplates {
		if t.FindingType == findingType {
			return s.fillTemplate(t.Template, placeholders)
		}
	}
	return ""
}

func (s *RemediationTemplateService) fillTemplate(tpl string, m map[string]string) string {
	for k, v := range m {
		tpl = strings.ReplaceAll(tpl, "{"+k+"}", v)
	}
	// Remove any remaining placeholders
	for {
		i := strings.Index(tpl, "{")
		if i < 0 {
			break
		}
		j := strings.Index(tpl[i:], "}")
		if j < 0 {
			break
		}
		j += i
		tpl = tpl[:i] + "(missing)" + tpl[j+1:]
	}
	return tpl
}

// GenerateFromQueueRow builds placeholders from a RemediationQueueRow and calls GenerateRemediationText.
func (s *RemediationTemplateService) GenerateFromQueueRow(findingType, severity string, serverName, ip, port, location, locationPath, env, serviceName, detailText string) string {
	portStr := port
	if portStr == "" {
		portStr = "—"
	}
	m := map[string]string{
		"server_name":      serverName,
		"ip":               ip,
		"port":             portStr,
		"location":         location,
		"location_path":    locationPath,
		"environment":      env,
		"service_name":     serviceName,
		"cert_cn":          "(certificate)",
		"expiry_date":      "",
		"cipher_suite":     "",
		"protocol_version": "",
		"key_exchange":     "",
		"key_size":         "",
	}
	if serverName != "" {
		m["server_name"] = serverName
	}
	if ip != "" {
		m["ip"] = ip
	}
	if portStr != "" {
		m["port"] = portStr
	}
	if location != "" {
		m["location"] = location
	}
	if locationPath != "" {
		m["location"] = locationPath
	}
	if env != "" {
		m["environment"] = env
	}
	if serviceName != "" {
		m["service_name"] = serviceName
	}
	// Use detail_text for extra context where applicable
	if detailText != "" {
		m["detail"] = detailText
	}
	return s.GenerateRemediationText(findingType, severity, m)
}

// ShortTitle returns a one-line title for a finding (used when detail_text is from mv).
func ShortTitle(findingType, severity, detailText string) string {
	switch findingType {
	case "expiring_cert", "expired_cert":
		return fmt.Sprintf("Certificate: %s", detailText)
	case "weak_cipher":
		return fmt.Sprintf("Weak cipher: %s", detailText)
	case "deprecated_protocol":
		return fmt.Sprintf("Deprecated protocol: %s", detailText)
	default:
		return detailText
	}
}
