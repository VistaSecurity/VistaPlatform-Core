package services

import (
	"context"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// Protocol normalization for DB lookup (seed uses TLS, SSH).
var protocolNorm = map[string]string{
	"HTTPS": "TLS", "TLS": "TLS", "SSL": "TLS",
	"SSH": "SSH",
}

type ServiceIdentificationService struct {
	db *database.DB
}

func NewServiceIdentificationService(db *database.DB) *ServiceIdentificationService {
	return &ServiceIdentificationService{db: db}
}

// IdentifyService returns service hints from raw_data (banner, JA3S stub, port heuristic).
// Order: 1) manual override on asset (caller checks), 2) SSH/SMTP/FTP banner in rawData, 3) JA3S stub, 4) port heuristic.
func (s *ServiceIdentificationService) IdentifyService(tenantID uuid.UUID, port int, protocol string, rawData map[string]interface{}) *models.ServiceHints {
	if rawData == nil {
		rawData = make(map[string]interface{})
	}

	// 2) Banner parsing (SSH, SMTP, FTP)
	if banner := getBannerFromRaw(rawData); banner != "" {
		if name, version := parseSSHBanner(banner); name != "" {
			return &models.ServiceHints{
				ServiceName:          name,
				ServiceVersion:       version,
				Confidence:           "high",
				IdentificationMethod: "banner",
				RawBanner:            banner,
			}
		}
		if name := parseSMTPBanner(banner); name != "" {
			return &models.ServiceHints{
				ServiceName:          name,
				Confidence:           "high",
				IdentificationMethod: "banner",
				RawBanner:            banner,
			}
		}
		if name, version := parseFTPBanner(banner); name != "" {
			return &models.ServiceHints{
				ServiceName:          name,
				ServiceVersion:       version,
				Confidence:           "high",
				IdentificationMethod: "banner",
				RawBanner:            banner,
			}
		}
	}

	// 3) JA3S stub (passive only; no mapping table in Phase 1)
	fp, _ := rawData["ja3s_fingerprint"].(string)
	if fp == "" {
		if nested, ok := rawData["raw_metadata"].(map[string]interface{}); ok {
			fp, _ = nested["ja3s_fingerprint"].(string)
		}
	}
	if fp != "" {
		// Could lookup fp in a future JA3S table; for now return generic TLS with medium confidence
		portName := s.GetPortHeuristic(tenantID, port, protocol)
		if portName == "" {
			portName = "TLS Service"
		}
		return &models.ServiceHints{
			ServiceName:          portName,
			JA3SFingerprint:      fp,
			Confidence:           "medium",
			IdentificationMethod: "ja3s",
		}
	}

	// 4) Port heuristic
	serviceName := s.GetPortHeuristic(tenantID, port, protocol)
	if serviceName == "" {
		return nil
	}
	return &models.ServiceHints{
		ServiceName:          serviceName,
		Confidence:           "low",
		IdentificationMethod: "port_heuristic",
	}
}

func getBannerFromRaw(rawData map[string]interface{}) string {
	if v, ok := rawData["ssh_banner"].(string); ok && v != "" {
		return v
	}
	if v, ok := rawData["banner"].(string); ok && v != "" {
		return v
	}
	if nested, ok := rawData["raw_metadata"].(map[string]interface{}); ok {
		if v, ok := nested["ssh_banner"].(string); ok && v != "" {
			return v
		}
		if v, ok := nested["banner"].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// GetPortHeuristic returns the service name for port+protocol from service_identification_rules (tenant then built-in).
func (s *ServiceIdentificationService) GetPortHeuristic(tenantID uuid.UUID, port int, protocol string) string {
	proto := protocolNorm[strings.ToUpper(protocol)]
	if proto == "" {
		proto = strings.ToUpper(protocol)
	}
	var name string
	// RLS-scoped: service_identification_rules carries the tenant_isolation policy.
	// The query intentionally also reads built-in rules (tenant_id IS NULL); today the
	// owner role bypasses RLS so wrapping is behavior-neutral. When RLS later enforces,
	// the policy must be extended to allow the tenant_id IS NULL built-in rows or this
	// fallback returns nothing (flagged for Phase 4).
	err := database.WithTenantTx(context.Background(), s.db, tenantID, func(tx *sqlx.Tx) error {
		// Prefer tenant-specific rule, then built-in
		return tx.QueryRow(`
			SELECT service_name FROM service_identification_rules
			WHERE port = $1 AND (protocol = $2 OR protocol = $3)
			AND (tenant_id = $4 OR tenant_id IS NULL)
			ORDER BY tenant_id DESC NULLS LAST
			LIMIT 1`,
			port, protocol, proto, tenantID).Scan(&name)
	})
	if err != nil {
		return ""
	}
	return name
}

var (
	sshBannerRe  = regexp.MustCompile(`(?i)SSH-2\.0-([^\s-]+)(?:_([^\s]+))?(?:\s|$)`)
	smtpBannerRe = regexp.MustCompile(`(?i)(?:220\s+[^\s]+\s+)?(?:ESMTP\s+)?(\w+)`)
	ftpBannerRe  = regexp.MustCompile(`(?i)220\s+[^\s]*\s+(\w+)(?:\s+([\d.]+))?(?:\s|$)`)
)

// parseSSHBanner extracts service name and version from SSH banner, e.g. "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".
func parseSSHBanner(banner string) (name, version string) {
	m := sshBannerRe.FindStringSubmatch(strings.TrimSpace(banner))
	if len(m) < 2 {
		return "", ""
	}
	name = m[1]
	if name == "OpenSSH" {
		name = "OpenSSH"
	} else if strings.HasPrefix(strings.ToLower(name), "dropbear") {
		name = "Dropbear SSH"
	}
	if len(m) >= 3 && m[2] != "" {
		version = m[2]
	}
	return name, version
}

// parseSMTPBanner extracts server name from SMTP banner, e.g. "220 mail.example.com ESMTP Postfix".
func parseSMTPBanner(banner string) (name string) {
	m := smtpBannerRe.FindStringSubmatch(strings.TrimSpace(banner))
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// parseFTPBanner extracts server name and version from FTP banner, e.g. "220 ProFTPD 1.3.6a".
func parseFTPBanner(banner string) (name, version string) {
	m := ftpBannerRe.FindStringSubmatch(strings.TrimSpace(banner))
	if len(m) < 2 {
		return "", ""
	}
	name = m[1]
	if len(m) >= 3 && m[2] != "" {
		version = m[2]
	}
	return name, version
}
