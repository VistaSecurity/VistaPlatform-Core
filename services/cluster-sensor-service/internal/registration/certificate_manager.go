package registration

import (
	"log"
	"time"

	"github.com/google/uuid"
)

// MonitorCertificateExpiration monitors certificate expiration and triggers rotation when needed
func (s *AutoRegisterService) MonitorCertificateExpiration() {
	ticker := time.NewTicker(24 * time.Hour) // Check daily
	defer ticker.Stop()

	// Check immediately on startup
	s.checkAndRotateCertificates()

	for range ticker.C {
		s.checkAndRotateCertificates()
	}
}

// checkAndRotateCertificates checks all certificates and rotates those expiring within 30 days
func (s *AutoRegisterService) checkAndRotateCertificates() {
	s.certMutex.RLock()
	tenantIDs := make([]uuid.UUID, 0, len(s.certificates))
	for tenantID := range s.certificates {
		tenantIDs = append(tenantIDs, tenantID)
	}
	s.certMutex.RUnlock()

	now := time.Now()
	rotationThreshold := 30 * 24 * time.Hour // 30 days

	for _, tenantID := range tenantIDs {
		s.certMutex.RLock()
		cert := s.certificates[tenantID]
		s.certMutex.RUnlock()

		if cert == nil {
			continue
		}

		// Check if certificate is expiring within 30 days
		timeUntilExpiry := cert.ExpiresAt.Sub(now)
		if timeUntilExpiry <= rotationThreshold {
			log.Printf("🔄 Certificate for tenant %s expiring in %v, initiating rotation...", tenantID, timeUntilExpiry)
			if err := s.RegisterForTenant(tenantID); err != nil {
				log.Printf("⚠️  Failed to rotate certificate for tenant %s: %v", tenantID, err)
			} else {
				log.Printf("✅ Certificate rotated successfully for tenant %s", tenantID)
			}
		}
	}
}
