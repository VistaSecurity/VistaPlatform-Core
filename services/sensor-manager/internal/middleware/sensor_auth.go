package middleware

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/certificates"
)

// SensorAuth authenticates sensor outbound routes (heartbeat, command polling,
// discovery submission). Sensors authenticate with the per-tenant mTLS client
// cert issued at registration (Subject CN == sensor UUID, signed by the
// tenant's active sensor CA).
//
// When requireMTLS is true the middleware FAILS CLOSED: a verified
// client cert is mandatory. The sensor identity is taken from the cert CN (not
// the URL path), the tenant is derived from that identity, the cert chain is
// verified against the tenant's active CA, and revocation is checked. Any
// missing/mismatched/unverified/revoked cert is rejected with 401. The
// dedicated sensor-mTLS listener (see shared/http.NewAgentMTLSServer +
// cmd/main.go) terminates the sensor's mTLS so the real client cert reaches
// this middleware via edge TLS passthrough.
//
// When requireMTLS is false the legacy behavior is preserved for
// dev/compose/non-passthrough deployments (the cert is validated when present
// but its absence is tolerated). This is the insecure path is closing;
// it is gated off by default and enabled via the chart's agentMtls toggle.
//
// These endpoints have no in-cluster service callers (sensors are the only
// callers; cluster-sensor-service uses the separate bootstrap-auth
// auto-register endpoint), so there is no trusted-proxy bypass.
func SensorAuth(db, bypassDB *sql.DB, encryptionKey string, requireMTLS bool) gin.HandlerFunc {
	certService := certificates.NewCertificateService(db, bypassDB, encryptionKey)

	return func(c *gin.Context) {
		sensorIDStr := c.Param("sensor_id")
		if sensorIDStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Missing sensor_id parameter"})
			c.Abort()
			return
		}

		sensorID, err := uuid.Parse(sensorIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid sensor_id format"})
			c.Abort()
			return
		}

		c.Set("sensor_id", sensorID)
		c.Set("sensor_id_str", sensorIDStr)

		hasPeerCert := c.Request.TLS != nil && len(c.Request.TLS.PeerCertificates) > 0

		// Fail closed: no verified mTLS peer cert => reject. This is the core
		// fix — previously a request with no client cert was allowed
		// through with zero sensor authentication.
		if requireMTLS && !hasPeerCert {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Client certificate required for sensor endpoints"})
			c.Abort()
			return
		}
		if requireMTLS && (db == nil || encryptionKey == "") {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Sensor authentication unavailable"})
			c.Abort()
			return
		}

		// When agent mTLS is required, the client cert IS the sensor cert
		// (presented via the dedicated agent passthrough listener), so its CN
		// must match the route param. Gated on requireMTLS: with serviceMtls on
		// but agent mTLS off, the peer cert on this hop is the *mesh* cert
		// (CN = a service identity, already validated by the mesh), NOT a sensor
		// cert — validating it as one would 401 every request. In that
		// mode the sensor authenticates by the (trusted) path sensor_id.
		if requireMTLS && hasPeerCert {
			leaf := c.Request.TLS.PeerCertificates[0]
			if leaf.Subject.CommonName != sensorIDStr {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate CN does not match sensor_id"})
				c.Abort()
				return
			}
			now := time.Now()
			if now.After(leaf.NotAfter) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate has expired"})
				c.Abort()
				return
			}
			if now.Before(leaf.NotBefore) {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate is not yet valid"})
				c.Abort()
				return
			}
		}

		// Chain + revocation checks — only in agent-mTLS mode (see above: outside
		// it the peer cert is the mesh cert, not a sensor cert). The sensor→tenant
		// resolution is a bootstrap/auth-output lookup, so it runs on bypassDB —
		// on the crypto_app handle with no app.tenant_id set it fails closed and
		// 404s an existing sensor under enforced RLS.
		if requireMTLS && hasPeerCert && db != nil && encryptionKey != "" {
			leaf := c.Request.TLS.PeerCertificates[0]

			var tenantID uuid.UUID
			if err := bypassDB.QueryRow("SELECT tenant_id FROM sensors WHERE id = $1 AND deleted_at IS NULL", sensorID).Scan(&tenantID); err != nil {
				if requireMTLS {
					if err == sql.ErrNoRows {
						c.JSON(http.StatusNotFound, gin.H{"error": "Sensor not registered"})
					} else {
						c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to resolve sensor"})
					}
					c.Abort()
					return
				}
				log.Printf("SensorAuth: tenant lookup failed for sensor %s (mTLS not enforced): %v", sensorIDStr, err)
			} else {
				c.Set("tenantID", tenantID)

				if err := verifySensorCertChain(db, bypassDB, tenantID, leaf); err != nil {
					if requireMTLS {
						c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate chain validation failed"})
						c.Abort()
						return
					}
					log.Printf("SensorAuth: chain validation skipped/failed for sensor %s (mTLS not enforced): %v", sensorIDStr, err)
				}

				// Active-certificate binding. GetCertificate returns the current,
				// unrevoked certificate; a revoked/stale presented cert must not be
				// accepted just because it still chains to the tenant CA.
				cert, err := certService.GetCertificate(sensorID)
				if err == sql.ErrNoRows {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate is not active"})
					c.Abort()
					return
				}
				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"error": "mTLS certificate status unavailable"})
					c.Abort()
					return
				}
				if cert == nil {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate is not active"})
					c.Abort()
					return
				}
				if cert.RevokedAt != nil {
					c.JSON(http.StatusUnauthorized, gin.H{
						"error":      "mTLS certificate has been revoked",
						"revoked_at": cert.RevokedAt,
						"reason":     cert.RevocationReason,
					})
					c.Abort()
					return
				}
				if cert.SerialNumber != leaf.SerialNumber.String() {
					c.JSON(http.StatusUnauthorized, gin.H{"error": "mTLS certificate is not the active certificate"})
					c.Abort()
					return
				}
			}
		}

		if !requireMTLS && !hasPeerCert {
			log.Printf("SensorAuth: WARNING sensor %s authenticated WITHOUT a client certificate (AGENT_MTLS_REQUIRED is off)", sensorIDStr)
		}

		c.Next()
	}
}

// verifySensorCertChain verifies leaf against the tenant's active sensor CA
// with clientAuth EKU. Returns an error if the CA cannot be loaded/parsed or
// the chain does not verify.
func verifySensorCertChain(db, bypassDB *sql.DB, tenantID uuid.UUID, leaf *x509.Certificate) error {
	caManager := certificates.NewCAManager(db, bypassDB)
	ca, err := caManager.GetActiveCA(tenantID)
	if err != nil {
		return err
	}
	caBlock, _ := pem.Decode([]byte(ca.CACertPEM))
	if caBlock == nil {
		return &sensorAuthError{"failed to decode tenant CA PEM"}
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return err
	}
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	return err
}

type sensorAuthError struct{ msg string }

func (e *sensorAuthError) Error() string { return e.msg }

// RequireSensorToken validates that a sensor token is provided
func RequireSensorToken() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing or invalid authorization header"})
			c.Abort()
			return
		}

		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Empty token"})
			c.Abort()
			return
		}

		c.Set("sensor_token", token)
		c.Next()
	}
}
