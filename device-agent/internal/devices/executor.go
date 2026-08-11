package devices

import (
	"context"
	"fmt"
	"time"

	"github.com/vistasecurity/vistaplatform/device-agent/internal/api"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/audit"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/security"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
)

// JobExecutor executes device interrogation jobs. The vendor/protocol logic
// lives in the shared deviceinterrogation core; this executor is a thin agent
// wrapper that decrypts credentials locally, runs the shared interrogator, and
// POSTs the results home. The in-cluster platform agent wraps the same core.
type JobExecutor struct {
	apiClient   *api.OutboundClient
	config      *config.Config
	registry    *di.Registry
	auditLogger *audit.AuditLogger
}

// NewJobExecutor creates a new job executor.
func NewJobExecutor(apiClient *api.OutboundClient, cfg *config.Config) *JobExecutor {
	return &JobExecutor{
		apiClient: apiClient,
		config:    cfg,
		registry:  di.NewRegistry(),
	}
}

// NewJobExecutorWithAudit creates a new job executor with audit logging enabled.
func NewJobExecutorWithAudit(apiClient *api.OutboundClient, cfg *config.Config, auditLogger *audit.AuditLogger) *JobExecutor {
	return &JobExecutor{
		apiClient:   apiClient,
		config:      cfg,
		registry:    di.NewRegistry(),
		auditLogger: auditLogger,
	}
}

// Execute executes a device interrogation job.
func (e *JobExecutor) Execute(job *models.Job) error {
	switch job.Type {
	case "device_interrogation":
		return e.executeDeviceInterrogation(job)
	case "cloud_discovery":
		return e.executeCloudDiscovery(job)
	default:
		return fmt.Errorf("unknown job type: %s", job.Type)
	}
}

// executeDeviceInterrogation executes a device interrogation job.
func (e *JobExecutor) executeDeviceInterrogation(job *models.Job) error {
	// Decrypt credentials (in-memory only)
	decryptedCreds, err := security.DecryptCredentials(job.Credentials, job.ID.String(), e.config.RegistrationKey)
	if err != nil {
		return e.submitFailure(job, fmt.Sprintf("Failed to decrypt credentials: %v", err))
	}
	defer security.ClearCredentials(decryptedCreds)

	// Extract device type from parameters or job
	deviceType := job.DeviceType
	if deviceType == "" {
		if dt, ok := job.Parameters["device_type"].(string); ok {
			deviceType = dt
		}
	}
	if deviceType == "" {
		return e.submitFailure(job, "device_type not specified in job")
	}

	interrogator, err := e.registry.Get(deviceType)
	if err != nil {
		return e.submitFailure(job, fmt.Sprintf("Unsupported device type: %s", deviceType))
	}

	device := buildDeviceInfo(deviceType, job.Parameters)
	creds := buildCredentials(decryptedCreds, job.Parameters)

	ctx := context.Background()
	result, err := interrogator.Interrogate(ctx, device, creds)
	if err != nil {
		if e.auditLogger != nil {
			e.auditLogger.LogInterrogation(job.ID.String(), device.IPAddress, deviceType, "failure",
				map[string]interface{}{"job_type": job.Type}, err)
		}
		return e.submitFailure(job, fmt.Sprintf("Device interrogation failed: %v", err))
	}

	if e.auditLogger != nil {
		e.auditLogger.LogInterrogation(job.ID.String(), device.IPAddress, deviceType, "success",
			map[string]interface{}{"job_type": job.Type, "asset_count": len(result.Assets)}, nil)
	}

	assets := convertInterrogateResult(result)

	jobResult := &models.JobResult{
		JobID:       job.ID,
		Success:     true,
		Assets:      assets,
		Metadata:    result.DeviceInfo,
		CompletedAt: time.Now(),
	}

	security.ClearCredentials(decryptedCreds)
	return e.apiClient.SubmitResult(jobResult)
}

// executeCloudDiscovery executes a cloud discovery job.
func (e *JobExecutor) executeCloudDiscovery(job *models.Job) error {
	return e.submitFailure(job, "Cloud discovery should be handled by platform service")
}

// submitFailure builds and submits a failed JobResult.
func (e *JobExecutor) submitFailure(job *models.Job, errMsg string) error {
	return e.apiClient.SubmitResult(&models.JobResult{
		JobID:       job.ID,
		Success:     false,
		Error:       errMsg,
		CompletedAt: time.Now(),
	})
}

// buildDeviceInfo maps job parameters onto the shared core's DeviceInfo.
func buildDeviceInfo(deviceType string, params map[string]interface{}) di.DeviceInfo {
	device := di.DeviceInfo{DeviceType: deviceType, Metadata: params}
	if v, ok := params["hostname"].(string); ok {
		device.Hostname = v
	}
	if v, ok := params["ip_address"].(string); ok {
		device.IPAddress = v
	}
	if v, ok := params["management_url"].(string); ok {
		device.ManagementURL = v
	}
	if v, ok := params["site_id"].(string); ok {
		device.SiteID = v
	}
	// SSH/management port — accept "ssh_port" or "port", encoded as a JSON number.
	if p, ok := params["ssh_port"].(float64); ok {
		device.Port = int(p)
	} else if p, ok := params["port"].(float64); ok {
		device.Port = int(p)
	}
	return device
}

// buildCredentials maps decrypted credentials + parameters onto the shared
// core's Credentials.
func buildCredentials(decrypted map[string]interface{}, params map[string]interface{}) di.Credentials {
	creds := di.Credentials{Custom: decrypted}
	if v, ok := decrypted["username"].(string); ok {
		creds.Username = v
	}
	if v, ok := decrypted["password"].(string); ok {
		creds.Password = v
	}
	if v, ok := decrypted["api_key"].(string); ok {
		creds.APIKey = v
	}
	if v, ok := decrypted["token"].(string); ok {
		creds.Token = v
	}
	// Per-device opt-out of TLS/host-key verification (self-signed appliance
	// mgmt endpoints, devices not yet in known_hosts). Defaults to false.
	if v, ok := params["insecure_skip_verify"].(bool); ok {
		creds.InsecureSkipVerify = v
	} else if v, ok := decrypted["insecure_skip_verify"].(bool); ok {
		creds.InsecureSkipVerify = v
	}
	return creds
}

// convertInterrogateResult maps the shared core's result onto the agent's
// enriched models.DiscoveredAsset format for platform submission.
func convertInterrogateResult(ir *di.InterrogateResult) []models.DiscoveredAsset {
	assets := make([]models.DiscoveredAsset, 0, len(ir.Assets))
	for i := range ir.Assets {
		ca := &ir.Assets[i]
		asset := models.DiscoveredAsset{
			Hostname:             ca.Hostname,
			IPAddress:            ca.IPAddress,
			Port:                 ca.Port,
			Protocol:             ca.Protocol,
			AssetType:            ca.AssetType,
			SupportedCiphers:     ca.SupportedCiphers,
			TLSVersions:          ca.TLSVersions,
			CertValidationStatus: ca.CertValidationStatus,
			CertValidationError:  ca.CertValidationError,
			Metadata:             ca.Metadata,
		}
		if ca.ProtocolVersion != nil {
			asset.ProtocolVersion = *ca.ProtocolVersion
		}
		if ca.CipherSuite != nil {
			asset.CipherSuite = *ca.CipherSuite
		}
		if ca.KeySize != nil {
			asset.KeySize = *ca.KeySize
		}
		if ca.KeyExchangeAlg != nil {
			asset.KeyExchangeAlgorithm = *ca.KeyExchangeAlg
		}
		if ca.HashAlgorithm != nil {
			asset.HashAlgorithm = *ca.HashAlgorithm
		}
		if ca.SSHInfo != nil {
			asset.SSHInfo = convertSSHInfo(ca.SSHInfo)
		}
		if ca.ServiceHints != nil {
			asset.ServiceHints = convertServiceHints(ca.ServiceHints)
		}
		if ca.Certificate != nil {
			asset.Certificate = convertCertInfo(ca.Certificate)
		}
		if len(ca.Certificates) > 0 {
			certs := make([]models.CertificateInfo, 0, len(ca.Certificates))
			for j := range ca.Certificates {
				certs = append(certs, *convertCertInfo(&ca.Certificates[j]))
			}
			asset.Certificates = certs
		}
		if ir.DeviceIdentity != nil {
			asset.DeviceInfo = convertDeviceIdentity(ir.DeviceIdentity)
		}
		assets = append(assets, asset)
	}
	return assets
}

func convertSSHInfo(s *di.SSHInfo) *models.SSHInfo {
	return &models.SSHInfo{
		Banner:               s.Banner,
		KeyTypes:             s.KeyTypes,
		HostKeyType:          s.HostKeyType,
		HostKeyFingerprint:   s.HostKeyFingerprint,
		KexAlgorithm:         s.KexAlgorithm,
		EncryptionAlgC2S:     s.EncryptionAlgC2S,
		EncryptionAlgS2C:     s.EncryptionAlgS2C,
		MACAlgC2S:            s.MACAlgC2S,
		MACAlgS2C:            s.MACAlgS2C,
		CompressionAlgorithm: s.CompressionAlgorithm,
	}
}

func convertServiceHints(s *di.ServiceHints) *models.ServiceHints {
	return &models.ServiceHints{
		ServiceName:          s.ServiceName,
		ServiceVersion:       s.ServiceVersion,
		Confidence:           s.Confidence,
		IdentificationMethod: s.IdentificationMethod,
	}
}

func convertDeviceIdentity(d *di.DeviceIdentity) *models.DeviceIdentity {
	return &models.DeviceIdentity{
		Vendor:          d.Vendor,
		Model:           d.Model,
		FirmwareVersion: d.FirmwareVersion,
		SerialNumber:    d.SerialNumber,
		OSVersion:       d.OSVersion,
	}
}

// convertCertInfo maps the shared/certificates.CertificateInfo (the core's
// canonical cert shape) onto the agent's models.CertificateInfo.
func convertCertInfo(c *di.CertificateInfo) *models.CertificateInfo {
	serial := c.SerialNumber
	if serial == "" {
		serial = c.Serial
	}
	return &models.CertificateInfo{
		SubjectDN:               c.SubjectDN,
		IssuerDN:                c.IssuerDN,
		SerialNumber:            serial,
		NotBefore:               c.NotBefore,
		NotAfter:                c.NotAfter,
		Fingerprint:             c.FingerprintSHA256,
		FingerprintSHA256:       c.FingerprintSHA256,
		FingerprintSHA1:         c.FingerprintSHA1,
		KeyAlgorithm:            c.KeyAlgorithm,
		KeySize:                 c.KeySize,
		SignatureAlgorithm:      c.SignatureAlg,
		IsCA:                    c.IsCA,
		CertificatePEM:          c.CertificatePEM,
		SubjectAlternativeNames: c.SubjectAlternativeNames,
		KeyUsage:                c.KeyUsage,
		ExtendedKeyUsage:        c.ExtendedKeyUsage,
		ChainOrder:              c.ChainOrder,
	}
}
