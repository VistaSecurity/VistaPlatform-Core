package gcp

// GCP Compute API response types for load balancer and TLS discovery

// TargetHTTPSProxy represents a GCP target HTTPS proxy resource
type TargetHTTPSProxy struct {
	Name              string   `json:"name"`
	SelfLink          string   `json:"selfLink"`
	URLMap            string   `json:"urlMap"`
	SSLPolicy         string   `json:"sslPolicy,omitempty"`
	SSLCertificates   []string `json:"sslCertificates"`
	Description       string   `json:"description,omitempty"`
	CreationTimestamp string   `json:"creationTimestamp,omitempty"`
}

// TargetSSLProxy represents a GCP target SSL proxy resource
type TargetSSLProxy struct {
	Name              string   `json:"name"`
	SelfLink          string   `json:"selfLink"`
	Service           string   `json:"service"`
	SSLPolicy         string   `json:"sslPolicy,omitempty"`
	SSLCertificates   []string `json:"sslCertificates"`
	Description       string   `json:"description,omitempty"`
	ProxyHeader       string   `json:"proxyHeader,omitempty"`
	CreationTimestamp string   `json:"creationTimestamp,omitempty"`
}

// SSLPolicy represents a GCP SSL policy resource
type SSLPolicy struct {
	Name              string   `json:"name"`
	SelfLink          string   `json:"selfLink"`
	Profile           string   `json:"profile"`         // COMPATIBLE, MODERN, RESTRICTED, CUSTOM
	MinTLSVersion     string   `json:"minTlsVersion"`   // TLS_1_0, TLS_1_1, TLS_1_2
	CustomFeatures    []string `json:"customFeatures"`  // Cipher suites for CUSTOM profile
	EnabledFeatures   []string `json:"enabledFeatures"` // Effective cipher suites
	Description       string   `json:"description,omitempty"`
	CreationTimestamp string   `json:"creationTimestamp,omitempty"`
}

// SSLCertificate represents a GCP SSL certificate resource
type SSLCertificate struct {
	Name                    string                 `json:"name"`
	SelfLink                string                 `json:"selfLink"`
	Type                    string                 `json:"type,omitempty"` // SELF_MANAGED or MANAGED
	SubjectAlternativeNames []string               `json:"subjectAlternativeNames,omitempty"`
	ExpireTime              string                 `json:"expireTime,omitempty"`
	Managed                 *ManagedSSLCertificate `json:"managed,omitempty"`
	Description             string                 `json:"description,omitempty"`
	CreationTimestamp       string                 `json:"creationTimestamp,omitempty"`
}

// ManagedSSLCertificate represents managed certificate details
type ManagedSSLCertificate struct {
	Domains      []string          `json:"domains,omitempty"`
	Status       string            `json:"status,omitempty"` // ACTIVE, PROVISIONING, etc.
	DomainStatus map[string]string `json:"domainStatus,omitempty"`
}

// ForwardingRule represents a GCP forwarding rule resource
type ForwardingRule struct {
	Name                string `json:"name"`
	SelfLink            string `json:"selfLink"`
	IPAddress           string `json:"IPAddress"`
	IPProtocol          string `json:"IPProtocol"`
	PortRange           string `json:"portRange"`
	Target              string `json:"target"`
	LoadBalancingScheme string `json:"loadBalancingScheme"` // EXTERNAL, INTERNAL
	Description         string `json:"description,omitempty"`
	CreationTimestamp   string `json:"creationTimestamp,omitempty"`
}

// List response wrappers for paginated API responses

type targetHTTPSProxyListResponse struct {
	Items         []TargetHTTPSProxy `json:"items"`
	NextPageToken string             `json:"nextPageToken"`
}

type targetSSLProxyListResponse struct {
	Items         []TargetSSLProxy `json:"items"`
	NextPageToken string           `json:"nextPageToken"`
}

type sslCertificateListResponse struct {
	Items         []SSLCertificate `json:"items"`
	NextPageToken string           `json:"nextPageToken"`
}

type forwardingRuleListResponse struct {
	Items         []ForwardingRule `json:"items"`
	NextPageToken string           `json:"nextPageToken"`
}

// --- Cloud KMS types ---

// KMSLocation represents a Cloud KMS location.
type KMSLocation struct {
	Name       string `json:"name"`
	LocationID string `json:"locationId"`
}

// KMSKeyRing represents a Cloud KMS key ring.
type KMSKeyRing struct {
	Name       string `json:"name"` // projects/{p}/locations/{loc}/keyRings/{kr}
	CreateTime string `json:"createTime,omitempty"`
}

// KMSCryptoKey represents a Cloud KMS crypto key.
type KMSCryptoKey struct {
	Name            string                  `json:"name"` // .../cryptoKeys/{key}
	Primary         *KMSCryptoKeyVersion    `json:"primary,omitempty"`
	Purpose         string                  `json:"purpose,omitempty"` // ENCRYPT_DECRYPT, ASYMMETRIC_SIGN, ...
	CreateTime      string                  `json:"createTime,omitempty"`
	NextRotation    string                  `json:"nextRotationTime,omitempty"`
	RotationPeriod  string                  `json:"rotationPeriod,omitempty"` // e.g. "7776000s"
	VersionTemplate *KMSCryptoKeyVersionTpl `json:"versionTemplate,omitempty"`
}

// KMSCryptoKeyVersion represents the primary version of a crypto key.
type KMSCryptoKeyVersion struct {
	Name            string `json:"name"`
	State           string `json:"state,omitempty"`           // ENABLED, DISABLED, DESTROYED, ...
	ProtectionLevel string `json:"protectionLevel,omitempty"` // SOFTWARE, HSM, EXTERNAL, ...
	Algorithm       string `json:"algorithm,omitempty"`
	CreateTime      string `json:"createTime,omitempty"`
}

// KMSCryptoKeyVersionTpl is the version template carried on a crypto key; it
// reports the algorithm/protection level even for asymmetric keys that have no
// primary version.
type KMSCryptoKeyVersionTpl struct {
	ProtectionLevel string `json:"protectionLevel,omitempty"`
	Algorithm       string `json:"algorithm,omitempty"`
}

type kmsLocationListResponse struct {
	Locations     []KMSLocation `json:"locations"`
	NextPageToken string        `json:"nextPageToken"`
}

type kmsKeyRingListResponse struct {
	KeyRings      []KMSKeyRing `json:"keyRings"`
	NextPageToken string       `json:"nextPageToken"`
}

type kmsCryptoKeyListResponse struct {
	CryptoKeys    []KMSCryptoKey `json:"cryptoKeys"`
	NextPageToken string         `json:"nextPageToken"`
}

// --- Cloud Storage types ---

// StorageBucket represents a Cloud Storage bucket (JSON API).
type StorageBucket struct {
	Name         string                   `json:"name"`
	Location     string                   `json:"location,omitempty"`
	StorageClass string                   `json:"storageClass,omitempty"`
	TimeCreated  string                   `json:"timeCreated,omitempty"`
	Encryption   *StorageBucketEncryption `json:"encryption,omitempty"`
}

// StorageBucketEncryption carries a bucket's default encryption configuration.
// When DefaultKmsKeyName is set the bucket uses a customer-managed CMEK; when
// empty it uses Google-managed (default) AES-256 encryption.
type StorageBucketEncryption struct {
	DefaultKmsKeyName string `json:"defaultKmsKeyName,omitempty"`
}

type storageBucketListResponse struct {
	Items         []StorageBucket `json:"items"`
	NextPageToken string          `json:"nextPageToken"`
}

// --- Cloud SQL types ---

// SQLInstance represents a Cloud SQL instance (Admin API).
type SQLInstance struct {
	Name                        string                   `json:"name"`
	DatabaseVersion             string                   `json:"databaseVersion,omitempty"` // POSTGRES_14, MYSQL_8_0, SQLSERVER_2019_STANDARD
	Region                      string                   `json:"region,omitempty"`
	BackendType                 string                   `json:"backendType,omitempty"`
	InstanceType                string                   `json:"instanceType,omitempty"`
	DiskEncryptionConfiguration *SQLDiskEncryptionConfig `json:"diskEncryptionConfiguration,omitempty"`
	Settings                    *SQLInstanceSettings     `json:"settings,omitempty"`
}

// SQLDiskEncryptionConfig carries a Cloud SQL instance's CMEK key, when set.
type SQLDiskEncryptionConfig struct {
	KmsKeyName string `json:"kmsKeyName,omitempty"`
}

// SQLInstanceSettings carries a subset of Cloud SQL instance settings.
type SQLInstanceSettings struct {
	Tier string `json:"tier,omitempty"`
}

type sqlInstanceListResponse struct {
	Items         []SQLInstance `json:"items"`
	NextPageToken string        `json:"nextPageToken"`
}

// MinTLSVersionToString converts GCP's TLS version enum to a human-readable string
func MinTLSVersionToString(v string) string {
	switch v {
	case "TLS_1_0":
		return "TLS 1.0"
	case "TLS_1_1":
		return "TLS 1.1"
	case "TLS_1_2":
		return "TLS 1.2"
	case "TLS_1_3":
		return "TLS 1.3"
	default:
		return v
	}
}
