package handlers

import (
	"encoding/json"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
)

// The shape returned by GET /jobs/{id}/results.
//
// This is a PROJECTION of device_jobs.results, never a passthrough. The stored
// payload is whatever the agent sent, and an agent talking to a vendor API can
// pick up material we have no business publishing — the UniFi collector used to
// return the controller's mesh PSK and per-device auth keys inside its metadata.
// Enumerating the fields we serve means a vendor field we have never seen
// cannot reach the browser just because someone added it upstream.
//
// Asset.Metadata is the one open-ended field, so it is additionally passed
// through deviceinterrogation.RedactMap on the way out.

// JobResultCertificate is one certificate in a discovered asset's chain.
type JobResultCertificate struct {
	SubjectDN         string   `json:"subject_dn,omitempty"`
	IssuerDN          string   `json:"issuer_dn,omitempty"`
	SerialNumber      string   `json:"serial_number,omitempty"`
	FingerprintSHA256 string   `json:"fingerprint_sha256,omitempty"`
	NotBefore         string   `json:"not_before,omitempty"`
	NotAfter          string   `json:"not_after,omitempty"`
	KeyAlgorithm      string   `json:"key_algorithm,omitempty"`
	KeySize           int      `json:"key_size,omitempty"`
	SignatureAlg      string   `json:"signature_alg,omitempty"`
	SubjectAltNames   []string `json:"subject_alternative_names,omitempty"`
	SelfSigned        bool     `json:"self_signed,omitempty"`
}

// JobResultAsset is one asset the interrogation discovered.
type JobResultAsset struct {
	Hostname  string `json:"hostname,omitempty"`
	IPAddress string `json:"ip_address,omitempty"`
	Port      int    `json:"port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	AssetType string `json:"asset_type,omitempty"`

	ProtocolVersion      string   `json:"protocol_version,omitempty"`
	CipherSuite          string   `json:"cipher_suite,omitempty"`
	KeyExchangeAlgorithm string   `json:"key_exchange_algorithm,omitempty"`
	HashAlgorithm        string   `json:"hash_algorithm,omitempty"`
	KeySize              int      `json:"key_size,omitempty"`
	TLSVersions          []string `json:"tls_versions,omitempty"`
	SupportedCiphers     []string `json:"supported_ciphers,omitempty"`

	CertValidationStatus string                 `json:"cert_validation_status,omitempty"`
	CertValidationError  string                 `json:"cert_validation_error,omitempty"`
	Certificates         []JobResultCertificate `json:"certificates,omitempty"`

	ServiceName string `json:"service_name,omitempty"`

	// CryptoObserved distinguishes an asset whose TLS posture was actually
	// measured from one that was only listed by a management API. Without it a
	// row with no cipher reads as "nothing found" when the truth is "never
	// probed" — the same honesty as a risk score of 0 meaning NOT ASSESSED.
	CryptoObserved bool `json:"crypto_observed"`

	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

// JobResultsResponse is the results endpoint's payload.
type JobResultsResponse struct {
	JobID   string            `json:"job_id"`
	Status  string            `json:"status"`
	Success *bool             `json:"success,omitempty"`
	Assets  []JobResultAsset  `json:"assets"`
	Summary JobResultsSummary `json:"summary"`
	// Processing is the post-processing verdict written by the result processor:
	// per-asset outcomes and any errors. Absent for jobs that ran before it
	// existed, or that produced no assets.
	Processing map[string]interface{} `json:"processing,omitempty"`
}

// JobResultsSummary is the headline count set.
type JobResultsSummary struct {
	TotalAssets int `json:"total_assets"`
	// WithCrypto counts assets whose TLS posture was genuinely observed.
	WithCrypto       int `json:"with_crypto"`
	WithCertificates int `json:"with_certificates"`
	// Materialized is how many assets became a discovery finding. It comes from
	// the processing log, NOT from the asset count, so a pipeline failure shows
	// up as "12 discovered / 0 materialized" instead of hiding behind the total.
	Materialized *int `json:"materialized,omitempty"`
}

// rawJobResults mirrors the stored agent payload closely enough to project it.
type rawJobResults struct {
	Success *bool `json:"success"`
	Assets  []struct {
		Hostname  string `json:"hostname"`
		IPAddress string `json:"ip_address"`
		Port      int    `json:"port"`
		Protocol  string `json:"protocol"`
		AssetType string `json:"asset_type"`

		ProtocolVersion      string   `json:"protocol_version"`
		CipherSuite          string   `json:"cipher_suite"`
		KeyExchangeAlgorithm string   `json:"key_exchange_algorithm"`
		HashAlgorithm        string   `json:"hash_algorithm"`
		KeySize              int      `json:"key_size"`
		TLSVersions          []string `json:"tls_versions"`
		SupportedCiphers     []string `json:"supported_ciphers"`

		CertValidationStatus string `json:"cert_validation_status"`
		CertValidationError  string `json:"cert_validation_error"`
		Certificates         []struct {
			SubjectDN         string   `json:"subject_dn"`
			IssuerDN          string   `json:"issuer_dn"`
			SerialNumber      string   `json:"serial_number"`
			FingerprintSHA256 string   `json:"fingerprint_sha256"`
			NotBefore         string   `json:"not_before"`
			NotAfter          string   `json:"not_after"`
			KeyAlgorithm      string   `json:"key_algorithm"`
			KeySize           int      `json:"key_size"`
			SignatureAlg      string   `json:"signature_alg"`
			SubjectAltNames   []string `json:"subject_alternative_names"`
		} `json:"certificates"`

		ServiceHints *struct {
			ServiceName string `json:"service_name"`
		} `json:"service_hints"`

		Metadata map[string]interface{} `json:"metadata"`
	} `json:"assets"`
	Processing map[string]interface{} `json:"processing"`
}

// buildJobResults projects the stored results JSON onto the response shape.
// An unparseable or empty payload yields an empty (not nil) asset list.
func buildJobResults(jobID, status, resultsJSON string) JobResultsResponse {
	out := JobResultsResponse{
		JobID:  jobID,
		Status: status,
		Assets: []JobResultAsset{},
	}
	if resultsJSON == "" {
		return out
	}

	var raw rawJobResults
	if err := json.Unmarshal([]byte(resultsJSON), &raw); err != nil {
		return out
	}

	out.Success = raw.Success
	out.Processing = deviceinterrogation.RedactMap(raw.Processing)

	for _, a := range raw.Assets {
		asset := JobResultAsset{
			Hostname:             a.Hostname,
			IPAddress:            a.IPAddress,
			Port:                 a.Port,
			Protocol:             a.Protocol,
			AssetType:            a.AssetType,
			ProtocolVersion:      a.ProtocolVersion,
			CipherSuite:          a.CipherSuite,
			KeyExchangeAlgorithm: a.KeyExchangeAlgorithm,
			HashAlgorithm:        a.HashAlgorithm,
			KeySize:              a.KeySize,
			TLSVersions:          a.TLSVersions,
			SupportedCiphers:     a.SupportedCiphers,
			CertValidationStatus: a.CertValidationStatus,
			CertValidationError:  a.CertValidationError,
			Metadata:             deviceinterrogation.RedactMap(a.Metadata),
		}
		if a.ServiceHints != nil {
			asset.ServiceName = a.ServiceHints.ServiceName
		}
		for _, c := range a.Certificates {
			asset.Certificates = append(asset.Certificates, JobResultCertificate{
				SubjectDN:         c.SubjectDN,
				IssuerDN:          c.IssuerDN,
				SerialNumber:      c.SerialNumber,
				FingerprintSHA256: c.FingerprintSHA256,
				NotBefore:         c.NotBefore,
				NotAfter:          c.NotAfter,
				KeyAlgorithm:      c.KeyAlgorithm,
				KeySize:           c.KeySize,
				SignatureAlg:      c.SignatureAlg,
				SubjectAltNames:   c.SubjectAltNames,
				SelfSigned:        c.SubjectDN != "" && c.SubjectDN == c.IssuerDN,
			})
		}

		// A cipher suite or negotiated version is the evidence of a real
		// handshake. A management API listing gives neither.
		asset.CryptoObserved = a.CipherSuite != "" || a.ProtocolVersion != ""

		out.Assets = append(out.Assets, asset)
		out.Summary.TotalAssets++
		if asset.CryptoObserved {
			out.Summary.WithCrypto++
		}
		if len(asset.Certificates) > 0 {
			out.Summary.WithCertificates++
		}
	}

	if raw.Processing != nil {
		if v, ok := raw.Processing["materialized"].(float64); ok {
			n := int(v)
			out.Summary.Materialized = &n
		}
	}

	return out
}
