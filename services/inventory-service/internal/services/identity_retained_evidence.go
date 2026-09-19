package services

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

const retainedEvidenceLimit = 50
const retainedCertificateLimit = 10

// RetainedEvidencePage projects typed evidence, never the replay payload. List
// APIs omit it; a detail read is bounded independently of sighting frequency.
type RetainedEvidencePage struct {
	Items   []RetainedEvidenceSummary `json:"items"`
	Total   int                       `json:"total"`
	Limit   int                       `json:"limit"`
	HasMore bool                      `json:"has_more"`
}
type RetainedEvidenceSummary struct {
	keyFingerprints           map[string]bool
	endpointKeys              map[string]bool
	certificateFingerprints   map[string]bool
	Kind                      string                       `json:"kind"`
	Scope                     string                       `json:"scope"`
	SourceRef                 string                       `json:"source_ref"`
	ObservedAt                *time.Time                   `json:"observed_at"`
	CollectorVersion          string                       `json:"collector_version,omitempty"`
	MaterializationState      string                       `json:"materialization_state"`
	Reason                    string                       `json:"reason,omitempty"`
	FactsCount                int                          `json:"facts_count"`
	SoftwareCount             int                          `json:"software_count"`
	EndpointsCount            int                          `json:"endpoints_count"`
	RelationshipsCount        int                          `json:"relationships_count"`
	Protocols                 []string                     `json:"protocols"`
	CertificatesCount         int                          `json:"certificates_count"`
	Certificates              []RetainedCertificateSummary `json:"certificates"`
	KeysCount                 int                          `json:"keys_count"`
	CryptoConfigurationsCount int                          `json:"crypto_configurations_count"`
}
type RetainedCertificateSummary struct {
	SHA256Fingerprint string     `json:"sha256_fingerprint"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	Expired           *bool      `json:"expired,omitempty"`
	SelfSigned        *bool      `json:"self_signed,omitempty"`
}

func (s *AssetService) retainedEvidence(ctx context.Context, tx *sqlx.Tx, tenant uuid.UUID, observation IdentityObservation) (*RetainedEvidencePage, error) {
	page := &RetainedEvidencePage{Items: []RetainedEvidenceSummary{}, Limit: retainedEvidenceLimit}
	waitingReason := "waiting_for_identity"
	if observation.AssetID != nil {
		var status string
		var deleted bool
		err := tx.QueryRowContext(ctx, `SELECT asset_status,deleted_at IS NOT NULL FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, *observation.AssetID).Scan(&status, &deleted)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		switch {
		case errors.Is(err, sql.ErrNoRows) || deleted:
			waitingReason = "linked_asset_unavailable"
		case status == "pending_approval":
			waitingReason = "waiting_for_approval"
		case status != "monitoring":
			waitingReason = "linked_asset_not_monitoring"
		default:
			waitingReason = "waiting_for_materialization"
		}
	}

	// Count before LIMIT. Payloads over one MiB still get a receipt summary but
	// are not decrypted/decoded into API memory. No arbitrary JSON is returned.
	rows, err := tx.QueryContext(ctx, `WITH evidence AS (
 SELECT CASE WHEN p.payload->>'kind'='host_observation' THEN 'passive_host' ELSE 'crypto' END AS kind,p.receipt_key AS key,
 r.observed_at,p.materialized_at,NULL::timestamptz AS superseded_at,p.last_error<>'' AS failed,
 p.payload::text AS payload,COALESCE(r.evidence,'{}'::jsonb) AS envelope,false AS encrypted
 FROM identity_observation_payloads p LEFT JOIN identity_observation_receipts r ON r.tenant_id=p.tenant_id AND r.observation_id=p.observation_id AND r.receipt_key=p.receipt_key
 WHERE p.tenant_id=$1 AND p.observation_id=$2
 UNION ALL SELECT 'host_inventory',receipt_key,observed_at,materialized_at,superseded_at,last_error<>'',payload::text,observation,false
 FROM identity_observation_host_inventories WHERE tenant_id=$1 AND observation_id=$2
 UNION ALL SELECT 'peer',context_id,observed_at,materialized_at,NULL::timestamptz,last_error<>'',payload::text,'{}'::jsonb,false
 FROM identity_observation_peer_contexts WHERE tenant_id=$1 AND observation_id=$2
 UNION ALL SELECT 'cloud',receipt_key,observed_at,materialized_at,NULL::timestamptz,last_error<>'',context_enc,'{}'::jsonb,true
 FROM identity_observation_cloud_contexts WHERE tenant_id=$1 AND observation_id=$2
 ) SELECT kind,observed_at,materialized_at,superseded_at,failed,
 CASE WHEN octet_length(payload)<=1048576 THEN payload ELSE '' END,envelope,encrypted,count(*) OVER()
 FROM evidence ORDER BY observed_at DESC NULLS LAST,kind,key LIMIT $3`, tenant, observation.ID, retainedEvidenceLimit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		item := RetainedEvidenceSummary{Scope: "observation", SourceRef: observation.SourceRef, Protocols: []string{}, Certificates: []RetainedCertificateSummary{}}
		var materialized, superseded *time.Time
		var failed, encrypted bool
		var payload string
		var envelope []byte
		if err := rows.Scan(&item.Kind, &item.ObservedAt, &materialized, &superseded, &failed, &payload, &envelope, &encrypted, &page.Total); err != nil {
			return nil, err
		}
		item.MaterializationState = "pending"
		switch {
		case materialized != nil:
			item.MaterializationState = "completed"
		case superseded != nil:
			item.MaterializationState = "superseded"
		case failed:
			item.MaterializationState = "retrying"
			item.Reason = "materialization_retry_scheduled"
		default:
			item.Reason = waitingReason
		}
		var source identity.Observation
		if json.Unmarshal(envelope, &source) == nil {
			item.CollectorVersion = source.Admission.CollectorVersion
			if source.Source.Ref != "" {
				item.SourceRef = source.Source.Ref
			}
		}
		if item.Kind == "peer" {
			item.Scope = "source_context"
		}
		if payload == "" {
			item.Reason = "summary_payload_too_large"
		} else {
			if encrypted {
				if s.integrationCipher == nil || !s.integrationCipher.Enabled() {
					payload = ""
				} else {
					plain, err := s.integrationCipher.DecryptValue(payload)
					if err != nil {
						payload = ""
					} else {
						payload = plain
					}
				}
				if payload == "" {
					item.Reason = "summary_temporarily_unavailable"
				}
			}
			if payload != "" {
				if err := projectRetainedEvidence(&item, []byte(payload)); err != nil {
					item.Reason = "summary_temporarily_unavailable"
				}
			}
		}
		page.Items = append(page.Items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	page.HasMore = page.Total > len(page.Items)
	return page, nil
}

func projectRetainedEvidence(out *RetainedEvidenceSummary, raw []byte) error {
	switch out.Kind {
	case "host_inventory":
		var report struct {
			Facts []struct {
				Key   string          `json:"key"`
				Value json.RawMessage `json:"value"`
			} `json:"facts"`
			Relationships []json.RawMessage            `json:"relationships"`
			Assets        []retainedCryptoSummaryInput `json:"assets"`
			DeviceInfo    struct {
				Packages   []json.RawMessage `json:"packages"`
				CertStores []struct {
					Certs []retainedCertificateInput `json:"certs"`
				} `json:"cert_stores"`
			} `json:"device_info"`
		}
		if err := json.Unmarshal(raw, &report); err != nil {
			return err
		}
		out.SoftwareCount = len(report.DeviceInfo.Packages)
		out.RelationshipsCount = len(report.Relationships)
		for _, fact := range report.Facts {
			if _, known := facts.Get(fact.Key); known {
				out.FactsCount++
			}
		}
		for _, asset := range report.Assets {
			projectRetainedCrypto(out, asset)
		}
		for _, store := range report.DeviceInfo.CertStores {
			for _, cert := range store.Certs {
				appendRetainedCertificate(out, cert)
			}
		}
	case "peer":
		var peer struct {
			Observations struct {
				Facts         []json.RawMessage
				Relationships []json.RawMessage
			}
			Source identity.Source
		}
		if err := json.Unmarshal(raw, &peer); err != nil {
			return err
		}
		out.FactsCount = len(peer.Observations.Facts)
		out.RelationshipsCount = len(peer.Observations.Relationships)
		if peer.Source.Ref != "" {
			out.SourceRef = peer.Source.Ref
		}
	case "cloud":
		// The envelope can also hold passwords and untyped vendor responses. Decode
		// only the allowlisted provider-context fields used for summary counts.
		var cloud struct {
			Device struct {
				DeviceType string
				Metadata   struct {
					KeyID         string                       `json:"key_id"`
					CryptoConfigs []retainedCryptoSummaryInput `json:"crypto_configs"`
				}
			}
			Observation identity.Observation
			Enumeration *struct {
				Facts      map[string]json.RawMessage
				Attributes map[string]json.RawMessage
			}
		}
		if err := json.Unmarshal(raw, &cloud); err != nil {
			return err
		}
		out.CollectorVersion = cloud.Observation.Admission.CollectorVersion
		if cloud.Observation.Source.Ref != "" {
			out.SourceRef = cloud.Observation.Source.Ref
		}
		if cloud.Enumeration != nil {
			out.FactsCount = len(cloud.Enumeration.Facts)
		}
		if (cloud.Device.DeviceType == "aws_kms" || cloud.Device.DeviceType == "azure_keyvault_key" || cloud.Device.DeviceType == "gcp_kms_crypto_key") && cloud.Device.Metadata.KeyID != "" {
			out.KeysCount = 1
		}
		for _, crypto := range cloud.Device.Metadata.CryptoConfigs {
			projectRetainedCrypto(out, crypto)
		}
	case "passive_host":
		var finding struct {
			RawData struct {
				Host struct {
					Vendor, Model string
					Addresses     []json.RawMessage
					Services      []string
				} `json:"host_observation"`
			} `json:"raw_data"`
		}
		if err := json.Unmarshal(raw, &finding); err != nil {
			return err
		}
		if finding.RawData.Host.Vendor != "" {
			out.FactsCount++
		}
		if finding.RawData.Host.Model != "" {
			out.FactsCount++
		}
	case "crypto":
		var finding retainedCryptoSummaryInput
		if err := json.Unmarshal(raw, &finding); err != nil {
			return err
		}
		projectRetainedCrypto(out, finding)
	}
	sort.Strings(out.Protocols)
	return nil
}

type retainedCryptoSummaryInput struct {
	IPAddress    string                     `json:"ip_address"`
	Hostname     string                     `json:"hostname"`
	Protocol     string                     `json:"protocol"`
	Port         int                        `json:"port"`
	Certificate  *retainedCertificateInput  `json:"certificate"`
	Certificates []retainedCertificateInput `json:"certificates"`
	SSHInfo      struct {
		Fingerprint string `json:"host_key_fingerprint"`
	} `json:"ssh_info"`
	RawData struct {
		SSHFingerprint     string                     `json:"ssh_host_key_fingerprint"`
		HostKeyFingerprint string                     `json:"host_key_fingerprint"`
		Certificate        *retainedCertificateInput  `json:"certificate"`
		Cert               *retainedCertificateInput  `json:"cert"`
		CertificateInfo    *retainedCertificateInput  `json:"certificate_info"`
		Certificates       []retainedCertificateInput `json:"certificates"`
	} `json:"raw_data"`
}
type retainedCertificateInput struct {
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	Fingerprint       string `json:"fingerprint"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
	PEM               string `json:"pem"`
	CertificatePEM    string `json:"certificate_pem"`
	SelfSigned        *bool  `json:"is_self_signed"`
}

func projectRetainedCrypto(out *RetainedEvidenceSummary, in retainedCryptoSummaryInput) {
	protocol := strings.ToUpper(strings.TrimSpace(in.Protocol))
	switch protocol {
	case "TLS", "SSL", "SSH", "HTTPS", "IPSEC", "WIREGUARD", "OPENVPN":
		found := false
		for _, p := range out.Protocols {
			if p == protocol {
				found = true
			}
		}
		if !found {
			out.Protocols = append(out.Protocols, protocol)
		}
		out.CryptoConfigurationsCount++
	}
	if protocol == "SSH" {
		for _, fingerprint := range []string{in.SSHInfo.Fingerprint, in.RawData.SSHFingerprint, in.RawData.HostKeyFingerprint} {
			raw := strings.TrimPrefix(fingerprint, "SHA256:")
			decoded, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(raw, "="))
			if err == nil && len(decoded) == 32 {
				if out.keyFingerprints == nil {
					out.keyFingerprints = map[string]bool{}
				}
				key := hex.EncodeToString(decoded)
				if !out.keyFingerprints[key] {
					out.keyFingerprints[key] = true
					out.KeysCount++
				}
				break
			}
		}
	}
	if in.Port > 0 && in.Port <= 65535 {
		transport := "tcp"
		if protocol == "UDP" {
			transport = "udp"
		}
		address := strings.TrimSpace(in.IPAddress)
		if address == "" {
			address = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(in.Hostname), "."))
		}
		key := address + ":" + strconv.Itoa(in.Port) + ":" + transport
		if out.endpointKeys == nil {
			out.endpointKeys = map[string]bool{}
		}
		if !out.endpointKeys[key] {
			out.endpointKeys[key] = true
			out.EndpointsCount++
		}
	}
	for _, cert := range []*retainedCertificateInput{in.Certificate, in.RawData.Certificate, in.RawData.Cert, in.RawData.CertificateInfo} {
		if cert != nil {
			appendRetainedCertificate(out, *cert)
		}
	}
	for _, cert := range append(in.Certificates, in.RawData.Certificates...) {
		appendRetainedCertificate(out, cert)
	}
}
func appendRetainedCertificate(out *RetainedEvidenceSummary, in retainedCertificateInput) {
	fingerprint := strings.ToLower(strings.ReplaceAll(in.FingerprintSHA256, ":", ""))
	if fingerprint == "" {
		fingerprint = strings.ToLower(strings.ReplaceAll(in.Fingerprint, ":", ""))
	}
	cert := RetainedCertificateSummary{SHA256Fingerprint: fingerprint, SelfSigned: in.SelfSigned}
	parseTime := func(raw string) *time.Time {
		if at, err := time.Parse(time.RFC3339, raw); err == nil {
			return &at
		}
		return nil
	}
	cert.NotBefore = parseTime(in.NotBefore)
	cert.NotAfter = parseTime(in.NotAfter)
	raw := in.CertificatePEM
	if raw == "" {
		raw = in.PEM
	}
	if block, _ := pem.Decode([]byte(raw)); block != nil && block.Type == "CERTIFICATE" {
		if parsed, err := x509.ParseCertificate(block.Bytes); err == nil {
			sum := sha256.Sum256(parsed.Raw)
			cert.SHA256Fingerprint = hex.EncodeToString(sum[:])
			cert.NotBefore = &parsed.NotBefore
			cert.NotAfter = &parsed.NotAfter
			self := parsed.CheckSignature(parsed.SignatureAlgorithm, parsed.RawTBSCertificate, parsed.Signature) == nil && strings.EqualFold(parsed.Subject.String(), parsed.Issuer.String())
			cert.SelfSigned = &self
		}
	}
	if len(cert.SHA256Fingerprint) != 64 {
		return
	}
	if _, err := hex.DecodeString(cert.SHA256Fingerprint); err != nil {
		return
	}
	if out.certificateFingerprints == nil {
		out.certificateFingerprints = map[string]bool{}
	}
	if out.certificateFingerprints[cert.SHA256Fingerprint] {
		return
	}
	out.certificateFingerprints[cert.SHA256Fingerprint] = true
	out.CertificatesCount++
	if cert.NotAfter != nil {
		expired := cert.NotAfter.Before(time.Now())
		cert.Expired = &expired
	}
	if len(out.Certificates) < retainedCertificateLimit {
		out.Certificates = append(out.Certificates, cert)
	}
}
