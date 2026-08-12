package deviceinterrogation

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// FortinetInterrogator interrogates Fortinet FortiGate appliances over the
// FortiOS REST API (/api/v2/cmdb/...). It extracts SSL-VPN settings, IPSec
// phase1 tunnels, and the local certificate store. This is the union of the
// former device-agent and device-interrogation-service copies — the latter's
// X.509 certificate parsing (the superset) routed through shared/certificates.
type FortinetInterrogator struct{}

// SupportedDeviceTypes implements DeviceInterrogator.
func (*FortinetInterrogator) SupportedDeviceTypes() []string {
	return []string{"fortinet", "fortigate"}
}

// Interrogate implements DeviceInterrogator.
func (*FortinetInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	baseURL, err := managementURL(device)
	if err != nil {
		return nil, err
	}
	client := newFortinetClient(baseURL, creds.Username, creds.Password, creds.InsecureSkipVerify)
	return client.interrogate(ctx)
}

// fortinetClient handles a single Fortinet device.
type fortinetClient struct {
	baseURL    string
	username   string
	password   string
	httpClient *http.Client
}

func newFortinetClient(baseURL, username, password string, insecureSkipVerify bool) *fortinetClient {
	return &fortinetClient{
		baseURL:  baseURL,
		username: username,
		password: password,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify}, //nolint:gosec // per-device opt-in for self-signed appliance mgmt certs
			},
			Timeout: 30 * time.Second,
		},
	}
}

// fortinetAPIResponse represents a FortiOS REST API response envelope.
type fortinetAPIResponse struct {
	Status       string                   `json:"status"`
	Serial       string                   `json:"serial"`
	Version      string                   `json:"version"`
	Build        int                      `json:"build"`
	Results      []map[string]interface{} `json:"results"`
	Error        int                      `json:"error"`
	ErrorMessage string                   `json:"error_message"`
}

func (c *fortinetClient) interrogate(ctx context.Context) (*InterrogateResult, error) {
	result := &InterrogateResult{
		Assets:     []CryptoAsset{},
		DeviceInfo: make(map[string]interface{}),
	}

	sysInfo, err := c.getSystemInfo(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get system info: %w", err)
	}
	result.DeviceInfo = sysInfo
	result.DeviceIdentity = fortinetIdentity(sysInfo)

	if sslVPNs, err := c.getResults(ctx, "/api/v2/cmdb/vpn.ssl/settings"); err != nil {
		fmt.Printf("Warning: failed to get SSL VPN configs: %v\n", err)
	} else {
		for _, vpn := range sslVPNs {
			result.Assets = append(result.Assets, c.convertSSLVPNToAsset(vpn))
		}
	}

	if tunnels, err := c.getResults(ctx, "/api/v2/cmdb/vpn.ipsec/phase1-interface"); err != nil {
		fmt.Printf("Warning: failed to get IPSec tunnels: %v\n", err)
	} else {
		for _, tunnel := range tunnels {
			result.Assets = append(result.Assets, c.convertIPSecToAsset(tunnel))
		}
	}

	if certs, err := c.getCertificates(ctx); err != nil {
		fmt.Printf("Warning: failed to get certificates: %v\n", err)
	} else {
		result.DeviceInfo["certificates"] = certs
	}

	return result, nil
}

func (c *fortinetClient) getSystemInfo(ctx context.Context) (map[string]interface{}, error) {
	resp, err := c.apiRequest(ctx, "GET", c.baseURL+"/api/v2/cmdb/system/status")
	if err != nil {
		return nil, err
	}
	info := make(map[string]interface{})
	if len(resp.Results) > 0 {
		info = resp.Results[0]
	}
	return info, nil
}

func (c *fortinetClient) getResults(ctx context.Context, path string) ([]map[string]interface{}, error) {
	resp, err := c.apiRequest(ctx, "GET", c.baseURL+path)
	if err != nil {
		return nil, err
	}
	if resp.Results == nil {
		return []map[string]interface{}{}, nil
	}
	return resp.Results, nil
}

// getCertificates retrieves the local certificate store and enriches each
// entry with parsed X.509 fields (the superset behavior from the former
// service copy).
func (c *fortinetClient) getCertificates(ctx context.Context) ([]map[string]interface{}, error) {
	resp, err := c.apiRequest(ctx, "GET", c.baseURL+"/api/v2/cmdb/certificate/local")
	if err != nil {
		return nil, err
	}
	if resp.Results == nil {
		return []map[string]interface{}{}, nil
	}
	processed := make([]map[string]interface{}, 0, len(resp.Results))
	for _, certData := range resp.Results {
		processed = append(processed, processFortinetCertificate(certData))
	}
	return processed, nil
}

func (c *fortinetClient) apiRequest(ctx context.Context, method, url string) (*fortinetAPIResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.username, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var apiResp fortinetAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if apiResp.Status != "success" && apiResp.Error != 0 {
		return nil, fmt.Errorf("API error: %s (code %d)", apiResp.ErrorMessage, apiResp.Error)
	}
	return &apiResp, nil
}

func fortinetIdentity(sysInfo map[string]interface{}) *DeviceIdentity {
	id := &DeviceIdentity{Vendor: "Fortinet"}
	if v, ok := sysInfo["version"].(string); ok {
		id.FirmwareVersion = v
		id.OSVersion = v
	}
	if v, ok := sysInfo["serial"].(string); ok {
		id.SerialNumber = v
	}
	if v, ok := sysInfo["model"].(string); ok {
		id.Model = v
	}
	return id
}

func (c *fortinetClient) convertSSLVPNToAsset(vpn map[string]interface{}) CryptoAsset {
	asset := CryptoAsset{Protocol: "SSL VPN", Port: 443, AssetType: "vpn_gateway", Metadata: vpn}

	if hostname, ok := vpn["server_hostname"].(string); ok {
		asset.Hostname = hostname
	}
	if ip, ok := vpn["server_ip"].(string); ok {
		asset.IPAddress = ip
	}
	if port, ok := vpn["port"].(float64); ok {
		asset.Port = int(port)
	}
	if cipher, ok := vpn["cipher"].(string); ok {
		asset.CipherSuite = strPtr(cipher)
		if keySize := fortinetKeySize(cipher); keySize > 0 {
			asset.KeySize = intPtr(keySize)
		}
	}
	if tlsVersion, ok := vpn["tls_version"].(string); ok {
		asset.ProtocolVersion = strPtr(tlsVersion)
	} else if minVersion, ok := vpn["min_tls_version"].(string); ok {
		asset.ProtocolVersion = strPtr(minVersion)
	}
	if asset.CipherSuite != nil {
		if hashAlg := fortinetHashAlg(*asset.CipherSuite); hashAlg != "" {
			asset.HashAlgorithm = strPtr(hashAlg)
		}
	}
	if certName, ok := vpn["server_cert"].(string); ok && certName != "" {
		asset.Metadata["certificate_name"] = certName
		asset.Metadata["certificate_source"] = "ssl_vpn_config"
	}
	return asset
}

func (c *fortinetClient) convertIPSecToAsset(tunnel map[string]interface{}) CryptoAsset {
	asset := CryptoAsset{Protocol: "IPSec", Port: 500, AssetType: "vpn_gateway", Metadata: tunnel}

	if name, ok := tunnel["name"].(string); ok {
		asset.Hostname = name
	}
	if remoteGw, ok := tunnel["remote-gw"].(string); ok {
		asset.IPAddress = remoteGw
	}
	if proposal, ok := tunnel["proposal"].(string); ok {
		asset.CipherSuite = strPtr(proposal)
		if keySize := fortinetKeySize(proposal); keySize > 0 {
			asset.KeySize = intPtr(keySize)
		}
		if hashAlg := fortinetHashAlg(proposal); hashAlg != "" {
			asset.HashAlgorithm = strPtr(hashAlg)
		}
	}
	if phase1Proposal, ok := tunnel["phase1name"].(string); ok {
		asset.Metadata["phase1_proposal"] = phase1Proposal
	}
	if encryption, ok := tunnel["encryption"].(string); ok {
		asset.Metadata["encryption_algorithm"] = encryption
		if keySize := fortinetKeySize(encryption); keySize > 0 {
			asset.KeySize = intPtr(keySize)
		}
	}
	if authentication, ok := tunnel["authentication"].(string); ok {
		asset.Metadata["authentication_algorithm"] = authentication
		if hashAlg := fortinetHashAlg(authentication); hashAlg != "" {
			asset.HashAlgorithm = strPtr(hashAlg)
		}
	}
	if dhGroup, ok := tunnel["dhgrp"].(string); ok {
		asset.Metadata["dh_group"] = dhGroup
	}
	if certName, ok := tunnel["certificate"].(string); ok && certName != "" {
		asset.Metadata["certificate_name"] = certName
		asset.Metadata["certificate_source"] = "ipsec_config"
	}
	if caCert, ok := tunnel["ca_cert"].(string); ok && caCert != "" {
		asset.Metadata["ca_certificate_name"] = caCert
	}
	return asset
}

// processFortinetCertificate enriches a raw certificate map with parsed X.509
// fields when a PEM/base64 body is present. Parsing goes through the canonical
// shared/certificates extractor; only the map projection — the shape
// FortiOS metadata consumers read — lives here.
func processFortinetCertificate(certData map[string]interface{}) map[string]interface{} {
	pemData := extractFortinetPEM(certData)
	if pemData == "" {
		return certData
	}
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		certData["certificate_pem"] = pemData
		return certData
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		certData["certificate_pem"] = pemData
		return certData
	}

	infos := certificates.ExtractCertificatesFromX509([]*x509.Certificate{cert})
	if len(infos) == 0 {
		certData["certificate_pem"] = pemData
		return certData
	}
	info := infos[0]

	certData["certificate_pem"] = pemData
	certData["fingerprint_sha256"] = info.FingerprintSHA256
	certData["fingerprint_sha1"] = info.FingerprintSHA1
	certData["subject_dn"] = info.SubjectDN
	certData["issuer_dn"] = info.IssuerDN
	certData["subject_alternative_names"] = info.SubjectAlternativeNames
	certData["key_usage"] = info.KeyUsage
	certData["extended_key_usage"] = info.ExtendedKeyUsage
	certData["public_key_algorithm"] = info.KeyAlgorithm
	certData["public_key_size"] = info.KeySize
	certData["signature_algorithm"] = info.SignatureAlg
	certData["is_ca"] = info.IsCA
	certData["is_self_signed"] = info.SubjectDN == info.IssuerDN
	certData["serial_number"] = info.SerialNumber
	certData["not_before"] = info.NotBefore
	certData["not_after"] = info.NotAfter
	return certData
}

func extractFortinetPEM(certData map[string]interface{}) string {
	for _, field := range []string{"cert", "certificate", "cert_pem", "pem"} {
		if v, ok := certData[field].(string); ok && v != "" {
			return certificates.NormalizePEM(v)
		}
	}
	if certBase64, ok := certData["cert_base64"].(string); ok && certBase64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(certBase64); err == nil {
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decoded}))
		}
	}
	return ""
}

// fortinetKeySize / fortinetHashAlg are string-heuristic extractors carried
// over verbatim from both copies. NOTE: these re-derive key size and hash from
// cipher/proposal strings rather than normalizing against the authoritative
// `algorithms` table — see item 1. That normalization belongs in
// the platform ingest path (the customer-deployed agent has no DB access), so
// it is intentionally NOT done here; this preserves the existing union behavior.
func fortinetKeySize(cipher string) int {
	if strings.Contains(cipher, "AES256") || strings.Contains(cipher, "256") {
		return 256
	}
	if strings.Contains(cipher, "AES128") || strings.Contains(cipher, "128") {
		return 128
	}
	return 0
}

func fortinetHashAlg(input string) string {
	in := strings.ToUpper(input)
	switch {
	case strings.Contains(in, "SHA256"), strings.Contains(in, "SHA-256"):
		return "SHA256"
	case strings.Contains(in, "SHA384"), strings.Contains(in, "SHA-384"):
		return "SHA384"
	case strings.Contains(in, "SHA512"), strings.Contains(in, "SHA-512"):
		return "SHA512"
	case strings.Contains(in, "SHA1"), strings.Contains(in, "SHA-1"):
		return "SHA1"
	case strings.Contains(in, "MD5"):
		return "MD5"
	}
	return ""
}

// managementURL and its helpers live in target.go — they are shared by every
// vendor interrogator, not Fortinet-specific.
