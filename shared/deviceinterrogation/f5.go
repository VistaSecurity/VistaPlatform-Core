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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/certificates"
)

// F5Interrogator interrogates F5 BIG-IP appliances over the iControl REST API
// (/mgmt/tm/...). It authenticates for a token, then reads sys/version, the
// ltm/virtual VIPs, and the client-ssl / server-ssl profiles, joining each
// enabled VIP to its SSL profile(s) to emit one TLS crypto asset per
// VIP×profile pairing. Certificates referenced by a profile's certKeyChain are
// fetched from sys/crypto/cert (with a certKeyChain-metadata fallback), decoded,
// and emitted as canonical CertificateInfo entries.
//
// This is the union of the former device-interrogation-service and device-agent
// copies: the service copy's iControl cert fetch/decode (the superset, routed
// through shared/certificates) plus the agent copy's TLS version-range parsing,
// key-exchange extraction, SupportedCiphers list, AssetType, and ServiceHints.
type F5Interrogator struct{}

// SupportedDeviceTypes implements DeviceInterrogator.
func (*F5Interrogator) SupportedDeviceTypes() []string {
	return []string{"f5", "f5_bigip", "bigip"}
}

// Interrogate implements DeviceInterrogator.
func (*F5Interrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	username := creds.Username
	password := creds.Password
	// Agent copy allowed credentials to arrive in the Custom map; preserve that.
	if username == "" {
		if u, ok := creds.Custom["username"].(string); ok {
			username = u
		}
	}
	if password == "" {
		if p, ok := creds.Custom["password"].(string); ok {
			password = p
		}
	}
	if username == "" || password == "" {
		return nil, fmt.Errorf("username and password required for F5 device")
	}

	baseURL, err := managementURL(device)
	if err != nil {
		return nil, err
	}

	client := newF5Client(baseURL, username, password, creds.Token, creds.InsecureSkipVerify)
	result, err := client.interrogate(ctx)
	if err != nil {
		return nil, err
	}
	result.DeviceIdentity = f5Identity(result.DeviceInfo)
	return result, nil
}

// f5Client handles a single F5 BIG-IP device over iControl REST.
type f5Client struct {
	baseURL    string
	username   string
	password   string
	token      string
	httpClient *http.Client
}

func newF5Client(baseURL, username, password, token string, insecureSkipVerify bool) *f5Client {
	return &f5Client{
		baseURL:  baseURL,
		username: username,
		password: password,
		token:    token,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify}, //nolint:gosec // per-device opt-in for self-signed appliance mgmt certs
			},
			Timeout: 30 * time.Second,
		},
	}
}

// f5APIResponse represents a generic iControl REST collection response.
type f5APIResponse struct {
	Kind  string                   `json:"kind"`
	Items []map[string]interface{} `json:"items"`
}

// f5VirtualServer represents an F5 virtual server (VIP).
type f5VirtualServer struct {
	Name        string
	Destination string
	Port        int
	Profiles    []map[string]interface{}
	Source      string
	Enabled     bool
	Metadata    map[string]interface{}
}

// f5SSLProfile represents an F5 client-ssl or server-ssl profile.
type f5SSLProfile struct {
	Name                string
	Kind                string
	Ciphers             string
	CipherList          []string
	CertKeyChain        []map[string]interface{}
	DefaultProfile      string
	SecureRenegotiation string
	TLSVersion          string
	Metadata            map[string]interface{}
}

func (c *f5Client) interrogate(ctx context.Context) (*InterrogateResult, error) {
	result := &InterrogateResult{
		Assets:     []CryptoAsset{},
		DeviceInfo: make(map[string]interface{}),
	}

	if err := c.authenticate(ctx); err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}

	if sysInfo, err := c.getSystemInfo(ctx); err != nil {
		fmt.Printf("Warning: failed to get system info: %v\n", err)
	} else {
		result.DeviceInfo = sysInfo
	}

	virtualServers, err := c.getVirtualServers(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get virtual servers: %w", err)
	}

	clientSSLProfiles, err := c.getClientSSLProfiles(ctx)
	if err != nil {
		fmt.Printf("Warning: failed to get client SSL profiles: %v\n", err)
	}
	serverSSLProfiles, err := c.getServerSSLProfiles(ctx)
	if err != nil {
		fmt.Printf("Warning: failed to get server SSL profiles: %v\n", err)
	}

	// Build a profile lookup keyed by profile name.
	profileMap := make(map[string]*f5SSLProfile)
	for i := range clientSSLProfiles {
		p := &clientSSLProfiles[i]
		profileMap[p.Name] = p
	}
	for i := range serverSSLProfiles {
		p := &serverSSLProfiles[i]
		profileMap[p.Name] = p
	}

	for _, vs := range virtualServers {
		if !vs.Enabled {
			continue
		}

		// Destination is "ip:port"; default to 443 when unparseable.
		destParts := strings.Split(vs.Destination, ":")
		if len(destParts) != 2 {
			continue
		}
		ipAddress := destParts[0]
		port := 443
		if p, err := f5ParseInt(destParts[1]); err == nil {
			port = p
		}

		for _, profileRef := range vs.Profiles {
			profileName, ok := profileRef["name"].(string)
			if !ok {
				continue
			}
			profile, found := profileMap[profileName]
			if !found {
				continue
			}
			result.Assets = append(result.Assets, c.convertVIPToAsset(ctx, vs, profile, ipAddress, port))
		}
	}

	return result, nil
}

// authenticate obtains an iControl REST token via the tmos login provider.
// On failure to extract a token it falls back to basic auth for later requests.
func (c *f5Client) authenticate(ctx context.Context) error {
	url := fmt.Sprintf("%s/mgmt/shared/authn/login", c.baseURL)

	authReq := map[string]string{
		"username":          c.username,
		"password":          c.password,
		"loginProviderName": "tmos",
	}
	reqBody, err := json.Marshal(authReq)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(reqBody)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("authentication failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var authResp map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}
	if tokenObj, ok := authResp["token"].(map[string]interface{}); ok {
		if token, ok := tokenObj["token"].(string); ok {
			c.token = token
			return nil
		}
	}
	// No token in the response — subsequent requests use basic auth.
	return nil
}

func (c *f5Client) getSystemInfo(ctx context.Context) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/mgmt/tm/sys/version", c.baseURL)
	resp, err := c.apiRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	info := make(map[string]interface{})
	if len(resp.Items) > 0 {
		info = resp.Items[0]
	}
	return info, nil
}

func (c *f5Client) getVirtualServers(ctx context.Context) ([]f5VirtualServer, error) {
	url := fmt.Sprintf("%s/mgmt/tm/ltm/virtual", c.baseURL)
	resp, err := c.apiRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	var virtualServers []f5VirtualServer
	for _, item := range resp.Items {
		vs := f5VirtualServer{
			Name:        f5GetString(item, "name"),
			Destination: f5GetString(item, "destination"),
			Source:      f5GetString(item, "source"),
			Enabled:     f5GetBool(item, "enabled"),
			Metadata:    item,
		}
		if destParts := strings.Split(vs.Destination, ":"); len(destParts) == 2 {
			if port, err := f5ParseInt(destParts[1]); err == nil {
				vs.Port = port
			}
		}
		if profiles, ok := item["profiles"].([]interface{}); ok {
			for _, p := range profiles {
				if profileMap, ok := p.(map[string]interface{}); ok {
					vs.Profiles = append(vs.Profiles, profileMap)
				}
			}
		}
		virtualServers = append(virtualServers, vs)
	}
	return virtualServers, nil
}

func (c *f5Client) getClientSSLProfiles(ctx context.Context) ([]f5SSLProfile, error) {
	return c.getSSLProfiles(ctx, "/mgmt/tm/ltm/profile/client-ssl", true)
}

func (c *f5Client) getServerSSLProfiles(ctx context.Context) ([]f5SSLProfile, error) {
	return c.getSSLProfiles(ctx, "/mgmt/tm/ltm/profile/server-ssl", false)
}

// getSSLProfiles reads an SSL-profile collection. certKeyChain extraction only
// applies to client-ssl profiles (server-ssl profiles don't carry one).
func (c *f5Client) getSSLProfiles(ctx context.Context, path string, withCertKeyChain bool) ([]f5SSLProfile, error) {
	url := c.baseURL + path
	resp, err := c.apiRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	var profiles []f5SSLProfile
	for _, item := range resp.Items {
		profile := f5SSLProfile{
			Name:     f5GetString(item, "name"),
			Kind:     f5GetString(item, "kind"),
			Ciphers:  f5GetString(item, "ciphers"),
			Metadata: item,
		}
		if cipherList, ok := item["cipherList"].([]interface{}); ok {
			for _, cl := range cipherList {
				if cipher, ok := cl.(string); ok {
					profile.CipherList = append(profile.CipherList, cipher)
				}
			}
		}
		if withCertKeyChain {
			if certKeyChains, ok := item["certKeyChain"].([]interface{}); ok {
				for _, ckc := range certKeyChains {
					if ckcMap, ok := ckc.(map[string]interface{}); ok {
						profile.CertKeyChain = append(profile.CertKeyChain, ckcMap)
					}
				}
			}
		}
		profile.DefaultProfile = f5GetString(item, "defaultsFrom")
		profile.SecureRenegotiation = f5GetString(item, "secureRenegotiation")
		profile.TLSVersion = f5GetString(item, "tlsVersion")
		profiles = append(profiles, profile)
	}
	return profiles, nil
}

// apiRequest makes an authenticated iControl REST request (token if present,
// otherwise basic auth).
func (c *f5Client) apiRequest(ctx context.Context, method, url string, body io.Reader) (*f5APIResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("X-F5-Auth-Token", c.token)
	} else {
		req.SetBasicAuth(c.username, c.password)
	}
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

	var apiResp f5APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	return &apiResp, nil
}

// convertVIPToAsset builds one CryptoAsset from a VIP joined to one SSL profile.
func (c *f5Client) convertVIPToAsset(ctx context.Context, vs f5VirtualServer, profile *f5SSLProfile, ipAddress string, port int) CryptoAsset {
	asset := CryptoAsset{
		Hostname:  vs.Name,
		IPAddress: ipAddress,
		Port:      port,
		Protocol:  "TLS",
		AssetType: "load_balancer",
		Metadata: map[string]interface{}{
			"virtual_server": vs.Name,
			"destination":    vs.Destination,
			"source":         vs.Source,
			"profile_name":   profile.Name,
			"profile_kind":   profile.Kind,
		},
		ServiceHints: &ServiceHints{
			ServiceName:          "F5 BIG-IP Virtual Server",
			Confidence:           "high",
			IdentificationMethod: "device_config",
		},
	}

	// TLS version(s): expand F5 ranges into a supported-version list.
	if profile.TLSVersion != "" {
		asset.TLSVersions = f5ParseTLSVersionRange(profile.TLSVersion)
		asset.ProtocolVersion = strPtr(profile.TLSVersion)
	} else {
		asset.ProtocolVersion = strPtr("TLS 1.2")
		asset.TLSVersions = []string{"TLS 1.2"}
	}

	// Cipher suites: populate both the selected and supported list.
	if len(profile.CipherList) > 0 {
		asset.SupportedCiphers = profile.CipherList
		asset.CipherSuite = strPtr(profile.CipherList[0])
	} else if profile.Ciphers != "" {
		// F5 stores ciphers as a colon-separated string.
		asset.SupportedCiphers = strings.Split(profile.Ciphers, ":")
		asset.CipherSuite = strPtr(profile.Ciphers)
	}

	// Derive key size / hash / key exchange from the cipher string heuristically.
	if asset.CipherSuite != nil {
		if keySize := f5ExtractKeySizeFromCipher(*asset.CipherSuite); keySize > 0 {
			asset.KeySize = intPtr(keySize)
		}
		if hashAlg := f5ExtractHashAlgorithm(*asset.CipherSuite); hashAlg != "" {
			asset.HashAlgorithm = strPtr(hashAlg)
		}
		if kex := f5ExtractKeyExchangeFromCipher(*asset.CipherSuite); kex != "" {
			asset.KeyExchangeAlg = strPtr(kex)
		}
	}

	// Certificates: fetch + decode each certKeyChain entry into canonical
	// CertificateInfo, preserving chain order. Emit into the canonical
	// Certificates (full chain) + Certificate (leaf) fields ( #3).
	if len(profile.CertKeyChain) > 0 {
		asset.Metadata["cert_key_chain"] = profile.CertKeyChain
		certs := c.extractCertificatesFromKeyChain(ctx, profile.CertKeyChain)
		if len(certs) > 0 {
			asset.Certificates = certs
			leaf := certs[0]
			asset.Certificate = &leaf
		}
	}

	if profile.SecureRenegotiation != "" {
		asset.Metadata["secure_renegotiation"] = profile.SecureRenegotiation
	}

	return asset
}

// extractCertificatesFromKeyChain resolves each certKeyChain entry to a parsed
// certificate: first via the sys/crypto/cert API, then falling back to a PEM
// embedded in the certKeyChain metadata. Chain order is preserved by position
// (0 = leaf, then intermediates).
func (c *f5Client) extractCertificatesFromKeyChain(ctx context.Context, certKeyChains []map[string]interface{}) []CertificateInfo {
	var result []CertificateInfo
	for i, ckc := range certKeyChains {
		var info *CertificateInfo

		if certName := f5GetString(ckc, "cert"); certName != "" {
			if fetched, err := c.getCertificate(ctx, certName); err == nil {
				info = fetched
			}
		}
		if info == nil {
			if certPEM := f5ExtractCertificatePEMFromKeyChain(ckc); certPEM != "" {
				info = f5ProcessCertificatePEM(certPEM)
			}
		}
		if info == nil {
			continue
		}
		info.ChainOrder = i
		result = append(result, *info)
	}
	return result
}

// getCertificate fetches a certificate from F5 by name and decodes it.
func (c *f5Client) getCertificate(ctx context.Context, certName string) (*CertificateInfo, error) {
	url := fmt.Sprintf("%s/mgmt/tm/sys/crypto/cert/%s", c.baseURL, f5CertName(certName))
	resp, err := c.apiRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	if len(resp.Items) == 0 {
		return nil, fmt.Errorf("certificate not found")
	}
	certPEM := f5ExtractCertificatePEMFromF5Response(resp.Items[0])
	if certPEM == "" {
		return nil, fmt.Errorf("no certificate PEM found")
	}
	info := f5ProcessCertificatePEM(certPEM)
	if info == nil {
		return nil, fmt.Errorf("failed to process certificate PEM")
	}
	return info, nil
}

// f5ExtractCertificatePEMFromF5Response pulls a PEM/base64 body out of a
// sys/crypto/cert API response item.
func f5ExtractCertificatePEMFromF5Response(certData map[string]interface{}) string {
	for _, field := range []string{"certificate", "cert", "certPem", "certificatePem"} {
		if v, ok := certData[field].(string); ok && v != "" {
			return f5NormalizePEM(v)
		}
	}
	if certBase64, ok := certData["certificateBase64"].(string); ok && certBase64 != "" {
		return f5DecodeBase64Certificate(certBase64)
	}
	return ""
}

// f5ExtractCertificatePEMFromKeyChain pulls a PEM body out of a certKeyChain
// metadata entry.
func f5ExtractCertificatePEMFromKeyChain(ckc map[string]interface{}) string {
	for _, field := range []string{"certificate", "cert"} {
		if v, ok := ckc[field].(string); ok && v != "" {
			return f5NormalizePEM(v)
		}
	}
	return ""
}

// f5ProcessCertificatePEM parses a PEM certificate and extracts all canonical
// fields through shared/certificates. On parse failure it returns a minimal
// CertificateInfo carrying just the PEM so the data isn't lost.
func f5ProcessCertificatePEM(pemData string) *CertificateInfo {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return &CertificateInfo{CertificatePEM: pemData}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return &CertificateInfo{CertificatePEM: pemData}
	}
	infos := certificates.ExtractCertificatesFromX509([]*x509.Certificate{cert})
	if len(infos) == 0 {
		return &CertificateInfo{CertificatePEM: pemData}
	}
	return &infos[0]
}

// f5NormalizePEM normalizes a certificate string to standard PEM via the
// canonical shared/certificates helper ( — this and the Fortinet copy
// were identical forks).
func f5NormalizePEM(pemData string) string {
	return certificates.NormalizePEM(pemData)
}

// f5DecodeBase64Certificate decodes a base64-encoded DER certificate to PEM.
func f5DecodeBase64Certificate(base64Data string) string {
	decoded, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		return ""
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: decoded}))
}

// f5Identity extracts structured device identity from F5 sys/version info.
func f5Identity(sysInfo map[string]interface{}) *DeviceIdentity {
	id := &DeviceIdentity{Vendor: "F5 Networks"}
	if version, ok := sysInfo["Version"].(string); ok {
		id.FirmwareVersion = version
		id.OSVersion = "TMOS " + version
	}
	if product, ok := sysInfo["Product"].(string); ok {
		id.Model = product
	}
	if platform, ok := sysInfo["Platform"].(string); ok && id.Model == "" {
		id.Model = platform
	}
	return id
}

// f5TLSVersionRangeRE matches F5-style TLS 1.x ranges, e.g. "1.0-1.3", "TLSv1.2 - 1.3".
var f5TLSVersionRangeRE = regexp.MustCompile(`(?i)1\.(\d)\s*[-–—]\s*1\.(\d)`)

// f5ParseTLSVersionRange parses an F5 TLS version string into a supported-version
// list. F5 may report ranges like "1.0-1.3" or a single version.
func f5ParseTLSVersionRange(tlsVersion string) []string {
	upper := strings.ToUpper(tlsVersion)
	var versions []string

	if m := f5TLSVersionRangeRE.FindStringSubmatch(tlsVersion); len(m) == 3 {
		lo, errLo := strconv.Atoi(m[1])
		hi, errHi := strconv.Atoi(m[2])
		if errLo == nil && errHi == nil {
			if lo > hi {
				lo, hi = hi, lo
			}
			for minor := hi; minor >= lo; minor-- {
				if label := f5TLSMinorVersionLabel(minor); label != "" {
					versions = append(versions, label)
				}
			}
		}
	}

	if len(versions) == 0 {
		if strings.Contains(upper, "1.3") {
			versions = append(versions, "TLS 1.3")
		}
		if strings.Contains(upper, "1.2") {
			versions = append(versions, "TLS 1.2")
		}
		if strings.Contains(upper, "1.1") {
			versions = append(versions, "TLS 1.1")
		}
		if strings.Contains(upper, "1.0") {
			versions = append(versions, "TLS 1.0")
		}
	}

	if len(versions) == 0 {
		versions = []string{"TLS 1.2"} // safe default
	}
	return versions
}

func f5TLSMinorVersionLabel(minor int) string {
	switch minor {
	case 0:
		return "TLS 1.0"
	case 1:
		return "TLS 1.1"
	case 2:
		return "TLS 1.2"
	case 3:
		return "TLS 1.3"
	default:
		return ""
	}
}

// f5ExtractKeyExchangeFromCipher derives the key exchange algorithm from a
// cipher suite name. TLS 1.3 suites use ECDHE by default.
func f5ExtractKeyExchangeFromCipher(cipher string) string {
	upper := strings.ToUpper(cipher)
	switch {
	case strings.Contains(upper, "ECDHE"):
		return "ECDHE"
	case strings.Contains(upper, "DHE") || strings.Contains(upper, "EDH"):
		return "DHE"
	case strings.HasPrefix(upper, "TLS_AES") || strings.HasPrefix(upper, "TLS_CHACHA"):
		return "ECDHE"
	case strings.Contains(upper, "RSA"):
		return "RSA"
	default:
		return ""
	}
}

// f5ExtractKeySizeFromCipher / f5ExtractHashAlgorithm are string-heuristic
// extractors carried over verbatim from both copies. NOTE: these re-derive key
// size and hash from cipher strings rather than normalizing against the
// authoritative `algorithms` table — see. That normalization belongs
// in the platform ingest path (the customer-deployed agent has no DB access),
// so it is intentionally NOT done here; this preserves the existing union
// behavior.
func f5ExtractKeySizeFromCipher(cipher string) int {
	cipherUpper := strings.ToUpper(cipher)
	if strings.Contains(cipherUpper, "AES256") || strings.Contains(cipherUpper, "_256") {
		return 256
	}
	if strings.Contains(cipherUpper, "AES128") || strings.Contains(cipherUpper, "_128") {
		return 128
	}
	return 0
}

func f5ExtractHashAlgorithm(input string) string {
	inputUpper := strings.ToUpper(input)
	switch {
	case strings.Contains(inputUpper, "SHA256"), strings.Contains(inputUpper, "SHA-256"):
		return "SHA256"
	case strings.Contains(inputUpper, "SHA384"), strings.Contains(inputUpper, "SHA-384"):
		return "SHA384"
	case strings.Contains(inputUpper, "SHA512"), strings.Contains(inputUpper, "SHA-512"):
		return "SHA512"
	case strings.Contains(inputUpper, "SHA1"), strings.Contains(inputUpper, "SHA-1"):
		return "SHA1"
	case strings.Contains(inputUpper, "MD5"):
		return "MD5"
	}
	return ""
}

// f5CertName encodes an F5 object name for use in an iControl REST URL path.
// F5 represents the partition folder separator "/" as "~", e.g.
// "/Common/default.crt" → "~Common~default.crt". Without this, every
// getCertificate fetch 404s and silently falls back to certKeyChain metadata.
func f5CertName(name string) string {
	return strings.ReplaceAll(name, "/", "~")
}

func f5GetString(m map[string]interface{}, key string) string {
	if val, ok := m[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func f5GetBool(m map[string]interface{}, key string) bool {
	if val, ok := m[key]; ok {
		if b, ok := val.(bool); ok {
			return b
		}
	}
	return false
}

func f5ParseInt(s string) (int, error) {
	var result int
	_, err := fmt.Sscanf(s, "%d", &result)
	return result, err
}
