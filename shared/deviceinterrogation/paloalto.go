package deviceinterrogation

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// PaloAltoInterrogator interrogates Palo Alto Networks PAN-OS appliances over
// the PAN-OS XML API. It authenticates via keygen (username/password → API
// key) and then extracts SSL-decrypt profiles and security rules that carry an
// SSL-decrypt action. This is the union of the former device-agent and
// device-interrogation-service copies, both of which were thin and nearly
// identical.
type PaloAltoInterrogator struct{}

// SupportedDeviceTypes implements DeviceInterrogator. The set is the union of
// the device-types both source copies handled ("palo_alto"/"paloalto" plus the
// agent copy's "panos").
func (*PaloAltoInterrogator) SupportedDeviceTypes() []string {
	return []string{"palo_alto", "paloalto", "panos"}
}

// Interrogate implements DeviceInterrogator.
func (*PaloAltoInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	// Resolve credentials, falling back to the freeform Custom map (the
	// device-agent wrapper supported username/password there).
	username := creds.Username
	password := creds.Password
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
		return nil, fmt.Errorf("username and password required for Palo Alto device")
	}

	baseURL, err := managementURL(device)
	if err != nil {
		return nil, err
	}

	client := newPanClient(baseURL, username, password, creds.InsecureSkipVerify)

	result, err := client.interrogate(ctx)
	if err != nil {
		return nil, err
	}

	// Attach the structured device identity shared across every asset (carried
	// over from the device-agent wrapper).
	result.DeviceIdentity = &DeviceIdentity{
		Vendor:    "Palo Alto Networks",
		OSVersion: "PAN-OS",
	}
	return result, nil
}

// panClient handles a single Palo Alto PAN-OS device.
type panClient struct {
	baseURL    string
	username   string
	password   string
	apiKey     string
	httpClient *http.Client
}

func newPanClient(baseURL, username, password string, insecureSkipVerify bool) *panClient {
	return &panClient{
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

// panResponse represents a PAN-OS XML API response envelope.
type panResponse struct {
	XMLName xml.Name  `xml:"response"`
	Status  string    `xml:"status,attr"`
	Code    string    `xml:"code,attr"`
	Result  panResult `xml:"result"`
}

// panResult represents the result section of a PAN-OS response.
type panResult struct {
	XMLName xml.Name  `xml:"result"`
	Config  panConfig `xml:"config"`
	Key     string    `xml:"key"`
}

// panConfig represents the config section.
type panConfig struct {
	XMLName xml.Name   `xml:"config"`
	Devices panDevices `xml:"devices"`
}

// panDevices represents the devices section.
type panDevices struct {
	XMLName xml.Name   `xml:"devices"`
	Entry   []panEntry `xml:"entry"`
}

// panEntry represents a device entry.
type panEntry struct {
	XMLName xml.Name   `xml:"entry"`
	Name    string     `xml:"name,attr"`
	VSys    panVSys    `xml:"vsys"`
	Network panNetwork `xml:"network"`
}

// panVSys represents virtual systems.
type panVSys struct {
	XMLName xml.Name       `xml:"vsys"`
	Entry   []panVSysEntry `xml:"entry"`
}

// panVSysEntry represents a vsys entry.
type panVSysEntry struct {
	XMLName  xml.Name    `xml:"entry"`
	Name     string      `xml:"name,attr"`
	Rulebase panRulebase `xml:"rulebase"`
}

// panRulebase represents a security rulebase.
type panRulebase struct {
	XMLName  xml.Name    `xml:"rulebase"`
	Security panSecurity `xml:"security"`
}

// panSecurity represents the security section.
type panSecurity struct {
	XMLName xml.Name `xml:"security"`
	Rules   panRules `xml:"rules"`
}

// panRules represents the security rules collection.
type panRules struct {
	XMLName xml.Name       `xml:"rules"`
	Entry   []panRuleEntry `xml:"entry"`
}

// panRuleEntry represents a single security rule.
type panRuleEntry struct {
	XMLName xml.Name `xml:"entry"`
	Name    string   `xml:"name,attr"`
	SSL     panSSL   `xml:"ssl"`
}

// panSSL represents SSL settings in a rule.
type panSSL struct {
	XMLName xml.Name `xml:"ssl"`
	Decrypt string   `xml:"decrypt"`
}

// panNetwork represents the network section.
type panNetwork struct {
	XMLName  xml.Name    `xml:"network"`
	Profiles panProfiles `xml:"profiles"`
}

// panProfiles represents the profiles section.
type panProfiles struct {
	XMLName    xml.Name      `xml:"profiles"`
	SSLDecrypt panSSLDecrypt `xml:"ssl-decrypt"`
}

// panSSLDecrypt represents the ssl-decrypt profiles collection.
type panSSLDecrypt struct {
	XMLName xml.Name             `xml:"ssl-decrypt"`
	Entry   []panSSLDecryptEntry `xml:"entry"`
}

// panSSLDecryptEntry represents a single SSL-decrypt profile.
type panSSLDecryptEntry struct {
	XMLName     xml.Name       `xml:"entry"`
	Name        string         `xml:"name,attr"`
	Certificate panCertificate `xml:"certificate"`
}

// panCertificate represents certificate configuration.
type panCertificate struct {
	XMLName xml.Name `xml:"certificate"`
	CA      string   `xml:"ca"`
}

func (c *panClient) interrogate(ctx context.Context) (*InterrogateResult, error) {
	result := &InterrogateResult{
		Assets:     []CryptoAsset{},
		DeviceInfo: make(map[string]interface{}),
	}

	// Authenticate: keygen → API key. Fatal — every subsequent call needs it.
	if err := c.getAPIKey(ctx); err != nil {
		return nil, fmt.Errorf("failed to get API key: %w", err)
	}

	// System information (non-fatal).
	if sysInfo, err := c.getSystemInfo(ctx); err != nil {
		fmt.Printf("Warning: failed to get system info: %v\n", err)
	} else {
		result.DeviceInfo = sysInfo
	}

	// SSL decrypt profiles (non-fatal).
	if profiles, err := c.getSSLDecryptProfiles(ctx); err != nil {
		fmt.Printf("Warning: failed to get SSL decrypt profiles: %v\n", err)
	} else {
		for _, profile := range profiles {
			result.Assets = append(result.Assets, c.convertSSLDecryptProfileToAsset(profile))
		}
	}

	// Security rules carrying an SSL-decrypt action (non-fatal).
	if rules, err := c.getSecurityRules(ctx); err != nil {
		fmt.Printf("Warning: failed to get security rules: %v\n", err)
	} else {
		for _, rule := range rules {
			if rule.SSL.Decrypt != "" {
				result.Assets = append(result.Assets, c.convertSecurityRuleToAsset(rule))
			}
		}
	}

	return result, nil
}

// getAPIKey authenticates via the keygen endpoint and stores the API key.
func (c *panClient) getAPIKey(ctx context.Context) error {
	apiURL := fmt.Sprintf("%s/api/", c.baseURL)

	formData := url.Values{}
	formData.Set("type", "keygen")
	formData.Set("user", c.username)
	formData.Set("password", c.password)

	req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(formData.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("API key request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API key request failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var panosResp panResponse
	if err := xml.NewDecoder(resp.Body).Decode(&panosResp); err != nil {
		return fmt.Errorf("failed to decode API key response: %w", err)
	}

	if panosResp.Status != "success" {
		return fmt.Errorf("API key request failed: %s", panosResp.Code)
	}

	c.apiKey = panosResp.Result.Key
	return nil
}

// getSystemInfo retrieves system information.
//
// NOTE: this is an intentional stub — it issues the show-system-info op command
// but does not yet parse the XML response, returning only a marker. Faithfully
// ported from both source copies; full system-info parsing is tracked as issue
// item 4.
func (c *panClient) getSystemInfo(ctx context.Context) (map[string]interface{}, error) {
	apiURL := fmt.Sprintf("%s/api/?type=op&cmd=<show><system><info></info></system></show>&key=%s", c.baseURL, c.apiKey)

	_, err := c.apiRequest(ctx, "GET", apiURL)
	if err != nil {
		return nil, err
	}

	info := make(map[string]interface{})
	// Parse XML response and extract system info.
	// For now, return basic info.
	info["api_key_obtained"] = true
	return info, nil
}

// getSSLDecryptProfiles retrieves SSL-decrypt profiles.
func (c *panClient) getSSLDecryptProfiles(ctx context.Context) ([]panSSLDecryptEntry, error) {
	xpath := "/config/devices/entry/network/profiles/ssl-decrypt"
	apiURL := fmt.Sprintf("%s/api/?type=config&action=get&xpath=%s&key=%s", c.baseURL, url.QueryEscape(xpath), c.apiKey)

	resp, err := c.apiRequest(ctx, "GET", apiURL)
	if err != nil {
		return nil, err
	}

	var panosResp panResponse
	if err := xml.NewDecoder(strings.NewReader(resp)).Decode(&panosResp); err != nil {
		return nil, fmt.Errorf("failed to decode SSL decrypt profiles response: %w", err)
	}

	if panosResp.Status != "success" {
		return nil, fmt.Errorf("failed to get SSL decrypt profiles: %s", panosResp.Code)
	}

	var profiles []panSSLDecryptEntry
	// Extract profiles from XML structure.
	if len(panosResp.Result.Config.Devices.Entry) > 0 {
		entry := panosResp.Result.Config.Devices.Entry[0]
		profiles = entry.Network.Profiles.SSLDecrypt.Entry
	}

	return profiles, nil
}

// getSecurityRules retrieves security rules with SSL settings.
func (c *panClient) getSecurityRules(ctx context.Context) ([]panRuleEntry, error) {
	xpath := "/config/devices/entry/vsys/entry/rulebase/security/rules"
	apiURL := fmt.Sprintf("%s/api/?type=config&action=get&xpath=%s&key=%s", c.baseURL, url.QueryEscape(xpath), c.apiKey)

	resp, err := c.apiRequest(ctx, "GET", apiURL)
	if err != nil {
		return nil, err
	}

	var panosResp panResponse
	if err := xml.NewDecoder(strings.NewReader(resp)).Decode(&panosResp); err != nil {
		return nil, fmt.Errorf("failed to decode security rules response: %w", err)
	}

	if panosResp.Status != "success" {
		return nil, fmt.Errorf("failed to get security rules: %s", panosResp.Code)
	}

	var rules []panRuleEntry
	// Extract rules from XML structure.
	if len(panosResp.Result.Config.Devices.Entry) > 0 {
		entry := panosResp.Result.Config.Devices.Entry[0]
		if len(entry.VSys.Entry) > 0 {
			vsysEntry := entry.VSys.Entry[0]
			rules = vsysEntry.Rulebase.Security.Rules.Entry
		}
	}

	return rules, nil
}

// apiRequest makes an authenticated API request to the device and returns the
// raw XML body.
func (c *panClient) apiRequest(ctx context.Context, method, apiURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, method, apiURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(bodyBytes), nil
}

// convertSSLDecryptProfileToAsset converts an SSL-decrypt profile to a CryptoAsset.
func (c *panClient) convertSSLDecryptProfileToAsset(profile panSSLDecryptEntry) CryptoAsset {
	return CryptoAsset{
		Hostname:  profile.Name,
		Protocol:  "TLS",
		Port:      443, // Default HTTPS port
		AssetType: "firewall",
		Metadata: map[string]interface{}{
			"profile_name":   profile.Name,
			"profile_type":   "ssl-decrypt",
			"certificate_ca": profile.Certificate.CA,
		},
		// NOTE: both source copies hardcoded ProtocolVersion = "TLS 1.2" here,
		// but the PAN-OS ssl-decrypt profile config doesn't report a negotiated
		// TLS version — it's genuinely unknown from this data. Leaving
		// ProtocolVersion unset (nil) rather than fabricating "TLS 1.2", per the
		// pointer-optional contract. See item 2.
	}
}

// convertSecurityRuleToAsset converts a security rule with SSL settings to a CryptoAsset.
func (c *panClient) convertSecurityRuleToAsset(rule panRuleEntry) CryptoAsset {
	return CryptoAsset{
		Hostname:  rule.Name,
		Protocol:  "TLS",
		Port:      443, // Default HTTPS port
		AssetType: "firewall",
		Metadata: map[string]interface{}{
			"rule_name":   rule.Name,
			"ssl_decrypt": rule.SSL.Decrypt,
		},
		// NOTE: both source copies hardcoded ProtocolVersion = "TLS 1.2" here,
		// but a security rule's ssl-decrypt action doesn't report a negotiated
		// TLS version — it's genuinely unknown from this data. Leaving
		// ProtocolVersion unset (nil) rather than fabricating "TLS 1.2", per the
		// pointer-optional contract. See item 2.
	}
}
