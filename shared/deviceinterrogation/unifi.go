package deviceinterrogation

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// UnifiInterrogator interrogates Ubiquiti UniFi controllers (legacy software
// controllers as well as UDM/UDR/UniFi-OS gateways) over the UniFi Network API.
// It enumerates managed devices (name/IP/MAC/model/firmware) and emits one
// synthetic TLS asset for the controller's management interface.
//
// This is the union of the former device-agent and device-interrogation-service
// copies. The base service copy contributed the apiPrefix logic that supports
// UDM/UDR controller paths (/proxy/network); the device-agent copy contributed
// the credentials.Custom fallback and the form-encoded legacy login path, both
// preserved here.
type UnifiInterrogator struct{}

// SupportedDeviceTypes implements DeviceInterrogator.
func (*UnifiInterrogator) SupportedDeviceTypes() []string {
	return []string{"unifi", "ubiquiti", "unifi_controller", "udm_pro"}
}

// Interrogate implements DeviceInterrogator.
func (*UnifiInterrogator) Interrogate(ctx context.Context, device DeviceInfo, creds Credentials) (*InterrogateResult, error) {
	// Credentials: prefer the structured fields, fall back to the freeform
	// Custom map (device-agent behavior — some callers stash creds there).
	username := creds.Username
	password := creds.Password
	if username == "" && creds.Custom != nil {
		if u, ok := creds.Custom["username"].(string); ok {
			username = u
		}
	}
	if password == "" && creds.Custom != nil {
		if p, ok := creds.Custom["password"].(string); ok {
			password = p
		}
	}
	if username == "" || password == "" {
		return nil, fmt.Errorf("username and password required for UniFi device")
	}

	// Site id: package DeviceInfo carries a first-class SiteID; fall back to
	// the freeform metadata key the device-agent used.
	siteID := device.SiteID
	if siteID == "" && device.Metadata != nil {
		if s, ok := device.Metadata["site_id"].(string); ok {
			siteID = s
		}
	}

	baseURL, err := managementURL(device)
	if err != nil {
		return nil, err
	}

	client := newUnifiClient(baseURL, username, password, siteID, creds.InsecureSkipVerify)

	result, err := client.interrogate(ctx)
	if err != nil {
		return nil, fmt.Errorf("unifi interrogation failed: %w", err)
	}

	// Structured device identity, derived from controller system info.
	result.DeviceIdentity = unifiIdentity(result.DeviceInfo)

	return result, nil
}

// unifiClient handles a single UniFi controller. UniFi auth is cookie + CSRF
// over HTTPS (typically port 8443).
type unifiClient struct {
	baseURL    string
	username   string
	password   string
	siteID     string
	httpClient *http.Client
	csrfToken  string
	cookies    []*http.Cookie
	// apiPrefix is "/proxy/network" for UDM/UDR/UniFi-OS gateways and "" for
	// legacy software controllers. Set during authenticate().
	apiPrefix string
	// insecureSkipVerify is retained for the management-interface TLS probe
	// (per-device opt-in for self-signed appliance mgmt certs).
	insecureSkipVerify bool
}

// unifiAPIResponse represents a UniFi Network API response envelope.
type unifiAPIResponse struct {
	Meta struct {
		RC  string `json:"rc"`
		Msg string `json:"msg,omitempty"`
	} `json:"meta"`
	Data []map[string]interface{} `json:"data"`
}

func newUnifiClient(baseURL, username, password, siteID string, insecureSkipVerify bool) *unifiClient {
	return &unifiClient{
		baseURL:            baseURL,
		username:           username,
		password:           password,
		siteID:             siteID,
		insecureSkipVerify: insecureSkipVerify,
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify}, //nolint:gosec // per-device opt-in for self-signed appliance mgmt certs
			},
			Timeout: 30 * time.Second,
		},
	}
}

func (c *unifiClient) interrogate(ctx context.Context) (*InterrogateResult, error) {
	result := &InterrogateResult{
		Assets:     []CryptoAsset{},
		DeviceInfo: make(map[string]interface{}),
	}

	if err := c.authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if sysInfo, err := c.getSystemInfo(ctx); err != nil {
		fmt.Printf("Warning: failed to get system info: %v\n", err)
	} else {
		result.DeviceInfo = sysInfo
	}

	site := c.siteID
	if site == "" {
		site = "default"
	}

	if devices, err := c.getDevices(ctx, site); err != nil {
		fmt.Printf("Warning: failed to get devices: %v\n", err)
	} else {
		for _, device := range devices {
			asset := c.convertDeviceToAsset(device, site)
			if asset.Hostname != "" || asset.IPAddress != "" {
				result.Assets = append(result.Assets, asset)
			}
		}
	}

	// Synthetic management-interface TLS asset for the controller itself.
	result.Assets = append(result.Assets, c.getManagementInterfaceAsset())

	// VPN networks (site-to-site IPsec / OpenVPN, WireGuard / OpenVPN / L2TP
	// remote-user servers) become vpn_gateway assets carrying the API-reported
	// crypto config.
	if confs, err := c.getNetworkConfs(ctx, site); err != nil {
		fmt.Printf("Warning: failed to get network configs: %v\n", err)
	} else {
		controllerHost, _ := unifiHostPort(c.baseURL)
		result.Assets = append(result.Assets, unifiVPNAssets(confs, controllerHost)...)
	}

	if settings, err := c.getSettings(ctx, site); err != nil {
		fmt.Printf("Warning: failed to get settings: %v\n", err)
	} else {
		result.DeviceInfo["settings"] = settings
	}

	return result, nil
}

// authenticate authenticates with the UniFi controller. It tries the UDM/UDR
// (UniFi-OS) JSON endpoint (/api/auth/login) first — on success it sets
// apiPrefix to "/proxy/network" so subsequent calls hit the proxied Network
// API. It then falls back to the legacy software-controller endpoints: first
// the JSON /api/login, then the older form-encoded /api/login (device-agent
// behavior), both with an empty apiPrefix.
func (c *unifiClient) authenticate(ctx context.Context) error {
	loginPayload, err := json.Marshal(map[string]string{
		"username": c.username,
		"password": c.password,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal login payload: %w", err)
	}

	// 1. UDM/UDR / UniFi-OS gateway (JSON).
	if err := c.attemptJSONLogin(ctx, "/api/auth/login", loginPayload); err == nil {
		c.apiPrefix = "/proxy/network"
		return nil
	}

	// 2. Legacy software controller (JSON).
	if err := c.attemptJSONLogin(ctx, "/api/login", loginPayload); err == nil {
		c.apiPrefix = ""
		return nil
	}

	// 3. Legacy software controller (form-encoded) — older controllers that
	//    reject the JSON body.
	if err := c.attemptFormLogin(ctx, "/api/login"); err != nil {
		return fmt.Errorf("login failed with status 401: %w", err)
	}
	c.apiPrefix = ""
	return nil
}

// attemptJSONLogin performs a single JSON login POST to the given path.
func (c *unifiClient) attemptJSONLogin(ctx context.Context, path string, loginData []byte) error {
	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, strings.NewReader(string(loginData)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return c.doLogin(req)
}

// attemptFormLogin performs a single form-encoded login POST to the given path.
func (c *unifiClient) attemptFormLogin(ctx context.Context, path string) error {
	form := url.Values{}
	form.Set("username", c.username)
	form.Set("password", c.password)

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.doLogin(req)
}

// doLogin executes a prepared login request and captures session cookies + CSRF.
func (c *unifiClient) doLogin(req *http.Request) error {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("login request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	c.cookies = resp.Cookies()
	for _, cookie := range c.cookies {
		if cookie.Name == "csrf_token" {
			c.csrfToken = cookie.Value
		}
	}
	if csrfHeader := resp.Header.Get("X-CSRF-Token"); csrfHeader != "" {
		c.csrfToken = csrfHeader
	}
	return nil
}

// apiRequest makes an authenticated API request to the UniFi controller,
// honoring apiPrefix and re-authenticating once on 401/403.
func (c *unifiClient) apiRequest(ctx context.Context, method, endpoint string, body io.Reader) (*unifiAPIResponse, error) {
	reqURL := fmt.Sprintf("%s%s%s", c.baseURL, c.apiPrefix, endpoint)

	req, err := http.NewRequestWithContext(ctx, method, reqURL, body)
	if err != nil {
		return nil, err
	}

	for _, cookie := range c.cookies {
		req.AddCookie(cookie)
	}
	if c.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API request failed: %w", err)
	}
	defer resp.Body.Close()

	// Re-authenticate once on 401/403, then retry.
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		if err := c.authenticate(ctx); err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}
		return c.apiRequest(ctx, method, endpoint, body)
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var apiResp unifiAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if apiResp.Meta.RC != "ok" {
		return nil, fmt.Errorf("API error: %s", apiResp.Meta.Msg)
	}
	return &apiResp, nil
}

// getSystemInfo retrieves controller/system information.
func (c *unifiClient) getSystemInfo(ctx context.Context) (map[string]interface{}, error) {
	resp, err := c.apiRequest(ctx, "GET", "/api/self", nil)
	if err != nil {
		return nil, err
	}
	info := make(map[string]interface{})
	if len(resp.Data) > 0 {
		info = resp.Data[0]
	}
	return info, nil
}

// getDevices retrieves managed devices for a site.
func (c *unifiClient) getDevices(ctx context.Context, site string) ([]map[string]interface{}, error) {
	resp, err := c.apiRequest(ctx, "GET", fmt.Sprintf("/api/s/%s/stat/device", site), nil)
	if err != nil {
		return nil, err
	}
	if resp.Data == nil {
		return []map[string]interface{}{}, nil
	}
	return resp.Data, nil
}

// getSettings retrieves settings for a site (may contain TLS/cert configs).
func (c *unifiClient) getSettings(ctx context.Context, site string) ([]map[string]interface{}, error) {
	resp, err := c.apiRequest(ctx, "GET", fmt.Sprintf("/api/s/%s/list/setting", site), nil)
	if err != nil {
		return nil, err
	}
	if resp.Data == nil {
		return []map[string]interface{}{}, nil
	}
	return resp.Data, nil
}

// convertDeviceToAsset converts a UniFi managed device to a CryptoAsset.
func (c *unifiClient) convertDeviceToAsset(device map[string]interface{}, site string) CryptoAsset {
	asset := CryptoAsset{
		Protocol: "TLS",
		Port:     8443, // Default UniFi management port
		Metadata: device,
	}

	if name, ok := device["name"].(string); ok {
		asset.Hostname = name
	}
	if ip, ok := device["ip"].(string); ok {
		asset.IPAddress = ip
	}
	if mac, ok := device["mac"].(string); ok {
		asset.Metadata["mac_address"] = mac
	}
	if model, ok := device["model"].(string); ok {
		asset.Metadata["model"] = model
	}
	if version, ok := device["version"].(string); ok {
		asset.Metadata["firmware_version"] = version
	}
	if deviceType, ok := device["type"].(string); ok {
		asset.Metadata["device_type"] = deviceType
	}

	// Management interface IP fallback.
	if configNetwork, ok := device["config_network"].(map[string]interface{}); ok {
		if ip, ok := configNetwork["ip"].(string); ok && asset.IPAddress == "" {
			asset.IPAddress = ip
		}
	}

	// NOTE ( item 2): the former copies hardcoded ProtocolVersion to
	// "TLS 1.2" here, but this comes from the controller's device inventory —
	// the real negotiated TLS version of each managed device is unknown at this
	// point. Leaving ProtocolVersion unset rather than fabricating a default.
	// (Safe: this is a synthetic inventory record, not an observed handshake.)

	asset.Metadata["site_id"] = site
	asset.Metadata["source"] = "unifi_device"

	return asset
}

// getManagementInterfaceAsset returns an asset for the controller's management
// interface. The UniFi Network API does not expose its own TLS posture, so we
// actively probe the management endpoint with the shared TLSProber to capture
// the real negotiated version, cipher suite, key exchange, and certificate
// chain. If the probe fails (mgmt port firewalled, etc.) we fall back to a
// synthetic record with no fabricated crypto, so the interface is still
// inventoried.
func (c *unifiClient) getManagementInterfaceAsset() CryptoAsset {
	host, port := unifiHostPort(c.baseURL)

	prober := &TLSProber{InsecureSkipVerify: c.insecureSkipVerify}
	if asset, err := prober.ProbeTLS(host, port); err == nil {
		asset.AssetType = "appliance"
		asset.ServiceHints = &ServiceHints{
			ServiceName:          "UniFi Controller",
			Confidence:           "high",
			IdentificationMethod: "device_interrogation",
		}
		if versions := prober.EnumerateTLSVersions(host, port); len(versions) > 0 {
			asset.TLSVersions = versions
		}
		if asset.Metadata == nil {
			asset.Metadata = make(map[string]interface{})
		}
		asset.Metadata["interface_type"] = "management"
		asset.Metadata["source"] = "unifi_controller"
		if asset.IPAddress == "" && net.ParseIP(host) != nil {
			asset.IPAddress = host
		}
		return *asset
	}

	// Probe failed — record the interface without fabricating crypto values.
	asset := CryptoAsset{
		Hostname: host,
		Port:     port,
		Protocol: "TLS",
		Metadata: map[string]interface{}{
			"interface_type": "management",
			"source":         "unifi_controller",
		},
	}
	if net.ParseIP(host) != nil {
		asset.IPAddress = host
	}
	return asset
}

// unifiHostPort extracts the controller host and management port from a base
// URL, defaulting to 443 (UDM/UDR/UniFi-OS) when no port is present. Legacy
// software controllers carry an explicit :8443 in their management URL.
func unifiHostPort(baseURL string) (string, int) {
	if u, err := url.Parse(baseURL); err == nil && u.Host != "" {
		host := u.Hostname()
		if p := u.Port(); p != "" {
			if pi, err := strconv.Atoi(p); err == nil {
				return host, pi
			}
		}
		return host, 443
	}

	// Fallback: no scheme — strip any leftover scheme and split host:port.
	s := strings.TrimPrefix(strings.TrimPrefix(baseURL, "https://"), "http://")
	if i := strings.LastIndex(s, ":"); i >= 0 {
		if pi, err := strconv.Atoi(s[i+1:]); err == nil {
			return s[:i], pi
		}
	}
	return s, 443
}

// unifiIdentity derives structured device identity from controller system info.
func unifiIdentity(sysInfo map[string]interface{}) *DeviceIdentity {
	identity := &DeviceIdentity{Vendor: "Ubiquiti"}
	if sysInfo == nil {
		return identity
	}
	if model, ok := sysInfo["model"].(string); ok {
		identity.Model = model
	}
	if version, ok := sysInfo["version"].(string); ok {
		identity.FirmwareVersion = version
		identity.OSVersion = "UniFi OS " + version
	}
	return identity
}
