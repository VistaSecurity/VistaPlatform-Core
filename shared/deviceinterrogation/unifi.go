package deviceinterrogation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// UnifiInterrogator interrogates Ubiquiti UniFi controllers (legacy software
// controllers as well as UDM/UDR/UniFi-OS gateways) over the UniFi Network API.
// It enumerates managed devices (name/IP/MAC/model/firmware), associated
// clients (`stat/sta`), and emits one synthetic TLS asset for the controller's
// management interface.
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
		httpClient:         newDeviceHTTPClient(insecureSkipVerify, deviceHTTPTimeout),
	}
}

func (c *unifiClient) interrogate(ctx context.Context) (*InterrogateResult, error) {
	result := &InterrogateResult{
		Assets:     []CryptoAsset{},
		DeviceInfo: make(map[string]interface{}),
		collector:  unifiCollector,
	}

	if err := c.authenticate(ctx); err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	if sysInfo, err := c.getSystemInfo(ctx); err != nil {
		result.warn(c.apiPrefix+"/api/self", err, "Controller session details not collected")
	} else {
		result.DeviceInfo = sysInfo
	}

	site := c.siteID
	if site == "" {
		site = "default"
	}

	// The site's networks are fetched BEFORE the devices now: they carry the
	// VLAN tag each network id stands for, which is what turns a port's opaque
	// `native_networkconf_id` into an interface VLAN (ADR-0004 D1 item 1).
	var networkConfs []map[string]interface{}
	if confs, err := c.getNetworkConfs(ctx, site); err != nil {
		result.warn(c.apiPrefix+"/api/s/"+site+"/rest/networkconf", err, "Networks, VLANs and VPNs not collected")
	} else {
		networkConfs = confs
	}
	vlanByNetworkID := unifiVLANByNetworkID(networkConfs)

	controllerHost, _ := unifiHostPort(c.baseURL)

	// Fetched before the device loop because the controller's display name is
	// part of how a managed device's member_of edge names its far end.
	if identity, err := c.getControllerIdentity(ctx, site); err != nil {
		result.warn(c.apiPrefix+"/api/s/"+site+"/list/setting", err, "Controller name not collected")
	} else {
		for k, v := range identity {
			result.DeviceInfo[k] = v
		}
	}

	if devices, err := c.getDevices(ctx, site); err != nil {
		result.warn(c.apiPrefix+"/api/s/"+site+"/stat/device", err, "Managed devices and their topology not collected")
	} else {
		controllerPeer := unifiControllerPeer(controllerHost, result.DeviceInfo)
		for _, device := range devices {
			asset := c.convertDeviceToAsset(device, site)
			if asset.Hostname != "" || asset.IPAddress != "" {
				result.Assets = append(result.Assets, asset)
			}
			// Ops facts and topology for the managed device itself. These are
			// about the DEVICE, not the controller, which is why they carry a
			// subject: a switch's port table is not the controller's.
			unifiEmitDeviceObservations(result, device, controllerPeer, vlanByNetworkID)
		}
	}

	// Synthetic management-interface TLS asset for the controller itself.
	result.Assets = append(result.Assets, c.getManagementInterfaceAsset())

	// VPN networks (site-to-site IPsec / OpenVPN, WireGuard / OpenVPN / L2TP
	// remote-user servers) become vpn_gateway assets carrying the API-reported
	// crypto config. Ordinary LAN and VLAN networks — the other ~90% of
	// this response, filtered away until now — become the controller's
	// net.vlans fact and, at ingest, the site's segments.
	result.Assets = append(result.Assets, unifiVPNAssets(networkConfs, controllerHost)...)
	unifiEmitNetworkFacts(result, networkConfs)

	if clients, err := c.getClients(ctx, site); err != nil {
		result.warn(c.apiPrefix+"/api/s/"+site+"/stat/sta", err, "Connected clients not collected")
	} else {
		unifiEmitClientObservations(result, clients)
	}

	// The controller's own management plane. Read off the URL we just
	// authenticated against rather than assumed: a legacy software controller
	// reached over plain HTTP is exactly the case the plaintext_management
	// finding exists for, and hardcoding "https" here would hide it.
	protocol, plaintext := unifiManagementProtocol(c.baseURL)
	result.addFact(factHWVendor, unifiVendor, ConfidenceDerived)
	result.addFact(factMgmtProtocol, protocol, ConfidenceReported)
	result.addFact(factMgmtPlaintext, plaintext, ConfidenceReported)

	return result, nil
}

// unifiManagementProtocol reports the management protocol and whether it
// carries credentials in the clear, from the controller base URL.
func unifiManagementProtocol(baseURL string) (string, bool) {
	if strings.HasPrefix(strings.ToLower(baseURL), "http://") {
		return "http", true
	}
	return "https", false
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

	// A refusal on ANY attempt is the answer. The three endpoints are tried in
	// turn, so a UniFi OS console that rejects the password on the first one
	// then answers the legacy paths with a 404 — and reporting that last 404
	// told the operator "not a UniFi controller" about a UniFi controller with
	// a wrong password.
	var refused error
	noteRefusal := func(err error) {
		var statusErr *deviceStatusError
		if refused == nil && errors.As(err, &statusErr) &&
			(statusErr.status == http.StatusUnauthorized || statusErr.status == http.StatusForbidden) {
			refused = err
		}
	}

	// 1. UDM/UDR / UniFi-OS gateway (JSON).
	err = c.attemptJSONLogin(ctx, "/api/auth/login", loginPayload)
	if err == nil {
		c.apiPrefix = "/proxy/network"
		return nil
	}
	noteRefusal(err)

	// 2. Legacy software controller (JSON).
	err = c.attemptJSONLogin(ctx, "/api/login", loginPayload)
	if err == nil {
		c.apiPrefix = ""
		return nil
	}
	noteRefusal(err)

	// 3. Legacy software controller (form-encoded) — older controllers that
	//    reject the JSON body.
	if err := c.attemptFormLogin(ctx, "/api/login"); err != nil {
		noteRefusal(err)
		if refused != nil {
			err = refused
		}
		return fmt.Errorf("login failed: %w", err)
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return httpStatusError("login", resp.StatusCode)
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

// unifiAPIError is the error for a response whose envelope says rc != "ok".
// The controller answers a refused read with `api.err.NoPermission` (and an
// expired session with `api.err.LoginRequired`), which is a permission problem
// however the HTTP status was dressed.
//
// Only a message of the controller's own `api.err.<Token>` shape is kept. Any
// other text in meta.msg is the controller's free text — it has been seen to
// carry a password — and this error is persisted as a warning.
func unifiAPIError(msg string) error {
	reason := WarningError
	if strings.Contains(msg, "NoPermission") || strings.Contains(msg, "LoginRequired") {
		reason = WarningPermissionDenied
	}
	if !unifiErrorToken.MatchString(msg) {
		msg = "unrecognised controller error"
	}
	return &vendorAPIError{reason: reason, msg: "API error: " + msg}
}

// unifiErrorToken is the shape of a UniFi controller error code.
var unifiErrorToken = regexp.MustCompile(`^api\.err\.[A-Za-z0-9_.]{1,64}$`)

// apiRequest makes an authenticated API request to the UniFi controller,
// honoring apiPrefix and re-authenticating once on 401/403.
func (c *unifiClient) apiRequest(ctx context.Context, method, endpoint string, body io.Reader) (*unifiAPIResponse, error) {
	return c.apiRequestAttempt(ctx, method, endpoint, body, false)
}

// apiRequestAttempt is one try of apiRequest. ONCE means once: the retry used
// to call apiRequest again, so an endpoint the account may not read (a 403 that
// no fresh session changes) logged in and retried without end, and one
// read-only admin profile hung the whole interrogation.
func (c *unifiClient) apiRequestAttempt(ctx context.Context, method, endpoint string, body io.Reader, retried bool) (*unifiAPIResponse, error) {
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
	defer func() { _ = resp.Body.Close() }()

	// Re-authenticate once on 401/403, then retry. A second refusal is the
	// answer, and falls through to the status error below.
	if !retried && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
		if err := c.authenticate(ctx); err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}
		return c.apiRequestAttempt(ctx, method, endpoint, body, true)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, httpStatusError("API request", resp.StatusCode)
	}

	var apiResp unifiAPIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}
	if apiResp.Meta.RC != "ok" {
		return nil, unifiAPIError(apiResp.Meta.Msg)
	}
	return &apiResp, nil
}

// getSystemInfo confirms the authenticated session and returns controller
// identity.
//
// /api/self returns the ADMIN ACCOUNT profile — uid, full name, email address,
// admin id, owner/super flags. We used to store that response verbatim as the
// job's device_info, which put the operator's personal email in every
// interrogation record for no benefit: nothing downstream ever read it. The
// call is retained because a successful response proves the session is live,
// but the body is discarded apart from the controller's own identity.
func (c *unifiClient) getSystemInfo(ctx context.Context) (map[string]interface{}, error) {
	resp, err := c.apiRequest(ctx, "GET", "/api/self", nil)
	if err != nil {
		return nil, err
	}
	info := map[string]interface{}{"authenticated": true}
	if len(resp.Data) > 0 {
		// site_name is the controller's site handle, not user identity.
		if site, ok := resp.Data[0]["site_name"].(string); ok && site != "" {
			info["site_name"] = site
		}
	}
	return info, nil
}

// getControllerIdentity returns the controller's own name/hostname from the
// site settings.
//
// The full `list/setting` payload is deliberately NOT retained. It carries the
// site mesh PSK (super_mgmt/connectivity x_mesh_psk), the SMTP relay password
// (super_smtp x_password) and RADIUS shared secrets. Nothing downstream read
// it; only the controller's display identity is of any use, so that is all we
// take.
func (c *unifiClient) getControllerIdentity(ctx context.Context, site string) (map[string]interface{}, error) {
	settings, err := c.getSettings(ctx, site)
	if err != nil {
		return nil, err
	}
	identity := map[string]interface{}{}
	for _, entry := range settings {
		if key, _ := entry["key"].(string); key != "super_identity" {
			continue
		}
		for _, field := range []string{"name", "hostname"} {
			if v, ok := entry[field].(string); ok && v != "" {
				identity["controller_"+field] = v
			}
		}
	}
	return identity, nil
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

// getClients retrieves the site's associated stations (wired and wireless
// clients). A 404 is treated as "this controller has no station list" rather
// than a failed interrogation — older mocks and some controller versions omit
// the endpoint, and managed-device inventory still succeeded.
func (c *unifiClient) getClients(ctx context.Context, site string) ([]map[string]interface{}, error) {
	resp, err := c.apiRequest(ctx, "GET", fmt.Sprintf("/api/s/%s/stat/sta", site), nil)
	if err != nil {
		if strings.Contains(err.Error(), "status 404") {
			return []map[string]interface{}{}, nil
		}
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

// unifiDeviceInventoryFields is the allowlist of `stat/device` fields we keep.
//
// The controller's device object carries ~120 fields, including x_authkey,
// x_vwirekey, syslog_key and the mesh PSK. We copied the whole thing into asset
// metadata, so every interrogation persisted those keys. We inventory
// cryptographic posture, not key material, and none of the omitted fields feed
// any downstream consumer — so the fix is to stop collecting them rather than to
// scrub them afterwards. Sanitize (redact.go) remains as a backstop.
//
// Add a field here only if something actually reads it.
//
// Widened for the ops set (ADR-0004 D1 item 1) with the SCALAR fields below the
// first group. The nested tables that widening also needs — uplink, port_table,
// ethernet_table, lldp_table — are deliberately NOT here: they are read through
// unifiDeviceStructuredFields (unifi_ops.go), which projects each entry onto its
// own allowlist and emits facts and edges. Adding one here instead would copy a
// 40-field vendor object per port into asset metadata, which is the original
// leak one level down.
var unifiDeviceInventoryFields = []string{
	"name",         // display name
	"ip",           // management address
	"mac",          // hardware identity
	"model",        // hardware model
	"type",         // uap / usw / ugw / udm
	"version",      // firmware version
	"serial",       // hardware serial
	"adopted",      // controller-managed or not
	"state",        // connection state
	"board_rev",    // hardware revision
	"model_in_eol", // end-of-life signal — real posture input
	"model_in_lts",
	"architecture",
	"kernel_version",

	// --- ops set (ADR-0004 D1) ---
	"uptime", // seconds since boot → net.uptime_seconds; a patching signal
}

// convertDeviceToAsset converts a UniFi managed device to a CryptoAsset,
// projecting the raw controller response onto unifiDeviceInventoryFields.
func (c *unifiClient) convertDeviceToAsset(device map[string]interface{}, site string) CryptoAsset {
	metadata := make(map[string]interface{}, len(unifiDeviceInventoryFields)+4)
	for _, field := range unifiDeviceInventoryFields {
		if v, ok := device[field]; ok && v != nil {
			metadata[field] = v
		}
	}

	asset := CryptoAsset{
		Protocol: "TLS",
		Port:     8443, // Default UniFi management port
		Metadata: metadata,
	}

	// The controller alias stays display context even when it looks like DNS.
	// A separate hostname field is the actual device hostname evidence.
	if hostname, ok := device["hostname"].(string); ok {
		asset.Hostname = canonicalHostnameOrEmpty(hostname)
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
//
// The subject is the CONTROLLER, so the class hint is wireless_controller —
// what a UDM, a Cloud Key or a software controller is in the taxonomy. The
// devices it manages get their own hints from their `type` (classhint.go).
func unifiIdentity(sysInfo map[string]interface{}) *DeviceIdentity {
	identity := &DeviceIdentity{Vendor: unifiVendor, ClassHint: unifiControllerClassHint()}
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
