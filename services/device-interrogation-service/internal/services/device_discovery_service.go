package services

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/network"
)

// DeviceDiscoveryService handles connecting to devices and discovering their information
type DeviceDiscoveryService struct {
	httpClient *http.Client
}

// NewDeviceDiscoveryService creates a new device discovery service
func NewDeviceDiscoveryService() *DeviceDiscoveryService {
	return &DeviceDiscoveryService{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // intentional — device discovery probes vendor management interfaces with self-signed/expired certs
				},
				// SSRF guard: the management URL is tenant-supplied, so
				// refuse internal/metadata IPs at connect time (closes the
				// resolve-then-dial TOCTOU even with InsecureSkipVerify on).
				DialContext: network.SafeDialContext(30 * time.Second),
			},
		},
	}
}

// DiscoveredDeviceInfo contains information discovered from a device
type DiscoveredDeviceInfo struct {
	Vendor          string
	Model           string
	SerialNumber    string
	Hostname        string
	IPAddress       string
	FirmwareVersion string
	MacAddress      string
}

// DiscoverDevice connects to a device and retrieves its information
func (s *DeviceDiscoveryService) DiscoverDevice(deviceType, managementURL, username, password string) (*DiscoveredDeviceInfo, error) {
	switch deviceType {
	case "unifi":
		return s.discoverUniFiDevice(managementURL, username, password)
	case "cisco":
		return s.discoverCiscoDevice(managementURL, username, password)
	case "f5":
		return s.discoverF5Device(managementURL, username, password)
	case "fortinet":
		return s.discoverFortinetDevice(managementURL, username, password)
	case "palo_alto":
		return s.discoverPaloAltoDevice(managementURL, username, password)
	default:
		return nil, fmt.Errorf("unsupported device type: %s", deviceType)
	}
}

// unifiLogin attempts to login to a UniFi device and returns session cookies
// Tries both UDM/UDR endpoint (/api/auth/login) and legacy controller endpoint (/api/login)
func (s *DeviceDiscoveryService) unifiLogin(managementURL, username, password string) ([]*http.Cookie, error) {
	loginPayload := map[string]string{
		"username": username,
		"password": password,
	}

	loginData, err := json.Marshal(loginPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal login payload: %w", err)
	}

	// Try UDM/UDR endpoint first (/api/auth/login)
	loginURL := strings.TrimRight(managementURL, "/") + "/api/auth/login"
	cookies, err := s.attemptUnifiLogin(loginURL, loginData)
	if err == nil {
		fmt.Printf("UniFi login successful using /api/auth/login\n")
		return cookies, nil
	}

	fmt.Printf("Failed to login with /api/auth/login: %v, trying /api/login\n", err)

	// Fallback to legacy controller endpoint (/api/login)
	loginURL = strings.TrimRight(managementURL, "/") + "/api/login"
	cookies, err = s.attemptUnifiLogin(loginURL, loginData)
	if err == nil {
		fmt.Printf("UniFi login successful using /api/login\n")
		return cookies, nil
	}

	return nil, fmt.Errorf("failed to login to UniFi device using both endpoints: %w", err)
}

// attemptUnifiLogin attempts a single login request to the given URL
func (s *DeviceDiscoveryService) attemptUnifiLogin(loginURL string, loginData []byte) ([]*http.Cookie, error) {
	req, err := http.NewRequest("POST", loginURL, strings.NewReader(string(loginData)))
	if err != nil {
		return nil, fmt.Errorf("failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute login request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("login failed with status %d: %s", resp.StatusCode, string(body))
	}

	return resp.Cookies(), nil
}

// discoverUniFiDevice discovers information from a UniFi device
func (s *DeviceDiscoveryService) discoverUniFiDevice(managementURL, username, password string) (*DiscoveredDeviceInfo, error) {
	// Step 1: Login to UniFi API
	// UDM/UDR devices use /api/auth/login, older controllers use /api/login
	// Try both endpoints
	cookies, err := s.unifiLogin(managementURL, username, password)
	if err != nil {
		return nil, err
	}

	// Step 2: Get system information
	// Try to get device info from the status endpoint
	statusURL := strings.TrimRight(managementURL, "/") + "/api/s/default/stat/device"

	req, err := http.NewRequest("GET", statusURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create status request: %w", err)
	}

	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get device status: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// If stat/device fails, try the sysinfo endpoint (for UDM/UDR)
		return s.getUniFiSystemInfo(managementURL, cookies)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var statusResp struct {
		Data []struct {
			Model   string `json:"model"`
			Serial  string `json:"serial"`
			Version string `json:"version"`
			Name    string `json:"name"`
			IP      string `json:"ip"`
			Mac     string `json:"mac"`
			Type    string `json:"type"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &statusResp); err != nil {
		return nil, fmt.Errorf("failed to parse device status: %w", err)
	}

	// Find the controller/gateway device
	for _, device := range statusResp.Data {
		if device.Type == "ugw" || device.Type == "udm" || device.Type == "udr" {
			return &DiscoveredDeviceInfo{
				Vendor:          "Ubiquiti",
				Model:           device.Model,
				SerialNumber:    device.Serial,
				Hostname:        device.Name,
				IPAddress:       device.IP,
				FirmwareVersion: device.Version,
				MacAddress:      device.Mac,
			}, nil
		}
	}

	// If no gateway found, return first device
	if len(statusResp.Data) > 0 {
		device := statusResp.Data[0]
		return &DiscoveredDeviceInfo{
			Vendor:          "Ubiquiti",
			Model:           device.Model,
			SerialNumber:    device.Serial,
			Hostname:        device.Name,
			IPAddress:       device.IP,
			FirmwareVersion: device.Version,
			MacAddress:      device.Mac,
		}, nil
	}

	return nil, fmt.Errorf("no devices found in UniFi controller")
}

// getUniFiSystemInfo gets system information for UDM/UDR devices
// Tries multiple endpoint patterns as UDM/UDR use different API structure
func (s *DeviceDiscoveryService) getUniFiSystemInfo(managementURL string, cookies []*http.Cookie) (*DiscoveredDeviceInfo, error) {
	// Try different sysinfo endpoints
	endpoints := []string{
		"/proxy/network/api/s/default/stat/sysinfo", // UDM/UDR proxy endpoint
		"/api/s/default/stat/sysinfo",               // Standard controller endpoint
		"/api/system",                               // Alternative UDM endpoint
	}

	for _, endpoint := range endpoints {
		sysinfoURL := strings.TrimRight(managementURL, "/") + endpoint
		fmt.Printf("Trying sysinfo endpoint: %s\n", endpoint)

		req, err := http.NewRequest("GET", sysinfoURL, nil)
		if err != nil {
			continue
		}

		for _, cookie := range cookies {
			req.AddCookie(cookie)
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			fmt.Printf("Failed to fetch %s: %v\n", endpoint, err)
			continue
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("Endpoint %s returned status %d\n", endpoint, resp.StatusCode)
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			continue
		}

		fmt.Printf("Got response from %s: %s\n", endpoint, string(body))

		// Try parsing as standard sysinfo response
		var sysinfoResp struct {
			Data []struct {
				Hostname string `json:"hostname"`
				Version  string `json:"version"`
				Model    string `json:"console_display_version"`
			} `json:"data"`
		}

		if err := json.Unmarshal(body, &sysinfoResp); err == nil && len(sysinfoResp.Data) > 0 {
			info := sysinfoResp.Data[0]
			fmt.Printf("Successfully parsed sysinfo from %s\n", endpoint)
			return &DiscoveredDeviceInfo{
				Vendor:          "Ubiquiti",
				Model:           info.Model,
				Hostname:        info.Hostname,
				FirmwareVersion: info.Version,
			}, nil
		}

		// Try parsing as system info response (UDM format)
		var systemResp struct {
			Hostname string `json:"hostname"`
			Version  string `json:"version"`
			Name     string `json:"name"`
		}

		if err := json.Unmarshal(body, &systemResp); err == nil && systemResp.Hostname != "" {
			fmt.Printf("Successfully parsed system info from %s\n", endpoint)
			return &DiscoveredDeviceInfo{
				Vendor:          "Ubiquiti",
				Model:           systemResp.Name,
				Hostname:        systemResp.Hostname,
				FirmwareVersion: systemResp.Version,
			}, nil
		}
	}

	return nil, fmt.Errorf("failed to get system info from any endpoint")
}

// Placeholder implementations for other device types
func (s *DeviceDiscoveryService) discoverCiscoDevice(managementURL, username, password string) (*DiscoveredDeviceInfo, error) {
	// TODO: Implement Cisco device discovery via SSH or REST API
	return &DiscoveredDeviceInfo{
		Vendor: "Cisco",
		Model:  "Unknown (discovery not yet implemented)",
	}, nil
}

func (s *DeviceDiscoveryService) discoverF5Device(managementURL, username, password string) (*DiscoveredDeviceInfo, error) {
	// TODO: Implement F5 device discovery via iControl REST API
	return &DiscoveredDeviceInfo{
		Vendor: "F5 Networks",
		Model:  "Unknown (discovery not yet implemented)",
	}, nil
}

func (s *DeviceDiscoveryService) discoverFortinetDevice(managementURL, username, password string) (*DiscoveredDeviceInfo, error) {
	// TODO: Implement Fortinet device discovery via FortiGate API
	return &DiscoveredDeviceInfo{
		Vendor: "Fortinet",
		Model:  "Unknown (discovery not yet implemented)",
	}, nil
}

func (s *DeviceDiscoveryService) discoverPaloAltoDevice(managementURL, username, password string) (*DiscoveredDeviceInfo, error) {
	// TODO: Implement Palo Alto device discovery via PAN-OS XML API
	return &DiscoveredDeviceInfo{
		Vendor: "Palo Alto Networks",
		Model:  "Unknown (discovery not yet implemented)",
	}, nil
}
