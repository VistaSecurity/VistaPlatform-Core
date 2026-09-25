package services

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
	"unicode"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// DeviceDiscoveryService answers "what is this device, and can we reach it" for
// the Add device flow and the Test connection button ( slice A,
// W1.8).
//
// It owns no vendor code. Both questions go through the shared Registry's
// Identify step, which runs each vendor collector's own system-info call over
// the collector's own guarded client — so onboarding and interrogation cannot
// disagree about what a device is, and the dial guard, redirect policy and
// redaction backstop are the ones interrogation already has. The previous
// version kept a UniFi-only HTTP client here and four stubs that returned
// "Unknown (discovery not yet implemented)" as a successful discovery for
// Cisco, F5, Fortinet and PAN-OS without dialling anything.
type DeviceDiscoveryService struct {
	registry *di.Registry
	// timeout bounds one identification end to end. A synchronous request is
	// waiting on it.
	timeout time.Duration
}

// DefaultIdentifyTimeout bounds Add device and Test connection. Long enough for
// a slow appliance's login (PAN-OS keygen can take seconds), short enough that
// an unreachable address fails while the operator is still looking.
const DefaultIdentifyTimeout = 20 * time.Second

// NewDeviceDiscoveryService builds the service over the shared Registry.
func NewDeviceDiscoveryService() *DeviceDiscoveryService {
	return &DeviceDiscoveryService{registry: di.NewRegistry(), timeout: DefaultIdentifyTimeout}
}

// WithTimeout returns a copy bounded by timeout instead of the default.
func (s *DeviceDiscoveryService) WithTimeout(timeout time.Duration) *DeviceDiscoveryService {
	cp := *s
	cp.timeout = timeout
	return &cp
}

// DeviceDiscoveryError is safe to return to a tenant. Code is one of the shared
// di.IdentifyFailure values (or credentials_missing); Message is fixed copy
// chosen by Code. Err is retained for logs only: its text can carry whatever a
// device answered, so it is never copied into a response.
type DeviceDiscoveryError struct {
	Code    string
	Message string
	Err     error
}

func (e *DeviceDiscoveryError) Error() string {
	if e.Err == nil {
		return e.Message
	}
	return e.Message + ": " + e.Err.Error()
}

func (e *DeviceDiscoveryError) Unwrap() error { return e.Err }

// CodeCredentialsMissing is Test connection's answer for a device that has no
// stored username and password of its own. It is not a shared identify
// failure: nothing was dialled.
const CodeCredentialsMissing = "credentials_missing"

// discoveryMessages is the tenant-facing copy for each failure.
var discoveryMessages = map[di.IdentifyFailure]string{
	di.IdentifyNotSupported:         "This device type can't be identified automatically. Enter its details by hand.",
	di.IdentifyInvalidTarget:        "The management address isn't usable. Use https://host[:port] for a web API, or the host (or ssh://host:port) for a Cisco device, with no credentials, query or fragment.",
	di.IdentifyTargetDisallowed:     "That management address isn't allowed. Loopback and link-local (including cloud metadata) addresses can't be probed, and a device may not redirect to another host.",
	di.IdentifyConnectionFailed:     "Couldn't connect to the management address. Check the address and port, and that it is reachable from the platform.",
	di.IdentifyTLSUntrusted:         "Connected, but the device's management certificate isn't trusted. If it is self-signed, turn on Skip TLS verification.",
	di.IdentifyAuthenticationFailed: "The device rejected the credentials, or the account can't read the device's system information.",
	di.IdentifyHostKeyMismatch:      "The device's SSH host key doesn't match the key pinned for it. No password was sent. If the device was replaced, clear the pinned key first.",
	di.IdentifyUnsupportedResponse:  "Something answered at that address, but not as this device type. Check the device type and the management address.",
	di.IdentifyFailed:               "The device answered, but its identity could not be read.",
}

// DiscoveryMessage is the fixed tenant-facing copy for an identify failure
// code, or "" for a code with none. Exported so a handler test can assert that
// a response carries exactly this and nothing the device said.
func DiscoveryMessage(code string) string {
	return discoveryMessages[di.IdentifyFailure(code)]
}

// discoveryError converts an Identify failure into the tenant-safe error.
func discoveryError(err error) *DeviceDiscoveryError {
	identifyErr := di.ClassifyIdentifyError(err)
	message, ok := discoveryMessages[identifyErr.Code]
	if !ok {
		message = discoveryMessages[di.IdentifyFailed]
	}
	return &DeviceDiscoveryError{Code: string(identifyErr.Code), Message: message, Err: err}
}

// DiscoveredDeviceInfo is what identification learned, shaped for a device
// record.
type DiscoveredDeviceInfo struct {
	Vendor          string
	Model           string
	SerialNumber    string
	Hostname        string
	IPAddress       string
	FirmwareVersion string
	MacAddress      string
	// TargetHost and TargetPort are where the identification connected — the
	// operator's address, resolved. Used to record how an SSH-managed device
	// is reached; never reported as something the device said.
	TargetHost string
	TargetPort int
	// SSHHostKeyFingerprint / SSHHostKeyType are the key an SSH identification
	// authenticated through, for the created device to pin.
	SSHHostKeyFingerprint string
	SSHHostKeyType        string
}

// DiscoveryRequest is the Add device probe's input: the four fields plus the
// explicit TLS opt-in.
type DiscoveryRequest struct {
	DeviceType            string
	ManagementURL         string
	Username              string
	Password              string
	TLSInsecureSkipVerify bool
}

// DiscoverDevice identifies the device at req.ManagementURL. Every failure is a
// *DeviceDiscoveryError.
func (s *DeviceDiscoveryService) DiscoverDevice(ctx context.Context, req DiscoveryRequest) (*DiscoveredDeviceInfo, error) {
	info, _, err := s.identify(ctx,
		di.DeviceInfo{DeviceType: req.DeviceType, ManagementURL: req.ManagementURL},
		di.Credentials{Username: req.Username, Password: req.Password, InsecureSkipVerify: req.TLSInsecureSkipVerify})
	return info, err
}

// ConnectionTestResult is a Test connection that reached the device and read
// its identity. LatencyMs is measured, end to end, for that identification.
type ConnectionTestResult struct {
	LatencyMs int64
	Info      *DiscoveredDeviceInfo
}

// TestConnection identifies a stored device with its stored credentials.
//
// It is the same Identify step Add device runs — a real login and the vendor's
// system-info call — not a ping, and not a read of the device's last known
// status: the button used to report success from `connection_status` with a
// hard-coded 42 ms, so a device that had never been contacted "passed".
func (s *DeviceDiscoveryService) TestConnection(ctx context.Context, device *models.Device, stored StoredDeviceCredentials, masterKey string) (*ConnectionTestResult, error) {
	if !stored.HasCredentials() {
		return nil, &DeviceDiscoveryError{
			Code:    CodeCredentialsMissing,
			Message: "This device has no stored username and password to test with. Edit the device to add them.",
			Err:     errors.New("no embedded credentials"),
		}
	}
	password, err := openStoredCredential(masterKey, stored.EncryptedPassword)
	if err != nil {
		return nil, err
	}
	coreDevice := buildCoreDeviceInfo(device, stored.ManagementURL)
	coreDevice.DeviceType = device.DeviceType
	info, latency, err := s.identify(ctx, coreDevice, di.Credentials{
		Username: stored.Username, Password: password,
		InsecureSkipVerify: EffectiveInsecureSkipVerify(device.DeviceType, stored.InsecureSkipVerify),
	})
	if err != nil {
		return nil, err
	}
	return &ConnectionTestResult{LatencyMs: latency.Milliseconds(), Info: info}, nil
}

func (s *DeviceDiscoveryService) identify(ctx context.Context, device di.DeviceInfo, creds di.Credentials) (*DiscoveredDeviceInfo, time.Duration, error) {
	timeout := s.timeout
	if timeout <= 0 {
		timeout = DefaultIdentifyTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	identification, err := s.registry.Identify(ctx, device, creds)
	elapsed := time.Since(start)
	if err != nil {
		return nil, elapsed, discoveryError(err)
	}
	return &DiscoveredDeviceInfo{
		Vendor:          identification.Vendor,
		Model:           identification.Model,
		SerialNumber:    identification.SerialNumber,
		Hostname:        identification.Hostname,
		IPAddress:       identification.IPAddress,
		FirmwareVersion: identification.FirmwareVersion,
		MacAddress:      identification.MACAddress,
		TargetHost:      identification.TargetHost,
		TargetPort:      identification.TargetPort,

		SSHHostKeyFingerprint: identification.SSHHostKeyFingerprint,
		SSHHostKeyType:        identification.SSHHostKeyType,
	}, elapsed, nil
}

// ApplyTo fills a create request from what identification learned, without
// overwriting anything the request already carries.
//
// Two addressing rules make the created device interrogable afterwards:
//
//   - the IP a device reports for itself wins; failing that, the address we
//     dialled is recorded when it is an IP literal;
//   - a device's reported name becomes its hostname only when it is usable as
//     one (no whitespace — a UniFi display name like "HQ Console" is not), and
//     an SSH-managed device dialled by DNS name keeps that name, because the
//     Cisco collector reaches a device by its record's IP or hostname, not by
//     its management URL.
func (d *DiscoveredDeviceInfo) ApplyTo(req *models.CreateDeviceRequest, sshManaged bool) {
	set := func(dst **string, v string) {
		if *dst == nil && strings.TrimSpace(v) != "" {
			value := strings.TrimSpace(v)
			*dst = &value
		}
	}
	set(&req.Vendor, d.Vendor)
	set(&req.Model, d.Model)
	set(&req.SerialNumber, d.SerialNumber)
	set(&req.FirmwareVersion, d.FirmwareVersion)

	ip := d.IPAddress
	if net.ParseIP(ip) == nil {
		ip = ""
	}
	targetIsIP := net.ParseIP(d.TargetHost) != nil
	if ip == "" && targetIsIP {
		ip = d.TargetHost
	}
	set(&req.IPAddress, ip)

	if req.Metadata == nil {
		req.Metadata = map[string]interface{}{}
	}
	switch {
	case sshManaged && !targetIsIP && d.TargetHost != "":
		set(&req.Hostname, d.TargetHost)
	case d.Hostname != "" && !strings.ContainsFunc(d.Hostname, unicode.IsSpace):
		set(&req.Hostname, d.Hostname)
	}
	if d.Hostname != "" && (req.Hostname == nil || *req.Hostname != d.Hostname) {
		// The device's own name, kept where a display name can live when it
		// could not become the record's hostname.
		req.Metadata["reported_name"] = d.Hostname
	}
	if d.MacAddress != "" {
		req.Metadata["mac_address"] = d.MacAddress
	}
	if sshManaged && d.TargetPort != 0 && d.TargetPort != 22 {
		// The Cisco collector reads a non-default SSH port from here.
		req.Metadata["ssh_port"] = float64(d.TargetPort)
	}

	// Admission evidence. The platform itself logged in to this device and read
	// its serial number from the device's own API or CLI — the same standing a
	// host-inventory agent's reading of its own host has. Under
	// identity_admission=enforce that is what lets Add device CREATE the asset
	// rather than retain it for review. Without a serial there is nothing
	// authoritative to admit on, and enforce retains the observation, as it
	// does for a device typed in by hand.
	if strings.TrimSpace(d.SerialNumber) != "" && req.SerialNumber != nil && *req.SerialNumber == strings.TrimSpace(d.SerialNumber) {
		req.ProbeEvidence = &identity.AdmissionEvidence{
			Direct:        true,
			Authoritative: true,
			ReceiptID:     "device_probe",
		}
	}
}

// EffectiveInsecureSkipVerify is the TLS opt-in as it may be applied to a
// device of deviceType: never for an SSH-managed type.
//
// The flag is set from a form labelled "Skip TLS verification". An SSH device
// has no TLS to skip, and the shared collector passes the same flag to
// sshtrust, where it switches off host-key verification — so a checkbox that
// was ticked for an F5 and carried across a type change, or set on a Cisco
// device before the form hid it, silently disabled the one check that keeps a
// device password off an impostor ( review B1/NB-7). Every place that
// turns a stored device into credentials goes through this.
func EffectiveInsecureSkipVerify(deviceType string, stored bool) bool {
	return stored && !IsSSHManagedDeviceType(deviceType)
}

// IsSSHManagedDeviceType reports whether a device type is reached over SSH by
// its record's IP or hostname (the Cisco collector) rather than by its
// management URL.
func IsSSHManagedDeviceType(deviceType string) bool {
	switch deviceType {
	case "cisco", "cisco_router", "cisco_switch", "cisco_asa":
		return true
	}
	return false
}
