package deviceinterrogation

import (
	"context"
	"strings"
)

// Identify for the HTTP-API vendors. Each one builds the collector's own
// client and calls the collector's own system-info reader and identity
// builder, so an identification and an interrogation cannot disagree about
// what a device is. Cisco, which is SSH, is in cisco_identify.go.
//
// Kept in one file apart from the collectors on purpose: the collectors are
// edited continuously (capability manifest, warnings, parser fixes), and this
// file depends on them only through the functions interrogation itself calls.

// Identify implements DeviceIdentifier: FortiOS `system/status`.
func (*FortinetInterrogator) Identify(ctx context.Context, device DeviceInfo, creds Credentials) (*DeviceIdentification, error) {
	username, password := usernamePassword(creds)
	if username == "" || password == "" {
		return nil, missingCredentials()
	}
	baseURL, err := managementURL(device)
	if err != nil {
		return nil, invalidTarget(err)
	}
	client := newFortinetClient(baseURL, username, password, creds.InsecureSkipVerify)
	sysInfo, err := client.getSystemInfo(ctx)
	if err != nil {
		return nil, err
	}
	return (&DeviceIdentification{
		DeviceIdentity: *fortinetIdentity(sysInfo),
		Hostname:       fortinetString(sysInfo, "hostname"),
	}).reachedAt(baseURL), nil
}

// Identify implements DeviceIdentifier: PAN-OS keygen, then `show system info`.
func (*PaloAltoInterrogator) Identify(ctx context.Context, device DeviceInfo, creds Credentials) (*DeviceIdentification, error) {
	username, password := usernamePassword(creds)
	if username == "" || password == "" {
		return nil, missingCredentials()
	}
	baseURL, err := managementURL(device)
	if err != nil {
		return nil, invalidTarget(err)
	}
	client := newPanClient(baseURL, username, password, creds.InsecureSkipVerify)
	if err := client.getAPIKey(ctx); err != nil {
		return nil, err
	}
	_, info, err := client.getSystemInfo(ctx)
	if err != nil {
		return nil, err
	}
	hostname := info.Hostname
	if hostname == "" {
		hostname = info.DeviceName
	}
	return (&DeviceIdentification{
		DeviceIdentity: *panIdentity(info),
		Hostname:       hostname,
		IPAddress:      info.IPAddress,
		MACAddress:     info.MACAddress,
	}).reachedAt(baseURL), nil
}

// Identify implements DeviceIdentifier: iControl login, `sys/version`, and the
// allowlisted `sys/hardware` leaves for the chassis model and serial.
func (*F5Interrogator) Identify(ctx context.Context, device DeviceInfo, creds Credentials) (*DeviceIdentification, error) {
	username, password := usernamePassword(creds)
	if username == "" || password == "" {
		return nil, missingCredentials()
	}
	baseURL, err := managementURL(device)
	if err != nil {
		return nil, invalidTarget(err)
	}
	client := newF5Client(baseURL, username, password, creds.Token, creds.InsecureSkipVerify)
	if err := client.authenticate(ctx); err != nil {
		return nil, err
	}
	sysInfo, err := client.getSystemInfo(ctx)
	if err != nil {
		return nil, err
	}
	identity := f5Identity(sysInfo)

	// The hardware read is the interrogation's own, and like there it is not
	// fatal: a Virtual Edition under some hypervisors reports an empty tree,
	// and sys/version has already proved this is a BIG-IP. Its warning goes
	// nowhere — an identification has no warnings to carry.
	hardware := client.f5Hardware(ctx, &InterrogateResult{collector: f5Collector})
	if model := f5FirstNonEmpty(hardware, "marketingName", "platform"); model != "" {
		identity.Model = model
	}
	identity.SerialNumber = f5FirstNonEmpty(hardware, "bigipChassisSerialNum", "hostBoardSerialNum")
	return (&DeviceIdentification{DeviceIdentity: *identity}).reachedAt(baseURL), nil
}

// unifiGatewayTypes are the `stat/device` types that are a site's gateway. On
// a UniFi OS console (UDM, UDR, UXG) that gateway IS the console we logged in
// to.
var unifiGatewayTypes = map[string]bool{"udm": true, "ugw": true, "uxg": true, "udr": true}

// Identify implements DeviceIdentifier: controller login, the site's
// `super_identity` setting, and the device list.
//
// Which managed device is the one we were pointed at: the one whose address is
// the host we dialled, else — on a UniFi OS console only — the site's gateway.
// A legacy software controller is not any of its managed devices, so there it
// is identified by its own configured name and nothing else. The previous
// discovery client fell back to "the first device in the list", which put an
// access point's serial on a controller record.
func (*UnifiInterrogator) Identify(ctx context.Context, device DeviceInfo, creds Credentials) (*DeviceIdentification, error) {
	username, password := usernamePassword(creds)
	if username == "" || password == "" {
		return nil, missingCredentials()
	}
	siteID := device.SiteID
	if siteID == "" && device.Metadata != nil {
		siteID, _ = device.Metadata["site_id"].(string)
	}
	site := siteID
	if site == "" {
		site = "default"
	}
	baseURL, err := managementURL(device)
	if err != nil {
		return nil, invalidTarget(err)
	}
	client := newUnifiClient(baseURL, username, password, siteID, creds.InsecureSkipVerify)
	if err := client.authenticate(ctx); err != nil {
		return nil, err
	}
	devices, err := client.getDevices(ctx, site)
	if err != nil {
		return nil, err
	}

	identification := &DeviceIdentification{DeviceIdentity: *unifiIdentity(nil)}
	// Non-fatal, as in the interrogation: a restricted admin may not read
	// site settings, and the device list has already proved the controller.
	if controller, err := client.getControllerIdentity(ctx, site); err == nil {
		for _, key := range []string{"controller_hostname", "controller_name"} {
			if v, _ := controller[key].(string); strings.TrimSpace(v) != "" {
				identification.Hostname = strings.TrimSpace(v)
				break
			}
		}
	}

	dialledHost, _ := unifiHostPort(baseURL)
	onConsole := client.apiPrefix == "/proxy/network"
	var self map[string]interface{}
	for _, d := range devices {
		if ip, _ := d["ip"].(string); ip != "" && ip == dialledHost {
			self = d
			break
		}
		if kind, _ := d["type"].(string); onConsole && self == nil && unifiGatewayTypes[strings.ToLower(kind)] {
			self = d
		}
	}
	if self != nil {
		str := func(key string) string { s, _ := self[key].(string); return strings.TrimSpace(s) }
		identification.Model = str("model")
		identification.SerialNumber = str("serial")
		if version := str("version"); version != "" {
			identification.FirmwareVersion = version
			identification.OSVersion = "UniFi OS " + version
		}
		if name := str("name"); name != "" {
			identification.Hostname = name
		}
		identification.IPAddress = str("ip")
		identification.MACAddress = str("mac")
	}
	return identification.reachedAt(baseURL), nil
}
