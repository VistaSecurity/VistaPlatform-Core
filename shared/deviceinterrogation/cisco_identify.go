package deviceinterrogation

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Cisco identification: `show version` and `show inventory` over SSH, parsed by
// the collector's own parsers (parseSystemInfo, ciscoParseInventory) and built
// into an identity by the collector's own ciscoDeviceIdentity. Kept out of
// cisco.go and cisco_ops.go, which are edited by other work in flight.
//
// Identification and interrogation deliberately share dialCisco: one SSRF
// guard, host-key policy, authentication stack and context watchdog. This is
// especially important on first contact, where Add device persists the exact
// host key this connection authenticated through.

// Identify implements DeviceIdentifier.
func (*CiscoInterrogator) Identify(ctx context.Context, device DeviceInfo, creds Credentials) (*DeviceIdentification, error) {
	host, port, err := ciscoIdentifyTarget(device)
	if err != nil {
		return nil, invalidTarget(err)
	}
	if creds.Username == "" || (creds.Password == "" && strings.TrimSpace(ciscoCustomString(creds, ciscoCredPrivateKey)) == "") {
		return nil, &IdentifyError{Code: IdentifyAuthenticationFailed, Err: errors.New("username and a password or SSH private key are required")}
	}

	// creds.InsecureSkipVerify is deliberately NOT passed on. On a Cisco device
	// the flag arrives from a form labelled "Skip TLS verification", and in
	// sshtrust it would switch off known_hosts verification instead — a TLS
	// opt-in silently becoming an SSH host-key opt-out ( review B1/NB-7).
	identifyDevice := device
	identifyDevice.IPAddress = host
	identifyDevice.Hostname = ""
	identifyDevice.Port = port
	identifyCreds := creds
	identifyCreds.InsecureSkipVerify = false
	client, err := dialCisco(ctx, identifyDevice, identifyCreds)
	if err != nil {
		return nil, err
	}
	defer func() { _ = client.Close() }()
	// runBounded does not watch ctx (session.Run cannot be cancelled), so the
	// deadline is enforced by closing the connection underneath it.
	stop := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stop()

	versionOut, _, err := client.runBounded(ctx, "show version")
	if err != nil {
		// The connection's read deadline and ctx's own timer fire at the same
		// instant, in either order: a session killed by the deadline can report
		// "exited without exit status" before ctx.Err() is set. Past the
		// deadline, the deadline is the reason.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
			return nil, context.DeadlineExceeded
		}
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			// The host ran the command and failed it: an SSH server that is
			// not a Cisco CLI.
			return nil, reasonErrorf(WarningNotSupported, "`show version` failed on the device (exit status %d)", exitErr.ExitStatus())
		}
		return nil, err
	}
	if ciscoAuthorizationRefused(versionOut) {
		return nil, reasonErrorf(WarningPermissionDenied, "the device refused `show version` to the account (command authorization)")
	}
	sysInfo, _ := client.parseSystemInfo(versionOut)
	if _, ok := sysInfo["version"]; !ok {
		if _, ok := sysInfo["model"]; !ok {
			return nil, &IdentifyError{Code: IdentifyUnsupportedResponse, Err: errors.New("`show version` output names no Cisco software version or hardware model")}
		}
	}

	// `show inventory` is optional, as it is in the interrogation: an ASA or
	// an older router may not implement it, and `show version` has already
	// identified the device.
	chassis := ciscoChassis{}
	if out, _, err := client.runBounded(ctx, "show inventory"); err == nil && !ciscoAuthorizationRefused(out) {
		chassis = ciscoParseInventory(out)
	}

	identity := ciscoDeviceIdentity(sysInfo, device.DeviceType, chassis.PID)
	if chassis.Serial != "" {
		// The chassis serial is the one the hardware catalogue joins on; the
		// interrogation's hw.serial fact prefers it for the same reason.
		identity.SerialNumber = chassis.Serial
	}
	return &DeviceIdentification{
		DeviceIdentity: *identity,
		Hostname:       ciscoHostnameFromVersion(versionOut),
		TargetHost:     host,
		TargetPort:     port,
		// The key this identification authenticated through. A caller that
		// creates a device from it pins it, so the first interrogation compares
		// against this key instead of trusting whatever answers next (NB-6).
		SSHHostKeyFingerprint: client.hostKeyFingerprint,
		SSHHostKeyType:        client.hostKeyType,
	}, nil
}

// ciscoHostnamePatterns read the device's configured name from `show version`:
// IOS and IOS-XE print "<name> uptime is …", ASA "<name> up 5 days …", NX-OS
// "  Device name: <name>". Each is anchored to the start of a line so a
// banner or a description cannot supply it.
var ciscoHostnamePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?m)^\s*Device name:\s*(\S+)\s*$`),
	regexp.MustCompile(`(?m)^(\S+)\s+uptime is\s`),
	regexp.MustCompile(`(?m)^(\S+)\s+up\s+\d+\s+(?:year|week|day|hour|min|sec)`),
}

// ciscoHostnameFromVersion returns the configured hostname in `show version`,
// or "".
func ciscoHostnameFromVersion(output string) string {
	for _, pattern := range ciscoHostnamePatterns {
		if m := pattern.FindStringSubmatch(output); len(m) > 1 {
			// "Kernel uptime is …" is NX-OS's own line, not a hostname.
			if strings.EqualFold(m[1], "kernel") {
				continue
			}
			return m[1]
		}
	}
	return ""
}

// ciscoIdentifyTarget resolves where to open SSH. The interrogation reads the
// device record's IP or hostname; "Add device" has only the management address
// the operator typed, which for a Cisco device may be a bare host, host:port,
// ssh://host[:port], or the https:// URL of its web UI (SSH is then on 22).
func ciscoIdentifyTarget(device DeviceInfo) (string, int, error) {
	host := device.IPAddress
	if host == "" {
		host = device.Hostname
	}
	port := device.Port

	if host == "" && strings.TrimSpace(device.ManagementURL) != "" {
		raw := strings.TrimSpace(device.ManagementURL)
		if !strings.Contains(raw, "://") {
			raw = "ssh://" + raw
		}
		shown := DisplayAddress(device.ManagementURL)
		u, err := url.Parse(raw)
		if err != nil {
			// Not %w: a *url.Error prints the whole input, userinfo included.
			return "", 0, fmt.Errorf("management address %q does not parse", shown)
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "ssh" && scheme != "https" && scheme != "http" {
			return "", 0, fmt.Errorf("management address %q must be a host, ssh://host[:port], or an http(s) URL", shown)
		}
		if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
			return "", 0, fmt.Errorf("management address %q must not carry credentials, a query or a fragment", shown)
		}
		if scheme == "ssh" && strings.Trim(u.Path, "/") != "" {
			return "", 0, fmt.Errorf("management address %q must not carry a path", shown)
		}
		host = u.Hostname()
		if scheme == "ssh" && u.Port() != "" && port == 0 {
			p, err := strconv.Atoi(u.Port())
			if err != nil || p < 1 || p > 65535 {
				return "", 0, fmt.Errorf("management address %q has an invalid port", shown)
			}
			port = p
		}
	}
	if host == "" {
		return "", 0, ErrNoTarget
	}
	if !validHost(host) {
		return "", 0, fmt.Errorf("%q is not a usable host", host)
	}
	if port == 0 {
		port = 22
	}
	return host, port, nil
}
