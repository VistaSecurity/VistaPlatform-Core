package services

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// PortScanner handles actual port scanning using nmap
type PortScanner struct {
	timeout   time.Duration
	tlsProber *TLSProber
	sshProber *SSHProber
	// otProber runs the shared OT/ICS + SMB active probes (Modbus, OPC-UA,
	// EtherNet/IP, BACnet, SMB) that nmap can't speak. TLS/SSH stay on the
	// bespoke probers above.
	otProber *shareddisc.Prober
}

// NewPortScanner creates a new port scanner instance
func NewPortScanner() *PortScanner {
	return &PortScanner{
		timeout:   30 * time.Second,
		tlsProber: NewTLSProber(10 * time.Second),
		sshProber: NewSSHProber(10 * time.Second),
		otProber:  shareddisc.NewProber(10 * time.Second),
	}
}

// sharedOTSMBEligible reports whether a protocol should be probed via the
// shared OT/SMB prober (TLS/SSH/HTTPS are handled by the bespoke probers).
func sharedOTSMBEligible(protocol string) bool {
	switch shareddisc.CanonicalProtocolName(protocol) {
	case "MODBUS", "OPCUA", "ETHERNETIP", "BACNET", "SMB":
		return true
	}
	return false
}

// probeSharedOTSMB runs the shared OT/ICS or SMB active probe for the finding's
// protocol/port (if eligible) and merges the result into finding.Data. This is
// the path nmap leaves unprobed — Modbus/OPC-UA/EtherNet-IP/BACnet/SMB targets
// previously got empty findings.
func (ps *PortScanner) probeSharedOTSMB(finding *models.DiscoveryFinding, target string, port int, protocolName, reqProtocol string) {
	proto := reqProtocol
	if !sharedOTSMBEligible(proto) {
		proto = protocolName
	}
	if !sharedOTSMBEligible(proto) {
		return
	}
	log.Printf("[PortScanner] Probing %s for %s:%d via shared prober", proto, target, port)
	res, err := ps.otProber.Probe(target, target, proto, port)
	if err != nil {
		finding.Data[strings.ToLower(shareddisc.CanonicalProtocolName(proto))+"_probe_error"] = err.Error()
		return
	}
	if res == nil {
		return
	}
	for k, v := range res.Metadata {
		finding.Data[k] = v
	}
	if res.Protocol != "" {
		finding.Protocol = res.Protocol
	}
	if res.Confidence > 0 {
		finding.ConfidenceScore = res.Confidence
	}
}

// tlsWrappedProtocols are the protocol names that mean "this listener speaks
// TLS" when a job explicitly asks for them. An explicit request is honoured on
// WHATEVER port the job named — the standalone sensor probes any requested
// port, and hard-coding 443/8443/636 here meant a TLS service on 9443, 465 or
// 993 produced an open-port finding with no crypto data and no error.
var tlsWrappedProtocols = map[string]bool{
	"TLS": true, "HTTPS": true, "SSL": true,
	"LDAPS": true, "SMTPS": true, "IMAPS": true, "POP3S": true, "FTPS": true,
}

// requestsTLS reports whether a protocol name explicitly denotes a TLS-wrapped
// service.
func requestsTLS(protocol string) bool {
	return tlsWrappedProtocols[shareddisc.CanonicalProtocolName(protocol)]
}

// shouldProbeTLS decides whether to run the TLS probe for a (protocol, port)
// pair: honour an explicit TLS request on any port, and otherwise fall back to
// the curated well-known-port map for unspecified sweeps.
func shouldProbeTLS(protocolName, reqProtocol string, port int) bool {
	return requestsTLS(reqProtocol) || requestsTLS(protocolName) || shareddisc.PortSpeaks(port, "TLS")
}

// shouldProbeSSH mirrors shouldProbeTLS for SSH.
func shouldProbeSSH(protocolName, reqProtocol string, port int) bool {
	return shareddisc.CanonicalProtocolName(reqProtocol) == "SSH" ||
		shareddisc.CanonicalProtocolName(protocolName) == "SSH" ||
		shareddisc.PortSpeaks(port, "SSH")
}

// isProbeEnabled checks whether a probe type is enabled for this scan.
// Returns true if no options are set or the option is not explicitly false.
func isProbeEnabled(opts map[string]interface{}, key string) bool {
	if opts == nil {
		return true
	}
	if val, ok := opts[key].(bool); ok {
		return val
	}
	return true // default: enabled
}

// validateNmapTarget validates that a target string is safe to pass to nmap.
// It must be a valid IP address or a hostname with only safe characters.
func validateNmapTarget(target string) error {
	if target == "" {
		return fmt.Errorf("empty target")
	}

	// If it's a valid IP address, allow it
	if net.ParseIP(target) != nil {
		return nil
	}

	// Reject targets that start with '-' to prevent nmap option injection
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("invalid target: must not start with '-'")
	}

	// Only allow valid hostname characters: alphanumeric, dots, hyphens
	for _, ch := range target {
		if !((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '-') {
			return fmt.Errorf("invalid target: contains illegal character %q", ch)
		}
	}

	if len(target) > 253 {
		return fmt.Errorf("invalid target: hostname too long")
	}

	return nil
}

// ScanTarget performs actual port scanning on a target
// target: The IP address or hostname to scan (for nmap/connection)
// originalHostname: The original hostname entered by user (for SNI and display), if nil uses target
// probeOpts: per-job capability policy (nil means all probes enabled)
func (ps *PortScanner) ScanTarget(target string, ports []int32, protocols []string, originalHostname *string, probeOpts map[string]interface{}) ([]models.DiscoveryFinding, error) {
	var findings []models.DiscoveryFinding

	// Validate target to prevent nmap argument injection
	if err := validateNmapTarget(target); err != nil {
		return nil, fmt.Errorf("target validation failed: %w", err)
	}

	// Convert ports to string slice for nmap
	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = strconv.Itoa(int(port))
	}
	portList := strings.Join(portStrings, ",")

	// Build nmap command
	args := []string{
		"-sS",                // SYN scan
		"-T4",                // Aggressive timing
		"-Pn",                // Skip host discovery
		"-n",                 // Never do DNS resolution
		"--max-retries", "1", // Reduce retries for speed
		"--max-rtt-timeout", "1s", // Reduce RTT timeout
		"-p", portList, // Ports to scan
		target, // Target to scan
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), ps.timeout)
	defer cancel()

	// Execute nmap
	cmd := exec.CommandContext(ctx, "nmap", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If nmap fails, fall back to basic connectivity check
		return ps.fallbackScan(target, ports, protocols, originalHostname, probeOpts)
	}

	// Parse nmap output
	findings = ps.parseNmapOutput(string(output), target, ports, protocols, originalHostname, probeOpts)

	return findings, nil
}

// parseNmapOutput parses nmap output and creates findings
func (ps *PortScanner) parseNmapOutput(output, target string, ports []int32, protocols []string, originalHostname *string, probeOpts map[string]interface{}) []models.DiscoveryFinding {
	var findings []models.DiscoveryFinding

	lines := strings.Split(output, "\n")
	inPortSection := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check if we're in the port section
		if strings.Contains(line, "PORT") && strings.Contains(line, "STATE") && strings.Contains(line, "SERVICE") {
			inPortSection = true
			continue
		}

		// Skip empty lines and non-port lines
		if !inPortSection || line == "" || strings.HasPrefix(line, "Nmap scan report") {
			continue
		}

		// Parse port line (format: port/protocol state service)
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		// Extract port and protocol
		portProto := strings.Split(parts[0], "/")
		if len(portProto) != 2 {
			continue
		}

		portStr := portProto[0]
		protocol := portProto[1]

		// Convert port to int
		port, err := strconv.Atoi(portStr)
		if err != nil {
			continue
		}

		// Check if this port was requested
		requestedPort := false
		for _, reqPort := range ports {
			if int(reqPort) == port {
				requestedPort = true
				break
			}
		}

		if !requestedPort {
			continue
		}

		// Check if port is open
		state := parts[1]
		if state == "open" || state == "open|filtered" {
			// Resolve target to IP. A hostname that fails to resolve yields no
			// IP — record that on the finding instead of dereferencing nil,
			// which panicked the whole job goroutine.
			resolvedIP, resolveErr := ps.resolveTargetIP(target)

			// Determine hostname for display and SNI
			displayHostname := target
			sniHostname := target
			if originalHostname != nil && *originalHostname != "" {
				displayHostname = *originalHostname
				sniHostname = *originalHostname
			}

			// Create finding for each requested protocol
			for _, reqProtocol := range protocols {
				// Map nmap protocol to our protocol
				protocolName := ps.mapProtocol(protocol, reqProtocol)

				finding := models.DiscoveryFinding{
					ExecutedVia:     "nmap",
					Protocol:        protocolName,
					Port:            port,
					ResolvedIP:      resolvedIP,
					Hostname:        displayHostname,
					ConfidenceScore: ps.calculateConfidence(state),
					CreatedAt:       time.Now(),
					Data:            make(map[string]interface{}),
				}
				if resolveErr != "" {
					finding.Data["dns_resolution_failed"] = true
					finding.Data["dns_resolution_error"] = resolveErr
				}

				// Probe TLS when the job asked for a TLS-wrapped protocol (on
				// whatever port it named) or when the port is a well-known TLS
				// port.
				if shouldProbeTLS(protocolName, reqProtocol, port) {
					log.Printf("[PortScanner] Probing TLS for %s:%d (protocolName=%s, reqProtocol=%s, SNI=%s)", target, port, protocolName, reqProtocol, sniHostname)
					skipVerEnum := !isProbeEnabled(probeOpts, "tls_version_enumeration")
					if tlsData, err := ps.tlsProber.ProbeTLS(sniHostname, port, skipVerEnum); err == nil {
						// Merge (not replace) so anything already recorded on
						// the finding — e.g. a resolution failure — survives.
						for k, v := range tlsData {
							finding.Data[k] = v
						}
						certCount := 0
						if certs, ok := tlsData["certificates"].([]interface{}); ok {
							certCount = len(certs)
						} else if certs, ok := tlsData["certificates"].([]map[string]interface{}); ok {
							certCount = len(certs)
						}
						log.Printf("[PortScanner] TLS probe successful for %s:%d, certificates=%d, cipher_suite=%v",
							target, port, certCount, tlsData["cipher_suite"])
						// Update protocol if we successfully probed TLS
						if strings.EqualFold(protocolName, "tcp") {
							protocolName = "TLS"
						}
						finding.Protocol = protocolName
					} else {
						// Log error but continue with basic finding
						log.Printf("[PortScanner] TLS probe failed for %s:%d: %v", target, port, err)
						finding.Data["tls_probe_error"] = err.Error()
					}
				} else {
					log.Printf("[PortScanner] Skipping TLS probe for %s:%d (protocolName=%s, reqProtocol=%s)",
						target, port, protocolName, reqProtocol)
				}

				// Probe SSH when the job asked for SSH (any port) or the port
				// is a well-known SSH port.
				if shouldProbeSSH(protocolName, reqProtocol, port) && isProbeEnabled(probeOpts, "ssh_probing") {
					log.Printf("[PortScanner] Probing SSH for %s:%d", target, port)
					if sshData, err := ps.sshProber.ProbeSSH(target, port); err == nil {
						for k, v := range sshData {
							finding.Data[k] = v
						}
						log.Printf("[PortScanner] SSH probe successful for %s:%d, host_key_type=%v",
							target, port, sshData["ssh_host_key_type"])
						if strings.EqualFold(protocolName, "tcp") {
							protocolName = "SSH"
						}
						finding.Protocol = protocolName
					} else {
						log.Printf("[PortScanner] SSH probe failed for %s:%d: %v", target, port, err)
						finding.Data["ssh_probe_error"] = err.Error()
					}
				}

				// OT/ICS + SMB protocols nmap can't speak: probe via the shared core.
				ps.probeSharedOTSMB(&finding, target, port, protocolName, reqProtocol)

				findings = append(findings, finding)
			}
		}
	}

	return findings
}

// fallbackScan performs a basic connectivity check when nmap fails
func (ps *PortScanner) fallbackScan(target string, ports []int32, protocols []string, originalHostname *string, probeOpts map[string]interface{}) ([]models.DiscoveryFinding, error) {
	var findings []models.DiscoveryFinding

	// Resolve target to IP (nil-safe: an unresolvable hostname is recorded on
	// the finding, not dereferenced).
	resolvedIP, resolveErr := ps.resolveTargetIP(target)

	// Determine hostname for display and SNI
	displayHostname := target
	sniHostname := target
	if originalHostname != nil && *originalHostname != "" {
		displayHostname = *originalHostname
		sniHostname = *originalHostname
	}

	// Check each port with basic TCP connection
	for _, port := range ports {
		address := net.JoinHostPort(target, strconv.Itoa(int(port)))

		conn, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err == nil {
			conn.Close()

			// Port is open, create findings for each protocol
			for _, protocol := range protocols {
				finding := models.DiscoveryFinding{
					ExecutedVia:     "tcp-connect",
					Protocol:        protocol,
					Port:            int(port),
					ResolvedIP:      resolvedIP,
					Hostname:        displayHostname,
					ConfidenceScore: 0.7, // Lower confidence for basic scan
					CreatedAt:       time.Now(),
					Data:            make(map[string]interface{}),
				}
				if resolveErr != "" {
					finding.Data["dns_resolution_failed"] = true
					finding.Data["dns_resolution_error"] = resolveErr
				}

				// Probe TLS on any explicitly requested TLS-wrapped protocol,
				// or on a well-known TLS port.
				if shouldProbeTLS(protocol, protocol, int(port)) {
					skipVerEnum := !isProbeEnabled(probeOpts, "tls_version_enumeration")
					if tlsData, err := ps.tlsProber.ProbeTLS(sniHostname, int(port), skipVerEnum); err == nil {
						for k, v := range tlsData {
							finding.Data[k] = v
						}
					} else {
						// Log error but continue with basic finding
						finding.Data["tls_probe_error"] = err.Error()
					}
				}

				// Probe SSH on an explicit SSH request or a well-known SSH port.
				if shouldProbeSSH(protocol, protocol, int(port)) && isProbeEnabled(probeOpts, "ssh_probing") {
					if sshData, err := ps.sshProber.ProbeSSH(target, int(port)); err == nil {
						for k, v := range sshData {
							finding.Data[k] = v
						}
					} else {
						finding.Data["ssh_probe_error"] = err.Error()
					}
				}

				// OT/ICS + SMB protocols nmap can't speak: probe via the shared core.
				ps.probeSharedOTSMB(&finding, target, int(port), protocol, protocol)

				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// resolveTargetIP resolves a target to an IP address, returning ("", reason)
// when it cannot be resolved. Callers must not assume a resolution succeeded:
// discovery_findings.resolved_ip is nullable precisely so an unresolvable
// target still produces a recorded result rather than a lost scan.
func (ps *PortScanner) resolveTargetIP(target string) (ip string, failureReason string) {
	// If it's already an IP address, return it
	if net.ParseIP(target) != nil {
		return target, ""
	}

	// Try to resolve the hostname to an IP address
	ips, err := net.LookupIP(target)
	if err != nil {
		return "", fmt.Sprintf("DNS resolution failed for %q: %v", target, err)
	}
	if len(ips) == 0 {
		return "", fmt.Sprintf("DNS resolution returned no addresses for %q", target)
	}

	// Prefer the first IPv4 address found
	for _, addr := range ips {
		if addr.To4() != nil {
			return addr.String(), ""
		}
	}

	// If no IPv4 found, return the first IP (IPv6)
	return ips[0].String(), ""
}

// mapProtocol maps nmap protocol names to our protocol names
func (ps *PortScanner) mapProtocol(nmapProtocol, requestedProtocol string) string {
	// If the requested protocol matches, use it
	if strings.EqualFold(nmapProtocol, requestedProtocol) {
		return requestedProtocol
	}

	// Map common nmap protocol names
	switch strings.ToLower(nmapProtocol) {
	case "tcp":
		// For TCP ports, preserve the requested protocol if it's more specific (TLS, HTTPS, etc.)
		// Only return "tcp" if the user didn't specify a more specific protocol
		requestedLower := strings.ToLower(requestedProtocol)
		if requestedLower == "tls" || requestedLower == "https" || requestedLower == "ssh" ||
			requestedLower == "smtps" || requestedLower == "imaps" || requestedLower == "pop3s" ||
			requestedLower == "ftps" || requestedLower == "ldaps" ||
			requestedLower == "smb" || requestedLower == "kerberos" || requestedLower == "rdp" {
			return requestedProtocol // Preserve user's protocol choice
		}
		return "tcp"
	case "microsoft-ds", "smb":
		return "SMB"
	case "kerberos-sec", "kerberos":
		return "Kerberos"
	case "udp":
		return "udp"
	case "http":
		return "http"
	case "https":
		return "https"
	case "ssh":
		return "ssh"
	case "ftp":
		return "ftp"
	case "smtp":
		return "smtp"
	case "dns":
		return "dns"
	default:
		return requestedProtocol
	}
}

// calculateConfidence calculates confidence score based on nmap state
func (ps *PortScanner) calculateConfidence(state string) float64 {
	switch state {
	case "open":
		return 0.95
	case "open|filtered":
		return 0.80
	case "filtered":
		return 0.60
	default:
		return 0.50
	}
}
