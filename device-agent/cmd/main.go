package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/api"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/audit"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/devices"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
	"golang.org/x/term"
)

// Version is stamped at build time via -ldflags "-X main.Version=<tag>"
// (see the Makefile's AGENT_LDFLAGS and release-core.yml). An unstamped
// build honestly reports "dev" rather than claiming to be a release.
var Version = "dev"

type DeviceAgent struct {
	config      *config.Config
	configPath  string
	apiClient   *api.OutboundClient
	jobExecutor *devices.JobExecutor
	auditLogger *audit.AuditLogger
}

type certificateRotator interface {
	CheckCertificateExpiration() (time.Time, bool, error)
	RotateCertificate() error
}

func main() {
	var (
		version    = flag.Bool("version", false, "Show version information")
		configFile = flag.String("config", "", "Path to configuration file (optional)")
		// verbose and interactive default ON: running the binary with no flags
		// is the install path, and an installer wants the dialogue and the
		// detail. Both step aside for an existing configuration (see
		// shouldRunInteractive) or an explicit -verbose=false /
		// -interactive=false.
		verbose     = flag.Bool("verbose", true, "Enable verbose logging (-verbose=false to quiet)")
		register    = flag.Bool("register", false, "Register with control plane")
		interactive = flag.Bool("interactive", true, "Run interactive configuration setup when no configuration exists (-interactive=false to skip)")
		// caFingerprint makes the trust decision out of band, for unattended
		// installs that cannot answer a prompt. The agent pins the platform CA
		// only if it hashes to this value — which, unlike the interactive
		// prompt, is not trust-on-first-use.
		caFingerprint = flag.String("ca-fingerprint", "",
			"Expected SHA-256 fingerprint of the platform's CA certificate. Required for unattended "+
				"enrollment against a platform whose certificate is signed by a private CA this host does not trust.")
	)
	flag.Parse()

	// Show version and exit
	if *version {
		fmt.Printf("VistaPlatform Device Agent v%s\n", Version)
		fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Go version: %s\n", runtime.Version())
		os.Exit(0)
	}

	// Initialize logging
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
	} else {
		log.SetFlags(log.LstdFlags)
	}

	log.Printf("🚀 Starting VistaPlatform Device Agent v%s", Version)
	log.Printf("Platform: %s/%s", runtime.GOOS, runtime.GOARCH)

	// Resolve the configuration file up front: an existing configuration is
	// what turns the interactive installer off, so the decision needs to know
	// about it before anything else happens.
	configPath := *configFile
	if configPath == "" {
		configPath = findDefaultConfigFile()
	}

	// Interactive configuration mode. This is the default on a fresh host —
	// running the binary with no arguments IS the install flow — and it starts
	// the agent when it finishes, so setup and first run are one step (the
	// sensor behaves identically).
	// term.IsTerminal, not a ModeCharDevice check: /dev/null IS a character
	// device, so the cheap check calls `agent < /dev/null` — how service
	// managers commonly start it — an interactive terminal and hangs on the
	// first prompt.
	if shouldRunInteractive(*interactive, isFlagSet("interactive"), configPath, *register, term.IsTerminal(int(os.Stdin.Fd()))) {
		cfg, setupPath, apiClient, err := runInteractiveSetup(*caFingerprint)
		if err != nil {
			log.Fatalf("❌ Interactive setup failed: %v", err)
		}
		if cfg == nil {
			// Operator cancelled at a prompt; nothing to run.
			return
		}
		fmt.Println()
		fmt.Println("✅ Setup complete — starting the device agent. Press Ctrl+C to stop.")
		fmt.Println()
		runAgent(cfg, setupPath, apiClient)
		return
	}

	// Load configuration
	var cfg *config.Config
	var err error

	if configPath != "" {
		log.Printf("📁 Loading configuration from file: %s", configPath)
		cfg, err = config.LoadFromFile(configPath)
		if err != nil {
			log.Printf("⚠️  Failed to load config file (%v), falling back to environment variables", err)
			cfg = config.Load()
			configPath = ""
		}
	} else {
		cfg = config.Load()
	}

	// Verbose logging is on by default; a `verbose:` key in the config file (or
	// the VERBOSE env var) is how an operator turns it back down for a
	// long-running install. An explicit -verbose on the command line still wins.
	if cfg.Verbose != nil && !isFlagSet("verbose") {
		if *cfg.Verbose {
			log.SetFlags(log.LstdFlags | log.Lshortfile)
		} else {
			log.SetFlags(log.LstdFlags)
			log.Println("Verbose logging disabled by configuration")
		}
	}

	// Require valid UUID for agent_id when set (same idea as sensor)
	if cfg.AgentID != "" {
		if _, err := uuid.Parse(cfg.AgentID); err != nil {
			log.Printf("⚠️  Agent ID %q is not a valid UUID — clearing it; re-registration may be required", cfg.AgentID)
			cfg.AgentID = ""
		}
	}

	// Unattended trust bootstrap. With --ca-fingerprint and no CA already in
	// config, fetch the platform's CA, verify it hashes to the expected value,
	// and pin it before the client is built. Without the flag nothing is
	// pinned and verification falls back to the system trust store — the right
	// behaviour for a platform holding a publicly-trusted certificate.
	if *caFingerprint != "" && cfg.Security.ServerCACert == "" {
		anchor, err := certificates.ResolveTrustAnchor(cfg.PlatformURL, *caFingerprint, nil, os.Stdout, false)
		if err != nil {
			log.Fatalf("❌ Could not establish trust with the platform: %v", err)
		}
		cfg.Security.ServerCACert = anchor.PEM
		log.Printf("🔒 Pinned platform CA: %s", anchor.Certificate.Subject.String())
	}

	// Create API client (outbound-only)
	apiClient := api.NewOutboundClient(cfg)
	apiClient.SetAgentVersion(Version)

	// Register with platform if requested
	if *register {
		log.Println("📝 Registering agent with platform...")
		if err := apiClient.Register(Version); err != nil {
			log.Fatalf("❌ Failed to register agent: %v", err)
		}
		log.Println("✅ Agent registered successfully")

		// Save certificates to disk
		if err := saveCertificates(cfg); err != nil {
			log.Printf("⚠️  Failed to save certificates to disk: %v", err)
			// Continue anyway - certificates are in memory
		} else {
			log.Printf("✅ Certificates saved to: %s/certs", cfg.DataPath)
		}

		// Save config file with agent ID and certificate paths
		if *configFile != "" {
			if err := saveConfigFile(*configFile, cfg); err != nil {
				log.Printf("⚠️  Failed to save config file: %v", err)
			} else {
				log.Printf("💾 Configuration saved to: %s", *configFile)
			}
		}

		return
	}

	// Sensor-style bootstrap: registration key present but no enrolled agent yet
	if cfg.RegistrationKey != "" && cfg.AgentID == "" {
		log.Println("📝 Registration key set without agent_id — registering with control plane...")
		if err := apiClient.Register(Version); err != nil {
			log.Printf("⚠️  Auto-registration failed (continuing without enrollment): %v", err)
		} else {
			log.Println("✅ Agent enrolled successfully")
			if err := saveCertificates(cfg); err != nil {
				log.Printf("⚠️  Failed to save certificates to disk: %v", err)
			} else {
				log.Printf("✅ Certificates saved to: %s/certs", cfg.DataPath)
			}
			if configPath == "" {
				configPath = filepath.Join(cfg.DataPath, "agent-config.yaml")
			}
			if err := saveConfigFile(configPath, cfg); err != nil {
				log.Printf("⚠️  Failed to save config file: %v", err)
			} else {
				log.Printf("💾 Configuration saved to: %s", configPath)
			}
		}
	}

	runAgent(cfg, configPath, apiClient)
}

// runAgent wires up the agent and runs it until the process is signalled. It is
// the single run path: both the config-file start and the interactive installer
// end here, so a freshly-configured agent behaves exactly like a restarted one.
// apiClient may be nil, in which case one is built from cfg.
func runAgent(cfg *config.Config, configPath string, apiClient *api.OutboundClient) {
	if apiClient == nil {
		apiClient = api.NewOutboundClient(cfg)
		apiClient.SetAgentVersion(Version)
	}

	// Initialize audit logger
	auditLogger, err := audit.NewAuditLogger(cfg.DataPath)
	if err != nil {
		log.Printf("⚠️  Failed to initialize audit logger: %v — audit logging disabled", err)
	} else {
		log.Printf("📋 Audit log: %s", auditLogger.GetPath())
	}

	// Create job executor
	jobExecutor := devices.NewJobExecutorWithAudit(apiClient, cfg, auditLogger)

	// Create agent
	agent := &DeviceAgent{
		config:      cfg,
		configPath:  configPath,
		apiClient:   apiClient,
		jobExecutor: jobExecutor,
		auditLogger: auditLogger,
	}

	// Start agent
	if err := agent.Start(); err != nil {
		log.Fatalf("❌ Failed to start agent: %v", err)
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down device agent...")
	agent.Stop()
	log.Println("✅ Device agent stopped")
}

// isFlagSet reports whether the named flag was given on the command line, as
// opposed to sitting at its default. The interactive/verbose defaults are ON,
// so "the operator asked for this" and "nobody said anything" have to be told
// apart before an existing configuration is allowed to override them.
func isFlagSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// findDefaultConfigFile returns the first readable config file in the standard
// locations, or "" when the host has never been configured.
func findDefaultConfigFile() string {
	for _, path := range []string{
		"agent-config.yaml",
		filepath.Join(getDefaultDataPath(), "agent-config.yaml"),
	} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// shouldRunInteractive decides whether to open the configuration dialogue.
//
// The dialogue is the default so a bare `./device-agent` on a fresh host walks
// the installer through setup and then starts polling for jobs. It steps aside
// for every signal that this is not a fresh interactive install:
//
//   - an explicit -interactive=false,
//   - an existing config file (the documented way to override the default),
//   - PLATFORM_URL in the environment (container/unattended deployment),
//   - -register, which is the scripted enrollment path,
//   - stdin that is not a terminal (tty=false), where a prompt would hang
//     forever with nobody to answer it.
//
// An explicit -interactive beats all of them: an operator asking to reconfigure
// a host that already has a config file gets the dialogue.
func shouldRunInteractive(want, explicit bool, configPath string, register, tty bool) bool {
	if !want {
		return false
	}
	if explicit {
		return true
	}
	if configPath != "" || os.Getenv("PLATFORM_URL") != "" || register {
		return false
	}
	return tty
}

// Start starts the device agent
func (a *DeviceAgent) Start() error {
	log.Println("✅ Device agent started")
	log.Printf("📍 Platform URL: %s", a.config.PlatformURL)
	log.Printf("🔄 Polling interval: %v", a.config.PollInterval)
	log.Printf("💓 Heartbeat interval: %v", a.config.HeartbeatInterval)

	if a.apiClient != nil && a.config.Security.UseTLS {
		go a.monitorCertificateRotation()
	}

	// Start job polling loop
	go a.pollForJobs()

	// Start heartbeat loop. Without it device_agents.last_heartbeat never moves
	// after registration: the agent is invisible to the platform's liveness
	// view, and a genuinely dead agent raises no discovery_agent_offline alert
	// because that detector excludes rows whose last_heartbeat is NULL.
	go a.sendHeartbeats()

	return nil
}

// Stop stops the device agent
func (a *DeviceAgent) Stop() {
	if a.auditLogger != nil {
		a.auditLogger.Close()
	}
}

// pollForJobs continuously polls for jobs from the platform
func (a *DeviceAgent) pollForJobs() {
	ticker := time.NewTicker(a.config.PollInterval)
	defer ticker.Stop()

	// Poll immediately on start
	a.executeJobPoll()

	for range ticker.C {
		a.executeJobPoll()
	}
}

// heartbeatSender is the slice of the API client the heartbeat loop needs, so
// the loop can be tested without a platform.
type heartbeatSender interface {
	SendHeartbeat() error
}

// sendHeartbeats reports liveness to the platform on the configured interval.
func (a *DeviceAgent) sendHeartbeats() {
	interval := a.config.HeartbeatInterval
	if interval <= 0 {
		interval = config.DefaultHeartbeatInterval
	}
	runHeartbeatLoop(a.apiClient, interval, nil)
}

// runHeartbeatLoop beats immediately, then on the interval, until stop closes.
// A failed beat is logged and retried on the next tick — a transient network
// blip must not silently end the agent's liveness reporting for the lifetime of
// the process.
func runHeartbeatLoop(sender heartbeatSender, interval time.Duration, stop <-chan struct{}) {
	if sender == nil {
		return
	}
	beat := func() {
		if err := sender.SendHeartbeat(); err != nil {
			log.Printf("⚠️  Heartbeat failed: %v", err)
		}
	}

	beat()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			beat()
		}
	}
}

func (a *DeviceAgent) monitorCertificateRotation() {
	a.checkAndRotateCertificate()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		a.checkAndRotateCertificate()
	}
}

func (a *DeviceAgent) checkAndRotateCertificate() {
	checkAndRotateAgentCertificate(
		a.apiClient,
		a.config,
		saveCertificates,
		func() error {
			if a.configPath == "" {
				return fmt.Errorf("no config file path set")
			}
			return saveConfigFile(a.configPath, a.config)
		},
	)
}

func checkAndRotateAgentCertificate(rotator certificateRotator, cfg *config.Config, saveCerts func(*config.Config) error, saveCfg func() error) bool {
	if rotator == nil {
		return false
	}

	expiresAt, expiringSoon, err := rotator.CheckCertificateExpiration()
	if err != nil {
		log.Printf("⚠️  Failed to check certificate expiration: %v", err)
		return false
	}

	if !expiringSoon {
		log.Printf("✅ Certificate valid until %s", expiresAt.Format(time.RFC3339))
		return false
	}

	log.Printf("🔄 Certificate expires on %s, rotating...", expiresAt.Format(time.RFC3339))
	if err := rotator.RotateCertificate(); err != nil {
		log.Printf("❌ Failed to rotate certificate: %v", err)
		return false
	}

	if saveCerts != nil {
		if err := saveCerts(cfg); err != nil {
			log.Printf("⚠️  Failed to persist rotated certificate to disk: %v", err)
		}
	}
	if saveCfg != nil {
		if err := saveCfg(); err != nil {
			log.Printf("⚠️  Failed to persist rotated certificate to config file: %v", err)
		}
	}

	log.Println("✅ Certificate rotated successfully")
	return true
}

// executeJobPoll polls for a job and executes it if available
func (a *DeviceAgent) executeJobPoll() {
	job, err := a.apiClient.GetNextJob()
	if err != nil {
		log.Printf("⚠️  Error polling for jobs: %v", err)
		return
	}

	if job == nil {
		// No job available
		return
	}

	log.Printf("📋 Received job: %s (type: %s)", job.ID, job.Type)

	// Execute job
	if err := a.jobExecutor.Execute(job); err != nil {
		log.Printf("❌ Error executing job %s: %v", job.ID, err)
		// Report error back to platform
		if err := a.apiClient.ReportJobError(job.ID, err.Error()); err != nil {
			log.Printf("⚠️  Failed to report job error: %v", err)
		}
		return
	}

	log.Printf("✅ Job %s completed successfully", job.ID)
}

// saveCertificates saves mTLS certificates to disk files
func saveCertificates(cfg *config.Config) error {
	return config.SaveCertificatesToFiles(
		cfg,
		cfg.Security.ClientCert,
		cfg.Security.ClientKey,
		cfg.Security.ServerCACert,
		cfg.DataPath,
	)
}

// saveConfigFile updates the config file with agent ID and certificate paths
func saveConfigFile(configPath string, cfg *config.Config) error {
	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	var configContent strings.Builder

	// Add header
	configContent.WriteString("# VistaPlatform Device Agent Configuration\n")
	configContent.WriteString(fmt.Sprintf("# Generated after registration\n\n"))

	// Write config with proper quoting for Windows paths
	configContent.WriteString(fmt.Sprintf("agent_id: %q\n", cfg.AgentID))
	configContent.WriteString(fmt.Sprintf("platform_url: %s\n", cfg.PlatformURL))
	configContent.WriteString(fmt.Sprintf("registration_key: %s\n", cfg.RegistrationKey))
	configContent.WriteString(fmt.Sprintf("poll_interval: %s\n", cfg.PollInterval))
	configContent.WriteString(fmt.Sprintf("data_path: %q\n", cfg.DataPath))
	// Only write `verbose:` when something actually set it. Writing the
	// resolved value would silently pin the command-line default into the file
	// and make it look like an operator choice.
	if cfg.Verbose != nil {
		configContent.WriteString(fmt.Sprintf("verbose: %t\n", *cfg.Verbose))
	}

	// Add security section with certificate paths
	if cfg.Security.ClientCertPath != "" {
		configContent.WriteString("\n# mTLS Certificate Configuration (auto-generated after registration)\n")
		configContent.WriteString("security:\n")
		configContent.WriteString(fmt.Sprintf("  client_cert_path: %q\n", cfg.Security.ClientCertPath))
		configContent.WriteString(fmt.Sprintf("  client_key_path: %q\n", cfg.Security.ClientKeyPath))
		configContent.WriteString(fmt.Sprintf("  server_ca_cert_path: %q\n", cfg.Security.ServerCACertPath))
		configContent.WriteString("  use_tls: true\n")
	}

	// Write to file
	if err := os.WriteFile(configPath, []byte(configContent.String()), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// connectivityResult summarizes a platform reachability probe for display
// during interactive setup.
type connectivityResult struct {
	ok      bool
	icon    string
	summary string
	detail  string
	// tlsUnverified reports that the platform answered TLS but its certificate
	// did not verify against this host's trust store. The path is open; only
	// trust is missing, which the caller resolves by pinning the platform CA.
	tlsUnverified bool
}

// testPlatformConnectivity probes the platform in three escalating steps — DNS
// resolution, a raw TCP connect, then an HTTP round-trip — so the installer
// learns *where* the path breaks (name resolution vs. a blocking firewall vs. a
// wrong port) instead of discovering it only when registration later fails. It
// never blocks for more than a few seconds per step.
func testPlatformConnectivity(rawURL string) connectivityResult {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return connectivityResult{icon: "❌", summary: "Invalid URL",
			detail: fmt.Sprintf("Could not parse %q as a URL.", rawURL)}
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	// 1. DNS resolution (only meaningful for names, not literal IPs).
	if net.ParseIP(host) == nil {
		if ips, derr := net.LookupHost(host); derr != nil || len(ips) == 0 {
			return connectivityResult{icon: "❌", summary: "DNS could not be resolved",
				detail: fmt.Sprintf("The hostname %q did not resolve. Check the URL spelling and this host's DNS settings.", host)}
		}
	}

	// 2. TCP connect — proves the firewall path to the port is open.
	addr := net.JoinHostPort(host, port)
	conn, cerr := net.DialTimeout("tcp", addr, 5*time.Second)
	if cerr != nil {
		summary := "Connection failed"
		detail := fmt.Sprintf("Could not open a TCP connection to %s.", addr)
		switch {
		case strings.Contains(cerr.Error(), "timeout"):
			summary = "Connection timed out"
			detail += " A firewall is most likely blocking the path between this host and the platform."
		case strings.Contains(cerr.Error(), "refused"):
			summary = "Connection refused"
			detail += " The host is reachable but nothing is listening on that port — double-check the port in the URL."
		}
		return connectivityResult{icon: "❌", summary: summary, detail: detail}
	}
	_ = conn.Close()

	// 3. HTTP round-trip — confirms the platform (or its gateway) answers.
	client := &http.Client{Timeout: 8 * time.Second}
	resp, herr := client.Get(rawURL)
	if herr != nil {
		msg := herr.Error()
		if strings.Contains(msg, "x509") || strings.Contains(msg, "certificate") || strings.Contains(msg, "tls") {
			// The server completed a TLS handshake, so the network path is open —
			// only certificate verification failed. Common with the internal
			// CAs many deployments use. The path is fine, but registration will
			// NOT proceed until this agent is given something to verify against,
			// so the caller must resolve trust before continuing.
			return connectivityResult{ok: true, tlsUnverified: true, icon: "⚠️", summary: "Reachable, but TLS certificate not verified",
				detail: "The port is open and the server speaks TLS, but its certificate could not be verified against this host's trust store. This is normal with internal/private CAs — you will be asked whether to trust it."}
		}
		return connectivityResult{icon: "⚠️", summary: "Port open, but no HTTP response",
			detail: fmt.Sprintf("Connected to %s but the HTTP request failed: %v", addr, herr)}
	}
	_ = resp.Body.Close()

	return connectivityResult{ok: true, icon: "✅", summary: "Platform is reachable",
		detail: fmt.Sprintf("Connected to %s and received HTTP %d.", addr, resp.StatusCode)}
}

// runInteractiveSetup runs an interactive configuration wizard. caFingerprint,
// when supplied, pre-answers the platform-CA trust question so a scripted
// install still gets a verified pin instead of a prompt it cannot answer.
//
// It returns the registered configuration, the path it was saved to, and the
// API client that performed the registration, so the caller can start the agent
// immediately — installing and running are one step, as they are for the
// sensor. A nil config with a nil error means the operator cancelled at a
// prompt; there is nothing to run and that is not a failure.
func runInteractiveSetup(caFingerprint string) (*config.Config, string, *api.OutboundClient, error) {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("🔧 VistaPlatform Device Agent - Interactive Configuration")
	fmt.Println("===========================================================")
	fmt.Println()

	// Platform URL — verify reachability before continuing. In firewalled
	// corporate networks an unreachable platform is the most common install
	// snag; testing it here turns a silent, frustrating failure later into
	// immediate, actionable feedback.
	var platformURL string
	var tlsUnverified bool
urlLoop:
	for {
		fmt.Print("Enter Platform URL (default: https://app.vistasecurity.io): ")
		platformURL, _ = reader.ReadString('\n')
		platformURL = strings.TrimSpace(platformURL)
		if platformURL == "" {
			platformURL = "https://app.vistasecurity.io"
		}

		fmt.Printf("\n🔌 Testing connectivity to %s ...\n", platformURL)
		res := testPlatformConnectivity(platformURL)
		fmt.Printf("   %s %s\n", res.icon, res.summary)
		if res.detail != "" {
			fmt.Printf("      %s\n", res.detail)
		}
		if res.ok {
			tlsUnverified = res.tlsUnverified
			fmt.Println()
			break
		}

		fmt.Print("\nConnectivity check did not pass. [R]etry URL, [C]ontinue anyway, or [Q]uit? (R/c/q): ")
		choice, _ := reader.ReadString('\n')
		switch strings.TrimSpace(strings.ToLower(choice)) {
		case "c", "continue":
			fmt.Println("   Continuing despite the failed connectivity check.")
			fmt.Println()
			break urlLoop
		case "q", "quit":
			fmt.Println("Setup cancelled.")
			return nil, "", nil, nil
		default:
			fmt.Println()
			// any other input (including just Enter) retries the URL
		}
	}

	// Trust bootstrap. The platform's certificate did not verify against this
	// host's trust store, so the agent has nothing to check the platform
	// against and registration would fail x509. Show the operator the CA the
	// platform presents and let them decide — the SSH known_hosts model. If
	// they accept, it is pinned to this agent's config and every subsequent
	// connection is verified against it; verification is never disabled.
	var pinnedCA string
	if tlsUnverified {
		anchor, err := certificates.ResolveTrustAnchor(platformURL, caFingerprint, reader, os.Stdout, true)
		if err != nil {
			if errors.Is(err, certificates.ErrTrustDeclined) {
				fmt.Println("Setup cancelled — no CA trusted.")
				return nil, "", nil, nil
			}
			if errors.Is(err, certificates.ErrCertificateNotForHost) {
				// Already explained in full, including why pinning cannot fix
				// it. Say what to do next instead of restating it as an error.
				fmt.Println("Setup cancelled — fix the platform's TLS certificate, then run setup again.")
				return nil, "", nil, nil
			}
			return nil, "", nil, fmt.Errorf("could not establish trust with the platform: %w", err)
		}
		pinnedCA = anchor.PEM
	}

	// Registration Key
	fmt.Println()
	fmt.Println("📋 Registration Key:")
	fmt.Println("   To register with the platform, you need a registration key.")
	fmt.Println("   Get one from the Device Agent Management page in the web UI.")
	fmt.Println()
	fmt.Print("Enter Registration Key (required): ")
	registrationKey, _ := reader.ReadString('\n')
	registrationKey = strings.TrimSpace(registrationKey)

	if registrationKey == "" {
		return nil, "", nil, fmt.Errorf("registration key is required")
	}

	// Data Path
	fmt.Print("Enter Data Path (default: auto-detect): ")
	dataPath, _ := reader.ReadString('\n')
	dataPath = strings.TrimSpace(dataPath)
	if dataPath == "" {
		dataPath = getDefaultDataPath()
	}

	// Poll Interval
	fmt.Print("Enter Poll Interval (default: 30s): ")
	pollIntervalStr, _ := reader.ReadString('\n')
	pollIntervalStr = strings.TrimSpace(pollIntervalStr)
	if pollIntervalStr == "" {
		pollIntervalStr = "30s"
	}
	pollInterval, err := time.ParseDuration(pollIntervalStr)
	if err != nil {
		log.Printf("⚠️  Invalid poll interval, using default 30s")
		pollInterval = 30 * time.Second
	}

	// Confirmation
	fmt.Println()
	fmt.Println("📋 Configuration Summary")
	fmt.Println("========================")
	fmt.Printf("Platform URL: %s\n", platformURL)
	fmt.Printf("Registration Key: %s***%s\n", registrationKey[:4], registrationKey[len(registrationKey)-4:])
	fmt.Printf("Data Path: %s\n", dataPath)
	fmt.Printf("Poll Interval: %v\n", pollInterval)
	fmt.Println()
	fmt.Print("Proceed with registration? (Y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))

	if confirm != "" && confirm != "y" && confirm != "yes" {
		fmt.Println("❌ Registration cancelled")
		return nil, "", nil, nil
	}

	// Create configuration
	cfg := &config.Config{
		PlatformURL:     platformURL,
		RegistrationKey: registrationKey,
		DataPath:        dataPath,
		PollInterval:    pollInterval,
		// Verbose is deliberately left unset (nil): the command-line default is
		// on, and writing a value here would freeze that decision into the
		// generated config where the operator did not ask for it.
	}
	cfg.HeartbeatInterval = config.DefaultHeartbeatInterval
	// The operator-approved CA must be on the config BEFORE the client is
	// constructed — that is what puts it in the transport's RootCAs, and
	// registration is the first call that needs it.
	if pinnedCA != "" {
		cfg.Security.ServerCACert = pinnedCA
	}

	// Create API client and register
	apiClient := api.NewOutboundClient(cfg)
	apiClient.SetAgentVersion(Version)

	log.Println("📝 Registering with platform...")
	if err := apiClient.Register(Version); err != nil {
		return nil, "", nil, fmt.Errorf("registration failed: %w", err)
	}
	log.Println("✅ Agent registered successfully")

	// Save certificates
	if err := saveCertificates(cfg); err != nil {
		log.Printf("⚠️  Failed to save certificates: %v", err)
	} else {
		log.Printf("✅ Certificates saved to: %s/certs", cfg.DataPath)
	}

	// Determine config file path
	configPath := filepath.Join(cfg.DataPath, "agent-config.yaml")

	// Save config file
	if err := saveConfigFile(configPath, cfg); err != nil {
		log.Printf("⚠️  Failed to save config file: %v", err)
	} else {
		log.Printf("💾 Configuration saved to: %s", configPath)
	}

	fmt.Println()
	fmt.Printf("ℹ️  On the next start the agent reads %s automatically — run the\n", configPath)
	fmt.Println("   binary with no arguments and it picks up where this left off.")

	return cfg, configPath, apiClient, nil
}

// getDefaultDataPath returns platform-specific default data path
func getDefaultDataPath() string {
	switch runtime.GOOS {
	case "windows":
		if appData := os.Getenv("LOCALAPPDATA"); appData != "" {
			return filepath.Join(appData, "CryptoDeviceAgent")
		}
		return "CryptoDeviceAgent"
	case "darwin":
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, "Library", "Application Support", "CryptoDeviceAgent")
		}
		return "/tmp/crypto-device-agent"
	default:
		return "/var/lib/crypto-device-agent"
	}
}
