package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/google/uuid"
	"github.com/gopacket/gopacket/pcap"
	"github.com/vistasecurity/vistaplatform/sensor/internal/api"
	"github.com/vistasecurity/vistaplatform/sensor/internal/capture"
	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
	"github.com/vistasecurity/vistaplatform/sensor/internal/discovery"
	"github.com/vistasecurity/vistaplatform/sensor/internal/enrichment"
	"github.com/vistasecurity/vistaplatform/sensor/internal/models"
	"github.com/vistasecurity/vistaplatform/sensor/internal/storage"
	"github.com/vistasecurity/vistaplatform/sensor/internal/testmode"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// Version is stamped at build time via -ldflags "-X main.Version=<tag>"
// (see the Makefile's AGENT_LDFLAGS and release-core.yml). An unstamped
// build honestly reports "dev" rather than claiming to be a release.
var Version = "dev"

type Sensor struct {
	config        *config.Config
	configPath    string // Path to the config file for saving updates
	packetCapture *capture.PacketCapture
	storage       *storage.EncryptedStorage
	apiClient     *api.OutboundClient
	sensorManager *api.SensorManagerClient
	jobExecutor   *discovery.JobExecutor
	tlsEnricher   *enrichment.TLSEnricher
	testLogger    *testmode.TestLogger
	discoveries   []*models.CryptoDiscovery
	// pendingRetry holds batches that failed to submit on the previous tick.
	// Retried before new discoveries on the next tick.  Capped to prevent
	// unbounded memory growth during extended outages.
	pendingRetry []*models.CryptoDiscovery
	retryCount   int
	mu           sync.RWMutex
	startTime    time.Time // Track when sensor started for uptime calculation
	// discoveryTicker is the live data-send ticker, published by the run loop so
	// an operator's reporting-interval change can Reset() it without a restart.
	discoveryTicker *time.Ticker
	// registered reports whether registration has completed. An unregistered
	// sensor captures packets it can never submit, so the run loop reads this to
	// keep saying so rather than logging as if all were well.
	registered bool
}

// isRegisteredNow reports whether registration has completed.
func (s *Sensor) isRegisteredNow() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.registered
}

func (s *Sensor) setRegistered(v bool) {
	s.mu.Lock()
	s.registered = v
	s.mu.Unlock()
}

// Registration retry schedule. Doubling from 30s to a 15-minute ceiling: quick
// enough that a control plane restarting mid-install is not noticed, slow enough
// that a fleet of sensors riding out a long outage does not become the reason it
// stays down.
const (
	registrationRetryInitial = 30 * time.Second
	registrationRetryMax     = 15 * time.Minute
)

// resolveRegistrationAtStartup performs the one-time registration decision and,
// when registration fails transiently, starts the background retry.
//
// Shared by both startup paths (main and startSensorWithConfig), which
// previously carried near-identical copies of this switch — the shape that lets
// a fix land in one and not the other.
//
// alreadyRequested is main's -register flag; the config-file path has no
// equivalent and passes false.
func (s *Sensor) resolveRegistrationAtStartup(alreadyRequested bool, stop <-chan struct{}) {
	cfg := s.config
	switch {
	case isRegistered(cfg):
		log.Printf("✅ Sensor already registered (ID: %s, certificate on disk) — skipping registration", cfg.SensorID)
		s.setRegistered(true)

	case alreadyRequested || cfg.RegistrationKey != "":
		log.Println("📝 Attempting to register with control plane...")
		err := s.register()
		if err == nil {
			s.setRegistered(true)
			log.Println("✅ Successfully registered with control plane")
			return
		}

		// An operator supplied a key, so they intend this sensor to report.
		// Failing to register is not a mode to continue in quietly: an
		// unregistered sensor captures on every worker and submits nothing.
		var rejected *api.RegistrationRejectedError
		if errors.As(err, &rejected) {
			log.Printf("⛔ Registration was REJECTED by the control plane (HTTP %d): %s", rejected.StatusCode, rejected.Body)
			log.Printf("⛔ The registration key is invalid, expired, or has already been used.")
			log.Printf("⛔ Generate a new key in the web UI (Discovery → Sensors & Agents → Register) and put it in the sensor's config.")
			log.Fatalf("❌ Refusing to start: a sensor that cannot register can capture but can never submit anything.")
		}
		log.Printf("⚠️  Registration FAILED: %v", err)
		log.Printf("⚠️  This sensor is NOT registered and can submit NOTHING until it is.")
		log.Printf("⚠️  Retrying in the background (first retry in %v, backing off to %v) — no restart needed if the control plane comes back.",
			registrationRetryInitial, registrationRetryMax)
		go s.retryRegistrationUntilSuccess(stop)

	default:
		log.Println("ℹ️  Skipping registration (no registration key provided)")
		if cfg.TestMode {
			log.Println("🧪 Running in test mode - discoveries will be logged to file")
		} else if cfg.SensorID == "" {
			log.Printf("⚠️  Warning: No sensor ID available. Discoveries cannot be submitted without registration.")
		}
	}
}

// startupStateLine is the line the sensor prints once it is up. It reports what
// actually happened: "started successfully" printed directly under a
// registration failure is what made hours of doing nothing look like health.
func (s *Sensor) startupStateLine(prefix string) string {
	if s.isRegisteredNow() || s.config.TestMode {
		return "✅ " + prefix + " started successfully"
	}
	return "⚠️  " + prefix + " started, but this sensor is UNREGISTERED — it is capturing traffic and can submit none of it."
}

// retryRegistrationUntilSuccess keeps attempting registration in the background
// after the first attempt failed.
//
// A sensor that cannot register cannot submit anything: it captures packets on
// every worker and reports nothing, forever. Before this existed, registration
// was attempted exactly once at startup and a failure was logged as a warning
// immediately followed by "Sensor started successfully" — which is how a real
// sensor ran for hours doing nothing while its logs read as healthy.
//
// Retrying rather than exiting is the right default: a sensor should survive the
// control plane restarting, and on a customer host an exited process may not
// come back without someone noticing. But a REJECTED registration is different —
// a consumed or invalid key returns the same answer forever, and only a human
// with a fresh key can fix it. That case stops the loop and says so.
func (s *Sensor) retryRegistrationUntilSuccess(stop <-chan struct{}) {
	delay := registrationRetryInitial
	for {
		select {
		case <-stop:
			return
		case <-time.After(delay):
		}

		if err := s.register(); err != nil {
			var rejected *api.RegistrationRejectedError
			if errors.As(err, &rejected) {
				log.Printf("⛔ Registration was REJECTED by the control plane (HTTP %d): %s", rejected.StatusCode, rejected.Body)
				log.Printf("⛔ This will not resolve on its own — the registration key is invalid, expired, or already used.")
				log.Printf("⛔ Generate a new key in the web UI (Discovery → Sensors & Agents → Register), put it in the sensor's config, and restart.")
				log.Printf("⛔ Giving up on registration. This sensor will keep capturing but can submit NOTHING.")
				return
			}
			log.Printf("⚠️  Registration retry failed (next attempt in %v): %v", delay, err)
			delay *= 2
			if delay > registrationRetryMax {
				delay = registrationRetryMax
			}
			continue
		}

		s.setRegistered(true)
		log.Printf("✅ Registration succeeded on retry — this sensor can now submit discoveries.")
		return
	}
}

func main() {
	// Command line flags
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
		interactive = flag.Bool("interactive", true, "Run interactive configuration mode when no configuration exists (-interactive=false to skip)")
		testMode    = flag.Bool("test", false, "Run in test mode (logs to file instead of control plane)")
		// caFingerprint makes the trust decision out of band, for unattended
		// installs that cannot answer a prompt. The sensor pins the platform CA
		// only if it hashes to this value — which, unlike the interactive
		// prompt, is not trust-on-first-use.
		caFingerprint = flag.String("ca-fingerprint", "",
			"Expected SHA-256 fingerprint of the control plane's CA certificate. Required for unattended "+
				"enrollment against a control plane whose certificate is signed by a private CA this host does not trust.")
	)
	flag.Parse()

	// Show version and exit
	if *version {
		fmt.Printf("VistaPlatform Network Sensor v%s\n", Version)
		fmt.Printf("Platform: %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Printf("Go version: %s\n", runtime.Version())
		os.Exit(0)
	}

	// Resolve the configuration file up front: an existing configuration is
	// what turns the interactive installer off, so the decision needs to know
	// about it before anything else happens.
	if *configFile == "" {
		*configFile = findDefaultConfigFile()
	}

	// Run interactive configuration mode. This is the default on a fresh host —
	// running the binary with no arguments IS the install flow — and it starts
	// the sensor when it finishes, so setup and first run are one step.
	if shouldRunInteractive(*interactive, isFlagSet("interactive"), *configFile, *register, term.IsTerminal(int(os.Stdin.Fd()))) {
		runInteractiveMode(*caFingerprint, *verbose)
		return
	}

	// Initialize logging. Tee log output into an in-memory ring buffer so the
	// export_logs command can return recent lines to the platform console.
	log.SetOutput(io.MultiWriter(os.Stderr, logRing))
	if *verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Println("Verbose logging enabled")
	} else {
		// Always show basic info even without verbose flag
		log.SetFlags(log.LstdFlags)
	}

	log.Printf("🚀 Starting VistaPlatform Network Sensor v%s", Version)
	log.Printf("Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	log.Printf("Command line flags: verbose=%v, register=%v, interactive=%v, test=%v, config=%s", *verbose, *register, *interactive, *testMode, *configFile)

	// Load configuration
	var cfg *config.Config
	var err error

	// Try to load from config file if specified
	if *configFile != "" {
		log.Printf("📁 Loading configuration from file: %s", *configFile)
		cfg, err = config.LoadFromFile(*configFile)
		if err != nil {
			log.Printf("⚠️  Failed to load config file (%v), falling back to environment variables", err)
			cfg = config.Load()
		} else {
			log.Printf("✅ Configuration loaded from file")
		}
	} else {
		log.Printf("⚠️  No valid config file found, falling back to environment variables and defaults")
		// Fall back to environment variables
		cfg = config.Load()
	}

	// The build-stamped binary version is the truth about what code is running;
	// a version copied into a config file or env var goes stale on upgrade.
	cfg.Version = Version

	// Verbose logging is on by default; a `verbose:` key in the config file (or
	// the VERBOSE env var) is how an operator turns it back down for a
	// long-running install. An explicit -verbose on the command line still wins.
	if cfg.Verbose != nil && !isFlagSet("verbose") {
		*verbose = *cfg.Verbose
		if *verbose {
			log.SetFlags(log.LstdFlags | log.Lshortfile)
		} else {
			log.SetFlags(log.LstdFlags)
			log.Println("Verbose logging disabled by configuration")
		}
	}

	log.Printf("Configuration loaded:")
	log.Printf("  Sensor ID: %s", cfg.SensorID)
	log.Printf("  Control Plane URL: %s", cfg.ControlPlaneURL)
	log.Printf("  Registration Key: %s", maskString(cfg.RegistrationKey))
	log.Printf("  Reporting Interval: %v", cfg.ReportingInterval)
	log.Printf("  Data Path: %s", cfg.Storage.DataPath)
	log.Printf("  Interfaces: %v", cfg.Capture.Interfaces)

	// Unattended trust bootstrap. With --ca-fingerprint and no CA already in
	// config, fetch the control plane's CA, verify it hashes to the expected
	// value, and pin it before any client is built. Without the flag nothing is
	// pinned and verification falls back to this host's system trust store —
	// the right behaviour for a control plane holding a publicly-trusted cert.
	if *caFingerprint != "" && cfg.Security.ServerCACert == "" {
		anchor, err := certificates.ResolveTrustAnchor(cfg.ControlPlaneURL, *caFingerprint, nil, os.Stdout, false)
		if err != nil {
			log.Fatalf("❌ Could not establish trust with the control plane: %v", err)
		}
		cfg.Security.ServerCACert = anchor.PEM
		log.Printf("🔒 Pinned control-plane CA: %s", anchor.Certificate.Subject.String())
	}

	// Set test mode in configuration
	if *testMode {
		cfg.TestMode = true
		log.Println("🧪 Running in TEST MODE - discoveries will be logged to file instead of control plane")
	}

	// Create sensor instance
	sensor := &Sensor{
		config:      cfg,
		configPath:  *configFile, // Store the config file path for saving updates
		discoveries: make([]*models.CryptoDiscovery, 0),
		startTime:   time.Now(), // Track start time for uptime
	}

	// Initialize components
	log.Println("🔧 Initializing sensor components...")
	if err := sensor.initialize(); err != nil {
		log.Fatalf("❌ Failed to initialize sensor: %v", err)
	}
	log.Println("✅ Sensor components initialized successfully")

	// Validate sensor ID format if set (must be UUID for API calls)
	if cfg.SensorID != "" {
		if _, err := uuid.Parse(cfg.SensorID); err != nil {
			log.Printf("⚠️  Warning: Sensor ID '%s' is not a valid UUID format. Clearing it - will be assigned during registration.", cfg.SensorID)
			cfg.SensorID = ""
			sensor.config.SensorID = ""
		}
	}

	// Register with control plane if requested.
	//
	// Registration keys are single-use: the control plane marks them "used" the
	// first time a sensor registers. A registration key therefore lingers in the
	// config file after the initial registration, but re-sending it on every
	// restart makes the control plane reject it ("Registration key has already
	// been used"). Skip registration entirely once we already hold a sensor ID
	// and a client certificate — that pair is proof of a completed registration.
	// registrationRetryStop ends the background retry loop at shutdown.
	registrationRetryStop := make(chan struct{})
	defer close(registrationRetryStop)

	sensor.resolveRegistrationAtStartup(*register, registrationRetryStop)

	// Start sensor
	log.Println("🚀 Starting sensor services...")
	if err := sensor.start(); err != nil {
		log.Fatalf("❌ Failed to start sensor: %v", err)
	}
	log.Println(sensor.startupStateLine("Sensor services"))

	// Handle graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// Ensure reporting interval is always positive
	if cfg.ReportingInterval <= 0 {
		log.Printf("⚠️  Invalid reporting interval (%v) - defaulting to 30s", cfg.ReportingInterval)
		cfg.ReportingInterval = 30 * time.Second
	}

	// Main sensor loop
	ticker := time.NewTicker(cfg.ReportingInterval)
	defer ticker.Stop()
	// Publish the discovery ticker so an operator's reporting-interval change is
	// applied live (handleUpdateConfig → applyReportingInterval resets it).
	sensor.mu.Lock()
	sensor.discoveryTicker = ticker
	sensor.mu.Unlock()

	// Certificate expiration check ticker (check daily)
	certCheckTicker := time.NewTicker(24 * time.Hour)
	defer certCheckTicker.Stop()

	// Cache cleanup ticker (cleanup every 10 minutes)
	cacheCleanupTicker := time.NewTicker(10 * time.Minute)
	defer cacheCleanupTicker.Stop()

	// Heartbeat ticker — independent of discovery submission
	heartbeatTicker := time.NewTicker(cfg.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	// Unregistered-state reminder. The failure mode was a log that read as
	// healthy while nothing was submitted, so an unregistered sensor says so on a
	// schedule rather than only at startup — an operator who scrolls back an hour
	// must still be able to see it. The handler goes quiet once registration
	// lands, so a healthy sensor prints nothing extra.
	unregisteredWarnTicker := time.NewTicker(10 * time.Minute)
	defer unregisteredWarnTicker.Stop()

	log.Println(sensor.startupStateLine("Sensor"))
	log.Println("📡 Monitoring network traffic for cryptographic configurations...")
	log.Printf("🔄 Reporting interval: %v", cfg.ReportingInterval)
	log.Println("💡 Press Ctrl+C to stop the sensor")

	// Check certificate expiration on startup
	if sensor.sensorManager != nil && cfg.Security.UseTLS {
		go sensor.checkAndRotateCertificate()
	}

	// Start TLS enricher worker pool (active probes for TLS 1.3 cert extraction)
	if sensor.tlsEnricher != nil {
		sensor.tlsEnricher.Start(3)
	}

	for {
		select {
		case <-ticker.C:
			log.Println("⏰ Processing discoveries...")
			sensor.processDiscoveries()
		case <-certCheckTicker.C:
			// Check certificate expiration daily
			if sensor.sensorManager != nil && cfg.Security.UseTLS {
				go sensor.checkAndRotateCertificate()
			}
		case <-unregisteredWarnTicker.C:
			// Only speaks while there is something wrong.
			if !sensor.isRegisteredNow() && !cfg.TestMode {
				log.Println("⚠️  Still UNREGISTERED — traffic is being captured and none of it can be submitted.")
			}
		case <-cacheCleanupTicker.C:
			// Clean up expired cache entries
			if sensor.packetCapture != nil && sensor.packetCapture.GetCache() != nil {
				sensor.packetCapture.GetCache().Cleanup()
				log.Println("🧹 Cache cleanup completed")
			}
		case <-heartbeatTicker.C:
			log.Println("💓 Sending heartbeat...")
			sensor.sendHeartbeat()
		case discovery := <-sensor.packetCapture.GetDiscoveries():
			log.Printf("🔍 New discovery received: %s on %s:%d", discovery.Protocol, discovery.DestIP, discovery.Port)
			sensor.handleDiscovery(discovery)
			// Check if this passive discovery needs TLS certificate enrichment
			if sensor.tlsEnricher != nil {
				sensor.tlsEnricher.MaybeEnrich(discovery)
			}
		case err := <-sensor.packetCapture.GetErrors():
			log.Printf("❌ Capture error: %v", err)
		case sig := <-signalChan:
			log.Printf("🛑 Received signal %v, shutting down gracefully...", sig)
			sensor.cleanup()
			log.Println("👋 Sensor shutdown complete")
			return
		}
	}
}

// initialize initializes all sensor components
func (s *Sensor) initialize() error {
	log.Println("🔧 Initializing sensor components...")

	// Initialize encrypted storage
	storage, err := storage.NewEncryptedStorage(s.config)
	if err != nil {
		return fmt.Errorf("failed to initialize storage: %v", err)
	}
	s.storage = storage

	// Initialize packet capture
	packetCapture := capture.NewPacketCapture(s.config)
	s.packetCapture = packetCapture

	// Initialize outbound-only API client
	apiClient := api.NewOutboundClient(s.config)
	s.apiClient = apiClient

	// Initialize sensor manager client (for registration and certificate management)
	sensorManager := api.NewSensorManagerClient(s.config)
	s.sensorManager = sensorManager

	// Initialize discovery job executor (sensor ID may be updated after registration)
	jobExecutor := discovery.NewJobExecutor(30*time.Second, s.config.SensorID)
	s.jobExecutor = jobExecutor

	// Initialize TLS enricher — uses the packet capture discoveries channel
	// so enrichment results flow through the same submission pipeline.
	tlsEnricher := enrichment.NewTLSEnricher(s.config, s.config.SensorID, packetCapture.GetDiscoveriesWritable())
	s.tlsEnricher = tlsEnricher

	// Initialize test logger if in test mode
	if s.config.TestMode {
		testLogger, err := testmode.NewTestLogger(s.config.Storage.DataPath)
		if err != nil {
			return fmt.Errorf("failed to initialize test logger: %v", err)
		}
		s.testLogger = testLogger
		log.Printf("🧪 Test logger initialized: %s", testLogger.GetLogPath())
	}

	log.Println("✅ Sensor components initialized")
	return nil
}

// isRegistered reports whether the sensor has already completed registration.
//
// A completed registration leaves two durable artifacts in the config: a sensor
// ID (the UUID the control plane assigned / accepted as the certificate CN) and
// an mTLS client certificate + key pair (loaded from disk by the config loader).
// When both are present the sensor can authenticate and submit discoveries on
// its own, so it must NOT attempt to re-register with the now-consumed
// single-use registration key — doing so is rejected by the control plane with
// "Registration key has already been used".
func isRegistered(cfg *config.Config) bool {
	if cfg.SensorID == "" {
		return false
	}
	if _, err := uuid.Parse(cfg.SensorID); err != nil {
		return false
	}
	return cfg.Security.ClientCert != "" && cfg.Security.ClientKey != ""
}

// register registers the sensor with the control plane
func (s *Sensor) register() error {
	log.Println("📝 Registering with control plane...")

	if s.sensorManager == nil {
		return fmt.Errorf("sensor manager client not initialized")
	}

	config, err := s.sensorManager.Register()
	if err != nil {
		return fmt.Errorf("registration failed: %v", err)
	}

	// Registration (via sensorManager) stored the client cert/key + server CA on
	// the shared config but left the outbound client on plain HTTP — it was built
	// before we held any cert. Activate mTLS now so this first session's
	// heartbeats and discovery submissions present the client cert, which
	// fail-closed sensor mTLS requires. Without this the sensor would only
	// speak mTLS after a restart (when certs are loaded from disk).
	if s.apiClient != nil {
		s.apiClient.ActivateMTLS()
	}

	// Update sensor ID from registration response
	if s.config.SensorID != "" {
		log.Printf("📝 Sensor ID: %s", s.config.SensorID)
	}

	// Update sensor configuration with received config
	s.updateConfig(config)

	// Save certificates to disk
	if err := saveCertificates(s.config); err != nil {
		log.Printf("⚠️  Failed to save certificates to disk: %v", err)
		// Continue anyway - certificates are in memory
	} else {
		log.Printf("✅ Certificates saved to: %s", filepath.Join(s.config.Storage.DataPath, "certs"))
	}

	// Save updated sensor ID and certificate paths to config file for persistence
	if err := s.saveConfigFile(); err != nil {
		log.Printf("⚠️  Failed to save config file with new sensor ID and certificates: %v", err)
		// Continue anyway - sensor ID is in memory and will work for this session
	} else {
		log.Printf("💾 Configuration saved to file with sensor ID")
	}

	// Update job executor with the confirmed sensor ID from registration
	if s.jobExecutor != nil {
		s.jobExecutor.SetSensorID(s.config.SensorID)
	}

	log.Printf("✅ Sensor registered successfully with ID: %s", s.config.SensorID)
	return nil
}

// saveConfigFile updates the config file with the current sensor ID
func (s *Sensor) saveConfigFile() error {
	if s.configPath == "" {
		return fmt.Errorf("no config file path set")
	}

	// Read the existing config file
	existingData, err := os.ReadFile(s.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	// Update the sensorId in the existing content.
	lines := strings.Split(string(existingData), "\n")
	sensorIDUpdated := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "sensorId:") {
			lines[i] = fmt.Sprintf("sensorId: \"%s\"", s.config.SensorID)
			sensorIDUpdated = true
		}
		// Persist the (possibly operator-changed) reporting interval so it
		// survives a restart. Real install configs always carry this line.
		if strings.HasPrefix(trimmed, "reportingIntervalSeconds:") {
			lines[i] = fmt.Sprintf("reportingIntervalSeconds: %d", int(s.config.ReportingInterval.Seconds()))
		}
		// Persist the control-plane URL: registration may have switched it to
		// the platform-advertised mTLS passthrough endpoint. Without
		// this a restart would reload the pre-registration edge URL, where
		// fail-closed mTLS rejects every call (client cert lost at the edge).
		if strings.HasPrefix(trimmed, "controlPlaneUrl:") && s.config.ControlPlaneURL != "" {
			lines[i] = fmt.Sprintf("controlPlaneUrl: %s", s.config.ControlPlaneURL)
		}
	}

	if !sensorIDUpdated {
		// If sensorId line wasn't found, add it after the first line (header)
		newLines := make([]string, 0, len(lines)+1)
		if len(lines) > 0 {
			newLines = append(newLines, lines[0])
			newLines = append(newLines, fmt.Sprintf("sensorId: \"%s\"", s.config.SensorID))
			newLines = append(newLines, lines[1:]...)
		} else {
			newLines = append(newLines, fmt.Sprintf("sensorId: \"%s\"", s.config.SensorID))
		}
		lines = newLines
	}

	// Add or update certificate paths when registration/rotation has provided
	// mTLS material. Rotation calls this repeatedly, so keep the block idempotent.
	if s.config.Security.ClientCertPath != "" {
		lines = upsertSecurityConfigBlock(lines, s.config.Security.ClientCertPath, s.config.Security.ClientKeyPath, s.config.Security.ServerCACertPath)
	}

	// Write the updated content back
	updatedContent := strings.Join(lines, "\n")
	if err := os.WriteFile(s.configPath, []byte(updatedContent), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	log.Printf("✅ Config file updated: %s", s.configPath)
	if s.config.Security.ClientCertPath != "" {
		log.Printf("📜 Certificate paths saved to config")
	}

	return nil
}

func upsertSecurityConfigBlock(lines []string, clientCertPath, clientKeyPath, serverCACertPath string) []string {
	securityStart := -1
	securityEnd := len(lines)
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if securityStart == -1 {
			if trimmed == "security:" && isTopLevelConfigLine(line) {
				securityStart = i
			}
			continue
		}
		if trimmed != "" && isTopLevelConfigLine(line) {
			securityEnd = i
			break
		}
	}

	values := map[string]string{
		"clientCertPath":   fmt.Sprintf("%q", clientCertPath),
		"clientKeyPath":    fmt.Sprintf("%q", clientKeyPath),
		"serverCACertPath": fmt.Sprintf("%q", serverCACertPath),
		"useTLS":           "true",
	}
	keys := []string{"clientCertPath", "clientKeyPath", "serverCACertPath", "useTLS"}

	if securityStart == -1 {
		securitySection := []string{
			"",
			"# mTLS Certificate Configuration (auto-generated after registration)",
			"security:",
		}
		for _, key := range keys {
			securitySection = append(securitySection, fmt.Sprintf("  %s: %s", key, values[key]))
		}
		return append(lines, securitySection...)
	}

	seen := make(map[string]bool, len(keys))
	for i := securityStart + 1; i < securityEnd; i++ {
		trimmed := strings.TrimSpace(lines[i])
		for _, key := range keys {
			if strings.HasPrefix(trimmed, key+":") {
				lines[i] = fmt.Sprintf("  %s: %s", key, values[key])
				seen[key] = true
				break
			}
		}
	}

	missing := make([]string, 0, len(keys))
	for _, key := range keys {
		if !seen[key] {
			missing = append(missing, fmt.Sprintf("  %s: %s", key, values[key]))
		}
	}
	if len(missing) == 0 {
		return lines
	}

	updated := make([]string, 0, len(lines)+len(missing))
	updated = append(updated, lines[:securityEnd]...)
	updated = append(updated, missing...)
	updated = append(updated, lines[securityEnd:]...)
	return updated
}

func isTopLevelConfigLine(line string) bool {
	return line == strings.TrimLeft(line, " \t")
}

// checkAndRotateCertificate checks certificate expiration and rotates if needed
func (s *Sensor) checkAndRotateCertificate() {
	if s.sensorManager == nil {
		return
	}

	expiresAt, expiringSoon, err := s.sensorManager.CheckCertificateExpiration()
	if err != nil {
		log.Printf("⚠️  Failed to check certificate expiration: %v", err)
		return
	}

	if expiringSoon {
		log.Printf("🔄 Certificate expires on %s, rotating...", expiresAt.Format(time.RFC3339))
		if err := s.sensorManager.RotateCertificate(); err != nil {
			log.Printf("❌ Failed to rotate certificate: %v", err)
			return
		}

		// RotateCertificate updated the shared config with the new cert/key and
		// hot-swapped the sensorManager transport, but two things still need doing
		// or the rotation is lost/half-applied:
		//  1. Persist the new cert to disk + config file — otherwise a restart
		//     reloads the OLD cert, which the platform has just REVOKED as part of
		//     rotation, and the sensor can no longer authenticate.
		//  2. Refresh the OutboundClient (heartbeat/discovery) transport — it is a
		//     separate client still holding the old (now-revoked) cert; under
		//     enforced mTLS its next call would be rejected.
		if err := saveCertificates(s.config); err != nil {
			log.Printf("⚠️  Failed to persist rotated certificate to disk: %v", err)
		}
		if err := s.saveConfigFile(); err != nil {
			log.Printf("⚠️  Failed to persist rotated certificate to config file: %v", err)
		}
		if s.apiClient != nil {
			s.apiClient.ActivateMTLS()
		}
		log.Println("✅ Certificate rotated successfully")
	} else {
		log.Printf("✅ Certificate valid until %s", expiresAt.Format(time.RFC3339))
	}
}

// start starts the sensor
func (s *Sensor) start() error {
	log.Println("🚀 Starting sensor...")

	// Start packet capture
	if err := s.packetCapture.Start(); err != nil {
		return fmt.Errorf("failed to start packet capture: %v", err)
	}

	log.Println("✅ Sensor started")
	return nil
}

// handleDiscovery handles a new discovery
func (s *Sensor) handleDiscovery(discovery *models.CryptoDiscovery) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Add to in-memory list
	s.discoveries = append(s.discoveries, discovery)

	// Store in encrypted storage
	if err := s.storage.StoreDiscovery(discovery); err != nil {
		log.Printf("❌ Failed to store discovery: %v", err)
	}

	log.Printf("🔍 Discovery: %s on %s:%d (confidence: %.2f)",
		discovery.Protocol, discovery.DestIP, discovery.Port, discovery.Confidence)
}

// retryCapLimit is the maximum number of discoveries held in the retry queue.
// When exceeded the oldest entries are dropped to prevent unbounded memory growth
// during extended control-plane outages.
const retryCapLimit = 1000

// processDiscoveries processes and sends discoveries to control plane.
// On submission failure the batch is moved to a retry queue and re-attempted
// on the next tick before new discoveries are submitted.
func (s *Sensor) processDiscoveries() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.discoveries) == 0 && len(s.pendingRetry) == 0 {
		return
	}

	if s.config.TestMode {
		// In test mode, log discoveries to file instead of sending to control plane
		all := append(s.pendingRetry, s.discoveries...)
		for _, discovery := range all {
			if err := s.testLogger.LogDiscovery(discovery); err != nil {
				log.Printf("❌ Failed to log discovery to test file: %v", err)
			}
		}
		log.Printf("📝 Logged %d discoveries to test file: %s", len(all), s.testLogger.GetLogPath())
		s.discoveries = s.discoveries[:0]
		s.pendingRetry = s.pendingRetry[:0]
		s.retryCount = 0
		return
	}

	// Validate sensor ID before submitting (must be valid UUID)
	if s.config.SensorID == "" {
		log.Printf("⚠️  Cannot submit discoveries: no sensor ID. Please register with control plane first.")
		return
	}
	if _, err := uuid.Parse(s.config.SensorID); err != nil {
		log.Printf("⚠️  Cannot submit discoveries: invalid sensor ID format '%s' (must be UUID). Please register with control plane.", s.config.SensorID)
		return
	}

	// Build the batch: retry queue first, then new discoveries
	batch := make([]*models.CryptoDiscovery, 0, len(s.pendingRetry)+len(s.discoveries))
	batch = append(batch, s.pendingRetry...)
	batch = append(batch, s.discoveries...)

	// Send discoveries to control plane
	if err := s.apiClient.SubmitDiscoveries(batch); err != nil {
		log.Printf("❌ Failed to submit %d discoveries (attempt %d): %v", len(batch), s.retryCount+1, err)
		// Move current discoveries into retry queue (do NOT clear them)
		s.pendingRetry = append(s.pendingRetry, s.discoveries...)
		s.discoveries = s.discoveries[:0]
		s.retryCount++
		// Cap the retry queue to bound memory use during extended outages
		if len(s.pendingRetry) > retryCapLimit {
			dropped := len(s.pendingRetry) - retryCapLimit
			log.Printf("⚠️  Retry queue overflow: dropping %d oldest discoveries (queue was %d, cap %d)", dropped, len(s.pendingRetry), retryCapLimit)
			s.pendingRetry = s.pendingRetry[dropped:]
		}
		return
	}

	log.Printf("📤 Submitted %d discoveries to control plane (including %d retried)", len(batch), len(s.pendingRetry))
	// Clear both queues after successful submission
	s.discoveries = s.discoveries[:0]
	s.pendingRetry = s.pendingRetry[:0]
	s.retryCount = 0
}

// sendHeartbeat builds sensor health metrics and sends a heartbeat to the control plane.
// It runs independently of discovery submission so the control plane always receives
// regular health signals even when there are no new discoveries.
func (s *Sensor) sendHeartbeat() {
	s.mu.RLock()
	discoveriesMade := int64(len(s.discoveries))
	s.mu.RUnlock()

	// Get cache stats for health metrics
	var cacheStats map[string]interface{}
	if s.packetCapture != nil && s.packetCapture.GetCache() != nil {
		cache := s.packetCapture.GetCache()
		stats := cache.Stats()
		cacheStats = map[string]interface{}{
			"cache_size":     stats.Size,
			"cache_hit_rate": stats.HitRate * 100, // Convert to percentage
			"cache_hits":     stats.Hits,
			"cache_misses":   stats.Misses,
		}
	} else {
		cacheStats = make(map[string]interface{})
	}

	// Get packet capture stats and check for anomalies
	var ifaceStats []models.InterfaceStatEntry
	var totalPackets int64
	// status must be one of the DB sensors_status_check values
	// (pending|active|inactive|error|offline). A high drop rate does NOT change
	// the status — the sensor is still active, just lossy — because writing an
	// out-of-enum value like "degraded" makes the heartbeat UPDATE violate the
	// CHECK constraint and 500, silently taking the sensor offline exactly when
	// it's under load. The degraded condition is surfaced via the per-interface
	// DropRatePct in InterfaceStats and the metrics["degraded"] flag below.
	status := "active"
	degraded := false
	if s.packetCapture != nil {
		ifaceStats = s.packetCapture.GetInterfaceStats()
		pkt, _ := s.packetCapture.GetStats()
		totalPackets = pkt
		// Anomaly detection: flag degradation if any interface drop rate exceeds 5%
		for _, istat := range ifaceStats {
			if istat.DropRatePct > 5.0 {
				degraded = true
				log.Printf("⚠️  Interface %s drop rate %.1f%% exceeds threshold", istat.InterfaceName, istat.DropRatePct)
			}
		}
	}

	// Calculate proper uptime
	uptime := int64(time.Since(s.startTime).Seconds())
	memoryUsage := getMemoryUsage()
	cpuUsage := getCPUUsage()

	// Create comprehensive metrics map
	metrics := make(map[string]interface{})
	metrics["uptime_seconds"] = uptime
	metrics["memory_usage_bytes"] = memoryUsage
	metrics["cpu_usage_percent"] = cpuUsage
	metrics["packets_captured"] = totalPackets
	metrics["discoveries_made"] = discoveriesMade
	metrics["errors_count"] = 0 // TODO: Track actual error count
	metrics["degraded"] = degraded
	if len(ifaceStats) > 0 {
		metrics["interface_stats"] = ifaceStats
	}

	// Add cache stats
	for k, v := range cacheStats {
		metrics[k] = v
	}

	// Resolved once so the flagged primary in Interfaces matches IPAddress exactly.
	primaryIP := s.config.CurrentIPAddress()

	health := &models.SensorHealth{
		SensorID:            s.config.SensorID,
		Status:              status,
		Version:             Version,
		LastHeartbeat:       time.Now(),
		Uptime:              uptime,
		MemoryUsage:         memoryUsage,
		CPUUsage:            cpuUsage,
		PacketsCaptured:     totalPackets,
		DiscoveriesMade:     discoveriesMade,
		Errors:              0, // TODO: Track actual error count
		Metrics:             metrics,
		InterfaceStats:      ifaceStats,
		AvailableInterfaces: api.AvailableInterfaceNames(),
		ReportingInterval:   int(s.config.ReportingInterval.Seconds()), // report current cadence so the platform tracks it
		// Self-reported: the platform cannot observe this address through NAT
		// and ingress, so it has to come from here. Empty leaves the stored
		// value untouched. Interfaces carries the rest of the host's addresses,
		// with the primary flagged, so a multi-homed capture host's real
		// coverage is visible rather than reduced to one address.
		IPAddress:  primaryIP,
		Interfaces: sharednetwork.HostAddresses(primaryIP),
		Timestamp:  time.Now(),
	}

	if s.config.TestMode {
		// In test mode, log heartbeat to file instead of sending to control plane
		if err := s.testLogger.LogHeartbeat(health); err != nil {
			log.Printf("❌ Failed to log heartbeat to test file: %v", err)
		} else {
			log.Printf("💓 Logged heartbeat to test file")
		}
	} else {
		commands, err := s.apiClient.Heartbeat(health)
		if err != nil {
			log.Printf("❌ Failed to send heartbeat: %v", err)
		} else {
			// Process received commands
			s.processCommands(commands)
		}
	}
}

// saveCertificates saves mTLS certificates to disk files
func saveCertificates(cfg *config.Config) error {
	return config.SaveCertificatesToFiles(
		cfg,
		cfg.Security.ClientCert,
		cfg.Security.ClientKey,
		cfg.Security.ServerCACert,
	)
}

// updateConfig updates sensor configuration
func (s *Sensor) updateConfig(config *models.SensorConfig) {
	// The reporting interval is owned by the sensor's own config (set at install,
	// changed via operator update_config commands) and reported UP to the control
	// plane — the registration response no longer dictates it. Only adopt a
	// server value as a fallback when the sensor somehow has none configured.
	if config.ReportingInterval > 0 && s.config.ReportingInterval <= 0 {
		s.config.ReportingInterval = time.Duration(config.ReportingInterval) * time.Second
	}

	// Update storage config only for non-zero values
	if config.StorageConfig.MaxStorageSize > 0 {
		s.config.Storage.MaxStorageSize = config.StorageConfig.MaxStorageSize
	}
	if config.StorageConfig.RotationSize > 0 {
		s.config.Storage.RotationSize = config.StorageConfig.RotationSize
	}
	if config.StorageConfig.RetentionDays > 0 {
		s.config.Storage.RetentionDays = config.StorageConfig.RetentionDays
	}

	// Update capture config
	s.config.Capture.ActiveProbing = config.CaptureConfig.ActiveProbing
	s.config.Capture.NetworkDiscovery = config.CaptureConfig.NetworkDiscovery
	if config.CaptureConfig.MaxConnections > 0 {
		s.config.Capture.MaxConnections = config.CaptureConfig.MaxConnections
	}
	if config.CaptureConfig.TimeoutSeconds > 0 {
		s.config.Capture.TimeoutSeconds = config.CaptureConfig.TimeoutSeconds
	}
	if config.CaptureConfig.DedupTTLMinutes > 0 {
		s.applyDedupTTL(config.CaptureConfig.DedupTTLMinutes)
	}

	// Update features
	if len(config.Features) > 0 {
		if s.config.Features == nil {
			s.config.Features = make(map[string]bool)
		}
		for feature, enabled := range config.Features {
			s.config.Features[feature] = enabled
		}
	}
}

// cleanup performs cleanup operations
func (s *Sensor) cleanup() {
	log.Println("🧹 Performing cleanup...")

	// Stop TLS enricher (drains pending probes)
	if s.tlsEnricher != nil {
		s.tlsEnricher.Stop()
	}

	// Stop packet capture
	if s.packetCapture != nil {
		s.packetCapture.Stop()
	}

	// Submit remaining discoveries
	if len(s.discoveries) > 0 {
		// Validate sensor ID before submitting (must be valid UUID)
		if s.config.SensorID == "" {
			log.Printf("⚠️  Cannot submit %d remaining discoveries: no sensor ID. Discoveries saved to encrypted storage.", len(s.discoveries))
		} else if _, err := uuid.Parse(s.config.SensorID); err != nil {
			log.Printf("⚠️  Cannot submit %d remaining discoveries: invalid sensor ID format '%s' (must be UUID). Discoveries saved to encrypted storage.", len(s.discoveries), s.config.SensorID)
		} else {
			log.Printf("📤 Submitting %d remaining discoveries...", len(s.discoveries))
			if err := s.apiClient.SubmitDiscoveries(s.discoveries); err != nil {
				log.Printf("❌ Failed to submit remaining discoveries: %v", err)
			} else {
				log.Printf("✅ Successfully submitted %d remaining discoveries", len(s.discoveries))
			}
		}
	}

	// Close storage
	if s.storage != nil {
		s.storage.Close()
	}

	// Close test logger
	if s.testLogger != nil {
		s.testLogger.Close()
		log.Printf("🧪 Test logger closed")
	}

	log.Println("✅ Cleanup completed")
}

// processCommands processes commands received from control plane
func (s *Sensor) processCommands(commands *models.SensorCommands) {
	if len(commands.Commands) == 0 {
		return
	}

	log.Printf("📋 Processing %d commands from control plane", len(commands.Commands))

	for _, command := range commands.Commands {
		s.processCommand(command)
	}
}

// processCommand processes a single command
// processCommand processes a single command
func (s *Sensor) processCommand(command models.Command) {
	log.Printf("🔧 Processing command: %s (type: %s)",
		command.ID, command.Type)

	var result *models.CommandResponse

	switch command.Type {
	case "restart":
		result = s.handleRestart(command)
	case "update_config":
		result = s.handleUpdateConfig(command)
	case "clear_cache":
		result = s.handleClearCache(command)
	case "trigger_scan":
		result = s.handleTriggerScan(command)
	case "update_interfaces":
		result = s.handleUpdateInterfaces(command)
	case "list_interfaces":
		result = s.handleListInterfaces(command)
	case "set_log_level":
		result = s.handleSetLogLevel(command)
	case "export_logs":
		result = s.handleExportLogs(command)
	default:
		log.Printf("⚠️ Unknown command type: %s", command.Type)
		result = &models.CommandResponse{
			ID:           uuid.New(),
			CommandID:    command.ID,
			SensorID:     s.config.SensorID,
			Status:       "error",
			Message:      fmt.Sprintf("Unknown command type: %s", command.Type),
			ResponseData: make(map[string]interface{}),
			Timestamp:    time.Now(),
		}
	}

	// Acknowledge command with result
	if result != nil && s.apiClient != nil {
		if err := s.apiClient.AcknowledgeCommand(command.ID, result); err != nil {
			log.Printf("❌ Failed to acknowledge command: %v", err)
		}
	}
}

// handleRestart handles sensor restart command
func (s *Sensor) handleRestart(command models.Command) *models.CommandResponse {
	log.Printf("🔄 Restart command received; exiting in 2s for supervisor relaunch")

	// Exit shortly after the acknowledgement is sent so the console records the
	// restart. The sensor relies on its process supervisor (systemd / docker /
	// kubernetes) to relaunch it.
	go func() {
		time.Sleep(2 * time.Second)
		log.Printf("🔄 Exiting now for restart")
		os.Exit(0)
	}()

	return &models.CommandResponse{
		ID:        uuid.New(),
		CommandID: command.ID,
		SensorID:  s.config.SensorID,
		Status:    "success",
		Message:   "Restart initiated; the sensor will exit in ~2s and be relaunched by its process supervisor (systemd/docker/kubernetes).",
		ResponseData: map[string]interface{}{
			"action":             "restart_initiated",
			"restart_in_seconds": 2,
			"pid":                os.Getpid(),
		},
		Timestamp: time.Now(),
	}
}

// applyDedupTTL propagates a new dedup TTL to both the connection cache and the
// TLS enricher debounce without requiring a restart.
func (s *Sensor) applyDedupTTL(minutes int) {
	ttl := time.Duration(minutes) * time.Minute
	s.config.Capture.DedupTTLMinutes = minutes
	if s.packetCapture != nil && s.packetCapture.GetCache() != nil {
		s.packetCapture.GetCache().SetTTL(ttl)
	}
	if s.tlsEnricher != nil {
		s.tlsEnricher.SetDebounceTTL(ttl)
	}
	log.Printf("📝 Dedup TTL updated to %d minutes", minutes)
}

// applyReportingInterval changes the data-send cadence at runtime: it updates
// the in-memory config, resets the live discovery ticker (no restart needed),
// and persists the value to the config file so it survives a restart. The next
// heartbeat reports the new interval back to the control plane.
func (s *Sensor) applyReportingInterval(seconds int) {
	s.config.ReportingInterval = time.Duration(seconds) * time.Second
	s.mu.Lock()
	if s.discoveryTicker != nil {
		s.discoveryTicker.Reset(s.config.ReportingInterval)
	}
	s.mu.Unlock()
	if err := s.saveConfigFile(); err != nil {
		log.Printf("⚠️  Reporting interval applied but not persisted: %v", err)
	}
	log.Printf("📝 Reporting interval updated to %v", s.config.ReportingInterval)
}

// handleUpdateConfig handles configuration update command
func (s *Sensor) handleUpdateConfig(command models.Command) *models.CommandResponse {
	log.Printf("📝 Configuration update command received")

	configData, ok := command.Payload["config"].(map[string]interface{})
	if !ok {
		return &models.CommandResponse{
			ID:           uuid.New(),
			CommandID:    command.ID,
			SensorID:     s.config.SensorID,
			Status:       "error",
			Message:      "Invalid config payload",
			ResponseData: make(map[string]interface{}),
			Timestamp:    time.Now(),
		}
	}

	// Apply configuration updates
	updatesApplied := 0

	if reportingInterval, ok := configData["reporting_interval"].(float64); ok && reportingInterval > 0 {
		s.applyReportingInterval(int(reportingInterval))
		updatesApplied++
	}

	if captureRaw, ok := configData["capture_config"].(map[string]interface{}); ok {
		if ap, ok := captureRaw["active_probing"].(bool); ok {
			s.config.Capture.ActiveProbing = ap
			updatesApplied++
			log.Printf("📝 Active probing set to: %v", ap)
		}
		if nd, ok := captureRaw["network_discovery"].(bool); ok {
			s.config.Capture.NetworkDiscovery = nd
			updatesApplied++
		}
		if dedupTTLRaw, ok := captureRaw["dedup_ttl_minutes"].(float64); ok && dedupTTLRaw > 0 {
			s.applyDedupTTL(int(dedupTTLRaw))
			updatesApplied++
		}
	}

	return &models.CommandResponse{
		ID:        uuid.New(),
		CommandID: command.ID,
		SensorID:  s.config.SensorID,
		Status:    "success",
		Message:   fmt.Sprintf("Configuration updated (%d settings changed)", updatesApplied),
		ResponseData: map[string]interface{}{
			"updates_applied": updatesApplied,
		},
		Timestamp: time.Now(),
	}
}

// handleClearCache handles cache clear command
func (s *Sensor) handleClearCache(command models.Command) *models.CommandResponse {
	log.Printf("🧹 Clear cache command received")

	if s.packetCapture != nil && s.packetCapture.GetCache() != nil {
		s.packetCapture.GetCache().Clear()
		log.Printf("✅ Connection cache cleared")

		return &models.CommandResponse{
			ID:        uuid.New(),
			CommandID: command.ID,
			SensorID:  s.config.SensorID,
			Status:    "success",
			Message:   "Cache cleared successfully",
			ResponseData: map[string]interface{}{
				"action": "cache_cleared",
			},
			Timestamp: time.Now(),
		}
	}

	return &models.CommandResponse{
		ID:           uuid.New(),
		CommandID:    command.ID,
		SensorID:     s.config.SensorID,
		Status:       "error",
		Message:      "Cache not available",
		ResponseData: make(map[string]interface{}),
		Timestamp:    time.Now(),
	}
}

// handleTriggerScan returns a snapshot of the sensor's current monitoring
// state. The sensor is primarily passive; targeted active scans run as
// discovery jobs, not ad-hoc commands — so this surfaces live capture status
// rather than kicking off a new scan.
func (s *Sensor) handleTriggerScan(command models.Command) *models.CommandResponse {
	log.Printf("🔍 Trigger scan command received; returning capture status snapshot")

	s.mu.RLock()
	pending := len(s.discoveries)
	s.mu.RUnlock()

	data := map[string]interface{}{
		"interfaces":          s.config.Capture.Interfaces,
		"active_probing":      s.config.Capture.ActiveProbing,
		"network_discovery":   s.config.Capture.NetworkDiscovery,
		"pending_discoveries": pending,
		"uptime_seconds":      int64(time.Since(s.startTime).Seconds()),
	}

	return &models.CommandResponse{
		ID:           uuid.New(),
		CommandID:    command.ID,
		SensorID:     s.config.SensorID,
		Status:       "success",
		Message:      "Capture status snapshot (sensor is passively monitoring; run a discovery job for targeted active scans)",
		ResponseData: data,
		Timestamp:    time.Now(),
	}
}

// handleUpdateInterfaces applies a new monitored-interface set: updates the
// running config, persists it to the config file, and restarts so capture comes
// back on the new set. If the config file can't be safely rewritten, it applies
// in-memory only and does NOT restart (so a malformed file is never corrupted
// and a restart can't revert to a stale set).
func (s *Sensor) handleUpdateInterfaces(command models.Command) *models.CommandResponse {
	log.Printf("🔌 Update interfaces command received")

	var requested []string
	switch v := command.Payload["interfaces"].(type) {
	case []interface{}:
		for _, item := range v {
			if name, ok := item.(string); ok && name != "" {
				requested = append(requested, name)
			}
		}
	case []string:
		requested = v
	}

	if len(requested) == 0 {
		return &models.CommandResponse{
			ID:           uuid.New(),
			CommandID:    command.ID,
			SensorID:     s.config.SensorID,
			Status:       "error",
			Message:      "No interfaces provided",
			ResponseData: make(map[string]interface{}),
			Timestamp:    time.Now(),
		}
	}

	previous := s.config.Capture.Interfaces
	s.config.Capture.Interfaces = requested // apply to running config

	persisted := true
	if err := s.persistMonitoredInterfaces(requested); err != nil {
		log.Printf("⚠️ Could not persist interface change to config file: %v", err)
		persisted = false
	}

	// Apply the change live by re-initializing packet capture on the new set —
	// NO process exit, so it works whether or not a supervisor is present
	// (manual run, systemd, docker, k8s alike).
	if err := s.reinitCapture(); err != nil {
		// New set failed to start (e.g. invalid interface) — revert so the
		// sensor keeps capturing on the previous set.
		log.Printf("❌ Failed to start capture on %v: %v — reverting to %v", requested, err, previous)
		s.config.Capture.Interfaces = previous
		_ = s.persistMonitoredInterfaces(previous)
		if revErr := s.reinitCapture(); revErr != nil {
			log.Printf("❌ Revert to previous interfaces also failed: %v", revErr)
		}
		return &models.CommandResponse{
			ID:        uuid.New(),
			CommandID: command.ID,
			SensorID:  s.config.SensorID,
			Status:    "error",
			Message:   fmt.Sprintf("Failed to apply interfaces %v: %v (reverted to %v)", requested, err, previous),
			ResponseData: map[string]interface{}{
				"previous_interfaces": previous,
				"applied_interfaces":  previous,
				"persisted":           persisted,
				"restarting":          false,
			},
			Timestamp: time.Now(),
		}
	}

	log.Printf("✅ Capture re-initialized on interfaces: %v", requested)
	return &models.CommandResponse{
		ID:        uuid.New(),
		CommandID: command.ID,
		SensorID:  s.config.SensorID,
		Status:    "success",
		Message:   "Interfaces updated; capture re-initialized on the new set (no restart needed)",
		ResponseData: map[string]interface{}{
			"previous_interfaces": previous,
			"applied_interfaces":  requested,
			"persisted":           persisted,
			"restarting":          false,
		},
		Timestamp: time.Now(),
	}
}

// reinitCapture tears down the running packet-capture + TLS-enricher and brings
// them back up on the current s.config.Capture.Interfaces — applying an
// interface change live, without exiting the process. Safe to run from the main
// goroutine (command processing happens synchronously in the heartbeat loop, so
// it never races the select that reads s.packetCapture's channels).
//
// Order matters: stop the enricher FIRST (it writes enrichment discoveries into
// the capture's discoveries channel) so nothing sends to that channel after
// PacketCapture.Stop() closes it. Capture sends are non-blocking, so Stop()'s
// wg.Wait() can't deadlock while the consumer loop is parked here.
func (s *Sensor) reinitCapture() error {
	if s.tlsEnricher != nil {
		s.tlsEnricher.Stop()
	}
	if s.packetCapture != nil {
		s.packetCapture.Stop()
	}

	pc := capture.NewPacketCapture(s.config)
	if err := pc.Start(); err != nil {
		return err
	}
	s.packetCapture = pc

	enr := enrichment.NewTLSEnricher(s.config, s.config.SensorID, pc.GetDiscoveriesWritable())
	enr.Start(3)
	s.tlsEnricher = enr
	return nil
}

// persistMonitoredInterfaces rewrites the capture.interfaces list in the sensor
// config file so a restart comes back monitoring the new set. It returns an
// error WITHOUT modifying the file if the interfaces block can't be located, so
// a malformed/unexpected file is never corrupted.
func (s *Sensor) persistMonitoredInterfaces(interfaces []string) error {
	if s.configPath == "" {
		return fmt.Errorf("no config file path set")
	}
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	lines := strings.Split(string(data), "\n")

	// Locate the "interfaces:" key line (any indentation), with nothing after
	// the colon (i.e. a block list follows).
	start := -1
	indent := ""
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if t == "interfaces:" {
			start = i
			indent = line[:strings.Index(line, "interfaces:")]
			break
		}
	}
	if start == -1 {
		return fmt.Errorf("interfaces block not found")
	}

	itemIndent := indent + "  "
	// Find the end of the existing list (consecutive blank or "- " item lines at
	// itemIndent).
	end := start + 1
	for end < len(lines) {
		if strings.TrimSpace(lines[end]) == "" {
			end++
			continue
		}
		if strings.HasPrefix(lines[end], itemIndent) && strings.HasPrefix(strings.TrimLeft(lines[end], " "), "-") {
			end++
			continue
		}
		break
	}

	block := []string{indent + "interfaces:"}
	for _, iface := range interfaces {
		block = append(block, fmt.Sprintf("%s- %s", itemIndent, iface))
	}

	out := make([]string, 0, len(lines))
	out = append(out, lines[:start]...)
	out = append(out, block...)
	out = append(out, lines[end:]...)

	if err := os.WriteFile(s.configPath, []byte(strings.Join(out, "\n")), 0644); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	log.Printf("✅ Persisted %d monitored interface(s) to config", len(interfaces))
	return nil
}

// handleListInterfaces reports the network interfaces present on the sensor
// host so the platform's interface picker can offer real choices instead of
// free-text, and shows which are currently being captured.
func (s *Sensor) handleListInterfaces(command models.Command) *models.CommandResponse {
	log.Printf("🔌 List interfaces command received")

	monitored := make(map[string]bool)
	for _, name := range s.config.Capture.Interfaces {
		monitored[name] = true
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return &models.CommandResponse{
			ID:           uuid.New(),
			CommandID:    command.ID,
			SensorID:     s.config.SensorID,
			Status:       "error",
			Message:      fmt.Sprintf("Failed to list interfaces: %v", err),
			ResponseData: make(map[string]interface{}),
			Timestamp:    time.Now(),
		}
	}

	list := make([]map[string]interface{}, 0, len(ifaces))
	for _, iface := range ifaces {
		var addrs []string
		if a, addrErr := iface.Addrs(); addrErr == nil {
			for _, addr := range a {
				addrs = append(addrs, addr.String())
			}
		}
		list = append(list, map[string]interface{}{
			"name":      iface.Name,
			"up":        iface.Flags&net.FlagUp != 0,
			"loopback":  iface.Flags&net.FlagLoopback != 0,
			"mtu":       iface.MTU,
			"addresses": addrs,
			"monitored": monitored[iface.Name],
		})
	}

	return &models.CommandResponse{
		ID:        uuid.New(),
		CommandID: command.ID,
		SensorID:  s.config.SensorID,
		Status:    "success",
		Message:   fmt.Sprintf("Found %d network interface(s)", len(list)),
		ResponseData: map[string]interface{}{
			"interfaces":           list,
			"monitored_interfaces": s.config.Capture.Interfaces,
		},
		Timestamp: time.Now(),
	}
}

// handleSetLogLevel handles log level change command
func (s *Sensor) handleSetLogLevel(command models.Command) *models.CommandResponse {
	log.Printf("📊 Set log level command received")

	level, ok := command.Payload["level"].(string)
	if !ok {
		return &models.CommandResponse{
			ID:           uuid.New(),
			CommandID:    command.ID,
			SensorID:     s.config.SensorID,
			Status:       "error",
			Message:      "Invalid log level payload",
			ResponseData: make(map[string]interface{}),
			Timestamp:    time.Now(),
		}
	}

	return &models.CommandResponse{
		ID:        uuid.New(),
		CommandID: command.ID,
		SensorID:  s.config.SensorID,
		Status:    "success",
		Message:   fmt.Sprintf("Log level set to: %s", level),
		ResponseData: map[string]interface{}{
			"log_level": level,
		},
		Timestamp: time.Now(),
	}
}

// handleExportLogs returns recent sensor log lines from the in-memory ring
// buffer. The payload may set {"lines": N} to bound how many are returned
// (default 200).
func (s *Sensor) handleExportLogs(command models.Command) *models.CommandResponse {
	log.Printf("📤 Export logs command received")

	n := 200
	if raw, ok := command.Payload["lines"].(float64); ok && raw > 0 {
		n = int(raw)
	}
	lines := logRing.tail(n)

	return &models.CommandResponse{
		ID:        uuid.New(),
		CommandID: command.ID,
		SensorID:  s.config.SensorID,
		Status:    "success",
		Message:   fmt.Sprintf("Exported %d recent log line(s)", len(lines)),
		ResponseData: map[string]interface{}{
			"line_count": len(lines),
			"lines":      lines,
		},
		Timestamp: time.Now(),
	}
}

// Helper functions for system metrics
func getMemoryUsage() int64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	// Return allocated memory in bytes
	return int64(m.Alloc)
}

func getCPUUsage() float64 {
	// Simple CPU usage estimation based on goroutine count and system load
	// For more accurate CPU usage, would need platform-specific code or external library
	numCPU := runtime.NumCPU()
	numGoroutine := runtime.NumGoroutine()

	// Rough estimate: if we have more goroutines than CPUs, estimate higher usage
	usage := float64(numGoroutine) / float64(numCPU) * 10.0
	if usage > 100.0 {
		usage = 100.0
	}

	return usage
}

// maskString masks sensitive strings for logging
func maskString(s string) string {
	if s == "" {
		return "(empty)"
	}
	if len(s) <= 4 {
		return "***"
	}
	return s[:2] + "***" + s[len(s)-2:]
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
		"config.yaml",
		filepath.Join(getDefaultDataPath(), "sensor-config.yaml"),
	} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

// shouldRunInteractive decides whether to open the configuration dialogue.
//
// The dialogue is the default so a bare `./sensor` on a fresh host walks the
// installer through setup and then starts capturing. It steps aside for every
// signal that this is not a fresh interactive install:
//
//   - an explicit -interactive=false,
//   - an existing config file (the documented way to override the default),
//   - CONTROL_PLANE_URL in the environment (container/unattended deployment),
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
	if configPath != "" || os.Getenv("CONTROL_PLANE_URL") != "" || register {
		return false
	}
	return tty
}

// runInteractiveMode runs the interactive configuration setup. caFingerprint,
// when supplied, pre-answers the control-plane CA trust question so a scripted
// install still gets a verified pin instead of a prompt it cannot answer.
func runInteractiveMode(caFingerprint string, verbose bool) {
	fmt.Println("🔧 VistaPlatform Network Sensor - Interactive Configuration")
	fmt.Println("=============================================================")
	fmt.Println()

	reader := bufio.NewReader(os.Stdin)

	// Get control plane URL and verify reachability before continuing. In
	// large, firewalled corporate networks an unreachable control plane is by
	// far the most common install snag — testing it here turns a silent,
	// frustrating failure later into immediate, actionable feedback.
	var controlPlaneURL string
	var tlsUnverified bool
urlLoop:
	for {
		fmt.Print("Enter Control Plane URL (default: https://app.vistasecurity.io): ")
		controlPlaneURL, _ = reader.ReadString('\n')
		controlPlaneURL = strings.TrimSpace(controlPlaneURL)
		if controlPlaneURL == "" {
			controlPlaneURL = "https://app.vistasecurity.io"
		}

		fmt.Printf("\n🔌 Testing connectivity to %s ...\n", controlPlaneURL)
		res := testControlPlaneConnectivity(controlPlaneURL)
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
			return
		default:
			fmt.Println()
			// any other input (including just Enter) retries the URL
		}
	}

	// Trust bootstrap. The control plane's certificate did not verify against
	// this host's trust store, so the sensor has nothing to check it against
	// and registration would fail x509. Show the operator the CA the platform
	// presents and let them decide — the SSH known_hosts model. If they accept,
	// it is pinned into the sensor's config and every subsequent connection is
	// verified against it; verification is never disabled.
	var pinnedCA string
	if tlsUnverified {
		anchor, err := certificates.ResolveTrustAnchor(controlPlaneURL, caFingerprint, reader, os.Stdout, true)
		if err != nil {
			if errors.Is(err, certificates.ErrTrustDeclined) {
				fmt.Println("Setup cancelled — no CA trusted.")
				return
			}
			if errors.Is(err, certificates.ErrCertificateNotForHost) {
				// ResolveTrustAnchor has already explained what is wrong and
				// why pinning cannot fix it. Say what to do next rather than
				// repeating the diagnosis as a bare error line.
				fmt.Println("Setup cancelled — fix the platform's TLS certificate, then run setup again.")
				return
			}
			fmt.Printf("❌ Could not establish trust with the control plane: %v\n", err)
			return
		}
		pinnedCA = anchor.PEM
	}

	// Get registration key
	fmt.Println()
	fmt.Println("📋 Registration Key:")
	fmt.Println("   To register with the control plane, you need a registration key.")
	fmt.Println("   Get one from the Sensor Management page in the web UI:")
	fmt.Println("   1. Click 'Register new' button")
	fmt.Println("   2. Fill in sensor name and IP address")
	fmt.Println("   3. Click 'Generate Registration Key'")
	fmt.Println("   4. Copy the registration key shown")
	fmt.Println()
	fmt.Println("   If you leave this empty, the sensor will start but will NOT register")
	fmt.Println("   or submit discoveries to the control plane (local capture only).")
	fmt.Print("Enter Registration Key (leave empty to skip registration): ")
	registrationKey, _ := reader.ReadString('\n')
	registrationKey = strings.TrimSpace(registrationKey)

	// Note: the sensor's UUID is assigned by the control plane during
	// registration (it proposes one in its CSR and the platform confirms it),
	// so there is no Sensor ID to prompt for here.

	// Get reporting interval
	fmt.Print("Enter Reporting Interval in seconds (default: 30): ")
	intervalStr, _ := reader.ReadString('\n')
	intervalStr = strings.TrimSpace(intervalStr)
	interval := 30
	if intervalStr != "" {
		if parsed, err := strconv.Atoi(intervalStr); err == nil {
			interval = parsed
		}
	}

	// Get data path
	fmt.Print("Enter Data Path (default: auto-detect): ")
	dataPath, _ := reader.ReadString('\n')
	dataPath = strings.TrimSpace(dataPath)
	if dataPath == "" {
		dataPath = getDefaultDataPath()
	}

	// Network interface selection
	fmt.Println("\n🌐 Network Interface Selection")
	interfaces := getAvailableInterfaces()
	if len(interfaces) == 0 {
		fmt.Println("❌ No network interfaces found!")
		return
	}

	// Pre-select the interface this host uses to reach the control plane — for
	// the common single-NIC deployment that means zero typing: the installer
	// just confirms the highlighted default.
	connectedIdx := detectConnectedInterfaceIdx(controlPlaneURL, interfaces)
	selectedInterfaces := selectInterfaces(reader, interfaces, connectedIdx)
	if len(selectedInterfaces) == 0 {
		fmt.Println("❌ No interfaces selected!")
		return
	}

	// Display configuration summary
	fmt.Println("\n📋 Configuration Summary")
	fmt.Println("========================")
	fmt.Printf("Control Plane URL: %s\n", controlPlaneURL)
	fmt.Printf("Registration Key: %s\n", maskString(registrationKey))
	fmt.Printf("Reporting Interval: %d seconds\n", interval)
	fmt.Printf("Data Path: %s\n", dataPath)
	fmt.Printf("Selected Interfaces: %v\n", selectedInterfaces)

	fmt.Print("\nSave this configuration and start the sensor? (Y/n): ")
	confirm, _ := reader.ReadString('\n')
	confirm = strings.TrimSpace(strings.ToLower(confirm))
	if confirm == "n" || confirm == "no" {
		fmt.Println("Configuration cancelled.")
		return
	}

	// Persist the operator-approved CA before the config that references it, so
	// a config pointing at a missing file is never written. The path (not the
	// PEM) goes into the YAML — config.loadCertificatesFromFiles reads it back
	// on every start, and the hand-rolled YAML writer below has no sane way to
	// emit a multi-line block scalar.
	caPath := ""
	if pinnedCA != "" {
		certsDir := filepath.Join(dataPath, "certs")
		if err := os.MkdirAll(certsDir, 0700); err != nil {
			fmt.Printf("❌ Failed to create certificates directory: %v\n", err)
			return
		}
		caPath = filepath.Join(certsDir, "platform-ca.crt")
		if err := os.WriteFile(caPath, []byte(pinnedCA), 0644); err != nil {
			fmt.Printf("❌ Failed to write platform CA: %v\n", err)
			return
		}
		fmt.Printf("🔒 Platform CA pinned at: %s\n", caPath)
	}

	// Create configuration file
	configPath := filepath.Join(dataPath, "sensor-config.yaml")
	if err := createConfigFile(configPath, controlPlaneURL, registrationKey, interval, dataPath, selectedInterfaces, caPath); err != nil {
		fmt.Printf("⚠️  Warning: Failed to create config file: %v\n", err)
		fmt.Println("   Configuration will only be available in current session.")
	} else {
		fmt.Printf("📁 Configuration saved to: %s\n", configPath)
	}

	// Set environment variables for current session
	os.Setenv("CONTROL_PLANE_URL", controlPlaneURL)
	if registrationKey != "" {
		os.Setenv("REGISTRATION_KEY", registrationKey)
	}
	os.Setenv("REPORTING_INTERVAL", fmt.Sprintf("%ds", interval))
	os.Setenv("DATA_PATH", dataPath)
	os.Setenv("INTERFACES", strings.Join(selectedInterfaces, ","))

	fmt.Println("\n✅ Configuration saved! Starting sensor...")
	fmt.Println("Press Ctrl+C to stop the sensor")
	fmt.Println()

	// Start the sensor with the configured settings
	startSensorWithConfig(verbose)
}

// generateSensorID generates a unique sensor ID
func generateSensorID() string {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown"
	}
	return fmt.Sprintf("%s-%d", hostname, time.Now().Unix())
}

// NetworkInterface represents a network interface
type NetworkInterface struct {
	Name        string
	Description string
	IP          string
}

// getAvailableInterfaces returns a list of available network interfaces
// On Windows, uses pcap device names (required for packet capture)
// On other platforms, uses net.Interfaces()
func getAvailableInterfaces() []NetworkInterface {
	var interfaces []NetworkInterface

	// On Windows, prefer pcap device names since that's what we need for capture
	if runtime.GOOS == "windows" {
		pcapDevs, err := pcap.FindAllDevs()
		if err == nil && len(pcapDevs) > 0 {
			// Use pcap device names on Windows
			for _, dev := range pcapDevs {
				// Skip loopback interfaces
				if strings.Contains(strings.ToLower(dev.Description), "loopback") ||
					strings.Contains(strings.ToLower(dev.Name), "loopback") {
					continue
				}

				// Extract IP from addresses if available
				var ip string
				for _, addr := range dev.Addresses {
					if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
						ip = addr.IP.String()
						break
					}
				}

				description := dev.Description
				if ip != "" {
					description = fmt.Sprintf("%s (IP: %s)", dev.Description, ip)
				} else if description == "" {
					description = dev.Name
				}

				interfaces = append(interfaces, NetworkInterface{
					Name:        dev.Name, // Use pcap device name
					Description: description,
					IP:          ip,
				})
			}
			return interfaces
		}
		// Fall through to net.Interfaces() if pcap fails
	}

	// Use standard net.Interfaces() for non-Windows or as fallback
	ifaces, err := net.Interfaces()
	if err != nil {
		return interfaces
	}

	for _, iface := range ifaces {
		// Skip loopback and inactive interfaces
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Get IP address
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		var ip string
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					ip = ipnet.IP.String()
					break
				}
			}
		}

		interfaces = append(interfaces, NetworkInterface{
			Name:        iface.Name,
			Description: fmt.Sprintf("IP: %s, MTU: %d", ip, iface.MTU),
			IP:          ip,
		})
	}

	return interfaces
}

// parseInterfaceSelection parses the user's interface selection
func parseInterfaceSelection(selection string, interfaces []NetworkInterface) []string {
	var selected []string

	parts := strings.Split(selection, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if idx, err := strconv.Atoi(part); err == nil {
			if idx >= 1 && idx <= len(interfaces) {
				selected = append(selected, interfaces[idx-1].Name)
			}
		}
	}

	return selected
}

// connectivityResult summarizes a control-plane reachability probe for display
// during interactive setup.
type connectivityResult struct {
	ok      bool
	icon    string
	summary string
	detail  string
	// tlsUnverified reports that the control plane answered TLS but its
	// certificate did not verify against this host's trust store. The path is
	// open; only trust is missing, which the caller resolves by pinning the CA.
	tlsUnverified bool
}

// testControlPlaneConnectivity probes the control plane in three escalating
// steps — DNS resolution, a raw TCP connect, then an HTTP round-trip — so the
// installer learns *where* the path breaks (name resolution vs. a blocking
// firewall vs. a wrong port) instead of discovering it only when registration
// later fails. It never blocks for more than a few seconds per step.
func testControlPlaneConnectivity(rawURL string) connectivityResult {
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
			detail += " A firewall is most likely blocking the path between this host and the control plane."
		case strings.Contains(cerr.Error(), "refused"):
			summary = "Connection refused"
			detail += " The host is reachable but nothing is listening on that port — double-check the port in the URL."
		}
		return connectivityResult{icon: "❌", summary: summary, detail: detail}
	}
	_ = conn.Close()

	// 3. HTTP round-trip — confirms the control plane (or its gateway) answers.
	client := &http.Client{Timeout: 8 * time.Second}
	resp, herr := client.Get(rawURL)
	if herr != nil {
		msg := herr.Error()
		if strings.Contains(msg, "x509") || strings.Contains(msg, "certificate") || strings.Contains(msg, "tls") {
			// The server completed a TLS handshake, so the network path is open —
			// only certificate *verification* failed. Common with the internal
			// CAs many deployments use, so treat it as a soft pass rather than
			// forcing a retry loop. Registration will NOT proceed until the
			// sensor is given something to verify against, so the caller must
			// resolve trust before continuing.
			return connectivityResult{ok: true, tlsUnverified: true, icon: "⚠️", summary: "Reachable, but TLS certificate not verified",
				detail: "The port is open and the server speaks TLS, but its certificate could not be verified against this host's trust store. This is normal with internal/private CAs — you will be asked whether to trust it."}
		}
		return connectivityResult{icon: "⚠️", summary: "Port open, but no HTTP response",
			detail: fmt.Sprintf("Connected to %s but the HTTP request failed: %v", addr, herr)}
	}
	_ = resp.Body.Close()

	return connectivityResult{ok: true, icon: "✅", summary: "Control plane is reachable",
		detail: fmt.Sprintf("Connected to %s and received HTTP %d.", addr, resp.StatusCode)}
}

// detectConnectedInterfaceIdx returns the index of the interface whose IP the OS
// would use to reach the control plane, or -1 if it can't be determined. That
// interface is the natural default to monitor, so the picker pre-selects it.
func detectConnectedInterfaceIdx(controlPlaneURL string, interfaces []NetworkInterface) int {
	outbound := outboundIPFor(controlPlaneURL)
	if outbound == "" {
		return -1
	}
	for i, iface := range interfaces {
		if iface.IP != "" && iface.IP == outbound {
			return i
		}
	}
	return -1
}

// outboundIPFor returns the local source IP the OS routing table would use to
// reach the control plane host (falling back to a public target). It opens a UDP
// socket but sends nothing — no packets leave the host; it only consults the
// route.
func outboundIPFor(controlPlaneURL string) string {
	target := "8.8.8.8:80"
	if u, err := url.Parse(controlPlaneURL); err == nil && u.Hostname() != "" {
		host := u.Hostname()
		port := u.Port()
		if port == "" {
			port = "80"
		}
		if ips, lerr := net.LookupHost(host); lerr == nil && len(ips) > 0 {
			target = net.JoinHostPort(ips[0], port)
		}
	}
	conn, err := net.Dial("udp", target)
	if err != nil {
		return ""
	}
	defer conn.Close()
	if udpAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return udpAddr.IP.String()
	}
	return ""
}

// selectInterfaces lets the installer choose one or more NICs to monitor. When
// stdin is an interactive terminal (and not Windows, where raw-mode ANSI is
// unreliable) it presents a no-typing arrow-key/space-toggle picker; otherwise
// it falls back to a numbered prompt. In both paths defaultIdx (the NIC used to
// reach the control plane, or -1) is pre-selected so the common case is a single
// keypress.
func selectInterfaces(reader *bufio.Reader, interfaces []NetworkInterface, defaultIdx int) []string {
	if runtime.GOOS != "windows" && term.IsTerminal(int(os.Stdin.Fd())) {
		if sel, err := selectInterfacesTUI(interfaces, defaultIdx); err == nil {
			return sel
		}
		// On any TUI failure, fall through to the robust text prompt.
	}
	return selectInterfacesText(reader, interfaces, defaultIdx)
}

// selectInterfacesText is the typing-based fallback used for piped stdin and on
// Windows. Pressing Enter with no input accepts the pre-selected default NIC.
func selectInterfacesText(reader *bufio.Reader, interfaces []NetworkInterface, defaultIdx int) []string {
	fmt.Println("Available network interfaces:")
	for i, iface := range interfaces {
		marker := " "
		if i == defaultIdx {
			marker = "*"
		}
		label := iface.Name
		if iface.Description != "" {
			label = fmt.Sprintf("%s (%s)", iface.Name, iface.Description)
		}
		fmt.Printf("  %s %d. %s\n", marker, i+1, label)
	}

	if defaultIdx >= 0 {
		fmt.Println("\n  (* = the interface this host uses to reach the control plane)")
		fmt.Printf("Press Enter to monitor the connected interface [%d], or type number(s) (comma-separated): ", defaultIdx+1)
	} else {
		fmt.Print("\nSelect interface(s) by number (comma-separated, e.g., 1,2 or just 1): ")
	}

	selection, _ := reader.ReadString('\n')
	selection = strings.TrimSpace(selection)
	if selection == "" && defaultIdx >= 0 {
		return []string{interfaces[defaultIdx].Name}
	}
	return parseInterfaceSelection(selection, interfaces)
}

// Logical keys returned by readInterfaceKey.
const (
	keyEnter = iota
	keySpace
	keyUp
	keyDown
	keyCtrlC
	keyOther
)

// readInterfaceKey reads a single keypress (one byte at a time, no read-ahead so
// it doesn't steal bytes from the outer line reader) and maps arrow-key escape
// sequences and j/k to logical navigation keys.
func readInterfaceKey() (int, error) {
	b, err := readStdinByte()
	if err != nil {
		return 0, err
	}
	switch b {
	case 3:
		return keyCtrlC, nil
	case '\r', '\n':
		return keyEnter, nil
	case ' ':
		return keySpace, nil
	case 'k':
		return keyUp, nil
	case 'j':
		return keyDown, nil
	case 0x1b: // ESC — possible arrow-key sequence: ESC [ A/B
		if b2, err := readStdinByte(); err != nil || b2 != '[' {
			return keyOther, nil
		}
		b3, err := readStdinByte()
		if err != nil {
			return keyOther, nil
		}
		switch b3 {
		case 'A':
			return keyUp, nil
		case 'B':
			return keyDown, nil
		}
		return keyOther, nil
	}
	return keyOther, nil
}

func readStdinByte() (byte, error) {
	var buf [1]byte
	n, err := os.Stdin.Read(buf[:])
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, io.EOF
	}
	return buf[0], nil
}

// selectInterfacesTUI renders an in-place checkbox list driven by arrow keys and
// space. It requires a real terminal; callers gate on term.IsTerminal and treat
// any returned error as a signal to fall back to the text prompt.
func selectInterfacesTUI(interfaces []NetworkInterface, defaultIdx int) ([]string, error) {
	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return nil, err
	}
	defer term.Restore(fd, oldState)

	checked := make([]bool, len(interfaces))
	cursor := 0
	if defaultIdx >= 0 && defaultIdx < len(interfaces) {
		checked[defaultIdx] = true
		cursor = defaultIdx
	}

	out := os.Stdout
	// Instructions printed once, above the redrawn list.
	fmt.Fprint(out, "\r\n  ↑/↓ move    space toggle    enter confirm    (connected NIC pre-selected)\r\n")

	firstRender := true
	for {
		if !firstRender {
			fmt.Fprintf(out, "\x1b[%dA", len(interfaces)) // move cursor up to overwrite
		}
		firstRender = false
		for i, iface := range interfaces {
			pointer := " "
			if i == cursor {
				pointer = ">"
			}
			box := "[ ]"
			if checked[i] {
				box = "[x]"
			}
			label := iface.Name
			if iface.IP != "" {
				label = fmt.Sprintf("%s — %s", iface.Name, iface.IP)
			}
			tag := ""
			if i == defaultIdx {
				tag = "  (connected)"
			}
			fmt.Fprintf(out, "\r\x1b[K %s %s %s%s\r\n", pointer, box, label, tag)
		}

		key, err := readInterfaceKey()
		if err != nil {
			return nil, err
		}
		switch key {
		case keyCtrlC:
			term.Restore(fd, oldState)
			fmt.Fprint(out, "\r\n")
			fmt.Println("Setup cancelled.")
			os.Exit(1)
		case keyEnter:
			var selected []string
			for i, c := range checked {
				if c {
					selected = append(selected, interfaces[i].Name)
				}
			}
			fmt.Fprint(out, "\r\n")
			return selected, nil
		case keySpace:
			checked[cursor] = !checked[cursor]
		case keyUp:
			if cursor > 0 {
				cursor--
			}
		case keyDown:
			if cursor < len(interfaces)-1 {
				cursor++
			}
		}
	}
}

// startSensorWithConfig starts the sensor with the configured environment variables
func startSensorWithConfig(verbose bool) {
	// Load configuration from the file that was just created
	configPath := filepath.Join(os.Getenv("DATA_PATH"), "sensor-config.yaml")
	if configPath == "" || os.Getenv("DATA_PATH") == "" {
		configPath = filepath.Join(getDefaultDataPath(), "sensor-config.yaml")
	}

	// Load configuration
	cfg, err := config.LoadFromFile(configPath)
	if err != nil {
		// Fall back to environment variables if config file can't be loaded
		fmt.Printf("⚠️  Warning: Failed to load config file (%v), using environment variables\n", err)
		cfg = config.Load()
	}

	// Build-stamped binary version wins over anything in the config file.
	cfg.Version = Version

	// Set test mode from environment if set
	if os.Getenv("TEST_MODE") == "true" {
		cfg.TestMode = true
	}

	// Same config-file override as the non-interactive path.
	if cfg.Verbose != nil && !isFlagSet("verbose") {
		verbose = *cfg.Verbose
	}

	// Initialize logging. Tee into the ring buffer so export_logs works on a
	// sensor started straight out of the installer, exactly as it does for one
	// started from a config file.
	log.SetOutput(io.MultiWriter(os.Stderr, logRing))
	if verbose {
		log.SetFlags(log.LstdFlags | log.Lshortfile)
		log.Println("Verbose logging enabled")
	} else {
		log.SetFlags(log.LstdFlags)
	}
	log.Printf("🚀 Starting VistaPlatform Network Sensor v%s", Version)
	log.Printf("Platform: %s/%s", runtime.GOOS, runtime.GOARCH)
	log.Printf("Configuration loaded from interactive setup")
	log.Printf("Configuration loaded:")
	log.Printf("  Sensor ID: %s", cfg.SensorID)
	log.Printf("  Control Plane URL: %s", cfg.ControlPlaneURL)
	log.Printf("  Registration Key: %s", maskString(cfg.RegistrationKey))
	log.Printf("  Reporting Interval: %v", cfg.ReportingInterval)
	log.Printf("  Data Path: %s", cfg.Storage.DataPath)
	log.Printf("  Interfaces: %v", cfg.Capture.Interfaces)
	if cfg.TestMode {
		log.Println("🧪 Running in TEST MODE - discoveries will be logged to file instead of control plane")
	}

	// Create sensor instance
	sensor := &Sensor{
		config:      cfg,
		configPath:  configPath, // Store the config file path for saving updates
		discoveries: make([]*models.CryptoDiscovery, 0),
		startTime:   time.Now(), // Track start time for uptime
	}

	// Initialize components
	log.Println("🔧 Initializing sensor components...")
	if err := sensor.initialize(); err != nil {
		log.Fatalf("❌ Failed to initialize sensor: %v", err)
	}
	log.Println("✅ Sensor components initialized successfully")

	// Validate sensor ID format if set (must be UUID for API calls)
	if cfg.SensorID != "" {
		if _, err := uuid.Parse(cfg.SensorID); err != nil {
			log.Printf("⚠️  Warning: Sensor ID '%s' is not a valid UUID format. Clearing it - will be assigned during registration.", cfg.SensorID)
			cfg.SensorID = ""
			sensor.config.SensorID = ""
		}
	}

	// Register with control plane if a registration key is provided and we are
	// not already registered. A consumed registration key lingers in the config
	// file; re-sending it on restart is rejected by the control plane. See the
	// note on isRegistered() in main() for the full rationale.
	// registrationRetryStop ends the background retry loop at shutdown.
	registrationRetryStop := make(chan struct{})
	defer close(registrationRetryStop)

	sensor.resolveRegistrationAtStartup(false, registrationRetryStop)

	// Start sensor
	log.Println("🚀 Starting sensor services...")
	if err := sensor.start(); err != nil {
		log.Fatalf("❌ Failed to start sensor: %v", err)
	}
	log.Println(sensor.startupStateLine("Sensor services"))

	// Handle graceful shutdown
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, syscall.SIGTERM)

	// Ensure reporting interval is always positive
	if cfg.ReportingInterval <= 0 {
		log.Printf("⚠️  Invalid reporting interval (%v) - defaulting to 30s", cfg.ReportingInterval)
		cfg.ReportingInterval = 30 * time.Second
	}

	// Main sensor loop
	ticker := time.NewTicker(cfg.ReportingInterval)
	defer ticker.Stop()
	// Publish the discovery ticker so an operator's reporting-interval change is
	// applied live (handleUpdateConfig → applyReportingInterval resets it).
	sensor.mu.Lock()
	sensor.discoveryTicker = ticker
	sensor.mu.Unlock()

	// Certificate expiration check ticker (check daily)
	certCheckTicker := time.NewTicker(24 * time.Hour)
	defer certCheckTicker.Stop()

	// Cache cleanup ticker (cleanup every 10 minutes)
	cacheCleanupTicker := time.NewTicker(10 * time.Minute)
	defer cacheCleanupTicker.Stop()

	// Heartbeat ticker — independent of discovery submission
	heartbeatTicker := time.NewTicker(cfg.HeartbeatInterval)
	defer heartbeatTicker.Stop()

	// Unregistered-state reminder. The failure mode was a log that read as
	// healthy while nothing was submitted, so an unregistered sensor says so on a
	// schedule rather than only at startup — an operator who scrolls back an hour
	// must still be able to see it. The handler goes quiet once registration
	// lands, so a healthy sensor prints nothing extra.
	unregisteredWarnTicker := time.NewTicker(10 * time.Minute)
	defer unregisteredWarnTicker.Stop()

	log.Println(sensor.startupStateLine("Sensor"))
	log.Println("📡 Monitoring network traffic for cryptographic configurations...")
	log.Printf("🔄 Reporting interval: %v", cfg.ReportingInterval)
	log.Println("💡 Press Ctrl+C to stop the sensor")

	// Check certificate expiration on startup
	if sensor.sensorManager != nil && cfg.Security.UseTLS {
		go sensor.checkAndRotateCertificate()
	}

	// Start TLS enricher worker pool (active probes for TLS 1.3 cert extraction)
	if sensor.tlsEnricher != nil {
		sensor.tlsEnricher.Start(3)
	}

	for {
		select {
		case <-ticker.C:
			log.Println("⏰ Processing discoveries...")
			sensor.processDiscoveries()
		case <-certCheckTicker.C:
			// Check certificate expiration daily
			if sensor.sensorManager != nil && cfg.Security.UseTLS {
				go sensor.checkAndRotateCertificate()
			}
		case <-unregisteredWarnTicker.C:
			// Only speaks while there is something wrong.
			if !sensor.isRegisteredNow() && !cfg.TestMode {
				log.Println("⚠️  Still UNREGISTERED — traffic is being captured and none of it can be submitted.")
			}
		case <-cacheCleanupTicker.C:
			// Clean up expired cache entries
			if sensor.packetCapture != nil && sensor.packetCapture.GetCache() != nil {
				sensor.packetCapture.GetCache().Cleanup()
				log.Println("🧹 Cache cleanup completed")
			}
		case <-heartbeatTicker.C:
			log.Println("💓 Sending heartbeat...")
			sensor.sendHeartbeat()
		case discovery := <-sensor.packetCapture.GetDiscoveries():
			log.Printf("🔍 New discovery received: %s on %s:%d", discovery.Protocol, discovery.DestIP, discovery.Port)
			sensor.handleDiscovery(discovery)
			// Check if this passive discovery needs TLS certificate enrichment
			if sensor.tlsEnricher != nil {
				sensor.tlsEnricher.MaybeEnrich(discovery)
			}
		case err := <-sensor.packetCapture.GetErrors():
			log.Printf("❌ Capture error: %v", err)
		case sig := <-signalChan:
			log.Printf("🛑 Received signal %v, shutting down gracefully...", sig)
			sensor.cleanup()
			log.Println("👋 Sensor shutdown complete")
			return
		}
	}
}

// getDefaultDataPath returns the appropriate default data path for the current OS
// This is a helper function that matches config.getDefaultDataPath()
func getDefaultDataPath() string {
	switch runtime.GOOS {
	case "windows":
		// Use user's AppData\Local directory on Windows
		if appData := os.Getenv("LOCALAPPDATA"); appData != "" {
			return filepath.Join(appData, "CryptoSensor")
		}
		// Fallback to current directory if LOCALAPPDATA is not set
		return "CryptoSensor"
	case "darwin":
		// Use user's Library/Application Support on macOS
		if home := os.Getenv("HOME"); home != "" {
			return filepath.Join(home, "Library", "Application Support", "CryptoSensor")
		}
		return "/tmp/crypto-sensor"
	default:
		// Linux and other Unix-like systems
		return "/var/lib/crypto-sensor"
	}
}

// createConfigFile creates a YAML configuration file with the provided settings
// createConfigFile writes the sensor's YAML config. serverCACertPath, when
// non-empty, is the operator-approved platform CA this sensor pins — emitted so
// it survives restarts and so the sensor verifies the control plane against it
// from the very first call, registration included.
func createConfigFile(configPath, controlPlaneURL, registrationKey string, interval int, dataPath string, interfaces []string, serverCACertPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}

	// Use proper YAML structure to avoid parsing errors
	type ConfigFile struct {
		ControlPlaneURL       string `yaml:"controlPlaneUrl"`
		RegistrationKey       string `yaml:"registrationKey"`
		ReportingIntervalSecs int    `yaml:"reportingIntervalSeconds"`
		Storage               struct {
			MaxStorageSize int64  `yaml:"maxStorageSize"`
			RotationSize   int64  `yaml:"rotationSize"`
			RetentionDays  int    `yaml:"retentionDays"`
			DataPath       string `yaml:"dataPath"`
			EncryptionKey  string `yaml:"encryptionKey"`
		} `yaml:"storage"`
		Capture struct {
			Interfaces       []string `yaml:"interfaces"`
			ActiveProbing    bool     `yaml:"activeProbing"`
			NetworkDiscovery bool     `yaml:"networkDiscovery"`
			MaxConnections   int      `yaml:"maxConnections"`
			TimeoutSeconds   int      `yaml:"timeoutSeconds"`
			BufferSize       int      `yaml:"bufferSize"`
		} `yaml:"capture"`
	}

	cfg := ConfigFile{
		ControlPlaneURL:       controlPlaneURL,
		RegistrationKey:       registrationKey,
		ReportingIntervalSecs: interval,
	}
	cfg.Storage.MaxStorageSize = 104857600 // 100 MB
	cfg.Storage.RotationSize = 10485760    // 10 MB
	cfg.Storage.RetentionDays = 7
	cfg.Storage.DataPath = dataPath
	cfg.Storage.EncryptionKey = ""
	cfg.Capture.Interfaces = interfaces
	cfg.Capture.ActiveProbing = true
	cfg.Capture.NetworkDiscovery = true
	cfg.Capture.MaxConnections = 1000
	cfg.Capture.TimeoutSeconds = 30
	cfg.Capture.BufferSize = 1048576 // 1 MB

	// Marshal to YAML with proper formatting
	// Use custom formatting to ensure Windows device paths are properly quoted
	var configContent strings.Builder

	// Add header comment
	fmt.Fprintf(&configContent, "# VistaPlatform Network Sensor Configuration\n# Generated by interactive configuration on %s\n\n", time.Now().Format("2006-01-02 15:04:05"))

	// Write config with proper quoting for Windows paths.
	// Note: sensorId is intentionally omitted — the control plane assigns it
	// during registration and Sensor.saveConfigFile() writes it back afterward.
	configContent.WriteString(fmt.Sprintf("controlPlaneUrl: %s\n", cfg.ControlPlaneURL))
	configContent.WriteString(fmt.Sprintf("registrationKey: %s\n", cfg.RegistrationKey))
	configContent.WriteString(fmt.Sprintf("reportingIntervalSeconds: %d\n", cfg.ReportingIntervalSecs))

	configContent.WriteString("storage:\n")
	configContent.WriteString(fmt.Sprintf("  maxStorageSize: %d\n", cfg.Storage.MaxStorageSize))
	configContent.WriteString(fmt.Sprintf("  rotationSize: %d\n", cfg.Storage.RotationSize))
	configContent.WriteString(fmt.Sprintf("  retentionDays: %d\n", cfg.Storage.RetentionDays))
	configContent.WriteString(fmt.Sprintf("  dataPath: %q\n", cfg.Storage.DataPath))
	configContent.WriteString(fmt.Sprintf("  encryptionKey: %q\n", cfg.Storage.EncryptionKey))

	configContent.WriteString("capture:\n")
	configContent.WriteString("  interfaces:\n")
	for _, iface := range cfg.Capture.Interfaces {
		// Always quote interface names to handle Windows device paths with backslashes
		configContent.WriteString(fmt.Sprintf("    - %q\n", iface))
	}
	configContent.WriteString(fmt.Sprintf("  activeProbing: %t\n", cfg.Capture.ActiveProbing))
	configContent.WriteString(fmt.Sprintf("  networkDiscovery: %t\n", cfg.Capture.NetworkDiscovery))
	configContent.WriteString(fmt.Sprintf("  maxConnections: %d\n", cfg.Capture.MaxConnections))
	configContent.WriteString(fmt.Sprintf("  timeoutSeconds: %d\n", cfg.Capture.TimeoutSeconds))
	configContent.WriteString(fmt.Sprintf("  bufferSize: %d\n", cfg.Capture.BufferSize))

	if serverCACertPath != "" {
		configContent.WriteString("\n# Platform CA approved during setup. The sensor verifies every control-plane\n")
		configContent.WriteString("# connection against this certificate. Removing it does not disable\n")
		configContent.WriteString("# verification — it falls back to this host's system trust store.\n")
		configContent.WriteString("security:\n")
		fmt.Fprintf(&configContent, "  serverCACertPath: %q\n", serverCACertPath)
	}

	// Add footer comment
	configContent.WriteString(fmt.Sprintf("\n# Environment variables (for reference)\n# CONTROL_PLANE_URL=%s\n# REGISTRATION_KEY=%s\n# REPORTING_INTERVAL=%ds\n# DATA_PATH=%s\n# INTERFACES=%s\n",
		controlPlaneURL, registrationKey, interval, dataPath, strings.Join(interfaces, ",")))

	// Write config file
	if err := os.WriteFile(configPath, []byte(configContent.String()), 0644); err != nil {
		return fmt.Errorf("failed to write config file: %v", err)
	}

	return nil
}
