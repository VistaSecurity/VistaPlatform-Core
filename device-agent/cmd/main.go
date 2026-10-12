package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/api"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/audit"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/config"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/devices"
	"github.com/vistasecurity/vistaplatform/shared/agentconfig/desiredstate"
	"github.com/vistasecurity/vistaplatform/shared/atomicfile"
	"github.com/vistasecurity/vistaplatform/shared/certificates"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// Version is stamped at build time via -ldflags "-X main.Version=<tag>"
// (see the Makefile's AGENT_LDFLAGS and release-core.yml). An unstamped
// build honestly reports "dev" rather than claiming to be a release.
var Version = "dev"

type DeviceAgent struct {
	// unpersistedCredentials is set when a rotated certificate could not be
	// written to disk; see checkAndRotateAgentCertificate.
	unpersistedCredentials atomicfile.Pending

	config      *config.Config
	configPath  string
	apiClient   *api.OutboundClient
	jobExecutor *devices.JobExecutor
	auditLogger *audit.AuditLogger

	// Lifecycle. lifeCtx is cancelled by Stop (which runAgent calls on
	// SIGINT/SIGTERM) and every loop selects on it. loops counts the loop
	// goroutines, so Stop can wait for a job still in flight to submit its
	// result before the process exits. All zero values work: a DeviceAgent
	// built without newDeviceAgent simply never stops its loops early.
	lifeMu     sync.Mutex
	lifeCtx    context.Context
	lifeCancel context.CancelFunc
	loops      sync.WaitGroup

	// Control-plane-managed runtime state. The config file supplies the
	// STARTING value for each of these; the platform owns them from the first
	// heartbeat onwards.
	applier       *desiredstate.Applier
	pollEvery     *interval
	beatEvery     *interval
	hostInventory *hostInventorySupervisor

	// collector is the host-inventory collection step. Nil means the real one;
	// it is a field only so a test can drive the REAL supervisor and the REAL
	// heartbeat wiring without walking the test machine's package database,
	// which takes seconds and reports whatever host the suite runs on.
	collector hostInventoryCollector
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
		// hostInventoryOnce is a SUPPORT flag: collect this host once, print
		// the report as JSON, exit. It reaches no network and needs no
		// enrollment, so an operator can review the ordinary host report before
		// enabling the schedule. Privacy-sensitive outbound peers are excluded
		// from this preview. The report is secrets-free by construction — see
		// shared/hostinventory.
		hostInventoryOnce = flag.Bool("host-inventory-once", false,
			"Collect this host's inventory once, print it as JSON, and exit. Sends nothing to the platform.")
	)
	flag.Parse()

	if *hostInventoryOnce {
		os.Exit(runHostInventoryOnce())
	}

	// Show version and exit
	if *version {
		fmt.Printf("Vista Platform Device Agent v%s\n", Version)
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

	log.Printf("🚀 Starting Vista Platform Device Agent v%s", Version)
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

	// Load configuration. A config file that exists but cannot be parsed is
	// fatal: falling back to defaults would start the agent against the wrong
	// platform with no identity while reporting success.
	if configPath != "" {
		log.Printf("📁 Loading configuration from file: %s", configPath)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Printf("❌ %v", err)
		exitProcess(exitNeedsOperator)
		return
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
		// Where the agent ID is kept. Without -config it used to be kept
		// nowhere, so the next start registered again with a spent key.
		savePath := *configFile
		if savePath == "" {
			savePath = filepath.Join(cfg.DataPath, "agent-config.yaml")
		}
		// Before anything is sent: an enrollment this process cannot save is
		// a spent key and an identity nobody holds (enrollment.go).
		if err := checkEnrollmentWritable(cfg.DataPath, savePath); err != nil {
			log.Printf("❌ %s", enrollmentUnwritableMessage(err, cfg.DataPath))
			exitProcess(exitNeedsOperator)
			return
		}
		log.Println("📝 Registering agent with platform...")
		if err := apiClient.Register(Version); err != nil {
			logRegistrationFailure(err)
			exitProcess(registrationFailureExitCode(err))
			return
		}
		log.Println("✅ Agent registered successfully")

		if err := saveCertificates(cfg); err != nil {
			log.Fatalf("❌ %s", enrollmentLostMessage(cfg.AgentID, err))
		}
		log.Printf("✅ Certificates saved to: %s/certs", cfg.DataPath)

		// Save config file with agent ID and certificate paths
		if err := saveConfigFile(savePath, cfg); err != nil {
			log.Fatalf("❌ %s", enrollmentLostMessage(cfg.AgentID, err))
		}
		log.Printf("💾 Configuration saved to: %s", savePath)

		return
	}

	// Sensor-style bootstrap: registration key present but no enrolled agent yet
	if cfg.RegistrationKey != "" && cfg.AgentID == "" {
		if configPath == "" {
			configPath = filepath.Join(cfg.DataPath, "agent-config.yaml")
		}
		if err := checkEnrollmentWritable(cfg.DataPath, configPath); err != nil {
			log.Printf("❌ %s", enrollmentUnwritableMessage(err, cfg.DataPath))
			exitProcess(exitNeedsOperator)
			return
		}
		log.Println("📝 Registration key set without agent_id — registering with control plane...")
		if err := apiClient.Register(Version); err != nil {
			// Exit rather than run unenrolled: an agent with no identity can
			// poll for nothing, and it never tried again. Under a service
			// manager the restart IS the retry; a rejected key is reported
			// as such, and the installers stop the service on it.
			logRegistrationFailure(err)
			exitProcess(registrationFailureExitCode(err))
			return
		}
		log.Println("✅ Agent enrolled successfully")
		if err := saveCertificates(cfg); err != nil {
			log.Fatalf("❌ %s", enrollmentLostMessage(cfg.AgentID, err))
		}
		log.Printf("✅ Certificates saved to: %s/certs", cfg.DataPath)
		if err := saveConfigFile(configPath, cfg); err != nil {
			log.Fatalf("❌ %s", enrollmentLostMessage(cfg.AgentID, err))
		}
		log.Printf("💾 Configuration saved to: %s", configPath)
	}

	runAgent(cfg, configPath, apiClient)
}

// runAgent wires up the agent and runs it until the process is signalled. It is
// the single run path: both the config-file start and the interactive installer
// end here, so a freshly-configured agent behaves exactly like a restarted one.
// apiClient may be nil, in which case one is built from cfg.
func runAgent(cfg *config.Config, configPath string, apiClient *api.OutboundClient) {
	agent := newDeviceAgent(cfg, configPath, apiClient)

	// Start agent
	if err := agent.Start(); err != nil {
		log.Fatalf("❌ Failed to start agent: %v", err)
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	signal.Stop(quit)

	log.Println("🛑 Shutting down device agent...")
	agent.Stop()
	log.Println("✅ Device agent stopped")
}

// newDeviceAgent builds a fully wired agent, ready to Start.
//
// Separate from runAgent so the wiring is reachable without the signal wait —
// and so it is wiring a test can drive rather than approximate. Every previous
// bug in this area was a missing CALL, not a broken function: a heartbeat that
// never carried the report, an applier never handed to the client. A test that
// builds its own plumbing cannot see any of them.
func newDeviceAgent(cfg *config.Config, configPath string, apiClient *api.OutboundClient) *DeviceAgent {
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

	// Control-plane-managed settings. The file values seed the runtime
	// state; from the first heartbeat the platform owns them, and a local edit
	// to a managed setting is overwritten on the next beat. That is the
	// intended behaviour, not a side effect: the console has to be the one
	// place an operator looks.
	agent.applier = desiredstate.New()
	desiredstate.SetAgentVersion(Version)
	agent.pollEvery = newInterval(cfg.PollInterval)
	agent.beatEvery = newInterval(cfg.HeartbeatInterval)
	agent.hostInventory = newHostInventorySupervisor(cfg.HostInventoryInterval, agent.collectHostInventory)
	registerManagedSettings(agent.applier, agent.hostInventory, agent.pollEvery, agent.beatEvery, func(on bool) {
		setVerboseLogging(on)
	})
	// What the file says this agent is running, told to the platform on every
	// beat. Without it the platform has nothing to go on for a device it has
	// never been configured for, resolves the built-in defaults, and the first
	// answer turns off whatever the file turned on.
	agent.applier.SetLocal(localValues(cfg))
	apiClient.SetConfigApplier(agent.applier)
	apiClient.SetRestartHandler(newRestartCoordinator(time.Now(), exitForRestart).onRequest)

	return agent
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
		a.goLoop(a.monitorCertificateRotation)
	}

	// Start job polling loop
	a.goLoop(a.pollForJobs)

	// Start heartbeat loop. Without it device_agents.last_heartbeat never moves
	// after registration: the agent is invisible to the platform's liveness
	// view, and a genuinely dead agent raises no discovery_agent_offline alert
	// because that detector excludes rows whose last_heartbeat is NULL.
	a.goLoop(a.sendHeartbeats)

	// Start the LOCAL host-inventory schedule, when the operator has turned it
	// on. It is not a job: the agent describes the host it is installed on, on
	// its own cadence, with no credentials and nothing for the platform to have
	// queued (asset-inventory ADR-0004 D3).
	//
	// Started through the supervisor so the control plane can turn it on and
	// off later; the file value is only the STARTING position.
	if a.config.HostInventoryEnabled {
		log.Printf("🖥️  Local host inventory enabled, every %v", a.config.HostInventoryInterval)
		if err := a.hostInventory.setEnabled(true); err != nil {
			log.Printf("⚠️  Could not start host inventory: %v", err)
		}
	}

	return nil
}

// collectHostInventory runs the local collection on start and then on the
// configured interval.
//
// On start as well as on the interval, because an agent that is restarted daily
// — a container, a laptop — would otherwise never reach its first tick and the
// feature would appear to do nothing.
func (a *DeviceAgent) collectHostInventory(iv *interval, stop <-chan struct{}) {
	if a.collector != nil {
		// Only a test sets one. Spelled as an early return rather than a
		// default, so the production path below stays the exact call it was.
		runLocalHostInventoryLoopWith(a.apiClient, a.config.AgentID, iv, stop, a.collector, productionHostInventoryFloor)
		return
	}
	collect := a.configuredHostInventoryCollector(devices.CollectLocalHostInventoryWithConnections)
	runLocalHostInventoryLoopWith(a.apiClient, a.config.AgentID, iv, stop, collect, productionHostInventoryFloor)
}

// configuredHostInventoryCollector is the production privacy boundary between
// local configuration and socket collection. Keeping that handoff in one small
// method lets a test prove both polarities without walking the test host's
// network stack or replacing the whole collection loop.
func (a *DeviceAgent) configuredHostInventoryCollector(collect hostInventoryConnectionCollector) hostInventoryCollector {
	return func(ctx context.Context, agentID string) (*hostinventory.Report, *di.InterrogateResult, error) {
		return collect(ctx, agentID, a.config.HostInventoryConnectionsEnabled)
	}
}

// hostInventorySubmitter is the slice of the API client the local loop needs,
// so the loop can be tested without a platform.
type hostInventorySubmitter interface {
	SubmitHostInventory(report *hostinventory.Report, observations *di.InterrogateResult) error
}

// runLocalHostInventoryLoop collects immediately, then on the interval, until
// stop closes.
//
// A failed collection or a failed submission is logged and retried on the next
// tick. It must not end the loop for the lifetime of the process: a transient
// network blip, or one boot where `ss` was momentarily unavailable, would
// otherwise silently stop host inventory forever on that host — the same
// reasoning as the heartbeat loop's.
func runLocalHostInventoryLoop(submitter hostInventorySubmitter, agentID string, every *interval, stop <-chan struct{}) {
	runLocalHostInventoryLoopWith(submitter, agentID, every, stop, devices.CollectLocalHostInventory, productionHostInventoryFloor)
}

// hostInventoryCollector is the collection step, injectable so the loop's
// TIMING can be tested without walking the test machine's package database.
// The real collector takes seconds and reports whatever host the suite happens
// to run on, which makes a timing assertion both slow and dependent on the
// runner.
type hostInventoryCollector func(ctx context.Context, agentID string) (*hostinventory.Report, *di.InterrogateResult, error)

type hostInventoryConnectionCollector func(ctx context.Context, agentID string, collectConnections bool) (*hostinventory.Report, *di.InterrogateResult, error)

// hostInventoryFloor is config.MinHostInventoryInterval, indirected only so a
// test can drive the REAL loop's timing in milliseconds. Production never
// changes it.
//
// The seam exists because the alternative was worse: with a one-hour floor, a
// behavioural test of "a pushed cadence wakes this loop" would have to wait an
// hour, so it would be written against a stub instead — and a stub is exactly
// what let the loop ship ignoring the interval while a test called
// "picks up a new cadence" passed.
//
// Passed per call rather than held in a package variable. A global seam is
// shared with every other test in the package and with goroutines from earlier
// ones still draining: the first version raced its own Cleanup, which the race
// detector caught, and making it atomic fixed the race while leaving the
// ordering correct only by luck. A parameter is correct by construction.
const productionHostInventoryFloor = config.MinHostInventoryInterval

func runLocalHostInventoryLoopWith(submitter hostInventorySubmitter, agentID string, every *interval, stop <-chan struct{}, collectFn hostInventoryCollector, floor time.Duration) {
	if submitter == nil {
		return
	}
	if every == nil {
		every = newInterval(config.DefaultHostInventoryInterval)
	}
	// The cadence is re-read before every wait, so a change pushed from the
	// control plane lands on the next cycle. The floor is applied HERE too,
	// not only at the platform: an older platform, or a hand-made request,
	// must not be able to make a customer's host walk its package database
	// every minute.
	currentInterval := func() time.Duration {
		d := every.get()
		if d < floor {
			d = floor
		}
		return d
	}

	collect := func() {
		ctx, cancel := context.WithTimeout(context.Background(), hostInventoryCollectTimeout)
		defer cancel()

		report, observations, err := collectFn(ctx, agentID)
		if err != nil {
			log.Printf("⚠️  Host inventory collection failed: %v", err)
			return
		}
		if err := submitter.SubmitHostInventory(report, observations); err != nil {
			log.Print(hostInventorySubmitFailure(err, currentInterval()))
			return
		}
		// Say what was learned AND what was not: a report with three failed
		// sections that logs "collected" reads as a success it is not.
		log.Printf("🖥️  Host inventory submitted: %s, %d packages, %d listeners, %d interfaces%s",
			report.Platform, len(report.Packages), len(report.Listeners), len(report.Interfaces),
			failedSectionSuffix(report))
	}

	collect()

	// Jittered timer rather than a fixed ticker.
	//
	// A ticker keeps a fleet in whatever phase it started in, forever. Agents
	// on a customer estate are rolled out and upgraded in batches, so "whatever
	// phase it started in" is commonly the same minute for hundreds of hosts —
	// and each one then walks its whole package database and posts a report
	// bounded at 16 MiB, at that minute, every day. Jitter spreads them and
	// keeps them spread, because each wait is drawn afresh.
	//
	// It is ADDED, never subtracted: the floor is a safety bound on how often a
	// customer's host is made to do this work, and jitter must not be a way
	// under it.
	//
	// The loop is also strictly sequential — collect() returns before the next
	// wait begins — so two collections can never overlap on one host, however
	// long one of them takes.
	// Waited through waitCycle, NOT a private timer, so a cadence pushed from
	// the control plane wakes this loop instead of landing after the wait
	// already in flight. With intervals allowed up to 30 days, a private timer
	// meant shortening 30 days to an hour could take 30 days to take effect —
	// on the headline setting of the feature that pushes it.
	//
	// The jitter is applied inside waitCycle via the shape function, so it is
	// still drawn afresh each cycle and still only ever ADDS to the interval.
	for waitCycle(every, stop, func(d time.Duration) time.Duration {
		if d < floor {
			d = floor
		}
		return jitteredInterval(d)
	}) {
		collect()
	}
}

// hostInventorySubmitFailure is the log line for a failed submission.
//
// Split out so both branches are testable — the distinction between them is the
// whole point, and a distinction that lives only inside a log call in a
// goroutine is one nothing can check.
//
// An over-cap report is NOT a transient failure. Every other submission error
// is worth trying again and this one is not: the same host produces the same
// size on the next run, so the line says so plainly and names the measured
// size, rather than leaving an operator to infer it from a report that never
// arrives. The loop retries neither — it returns and waits for the next
// scheduled collection either way — but only one of them is worth an operator's
// attention today.
func hostInventorySubmitFailure(err error, interval time.Duration) string {
	var tooLarge *api.ReportTooLargeError
	if errors.As(err, &tooLarge) {
		return fmt.Sprintf("⚠️  Host inventory NOT submitted — report too large: %d bytes exceeds the platform's cap. "+
			"This will not fix itself: the next collection (in ~%v) will be the same size. "+
			"Reduce what is collected or raise the platform's cap. Platform said: %s",
			tooLarge.Bytes, interval, tooLarge.Detail)
	}
	return fmt.Sprintf("⚠️  Host inventory submission failed (retrying at the next scheduled collection, in ~%v): %v", interval, err)
}

// hostInventoryJitterFraction is how much may be added to an interval: at most
// a tenth, so a 24-hour cadence spreads a fleet over ~2.4 hours while staying
// recognisably daily.
const hostInventoryJitterFraction = 10

// jitteredInterval returns interval plus a random fraction of it, up to
// 1/hostInventoryJitterFraction.
//
// Never less than interval — see the caller. math/rand/v2 is the right
// generator here: this is scheduling, not a secret, and a crypto/rand failure
// mode inside a scheduling loop would be a new way for host inventory to stop.
func jitteredInterval(interval time.Duration) time.Duration {
	if interval <= 0 {
		return interval
	}
	span := interval / hostInventoryJitterFraction
	if span <= 0 {
		return interval
	}
	return interval + time.Duration(rand.Int64N(int64(span)))
}

// failedSectionSuffix names the sections that did not complete, so the log line
// cannot report a partial collection as a whole one.
func failedSectionSuffix(report *hostinventory.Report) string {
	var failed []string
	for section, state := range report.Sections {
		if state == hostinventory.SectionFailed {
			failed = append(failed, section)
		}
	}
	if len(failed) == 0 {
		return ""
	}
	sort.Strings(failed)
	return " (failed: " + strings.Join(failed, ", ") + ")"
}

// hostInventoryCollectTimeout bounds one local collection.
const hostInventoryCollectTimeout = 10 * time.Minute

// runHostInventoryOnce implements --host-inventory-once: collect, print, exit.
//
// It reads no configuration and opens no connection, so it works on a host that
// has never been enrolled — which is the point, since the question it answers is
// "what would this agent send if I turned host inventory on?". The report it
// prints is the same object the scheduler submits.
func runHostInventoryOnce() int {
	ctx, cancel := context.WithTimeout(context.Background(), hostInventoryCollectTimeout)
	defer cancel()

	report, observations, err := devices.CollectLocalHostInventory(ctx, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "host inventory failed: %v\n", err)
		return 1
	}

	out := map[string]any{"report": report, "observations": observations}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "could not render the report: %v\n", err)
		return 1
	}
	// A collection with failed sections is a partial answer, and exiting 0 for
	// it would tell a script everything was fine. The report is still printed —
	// a partial inventory is worth reading.
	if failedSectionSuffix(report) != "" {
		fmt.Fprintf(os.Stderr, "note: some sections did not complete%s\n", failedSectionSuffix(report))
		return 2
	}
	return 0
}

// shutdownGrace bounds how long Stop waits for the loops, and so for a job in
// flight to finish and submit its result, before the process exits anyway.
const shutdownGrace = 30 * time.Second

// context returns the agent's lifetime context, creating it on first use.
func (a *DeviceAgent) context() context.Context {
	a.lifeMu.Lock()
	defer a.lifeMu.Unlock()
	if a.lifeCtx == nil {
		a.lifeCtx, a.lifeCancel = context.WithCancel(context.Background())
	}
	return a.lifeCtx
}

// goLoop runs fn as one of the agent's loops, tracked so Stop can wait for it.
func (a *DeviceAgent) goLoop(fn func()) {
	a.loops.Add(1)
	go func() {
		defer a.loops.Done()
		fn()
	}()
}

// Stop stops the device agent: it cancels every loop, then waits up to
// shutdownGrace for a job already running to finish and submit its result.
func (a *DeviceAgent) Stop() {
	a.context() // make sure there is something to cancel
	a.lifeMu.Lock()
	cancel := a.lifeCancel
	a.lifeMu.Unlock()
	cancel()

	if a.hostInventory != nil {
		if err := a.hostInventory.setEnabled(false); err != nil {
			log.Printf("⚠️  Could not stop host inventory: %v", err)
		}
	}

	if !waitTimeout(&a.loops, shutdownGrace) {
		log.Printf("⚠️  Shutdown timed out after %v with a job still running; its result may be lost", shutdownGrace)
	}

	if a.auditLogger != nil {
		// Close on a file being WRITTEN can surface a lost final write.
		if err := a.auditLogger.Close(); err != nil {
			log.Printf("⚠️  Failed to close audit log %s: %v", a.auditLogger.GetPath(), err)
		}
	}
}

// waitTimeout waits for wg, reporting false if d elapsed first.
func waitTimeout(wg *sync.WaitGroup, d time.Duration) bool {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// pollForJobs continuously polls for jobs from the platform until the agent is
// stopped.
//
// The interval is re-read every tick rather than fixed at startup, so a change
// pushed from the control plane takes effect without a restart.
func (a *DeviceAgent) pollForJobs() {
	everyInterval(a.pollEvery, a.context().Done(), a.executeJobPoll)
}

// heartbeatSender is the slice of the API client the heartbeat loop needs, so
// the loop can be tested without a platform.
type heartbeatSender interface {
	SendHeartbeat() error
}

// sendHeartbeats reports liveness to the platform on the configured interval,
// re-read every beat so the control plane can change it live.
func (a *DeviceAgent) sendHeartbeats() {
	if a.apiClient == nil {
		runHeartbeatLoop(nil, a.beatEvery, a.context().Done())
		return
	}
	runHeartbeatLoop(retryingSender{heartbeatSender: a.apiClient, before: a.retryUnpersistedCredentials}, a.beatEvery, a.context().Done())
}

// retryingSender runs before ahead of every beat.
type retryingSender struct {
	heartbeatSender
	before func()
}

func (r retryingSender) SendHeartbeat() error {
	r.before()
	return r.heartbeatSender.SendHeartbeat()
}

// runHeartbeatLoop beats immediately, then on the interval, until stop closes.
// A failed beat is logged and retried on the next tick — a transient network
// blip must not silently end the agent's liveness reporting for the lifetime of
// the process.
func runHeartbeatLoop(sender heartbeatSender, every *interval, stop <-chan struct{}) {
	if sender == nil {
		return
	}
	if every == nil {
		every = newInterval(config.DefaultHeartbeatInterval)
	}
	everyInterval(every, stop, func() {
		if err := sender.SendHeartbeat(); err != nil {
			log.Printf("⚠️  Heartbeat failed: %v", err)
		}
	})
}

func (a *DeviceAgent) monitorCertificateRotation() {
	a.checkAndRotateCertificate()

	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-a.context().Done():
			return
		case <-ticker.C:
			a.checkAndRotateCertificate()
		}
	}
}

// Persisting a rotated certificate is retried a few times before the agent
// gives up and holds it in memory only. Variables so tests do not sleep.
var (
	rotationPersistAttempts = 3
	rotationPersistDelay    = time.Second
)

func (a *DeviceAgent) persistCredentials() error {
	if err := saveCertificates(a.config); err != nil {
		return fmt.Errorf("certificates: %w", err)
	}
	if a.configPath == "" {
		return fmt.Errorf("config file: no config file path set")
	}
	if err := saveConfigFile(a.configPath, a.config); err != nil {
		return fmt.Errorf("config file: %w", err)
	}
	return nil
}

func (a *DeviceAgent) checkAndRotateCertificate() {
	checkAndRotateAgentCertificate(a.apiClient, a.config, a.persistCredentials, &a.unpersistedCredentials)
	a.pruneAgentSecrets()
}

// pruneAgentSecrets stops keeping the previous agent secret once its window has
// passed (agentcreds.PreviousSecretWindow): in memory it is already ignored, and
// this rewrites the secret file so a replaced secret does not outlive its use on
// disk. Best effort; the next daily check tries again.
func (a *DeviceAgent) pruneAgentSecrets() {
	if !a.config.PruneAgentSecrets(time.Now()) {
		return
	}
	if err := a.persistCredentials(); err != nil {
		log.Printf("⚠️  Could not drop the expired previous agent secret from disk: %v", err)
	}
}

// retryUnpersistedCredentials runs on every heartbeat. While a rotated
// certificate has not reached disk it says so at error level and tries again.
func (a *DeviceAgent) retryUnpersistedCredentials() {
	pending := a.unpersistedCredentials.Err()
	if pending == nil {
		return
	}
	if err := a.persistCredentials(); err != nil {
		a.unpersistedCredentials.Set(err)
		log.Printf("❌ Rotated certificate is still NOT saved to disk (%v) — a restart now would lock this agent out", err)
		return
	}
	a.unpersistedCredentials.Clear()
	log.Printf("✅ Rotated certificate is now saved to disk (earlier failure: %v)", pending)
}

// checkAndRotateAgentCertificate rotates the client certificate when it is
// close to expiry and persists the result. It returns true when the platform
// rotated the certificate, whether or not the new one reached disk.
//
// The platform revokes the old certificate as part of rotation, so persisting
// is not optional: when it fails after retries the new material stays in
// memory, pending records why, and the failure is re-reported on every
// heartbeat. "rotated successfully" is only logged once it is on disk.
func checkAndRotateAgentCertificate(rotator certificateRotator, cfg *config.Config, persist func() error, pending *atomicfile.Pending) bool {
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

	if persist != nil {
		if err := atomicfile.Retry(rotationPersistAttempts, rotationPersistDelay, persist); err != nil {
			if pending != nil {
				pending.Set(err)
			}
			log.Printf("❌ Certificate rotated on the platform but the new certificate could NOT be saved: %v", err)
			log.Printf("❌ The previous certificate is revoked. The agent keeps working on the new one in memory, but a restart before it is saved will lock this agent out. Retrying on every heartbeat; fix the permissions or free space on %s.", cfg.DataPath)
			return true
		}
	}
	if pending != nil {
		pending.Clear()
	}

	log.Println("✅ Certificate rotated successfully")
	return true
}

// executeJobPoll polls for a job and executes it if available.
//
// The job runs on a context detached from the agent's lifetime: a SIGTERM stops
// the loops from taking NEW work but must not abort the interrogation already
// running, whose result Stop waits for. The job's own timeout still bounds it.
func (a *DeviceAgent) executeJobPoll() {
	if a.context().Err() != nil {
		return
	}
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
	if err := a.jobExecutor.Execute(context.WithoutCancel(a.context()), job); err != nil {
		log.Printf("❌ Error executing job %s: %v", job.ID, err)
		// Report error back to platform (redacted, with retries)
		if err := a.jobExecutor.ReportError(job.ID, err.Error()); err != nil {
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

// persistedConfig is exactly what the agent records about itself. It is a
// separate struct from config.Config on purpose: Config also carries the PEM
// certificate, key and CA, which belong in the certs directory (0600 key file),
// never in the config file. Every other Config field is listed here.
type persistedConfig struct {
	AgentID                         string         `yaml:"agent_id"`
	PlatformURL                     string         `yaml:"platform_url"`
	RegistrationKey                 string         `yaml:"registration_key,omitempty"`
	RegistrationKeySHA256           string         `yaml:"registration_key_sha256,omitempty"`
	PollInterval                    time.Duration  `yaml:"poll_interval"`
	HeartbeatInterval               time.Duration  `yaml:"heartbeat_interval,omitempty"`
	DataPath                        string         `yaml:"data_path"`
	Verbose                         *bool          `yaml:"verbose,omitempty"`
	HostInventoryEnabled            bool           `yaml:"host_inventory_enabled,omitempty"`
	HostInventoryInterval           time.Duration  `yaml:"host_inventory_interval,omitempty"`
	HostInventoryConnectionsEnabled bool           `yaml:"host_inventory_connections_enabled,omitempty"`
	Security                        *persistedSecu `yaml:"security,omitempty"`
}

type persistedSecu struct {
	ClientCertPath   string `yaml:"client_cert_path"`
	ClientKeyPath    string `yaml:"client_key_path"`
	ServerCACertPath string `yaml:"server_ca_cert_path"`
	AgentSecretPath  string `yaml:"agent_secret_path,omitempty"`
	UseTLS           bool   `yaml:"use_tls"`
}

func newPersistedConfig(cfg *config.Config) persistedConfig {
	p := persistedConfig{
		AgentID:                         cfg.AgentID,
		PlatformURL:                     cfg.PlatformURL,
		PollInterval:                    cfg.PollInterval,
		HeartbeatInterval:               cfg.HeartbeatInterval,
		DataPath:                        cfg.DataPath,
		Verbose:                         cfg.Verbose,
		HostInventoryEnabled:            cfg.HostInventoryEnabled,
		HostInventoryConnectionsEnabled: cfg.HostInventoryConnectionsEnabled,
	}
	// The registration key is single use and spent at enrolment. Once the agent
	// secret that replaced it as the credential-key root is safely on disk
	// (Security.AgentSecretPath is only set after the atomic write succeeded) the
	// key is NOT written any more: a fingerprint stands in for it so the
	// installer can still tell "already enrolled with this key". Until then — an
	// older platform that issued no secret, or a failed save — it stays, because
	// it is still what opens the platform's envelopes.
	if cfg.RegistrationKeyRetained() {
		p.RegistrationKey = cfg.RegistrationKey
	} else {
		p.RegistrationKeySHA256 = cfg.RegistrationKeyFingerprint()
	}
	// The interval only means something once local host inventory is on.
	if cfg.HostInventoryEnabled {
		p.HostInventoryInterval = cfg.HostInventoryInterval
	}
	if cfg.Security.ClientCertPath != "" {
		p.Security = &persistedSecu{
			ClientCertPath:   cfg.Security.ClientCertPath,
			ClientKeyPath:    cfg.Security.ClientKeyPath,
			ServerCACertPath: cfg.Security.ServerCACertPath,
			AgentSecretPath:  cfg.Security.AgentSecretPath,
			UseTLS:           true,
		}
	}
	return p
}

// saveConfigFile updates the config file with the agent ID and certificate
// paths. It marshals with the yaml library (so values holding '#', ': ' or
// quotes round-trip) and merges into the existing document, so comments and
// keys this build does not know about survive a rewrite. The file is replaced
// atomically.
func saveConfigFile(configPath string, cfg *config.Config) error {
	// Ensure directory exists
	dir := filepath.Dir(configPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	var desired yaml.Node
	if err := desired.Encode(newPersistedConfig(cfg)); err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}
	quoteStrings(&desired)

	root := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	doc := &yaml.Node{
		Kind:        yaml.DocumentNode,
		Content:     []*yaml.Node{root},
		HeadComment: "Vista Platform Device Agent Configuration\nGenerated after registration",
	}
	if existing, err := os.ReadFile(configPath); err == nil {
		var parsed yaml.Node
		if yerr := yaml.Unmarshal(existing, &parsed); yerr == nil && parsed.Kind == yaml.DocumentNode &&
			len(parsed.Content) == 1 && parsed.Content[0].Kind == yaml.MappingNode {
			doc = &parsed
			root = parsed.Content[0]
		}
	}
	mergeMapping(root, &desired)
	// A managed key the agent no longer sets (verbose back to unset, host
	// inventory turned off) must not linger from the previous write.
	for _, key := range managedConfigKeys {
		if !hasKey(&desired, key) {
			removeKey(root, key)
		}
	}

	out, err := yaml.Marshal(doc)
	if err != nil {
		return fmt.Errorf("failed to encode config: %w", err)
	}
	if err := writeSecretConfigFile(configPath, out); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

// managedConfigKeys are the top-level keys persistedConfig can write.
var managedConfigKeys = []string{
	"agent_id", "platform_url", "registration_key", "registration_key_sha256", "poll_interval", "heartbeat_interval",
	"data_path", "verbose", "host_inventory_enabled", "host_inventory_interval",
	"host_inventory_connections_enabled", "security",
}

func hasKey(m *yaml.Node, key string) bool {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return true
		}
	}
	return false
}

func removeKey(m *yaml.Node, key string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

// quoteStrings double-quotes every string scalar value, so no value can be
// read back as anything but the string that was written. Mapping keys are left
// bare.
func quoteStrings(n *yaml.Node) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			quoteStrings(n.Content[i])
		}
	case yaml.SequenceNode, yaml.DocumentNode:
		for _, c := range n.Content {
			quoteStrings(c)
		}
	case yaml.ScalarNode:
		if n.Tag == "!!str" {
			n.Style = yaml.DoubleQuotedStyle
		}
	}
}

// mergeMapping sets every key of src into dst: an existing key keeps its
// position and comments but takes the new value; a new key is appended.
func mergeMapping(dst, src *yaml.Node) {
	for i := 0; i+1 < len(src.Content); i += 2 {
		key, val := src.Content[i], src.Content[i+1]
		found := false
		for j := 0; j+1 < len(dst.Content); j += 2 {
			if dst.Content[j].Value != key.Value {
				continue
			}
			found = true
			cur := dst.Content[j+1]
			if cur.Kind == yaml.MappingNode && val.Kind == yaml.MappingNode {
				mergeMapping(cur, val)
			} else {
				val.HeadComment, val.LineComment, val.FootComment = cur.HeadComment, cur.LineComment, cur.FootComment
				dst.Content[j+1] = val
			}
			break
		}
		if !found {
			dst.Content = append(dst.Content, key, val)
		}
	}
}

// writeSecretConfigFile writes an agent configuration file owner-only.
//
// Until the agent holds an agent secret the file carries `registration_key:` in
// plaintext, and that key is then the agentSecret input to agentcreds.DeriveKey —
// the AES key that unwraps every credential envelope the platform hands this
// agent (F5, Cisco, Fortinet, Palo Alto and UniFi administrator passwords). At
// 0644 any unprivileged local user on the agent host could read the key and
// decrypt them. The adjacent client private key has always been written 0600;
// this matches it. Once the platform has issued an agent secret the key
// is no longer written at all.
//
// The write is atomic (temp file in the same directory, then rename) so a crash
// never leaves a truncated config, and the mode is set explicitly on every
// write so an upgrade over a config an older build left world-readable is
// tightened.
func writeSecretConfigFile(path string, data []byte) error {
	return atomicfile.Write(path, data, 0o600)
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

	fmt.Println("🔧 Vista Platform Device Agent - Interactive Configuration")
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

	configPath := filepath.Join(cfg.DataPath, "agent-config.yaml")
	if err := checkEnrollmentWritable(cfg.DataPath, configPath); err != nil {
		return nil, "", nil, fmt.Errorf("%s", enrollmentUnwritableMessage(err, cfg.DataPath))
	}

	// Create API client and register
	apiClient := api.NewOutboundClient(cfg)
	apiClient.SetAgentVersion(Version)

	log.Println("📝 Registering with platform...")
	if err := apiClient.Register(Version); err != nil {
		logRegistrationFailure(err)
		return nil, "", nil, fmt.Errorf("registration failed: %w", err)
	}
	log.Println("✅ Agent registered successfully")

	if err := saveCertificates(cfg); err != nil {
		return nil, "", nil, fmt.Errorf("%s", enrollmentLostMessage(cfg.AgentID, err))
	}
	log.Printf("✅ Certificates saved to: %s/certs", cfg.DataPath)
	if err := saveConfigFile(configPath, cfg); err != nil {
		return nil, "", nil, fmt.Errorf("%s", enrollmentLostMessage(cfg.AgentID, err))
	}
	log.Printf("💾 Configuration saved to: %s", configPath)

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
