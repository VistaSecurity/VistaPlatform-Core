package discovery

// The server-side definition of a scan ( WP3): how deep to look, at which
// ports, how fast, from where — and, per target, what the server actually
// allowed. POST /discovery/jobs accepts these fields; cluster-sensor-service
// turns them into a ScanPlan, stores it on the job (metadata.scan_plan) and
// returns it on the create response and GET /discovery/jobs/{id}. The executor
// that reads it (work units, WP2) is not this file's concern.
//
// Two services read the request (inventory-service validates it so the person
// reads why; cluster-sensor-service decides), so the rules live here once and
// both call ResolveJobRequest. The plan JSON shape lives here once too, so the
// two services cannot disagree about it.
//
// THE PER-TARGET EXTERNAL CAP (owner decision D3) is a guardrail for targets
// nobody has claimed, not an access control. A target outside private address
// space and outside every network segment the tenant registered is scanned at
// Standard depth at most; a person with `settings.update` can register the
// range as theirs, after which it is internal and may be scanned deeper. That
// is intended ("we don't judge, we enable"). What the cap buys is that the
// platform's own address is not used to sweep all 65,535 ports of a third
// party's block on a click, and that a deeper scan of someone else's network
// leaves a paper trail: the segment registration (audited) and, on the job,
// the segment that granted ownership (PlanTarget.SegmentID).

import (
	"errors"
	"fmt"
	"log"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

// ScanDepth names how much of each target a scan looks at.
type ScanDepth string

const (
	// DepthQuick is the curated crypto and infrastructure TCP ports only
	// (QuickPorts).
	DepthQuick ScanDepth = "quick"
	// DepthStandard is the Standard TCP set (StandardPorts) plus the curated
	// UDP services. The default.
	DepthStandard ScanDepth = "standard"
	// DepthThorough is every TCP port plus the curated UDP services.
	DepthThorough ScanDepth = "thorough"
	// DepthCustom is exactly the TCP and UDP ports the request names.
	DepthCustom ScanDepth = "custom"
)

// Run-from choices: where a scan runs. Auto is the eligible tenant sensor
// when there is exactly one, else the platform (owner decision D7).
const (
	RunFromAuto     = "auto"
	RunFromPlatform = "platform"
	RunFromSensor   = "sensor"
)

// Executors a plan resolves to.
const (
	ExecutorPlatform = "platform"
	ExecutorSensor   = "sensor"
)

// TargetClass is what the target-authorization guard decided a target is.
type TargetClass string

const (
	// ClassPrivate: inside private address space (RFC 1918 / RFC 4193).
	ClassPrivate TargetClass = "private"
	// ClassRegisteredSegment: public space inside a network segment the tenant
	// registered (or claimed) as its own. PlanTarget.SegmentID names it.
	ClassRegisteredSegment TargetClass = "registered_segment"
	// ClassExternal: neither; scanned only on a person's confirmation, and at
	// Standard depth at most.
	ClassExternal TargetClass = "external"
)

// ScanPlanMetadataKey is where a job's plan lives in discovery_jobs.metadata.
// Server-written, beside `options` rather than inside it, because `options` is
// caller-supplied and a plan never is.
const ScanPlanMetadataKey = "scan_plan"

// CodeScanPlanUnavailable is the code of the 422 a scan-plan request got on a
// deployment whose plan execution was switched off. Nothing produces it since
// WP5 removed that switch with the legacy executors (the engine is the
// only executor); it stays because inventory-service relays the code, for an
// older cluster-sensor-service.
const CodeScanPlanUnavailable = "scan_plan_unavailable"

// ScanPlanUnavailableError refused a scan-plan request on a deployment whose
// plan execution was switched off. See CodeScanPlanUnavailable.
type ScanPlanUnavailableError struct{}

func (*ScanPlanUnavailableError) Error() string {
	return "scan depth is switched off on this deployment; use protocols and ports"
}

// CodeScanBudgetExceeded is the machine-readable code of the 422 a job gets
// when its estimated probe count is above the installation's budget.
const CodeScanBudgetExceeded = "scan_budget_exceeded"

// MaxExternalCustomTCPPorts is the most TCP ports a custom scan may probe on a
// target outside the registered networks — on the order of Standard's 1,364.
const MaxExternalCustomTCPPorts = 1024

// Probe budget (hole H19).
//
// estimated probes = Σ over targets (addresses × (TCP ports + UDP ports)).
//
// The default admits the two shapes the product is for and refuses the next
// step up:
//
//   - Thorough on one /24: 256 × (65,535 + 11) ≈ 16.8 M probes;
//   - Standard on the largest job the target-size limit admits: 16,384
//     addresses × (1,364 + 11) ≈ 22.5 M;
//   - Thorough on a /23 (≈ 33.6 M) is refused: split it.
//
// The shared engine measured ≈ 33.6 k ports/s at the normal pace on loopback
//so 25 M is ≈ 12 minutes in the best case; on a network where most
// ports are filtered it is hours, which is why a job of that size needs work
// units (WP2) and why this is a budget rather than a guess at duration.
const (
	EnvMaxJobProbes            = "DISCOVERY_MAX_JOB_PROBES"
	DefaultMaxJobProbes uint64 = 25_000_000
	// MaxJobProbesCeiling is the largest estimate any job can have — every
	// address a job may name, every TCP and every UDP port — so a knob above
	// it would mean nothing.
	MaxJobProbesCeiling uint64 = MaxJobAddresses * 2 * 65535
)

// MaxJobProbesFromEnv reads the installation's probe budget. It is read in one
// place (cluster-sensor-service's job creation) and FAILS CLOSED: an unset
// value is the default; a value that is not a whole number between 1 and
// MaxJobProbesCeiling is the default too, and says so in the log — never
// "unlimited", never "nothing".
func MaxJobProbesFromEnv() uint64 {
	raw := strings.TrimSpace(os.Getenv(EnvMaxJobProbes))
	if raw == "" {
		return DefaultMaxJobProbes
	}
	n, err := strconv.ParseUint(raw, 10, 64)
	if err != nil || n < 1 || n > MaxJobProbesCeiling {
		log.Printf("[discovery] %s=%q is not a whole number between 1 and %d; using %d", EnvMaxJobProbes, raw, MaxJobProbesCeiling, DefaultMaxJobProbes)
		return DefaultMaxJobProbes
	}
	return n
}

// CuratedUDPScanPorts is the UDP set of the Standard and Thorough depths, and
// the most a target outside the registered networks is probed on over UDP:
// the shared engine's per-service UDP probe set (CuratedUDPPorts — DNS, NTP,
// SNMP, QUIC/DTLS, IKE, OpenVPN, SSDP, mDNS), one source for both, so the plan
// can never name a UDP port the engine has no probe for. OT UDP ports are not
// in it; they need the OT opt-in.
func CuratedUDPScanPorts() PortSet {
	set, err := NewPortSet(CuratedUDPPorts()...)
	if err != nil {
		panic("discovery: bad curated UDP port: " + err.Error())
	}
	return set
}

// ScanSpec is a validated scan-plan request: what to look at and how fast.
type ScanSpec struct {
	Depth ScanDepth
	TCP   PortSet
	UDP   PortSet
	Pace  Pace
}

// ScanRequestError is a scan-plan request the server will not accept as
// written. It is the caller's to fix: services answer 400 validation_error
// with Error() as the details.
type ScanRequestError struct{ Message string }

func (e *ScanRequestError) Error() string { return e.Message }

func requestError(format string, args ...interface{}) error {
	return &ScanRequestError{Message: fmt.Sprintf(format, args...)}
}

// JobRequestFields is everything in a create-job request that decides its
// shape: the scan-plan fields and the legacy fields they replace.
type JobRequestFields struct {
	ScanDepth string
	TCPPorts  string
	UDPPorts  string
	Pace      string
	RunFrom   string
	SensorID  string

	Protocols          []string
	Ports              []int
	OTProbeProtocols   []string
	ExecutionMode      string
	PreferredSensorIDs []string

	// DryRun is the request's `dry_run`: preview the plan, create nothing.
	// Only a scan-plan request has a plan to preview.
	DryRun bool
}

func (f JobRequestFields) planFieldsPresent() []string {
	var out []string
	for _, kv := range [][2]string{
		{"scan_depth", f.ScanDepth}, {"tcp_ports", f.TCPPorts}, {"udp_ports", f.UDPPorts},
		{"pace", f.Pace}, {"run_from", f.RunFrom}, {"sensor_id", f.SensorID},
	} {
		if strings.TrimSpace(kv[1]) != "" {
			out = append(out, kv[0])
		}
	}
	return out
}

// JobRequestShape is what ResolveJobRequest decided.
type JobRequestShape struct {
	// Plan is true for the scan-plan path; false is the legacy
	// protocols × ports path, which behaves exactly as before.
	Plan    bool
	Spec    ScanSpec
	RunFrom string
	// SensorID is the tenant sensor named by run_from "sensor".
	SensorID string
}

// ResolveJobRequest decides which path a create-job request takes and
// validates the scan-plan half of it.
//
//   - protocols or ports present → the LEGACY shape. No scan-plan field may
//     accompany them.
//   - neither, and no scan-plan field, but ot_probe_protocols → legacy too: an
//     OT-only request.
//
// cluster-sensor-service translates a legacy-shaped request into a plan first
// (TranslateLegacyJobRequest, D2/WP5) and only creates the legacy shape
// for a tenant sensor that cannot run a plan; inventory-service calls this on
// the request as sent.
//   - otherwise the SCAN-PLAN path; scan_depth defaults to standard (owner
//     decision D4) and run_from to auto. Protocols are not requested on this
//     path: services are identified from what answers.
//
// execution_mode is the legacy spelling of run_from and is accepted on the
// scan-plan path as an alias (auto → auto; cloud, async → platform; sensors +
// one preferred_sensor_id → sensor) but never together with run_from.
//
// dry_run is only meaningful on the scan-plan path (the legacy path has no
// plan); on the legacy path it is refused, naming why.
func ResolveJobRequest(f JobRequestFields) (JobRequestShape, error) {
	planFields := f.planFieldsPresent()
	legacy := len(f.Protocols) > 0 || len(f.Ports) > 0
	noPlan := func() (JobRequestShape, error) {
		if f.DryRun {
			return JobRequestShape{}, requestError("dry_run previews a scan-depth request and this one names protocols/ports (or only OT probes), which has no plan to preview: send scan_depth (and tcp_ports/udp_ports for custom), or drop dry_run")
		}
		return JobRequestShape{}, nil
	}
	if legacy {
		if len(planFields) > 0 {
			return JobRequestShape{}, requestError("%s cannot be combined with protocols/ports: send scan_depth (and tcp_ports/udp_ports for custom) instead of protocols and ports, not both",
				strings.Join(planFields, ", "))
		}
		return noPlan()
	}
	if len(planFields) == 0 && len(f.OTProbeProtocols) > 0 {
		return noPlan()
	}

	spec, err := parseScanSpec(f.ScanDepth, f.TCPPorts, f.UDPPorts, f.Pace)
	if err != nil {
		return JobRequestShape{}, err
	}
	shape := JobRequestShape{Plan: true, Spec: spec}

	runFrom := strings.ToLower(strings.TrimSpace(f.RunFrom))
	mode := strings.ToLower(strings.TrimSpace(f.ExecutionMode))
	sensorID := strings.TrimSpace(f.SensorID)
	switch {
	case runFrom != "" && mode != "":
		return JobRequestShape{}, requestError("run_from and execution_mode cannot both be set: execution_mode is the legacy spelling of run_from; send run_from")
	case runFrom != "" && len(f.PreferredSensorIDs) > 0:
		return JobRequestShape{}, requestError("preferred_sensor_ids does not apply with run_from: name the sensor with sensor_id and run_from \"sensor\"")
	case runFrom == "":
		switch mode {
		case "", "auto":
			runFrom = RunFromAuto
		case "cloud", "async":
			runFrom = RunFromPlatform
		case "sensors":
			if len(f.PreferredSensorIDs) != 1 {
				return JobRequestShape{}, requestError("execution_mode \"sensors\" needs exactly one preferred_sensor_id — the tenant sensor to run from")
			}
			runFrom, sensorID = RunFromSensor, strings.TrimSpace(f.PreferredSensorIDs[0])
		default:
			return JobRequestShape{}, requestError("execution_mode %q is not one of auto, cloud, sensors; send run_from (auto, platform or sensor)", f.ExecutionMode)
		}
	}
	switch runFrom {
	case RunFromAuto, RunFromPlatform:
		if sensorID != "" {
			return JobRequestShape{}, requestError("sensor_id only applies to run_from \"sensor\"")
		}
	case RunFromSensor:
		if sensorID == "" {
			return JobRequestShape{}, requestError("run_from \"sensor\" needs a sensor_id — the tenant sensor to run from")
		}
		if _, err := uuid.Parse(sensorID); err != nil {
			return JobRequestShape{}, requestError("sensor_id %q is not a UUID", sensorID)
		}
	default:
		return JobRequestShape{}, requestError("run_from %q is not one of auto, platform, sensor", f.RunFrom)
	}
	shape.RunFrom, shape.SensorID = runFrom, sensorID
	return shape, nil
}

// parseScanSpec validates depth, ports and pace.
func parseScanSpec(depthRaw, tcpRaw, udpRaw, paceRaw string) (ScanSpec, error) {
	depth := ScanDepth(strings.ToLower(strings.TrimSpace(depthRaw)))
	if depth == "" {
		depth = DepthStandard
	}
	pace, err := ParsePace(paceRaw)
	if err != nil {
		return ScanSpec{}, requestError("pace: %v", err)
	}
	spec := ScanSpec{Depth: depth, Pace: pace}
	hasTCP, hasUDP := strings.TrimSpace(tcpRaw) != "", strings.TrimSpace(udpRaw) != ""

	switch depth {
	case DepthQuick, DepthStandard, DepthThorough:
		if hasTCP || hasUDP {
			return ScanSpec{}, requestError("tcp_ports and udp_ports apply only to scan_depth \"custom\"; %q uses its own port set", depth)
		}
		spec.TCP, spec.UDP = presetPorts(depth)
	case DepthCustom:
		if !hasTCP && !hasUDP {
			return ScanSpec{}, requestError("scan_depth \"custom\" needs tcp_ports, udp_ports or both (e.g. tcp_ports \"22,443,8000-8100\")")
		}
		if hasTCP {
			if spec.TCP, err = ParsePortSpec(tcpRaw); err != nil {
				return ScanSpec{}, requestError("tcp_ports: %v", err)
			}
		}
		if hasUDP {
			if spec.UDP, err = ParsePortSpec(udpRaw); err != nil {
				return ScanSpec{}, requestError("udp_ports: %v", err)
			}
		}
	default:
		return ScanSpec{}, requestError("scan_depth %q is not one of quick, standard, thorough, custom", depthRaw)
	}
	return spec, nil
}

// presetPorts is a preset depth's TCP and UDP sets.
func presetPorts(depth ScanDepth) (PortSet, PortSet) {
	switch depth {
	case DepthQuick:
		return QuickPorts(), PortSet{}
	case DepthStandard:
		return StandardPorts(), CuratedUDPScanPorts()
	case DepthThorough:
		return ThoroughPorts(), CuratedUDPScanPorts()
	}
	return PortSet{}, PortSet{}
}

// ScanPlan is what the server decided a job will do: the request as validated,
// where it runs and why, and per target the depth actually allowed. Stored on
// the job under metadata.scan_plan and returned as `plan`.
type ScanPlan struct {
	// Depth, Pace and the requested port sets, in ParsePortSpec form.
	Depth        ScanDepth `json:"depth"`
	Pace         Pace      `json:"pace"`
	TCPPorts     string    `json:"tcp_ports"`
	UDPPorts     string    `json:"udp_ports"`
	TCPPortCount int       `json:"tcp_port_count"`
	UDPPortCount int       `json:"udp_port_count"`

	// RunFromRequested is what the request asked for (auto, platform,
	// sensor); ExecutorResolved is where the job runs (platform, sensor) and
	// ExecutorReason says why in a sentence. SensorID/SensorName name the
	// tenant sensor when it runs on one.
	RunFromRequested string `json:"run_from_requested"`
	ExecutorResolved string `json:"executor_resolved"`
	ExecutorReason   string `json:"executor_reason"`
	SensorID         string `json:"sensor_id,omitempty"`
	SensorName       string `json:"sensor_name,omitempty"`

	// DepthAdjustments lists every target run at less than was asked, and why.
	DepthAdjustments []DepthAdjustment `json:"depth_adjustments"`
	Targets          []PlanTarget      `json:"targets"`

	// EstimatedProbes is Σ addresses × (TCP + UDP ports) over the targets as
	// planned (after any cap); ProbeLimit is the budget it was checked against.
	EstimatedProbes uint64 `json:"estimated_probes"`
	ProbeLimit      uint64 `json:"probe_limit"`
}

// DepthAdjustment is one target scanned at less than the request asked for.
type DepthAdjustment struct {
	Target    string    `json:"target"`
	Requested ScanDepth `json:"requested"`
	Applied   ScanDepth `json:"applied"`
	Reason    string    `json:"reason"`
}

// PlanTarget is one target as planned.
type PlanTarget struct {
	Target string      `json:"target"`
	Class  TargetClass `json:"class"`
	// SegmentID is the registered network segment that made a public target
	// the tenant's (class registered_segment): who claimed what, then scanned
	// it, is answerable from the job alone.
	SegmentID string `json:"segment_id,omitempty"`
	// Depth is the depth applied to this target.
	Depth ScanDepth `json:"depth"`
	// SNICandidates are names the target is known by (at most
	// MaxSNICandidates, DNS names; see SanitizeSNICandidates), offered as SNI to
	// a TLS port of this target that answers a nameless ClientHello with an
	// alert. Optional and additive: an executor that predates it ignores the
	// field and scans exactly as before. Never resolved, never a place to
	// connect to.
	SNICandidates []string `json:"sni_candidates,omitempty"`
	// Addresses is how many addresses the target names (a hostname counts 1).
	Addresses    uint64 `json:"addresses"`
	TCPPorts     string `json:"tcp_ports"`
	UDPPorts     string `json:"udp_ports"`
	TCPPortCount int    `json:"tcp_port_count"`
	UDPPortCount int    `json:"udp_port_count"`
	// EstimatedProbes is Addresses × (TCPPortCount + UDPPortCount).
	EstimatedProbes uint64 `json:"estimated_probes"`
}

// PlanTargetInput is one target as the authorization guard classified it.
type PlanTargetInput struct {
	Target    string
	Class     TargetClass
	SegmentID string
	// SNICandidates is what the requester supplied for this target; BuildScanPlan
	// sanitizes it, so what the plan records is already bounded and valid.
	SNICandidates []string
}

// BuildScanPlan plans every target: the requested depth for a private or
// registered target, at most Standard for an external one (see the file
// comment), plus extraTCP — ports a target named explicitly (a URL's
// `:8443`) — on every target. It does not decide the executor or check the
// budget; the caller does both.
func BuildScanPlan(spec ScanSpec, extraTCP []int, targets []PlanTargetInput) (ScanPlan, error) {
	extra, err := NewPortSet(extraTCP...)
	if err != nil {
		return ScanPlan{}, err
	}
	requestedTCP := spec.TCP.Union(extra)
	plan := ScanPlan{
		Depth:            spec.Depth,
		Pace:             spec.Pace,
		TCPPorts:         requestedTCP.String(),
		UDPPorts:         spec.UDP.String(),
		TCPPortCount:     requestedTCP.Len(),
		UDPPortCount:     spec.UDP.Len(),
		DepthAdjustments: []DepthAdjustment{},
		Targets:          make([]PlanTarget, 0, len(targets)),
	}
	for _, t := range targets {
		size, err := TargetSize(t.Target)
		if err != nil {
			return ScanPlan{}, err
		}
		pt := PlanTarget{Target: t.Target, Class: t.Class, SegmentID: t.SegmentID, Depth: spec.Depth, Addresses: saturatingUint64(size),
			SNICandidates: SanitizeSNICandidates(t.SNICandidates)}
		tcp, udp := requestedTCP, spec.UDP
		if t.Class == ClassExternal {
			var adj *DepthAdjustment
			pt.Depth, tcp, udp, adj = capExternal(spec, extra, t.Target)
			if adj != nil {
				plan.DepthAdjustments = append(plan.DepthAdjustments, *adj)
			}
		}
		pt.TCPPorts, pt.UDPPorts = tcp.String(), udp.String()
		pt.TCPPortCount, pt.UDPPortCount = tcp.Len(), udp.Len()
		pt.EstimatedProbes = saturatingMul(pt.Addresses, uint64(pt.TCPPortCount+pt.UDPPortCount))
		plan.EstimatedProbes = saturatingAdd(plan.EstimatedProbes, pt.EstimatedProbes)
		plan.Targets = append(plan.Targets, pt)
	}
	return plan, nil
}

// externalCapReason is the sentence every external downgrade starts with.
const externalCapReason = "outside your registered networks: Standard is the deepest scan allowed; register the range if it is yours"

// capExternal applies decision D3 to one external target: Quick and Standard
// unchanged, Thorough down to Standard, Custom to at most
// MaxExternalCustomTCPPorts TCP ports (the lowest of those asked for) and only
// the curated UDP services among those asked for.
func capExternal(spec ScanSpec, extra PortSet, target string) (ScanDepth, PortSet, PortSet, *DepthAdjustment) {
	switch spec.Depth {
	case DepthQuick, DepthStandard:
		return spec.Depth, spec.TCP.Union(extra), spec.UDP, nil
	case DepthThorough:
		tcp, udp := presetPorts(DepthStandard)
		return DepthStandard, tcp.Union(extra), udp, &DepthAdjustment{
			Target: target, Requested: DepthThorough, Applied: DepthStandard, Reason: externalCapReason,
		}
	}
	// Custom.
	tcp := spec.TCP.Union(extra)
	var why []string
	if tcp.Len() > MaxExternalCustomTCPPorts {
		why = append(why, fmt.Sprintf("a custom scan probes at most %d TCP ports there, so the lowest %d of the %d requested are kept",
			MaxExternalCustomTCPPorts, MaxExternalCustomTCPPorts, tcp.Len()))
		tcp = PortSet{ports: tcp.ports[:MaxExternalCustomTCPPorts]}
	}
	curated := CuratedUDPScanPorts()
	udp := spec.UDP
	if dropped := udp.Without(curated); dropped.Len() > 0 {
		why = append(why, fmt.Sprintf("only the curated UDP services are probed there (%s), so UDP %s is not", curated.String(), dropped.String()))
		udp = udp.Without(dropped)
	}
	if len(why) == 0 {
		return DepthCustom, tcp, udp, nil
	}
	return DepthCustom, tcp, udp, &DepthAdjustment{
		Target: target, Requested: DepthCustom, Applied: DepthCustom,
		Reason: "outside your registered networks: " + strings.Join(why, "; ") + "; register the range if it is yours",
	}
}

// ScanBudgetError is a job whose estimated probes exceed the budget.
type ScanBudgetError struct {
	Estimated uint64
	Limit     uint64
	// Largest is the single target contributing the most probes.
	Largest PlanTarget
}

func (e *ScanBudgetError) Error() string {
	return fmt.Sprintf("this scan would send about %s probes (addresses × ports), and one scan may send at most %s; the largest part is %q: %s address(es) × %s port(s) = %s. Lower the scan depth, or split the targets across scans",
		groupDigits(e.Estimated), groupDigits(e.Limit), e.Largest.Target,
		groupDigits(e.Largest.Addresses), groupDigits(uint64(e.Largest.TCPPortCount+e.Largest.UDPPortCount)), groupDigits(e.Largest.EstimatedProbes))
}

// IsScanBudgetError reports whether err is a *ScanBudgetError and returns it.
func IsScanBudgetError(err error) (*ScanBudgetError, bool) {
	var e *ScanBudgetError
	ok := errors.As(err, &e)
	return e, ok
}

// CheckBudget records limit on the plan and refuses a plan above it.
func (p *ScanPlan) CheckBudget(limit uint64) error {
	p.ProbeLimit = limit
	if p.EstimatedProbes <= limit {
		return nil
	}
	e := &ScanBudgetError{Estimated: p.EstimatedProbes, Limit: limit}
	for _, t := range p.Targets {
		if t.EstimatedProbes > e.Largest.EstimatedProbes {
			e.Largest = t
		}
	}
	return e
}

func saturatingUint64(n *big.Int) uint64 {
	if n.Sign() < 0 {
		return 0
	}
	if !n.IsUint64() {
		return ^uint64(0)
	}
	return n.Uint64()
}

func saturatingMul(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > ^uint64(0)/b {
		return ^uint64(0)
	}
	return a * b
}

func saturatingAdd(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}

// groupDigits renders 25000000 as "25,000,000".
func groupDigits(n uint64) string {
	s := strconv.FormatUint(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	lead := len(s) % 3
	if lead > 0 {
		b.WriteString(s[:lead])
	}
	for i := lead; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// TCPPortSet is the target's planned TCP ports as a PortSet (empty when the
// plan names none, e.g. a UDP-only custom scan).
func (t PlanTarget) TCPPortSet() (PortSet, error) { return planPortSet(t.TCPPorts) }

// UDPPortSet is the target's planned UDP ports as a PortSet.
func (t PlanTarget) UDPPortSet() (PortSet, error) { return planPortSet(t.UDPPorts) }

func planPortSet(spec string) (PortSet, error) {
	if strings.TrimSpace(spec) == "" {
		return PortSet{}, nil
	}
	return parsePortSpec(spec, 0)
}
