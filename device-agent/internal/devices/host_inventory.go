package devices

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/models"
	"github.com/vistasecurity/vistaplatform/device-agent/internal/security"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
)

// Host inventory, both modes, over the one collector library.
//
// LOCAL mode is not a job. The agent is installed on the host it describes, it
// needs no credentials to describe it, and there is nothing for the platform to
// schedule: it collects on start and on an interval and posts the result to the
// agent-authenticated intake endpoint. See the scheduler in cmd/main.go.
//
// REMOTE mode IS a job, and it arrives and is credentialled exactly the way a
// device_interrogation job is — the same decrypt-locally-and-clear discipline,
// the same parameters block. What differs is only which [hostinventory.Runner]
// the collector is handed.

// JobTypeHostInventory is the job type the platform queues for a remote
// collection.
const JobTypeHostInventory = "host_inventory"

// hostInventoryTimeout bounds one whole collection. A remote target that has
// gone unresponsive must not hold the agent's single job slot indefinitely.
const hostInventoryTimeout = 10 * time.Minute

// executeHostInventory runs a queued host-inventory job.
//
// Only remote mode reaches here. A job asking for local mode is REFUSED rather
// than quietly run: local collection is agent-originated and posts to its own
// endpoint, so honouring a local-mode job would produce a result the platform
// has no row to attach it to, and a job that appears to succeed while landing
// nowhere is worse than one that fails.
func (e *JobExecutor) executeHostInventory(job *models.Job) error {
	mode := hostinventory.Mode(strings.ToLower(paramString(job.Parameters, "mode")))
	switch mode {
	case hostinventory.ModeRemote:
	case hostinventory.ModeLocal, "":
		return e.submitFailure(job, "host_inventory jobs must set parameters.mode to \"remote\"; "+
			"local collection is agent-originated and is not scheduled as a job")
	default:
		return e.submitFailure(job, fmt.Sprintf("unknown host inventory mode %q", mode))
	}

	transport, err := hostinventory.ParseTransport(paramString(job.Parameters, "transport"))
	if err != nil {
		return e.submitFailure(job, err.Error())
	}

	decrypted, err := security.DecryptCredentials(job.Credentials, job.ID.String(), e.config.RegistrationKey)
	if err != nil {
		return e.submitFailure(job, fmt.Sprintf("Failed to decrypt credentials: %v", err))
	}
	defer security.ClearCredentials(decrypted)

	runner, err := buildRemoteRunner(transport, job.Parameters, decrypted)
	if err != nil {
		return e.submitFailure(job, fmt.Sprintf("Could not reach the target: %v", err))
	}
	defer func() {
		if closer, ok := runner.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), hostInventoryTimeout)
	defer cancel()

	// Remote-peer collection is privacy-sensitive and therefore requires an
	// explicit job parameter; host inventory alone does not enable it.
	report, err := hostinventory.Collect(ctx, runner, hostinventory.Options{
		Mode:               hostinventory.ModeRemote,
		CollectConnections: paramBool(job.Parameters, "collect_connections"),
	})
	// Credentials are done with the moment the collection is: the report holds
	// none of them and nothing below needs them.
	security.ClearCredentials(decrypted)
	if err != nil {
		if e.auditLogger != nil {
			e.auditLogger.LogInterrogation(job.ID.String(), paramString(job.Parameters, "ip_address"), JobTypeHostInventory, "failure",
				map[string]interface{}{"job_type": job.Type}, err)
		}
		return e.submitFailure(job, fmt.Sprintf("Host inventory failed: %v", err))
	}

	result, err := hostinventory.ToObservations(report)
	if err != nil {
		return e.submitFailure(job, fmt.Sprintf("Could not project the host inventory: %v", err))
	}

	if e.auditLogger != nil {
		e.auditLogger.LogInterrogation(job.ID.String(), paramString(job.Parameters, "ip_address"), JobTypeHostInventory, "success",
			map[string]interface{}{
				"job_type":      job.Type,
				"platform":      report.Platform,
				"package_count": len(report.Packages),
				"listeners":     len(report.Listeners),
			}, nil)
	}

	return e.submitter.SubmitResult(hostInventoryJobResult(job.ID, result))
}

// hostInventoryJobResult is the envelope a remote collection travels to the
// platform in.
//
// It is its own function because the success path above cannot be reached in a
// test without a live SSH target, and the one thing most worth pinning about it
// is a field that was MISSING: this executor did not forward `result.Facts`,
// which was invisible while the platform held host-inventory results and would
// have made remote mode materialise into an anonymous asset with no facts the
// moment the hold was lifted. A struct literal buried in a function no test can
// call is exactly where that hides, so the literal is here and
// TestHostInventoryJobResult_CarriesTheFacts drives it with a real projection.
func hostInventoryJobResult(jobID uuid.UUID, result *di.InterrogateResult) *models.JobResult {
	return &models.JobResult{
		JobID:   jobID,
		Success: true,
		Assets:  convertInterrogateResult(result),
		// The facts ARE the host inventory. Without them a remote collection
		// arrives as a list of open ports and a metadata blob: no OS, no
		// kernel, no hardware identity, no package count, and — because the
		// identifiers ride on each fact's subject — nothing for the
		// identification engine to bind the report to an asset by. The
		// interrogation executor has forwarded them since; this path did
		// not.
		//
		// No Relationships: a host inventory observes no edges. A listening
		// socket is ground truth for `runs_on`, but that edge's other end is a
		// SERVICE asset nothing has created yet (BUILD_PLAN 2.11b item 2).
		Facts: result.Facts,
		// The package list the platform materialises rides in here, as
		// `device_info.packages`. The consumer refuses to run its absent-install
		// sweep when this half arrives without it — see softwareListArrived.
		Metadata:    result.DeviceInfo,
		CompletedAt: time.Now(),
	}
}

// buildRemoteRunner opens the transport a remote collection runs over.
//
// Only SSH exists. [hostinventory.ParseTransport] has already refused `winrm`
// with an explanation by the time this is called, so the default branch here is
// a programming error rather than an operator one.
func buildRemoteRunner(transport hostinventory.Transport, params, creds map[string]interface{}) (hostinventory.Runner, error) {
	if transport != hostinventory.TransportSSH {
		return nil, fmt.Errorf("unsupported transport %q", transport)
	}

	host := paramString(params, "ip_address")
	if host == "" {
		host = paramString(params, "hostname")
	}
	if host == "" {
		return nil, fmt.Errorf("the job names no ip_address or hostname to collect from")
	}

	cfg := hostinventory.SSHConfig{
		Host:          host,
		Port:          paramInt(params, "ssh_port", paramInt(params, "port", 22)),
		User:          credString(creds, "username"),
		Password:      credString(creds, "password"),
		PrivateKeyPEM: credString(creds, "private_key"),
		Passphrase:    credString(creds, "passphrase"),
	}
	// Per-target opt-out of host-key verification, spelled the same way every
	// other interrogator spells it so an operator learns it once.
	if v, ok := params["insecure_skip_verify"].(bool); ok {
		cfg.InsecureSkipHostKeyVerify = v
	} else if v, ok := creds["insecure_skip_verify"].(bool); ok {
		cfg.InsecureSkipHostKeyVerify = v
	}

	return hostinventory.NewSSHRunner(cfg)
}

// CollectLocalHostInventory runs a local collection and returns the sanitised
// observations alongside the raw report.
//
// Exported because the scheduler in cmd/main.go and the --host-inventory-once
// support flag both need it, and because a second copy of "which options does
// local mode use" is a second place for the two to drift.
func CollectLocalHostInventory(ctx context.Context, agentID string) (*hostinventory.Report, *di.InterrogateResult, error) {
	return CollectLocalHostInventoryWithConnections(ctx, agentID, false)
}

// CollectLocalHostInventoryWithConnections is the production local collector.
// The boolean comes only from the explicit agent privacy setting.
func CollectLocalHostInventoryWithConnections(ctx context.Context, agentID string, collectConnections bool) (*hostinventory.Report, *di.InterrogateResult, error) {
	report, err := hostinventory.Collect(ctx, hostinventory.NewLocalRunner(), hostinventory.Options{
		Mode:               hostinventory.ModeLocal,
		AgentID:            agentID,
		CollectConnections: collectConnections,
		// The one documented divergence from remote mode, and it only fires
		// after `ip -j addr` has already failed — which it does on a minimal
		// image that ships no iproute2.
		LocalInterfaceFallback: true,
	})
	if err != nil {
		return nil, nil, err
	}
	result, err := hostinventory.ToObservations(report)
	if err != nil {
		return report, nil, err
	}
	return report, result, nil
}

func paramBool(params map[string]interface{}, key string) bool {
	v, _ := params[key].(bool)
	return v
}

// paramString reads a string job parameter.
func paramString(params map[string]interface{}, key string) string {
	if v, ok := params[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// paramInt reads a numeric job parameter. JSON numbers arrive as float64.
func paramInt(params map[string]interface{}, key string, fallback int) int {
	switch v := params[key].(type) {
	case float64:
		if v > 0 {
			return int(v)
		}
	case int:
		if v > 0 {
			return v
		}
	}
	return fallback
}

// credString reads a string credential field.
func credString(creds map[string]interface{}, key string) string {
	if v, ok := creds[key].(string); ok {
		return v
	}
	return ""
}
