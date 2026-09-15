package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/hostinventory"
)

// HostInventorySubmission is the body of a LOCAL host-inventory post.
//
// It carries both halves deliberately. Observations are what the platform
// materialises into facts, endpoints and software installs; the Report is the
// collector's own account of what it ran and what failed, and it is the only
// thing that can answer "why does this host have no packages" six months later.
// Dropping it would leave the section outcomes — the whole three-valued honesty
// apparatus — with nowhere to live.
//
// The Report travels WITHOUT its package list; see withoutPackageList.
type HostInventorySubmission struct {
	AgentID      uuid.UUID             `json:"agent_id"`
	Mode         string                `json:"mode"`
	CollectedAt  time.Time             `json:"collected_at"`
	Report       *hostinventory.Report `json:"report"`
	Observations *di.InterrogateResult `json:"observations"`
	AgentVersion string                `json:"agent_version,omitempty"`
}

// withoutPackageList returns a copy of the report with its package list
// removed, marked as removed.
//
// The package list used to ride the wire TWICE — once in `report.packages` and
// once in `observations.device_info.packages` — and the two were identical in
// size, because the projection enumerates every field a Package has. Measured
// on a real Ubuntu 24.04 collection that was 443 bytes per package across the
// whole submission, exactly half of it duplicate, and a 20,000-package host
// paid for both copies.
//
// The copy that survives is the OBSERVATIONS' one, and which one survives is
// not arbitrary: only that half has been through di.Sanitize, and it is the
// half the platform materialises into software_installs. The report's copy is
// the collector's own record — what `--host-inventory-once` prints, and what
// the local caller gets back from Collect — so it is dropped at the WIRE, not
// at the source.
//
// A shallow copy: every other field, including the Sections map, is shared with
// the caller's report deliberately. Nothing here mutates them, and the report
// is marshalled immediately.
//
// The CERT-STORE summary still rides twice and is left alone. It is bounded at
// three stores of 500 certificates against 20,000 packages — an order of
// magnitude less — and it is the half a hygiene finding will read (BUILD_PLAN
// 3.5). Halving the big one is the change worth making now.
// The marker says a list was ELIDED, not that this function ran. Setting it
// unconditionally would put it on a report whose package step FAILED and had no
// list to drop — and the platform's intake refuses a marked submission that
// carries no observations list, because that combination can only mean the
// surviving copy was lost. A marker on a failed step would make every such host
// a 400.
func withoutPackageList(report *hostinventory.Report) *hostinventory.Report {
	if report == nil {
		return nil
	}
	trimmed := *report
	if len(trimmed.Packages) == 0 {
		return &trimmed
	}
	trimmed.Packages = nil
	// Without this an empty list under Sections["packages"] == "ok" reads as
	// "we enumerated and found no packages" — the exact three-valued collapse
	// the Sections map exists to prevent.
	trimmed.PackagesOmitted = true
	return &trimmed
}

// SubmitHostInventory posts a local host-inventory collection.
//
// It is its own endpoint rather than a job result because a local collection
// has no job: the agent describes the host it runs on, on its own schedule,
// with no credentials and nothing for the platform to have scheduled. Routing
// it through /results would need a job row invented for it, and a job that
// nobody queued is a lie in the job list.
func (c *OutboundClient) SubmitHostInventory(report *hostinventory.Report, observations *di.InterrogateResult) error {
	if c.agentID == uuid.Nil {
		return fmt.Errorf("agent not registered")
	}
	if report == nil || observations == nil {
		return fmt.Errorf("host inventory submission is empty")
	}

	body := HostInventorySubmission{
		AgentID:      c.agentID,
		Mode:         string(report.Mode),
		CollectedAt:  report.Collected,
		Report:       withoutPackageList(report),
		Observations: observations,
		AgentVersion: c.agentVersion,
	}

	jsonData, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal host inventory: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/device-interrogation-service/agents/host-inventory", c.baseURL)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The agent id also rides in a header so AgentAuth can identify the caller
	// without parsing the body — the same shape the other outbound routes get
	// from their :id path parameter.
	req.Header.Set("X-Agent-ID", c.agentID.String())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send host inventory: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusRequestEntityTooLarge {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return &ReportTooLargeError{Bytes: len(jsonData), Detail: strings.TrimSpace(string(msg))}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusAccepted {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("failed to submit host inventory: %s (status: %d)", string(msg), resp.StatusCode)
	}
	return nil
}

// ErrReportTooLarge marks a submission the platform refused on size.
//
// It is a distinct sentinel because it is a distinct KIND of failure: every
// other submission error is worth trying again (the platform was restarting,
// the network blipped), and this one is not. The same host produces the same
// size next run, so a caller that retries it is a caller that will retry it
// forever and never report.
var ErrReportTooLarge = errors.New("host inventory report exceeds the platform's size cap")

// ReportTooLargeError carries the size the agent actually sent.
//
// The agent is the only side that knows it: the platform stops reading at its
// cap, so the number in its 413 is what the request DECLARED. Reporting the
// measured length here is what lets an operator see the real gap between the
// report and the cap rather than guess at it.
type ReportTooLargeError struct {
	// Bytes is the marshalled submission length, measured.
	Bytes int
	// Detail is the platform's explanation, bounded.
	Detail string
}

func (e *ReportTooLargeError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("host inventory report too large: %d bytes rejected by the platform", e.Bytes)
	}
	return fmt.Sprintf("host inventory report too large: %d bytes rejected by the platform: %s", e.Bytes, e.Detail)
}

// Is makes errors.Is(err, ErrReportTooLarge) work for callers that only need
// the category.
func (e *ReportTooLargeError) Is(target error) bool { return target == ErrReportTooLarge }
