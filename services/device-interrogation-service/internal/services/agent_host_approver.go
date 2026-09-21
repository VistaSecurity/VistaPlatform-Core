package services

// Approving the host a device agent runs on.
//
// A LOCAL host inventory is the agent's own account of the machine it is
// installed on. Someone with administrative access to that machine installed
// the tenant's agent and enrolled it with the tenant's registration key, which
// is a stronger statement of "this host is ours" than any discovery can make —
// and it is the statement Discovery → Approvals exists to collect. Asking for
// it again left the one host whose software inventory the platform had
// actually collected sitting outside the SBOM it was collected for.
//
// The approval itself is NOT reimplemented here. inventory-service owns what an
// approval means — the status, the history row, the edge promotion, the
// lifecycle event, and the replay of the findings a sensor deferred while the
// host waited — and an approval that skipped any of those would leave a host
// that is `monitoring` and still not in inventory. So this file is a client of
// inventory-service's internal agent-host approval route, over the same
// HMAC-signed, mTLS-aware transport discovery-processor-service uses for its
// imports, and the decision of whether to ASK is the ingest's (see
// HostInventoryIngest.approveAgentHost).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// AgentHostApprover admits the host an agent runs on. Implemented over HTTP by
// InventoryAgentHostApprover; tests substitute a recorder.
type AgentHostApprover interface {
	// ApproveAgentHost reports whether the asset was moved into inventory.
	// `false, nil` is a normal answer — already monitoring, denied, not in the
	// queue — and the caller does not retry it. An error is a transport or
	// server failure the next scheduled report will retry naturally.
	ApproveAgentHost(ctx context.Context, tenantID, assetID, agentID uuid.UUID) (bool, error)
}

// agentHostApprovalPath is inventory-service's internal route. It is registered
// under the service prefix only — there is no bare /assets/... twin — and it is
// deliberately not in the OpenAPI contract.
const agentHostApprovalPath = "/api/v1/inventory-service/assets/auto-approve/agent-host"

// approvalTimeout bounds the call. The intake has already stored and
// materialised the report by the time this runs, and the agent is waiting on
// the response; a slow approval must not turn a successful collection into a
// timeout the agent reads as failure.
const approvalTimeout = 10 * time.Second

// InventoryAgentHostApprover calls inventory-service.
type InventoryAgentHostApprover struct {
	baseURL string
	client  *http.Client
}

// NewInventoryAgentHostApprover builds the client. baseURL is inventory-
// service's peer URL (sharedconfig.PeerServiceURLAuto resolves it for the
// process's mTLS mode); client is nil for plaintext or an mTLS client from
// sharedhttp.NewMTLSClient — the caller knows which, this does not.
func NewInventoryAgentHostApprover(baseURL string, client *http.Client) *InventoryAgentHostApprover {
	if client == nil {
		client = &http.Client{}
	}
	client.Timeout = approvalTimeout
	return &InventoryAgentHostApprover{baseURL: baseURL, client: client}
}

type agentHostApprovalRequest struct {
	AssetID string `json:"asset_id"`
	AgentID string `json:"agent_id"`
}

type agentHostApprovalResponse struct {
	Approved bool   `json:"approved"`
	Error    string `json:"error,omitempty"`
}

// ApproveAgentHost implements AgentHostApprover.
func (a *InventoryAgentHostApprover) ApproveAgentHost(ctx context.Context, tenantID, assetID, agentID uuid.UUID) (bool, error) {
	if tenantID == uuid.Nil || assetID == uuid.Nil || agentID == uuid.Nil {
		return false, errors.New("agent-host approval: tenant, asset and agent ids are all required")
	}
	body, err := json.Marshal(agentHostApprovalRequest{AssetID: assetID.String(), AgentID: agentID.String()})
	if err != nil {
		return false, fmt.Errorf("agent-host approval: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+agentHostApprovalPath, bytes.NewReader(body)) //nolint:gosec // internal service-to-service call to a peer URL from trusted config, not user input
	if err != nil {
		return false, fmt.Errorf("agent-host approval: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The tenant header is SIGNED (serviceauth folds it into the message when
	// present), so it goes on before signing, not after.
	req.Header.Set(serviceauth.HeaderTenantID, tenantID.String())
	serviceauth.SignRequestFromEnv(req)

	resp, err := a.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("agent-host approval: inventory-service unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	var out agentHostApprovalResponse
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		detail := out.Error
		if detail == "" {
			detail = string(raw)
		}
		return false, fmt.Errorf("agent-host approval: inventory-service answered %d: %s", resp.StatusCode, detail)
	}
	return out.Approved, nil
}
