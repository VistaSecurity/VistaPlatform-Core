package services

// Landing discovered cloud KMS keys in the key inventory a person can see.
//
// Discovery used to end at the `kms_keys` table — a SECOND key inventory,
// parallel to the first-class `keys` table behind Inventory → Keys, with
// nothing joining them and exactly one reader: an /experimental/kms-keys
// endpoint no frontend calls. A discovered key was therefore invisible: a
// fully-wired backend with no consumer, which is the failure mode the
// reachability rule exists to prevent.
//
// The key row is NOT written here. inventory-service owns what a key row is —
// the dedup identity, the NIST SP 800-57 lifecycle vocabulary, and the
// resolution of an algorithm against the catalogue — so this posts the
// provider's own account of each key over the same HMAC-signed, mTLS-aware
// transport the agent-host approval uses, and lets that service decide what it
// means. `kms_keys` keeps being written as before; retiring it is a separate
// decision.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	sharedconfig "github.com/vistasecurity/vistaplatform/shared/config"
	sharedhttp "github.com/vistasecurity/vistaplatform/shared/http"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

// CloudKeyRecord is one key as the PROVIDER describes it. It is the wire shape
// of inventory-service's internal cloud-key intake; the json tags must match
// services.CloudKeyRecord over there.
type CloudKeyRecord struct {
	Provider           string     `json:"provider"`
	KeyID              string     `json:"key_id"`
	KeyARN             string     `json:"key_arn,omitempty"`
	KeyName            string     `json:"key_name,omitempty"`
	KeySpec            string     `json:"key_spec,omitempty"`
	KeyUsage           string     `json:"key_usage,omitempty"`
	KeyState           string     `json:"key_state,omitempty"`
	KeyManager         string     `json:"key_manager,omitempty"`
	Origin             string     `json:"origin,omitempty"`
	Description        string     `json:"description,omitempty"`
	Region             string     `json:"region,omitempty"`
	AccountID          string     `json:"account_id,omitempty"`
	IntegrationID      string     `json:"integration_id,omitempty"`
	CreationDate       *time.Time `json:"creation_date,omitempty"`
	RotationEnabled    bool       `json:"rotation_enabled,omitempty"`
	RotationPeriodDays int        `json:"rotation_period_days,omitempty"`
	MultiRegion        bool       `json:"multi_region,omitempty"`
	Aliases            []string   `json:"aliases,omitempty"`
}

// CloudKeyPublisher hands discovered cloud keys to the key inventory.
// Implemented over HTTP by InventoryCloudKeyPublisher; tests substitute a
// recorder.
type CloudKeyPublisher interface {
	// PublishCloudKeys returns how many rows the key inventory wrote.
	PublishCloudKeys(ctx context.Context, tenantID uuid.UUID, records []CloudKeyRecord) (int, error)
}

// cloudKeyIngestPath is inventory-service's internal route. Registered under
// the service prefix only, and deliberately not in the OpenAPI contract.
const cloudKeyIngestPath = "/api/v1/inventory-service/keys/cloud"

// cloudKeyIngestTimeout bounds the call. A cloud discovery has already stored
// its findings by the time this runs; a slow inventory must not turn a
// successful discovery into a failed job.
const cloudKeyIngestTimeout = 20 * time.Second

// InventoryCloudKeyPublisher calls inventory-service.
type InventoryCloudKeyPublisher struct {
	baseURL string
	client  *http.Client
}

// NewInventoryCloudKeyPublisher builds the client. baseURL is inventory-
// service's peer URL; client is nil for plaintext or an mTLS client from
// sharedhttp.NewMTLSClient — the caller knows which, this does not.
func NewInventoryCloudKeyPublisher(baseURL string, client *http.Client) *InventoryCloudKeyPublisher {
	if client == nil {
		client = &http.Client{}
	}
	client.Timeout = cloudKeyIngestTimeout
	return &InventoryCloudKeyPublisher{baseURL: baseURL, client: client}
}

// NewInventoryCloudKeyPublisherFromEnv builds the publisher the way the process
// is configured, without threading config through every KMS discovery call
// site. The peer URL follows the process's mTLS mode; under mTLS the client
// presents this service's certificate, because PeerURL then resolves to the
// 8443 listener which demands one — a plain http.Client there fails the
// handshake, and the discovery would report the peer down.
//
// A client that cannot be built (a missing cert under mTLS) returns nil, which
// the caller tolerates: `kms_keys` is still written and the log says why,
// rather than a discovery failing outright.
func NewInventoryCloudKeyPublisherFromEnv() CloudKeyPublisher {
	baseURL := sharedconfig.PeerServiceURLAuto("INVENTORY_SERVICE_URL", "inventory-service")
	var client *http.Client
	if sharedconfig.MTLSEnabled() {
		c, err := sharedhttp.NewMTLSClient(
			sharedconfig.GetEnv("CLIENT_CERT_PATH", "/app/certs/client-cert.pem"),
			sharedconfig.GetEnv("CLIENT_KEY_PATH", "/app/certs/client-key.pem"),
			sharedconfig.GetEnv("PLATFORM_CA_CERT_PATH", "/app/certs/platform-ca-cert.pem"),
		)
		if err != nil {
			log.Printf("cloud key publish DISABLED: mTLS client for inventory-service could not be built: %v", err)
			return nil
		}
		client = c
	}
	return NewInventoryCloudKeyPublisher(baseURL, client)
}

type cloudKeyIngestRequest struct {
	Keys []CloudKeyRecord `json:"keys"`
}

type cloudKeyIngestResponse struct {
	Written int    `json:"written"`
	Error   string `json:"error,omitempty"`
}

// PublishCloudKeys implements CloudKeyPublisher.
func (p *InventoryCloudKeyPublisher) PublishCloudKeys(ctx context.Context, tenantID uuid.UUID, records []CloudKeyRecord) (int, error) {
	if tenantID == uuid.Nil {
		return 0, errors.New("cloud key publish: tenant id is required")
	}
	if len(records) == 0 {
		return 0, nil
	}
	body, err := json.Marshal(cloudKeyIngestRequest{Keys: records})
	if err != nil {
		return 0, fmt.Errorf("cloud key publish: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+cloudKeyIngestPath, bytes.NewReader(body)) //nolint:gosec // internal service-to-service call to a peer URL from trusted config, not user input
	if err != nil {
		return 0, fmt.Errorf("cloud key publish: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The tenant header is SIGNED (serviceauth folds it into the message when
	// present), so it goes on before signing, not after.
	req.Header.Set(serviceauth.HeaderTenantID, tenantID.String())
	serviceauth.SignRequestFromEnv(req)

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("cloud key publish: inventory-service unreachable: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	var out cloudKeyIngestResponse
	_ = json.Unmarshal(raw, &out)
	if resp.StatusCode != http.StatusOK {
		detail := out.Error
		if detail == "" {
			detail = string(raw)
		}
		return out.Written, fmt.Errorf("cloud key publish: inventory-service answered %d: %s", resp.StatusCode, detail)
	}
	return out.Written, nil
}

// cloudKeyRecordsFrom projects KMS findings onto the wire shape. A straight
// field copy: the discovery side reports what the provider said and does not
// decide what it means.
//
// Nothing sensitive can travel here — DescribeKey returns key METADATA, never
// key material, and the finding struct has no field that could carry any.
func cloudKeyRecordsFrom(provider string, integrationID uuid.UUID, findings []KMSKeyFinding) []CloudKeyRecord {
	records := make([]CloudKeyRecord, 0, len(findings))
	for _, f := range findings {
		rec := CloudKeyRecord{
			Provider:           provider,
			KeyID:              f.KeyID,
			KeyARN:             f.KeyARN,
			KeySpec:            f.KeySpec,
			KeyUsage:           f.KeyUsage,
			KeyState:           f.KeyState,
			KeyManager:         f.KeyManager,
			Origin:             f.Origin,
			Description:        f.Description,
			Region:             f.Region,
			AccountID:          f.AccountID,
			RotationEnabled:    f.RotationEnabled,
			RotationPeriodDays: f.RotationPeriodDays,
			MultiRegion:        f.MultiRegion,
			Aliases:            f.AliasNames,
		}
		if integrationID != uuid.Nil {
			rec.IntegrationID = integrationID.String()
		}
		if len(f.AliasNames) > 0 {
			rec.KeyName = f.AliasNames[0]
		}
		if !f.CreationDate.IsZero() {
			t := f.CreationDate
			rec.CreationDate = &t
		}
		records = append(records, rec)
	}
	return records
}
