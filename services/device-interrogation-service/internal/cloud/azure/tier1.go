package azure

// Tier-1 cloud classes on Azure (asset-inventory ADR-0009 D2; DCIM row 4.6):
// Function Apps, AKS clusters, Key Vault secrets and DNS zones, read over the
// same ARM pipeline as CheckSubscription (generic GETs, decoded straight into
// the projection structs below).
//
// Not retrieved: a Function App's application settings (their VALUES are the
// app's secrets, and ARM only hands out the names together with the values —
// `config/appsettings/list` — so the names are not collected on Azure); a
// Key Vault secret's value (the management-plane secret listing carries none);
// DNS record values. RBAC: the built-in Reader role.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

const maxARMPages = 200

// armList GETs an ARM collection under the subscription and every nextLink
// after it, handing each page's `value` array to fn.
func (c *Client) armList(ctx context.Context, path, apiVersion string, fn func(json.RawMessage) error) error {
	cl, err := arm.NewClient("vistaplatform/device-interrogation-service", "v1.0.0", c.credential, c.armOptions)
	if err != nil {
		return fmt.Errorf("failed to create ARM client: %w", err)
	}
	next := runtime.JoinPaths(cl.Endpoint(), "subscriptions", url.PathEscape(c.subscriptionID), path)
	first := true
	for page := 0; page < maxARMPages && next != ""; page++ {
		req, err := runtime.NewRequest(ctx, http.MethodGet, next)
		if err != nil {
			return err
		}
		if first {
			q := req.Raw().URL.Query()
			q.Set("api-version", apiVersion)
			req.Raw().URL.RawQuery = q.Encode()
			first = false
		}
		req.Raw().Header.Set("Accept", "application/json")
		resp, err := cl.Pipeline().Do(req)
		if err != nil {
			return err
		}
		if !runtime.HasStatusCode(resp, http.StatusOK) {
			return runtime.NewResponseError(resp)
		}
		var body struct {
			Value    []json.RawMessage `json:"value"`
			NextLink string            `json:"nextLink"`
		}
		if err := runtime.UnmarshalAsJSON(resp, &body); err != nil {
			return fmt.Errorf("unreadable ARM response for %s: %w", path, err)
		}
		for _, v := range body.Value {
			if err := fn(v); err != nil {
				return err
			}
		}
		next = body.NextLink
	}
	return nil
}

// armTags projects ARM tags through the name-based redactor.
func armTags(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k = strings.TrimSpace(k); k != "" {
			out[k] = redact.String(k, v)
		}
	}
	return out
}

// FunctionApp is a Function App's projection.
type FunctionApp struct {
	ResourceID   string            `json:"resource_id"`
	Name         string            `json:"name"`
	Location     string            `json:"location"`
	State        string            `json:"state,omitempty"`
	Runtime      string            `json:"runtime,omitempty"`
	IdentityName string            `json:"identity_name,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
}

// ListFunctionApps lists the subscription's Function Apps
// (Microsoft.Web/sites whose kind names functionapp).
func (c *Client) ListFunctionApps(ctx context.Context) ([]FunctionApp, error) {
	var out []FunctionApp
	err := c.armList(ctx, "providers/Microsoft.Web/sites", "2023-12-01", func(raw json.RawMessage) error {
		var s struct {
			ID       string            `json:"id"`
			Name     string            `json:"name"`
			Kind     string            `json:"kind"`
			Location string            `json:"location"`
			Tags     map[string]string `json:"tags"`
			Identity *struct {
				Type string `json:"type"`
			} `json:"identity"`
			Properties struct {
				State      string `json:"state"`
				SiteConfig *struct {
					LinuxFxVersion string `json:"linuxFxVersion"`
				} `json:"siteConfig"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		if s.ID == "" || !strings.Contains(strings.ToLower(s.Kind), "functionapp") {
			return nil
		}
		fa := FunctionApp{ResourceID: s.ID, Name: s.Name, Location: s.Location, State: s.Properties.State, Tags: armTags(s.Tags)}
		if s.Properties.SiteConfig != nil {
			fa.Runtime = s.Properties.SiteConfig.LinuxFxVersion
		}
		if s.Identity != nil && strings.Contains(strings.ToLower(s.Identity.Type), "systemassigned") {
			fa.IdentityName = s.Name
		}
		out = append(out, fa)
		return nil
	})
	return out, err
}

// ManagedCluster is an AKS cluster's projection.
type ManagedCluster struct {
	ResourceID        string            `json:"resource_id"`
	Name              string            `json:"name"`
	Location          string            `json:"location"`
	KubernetesVersion string            `json:"kubernetes_version,omitempty"`
	State             string            `json:"state,omitempty"`
	PrivateCluster    bool              `json:"private_cluster"`
	Tags              map[string]string `json:"tags,omitempty"`
}

// ListManagedClusters lists the subscription's AKS clusters.
func (c *Client) ListManagedClusters(ctx context.Context) ([]ManagedCluster, error) {
	var out []ManagedCluster
	err := c.armList(ctx, "providers/Microsoft.ContainerService/managedClusters", "2024-02-01", func(raw json.RawMessage) error {
		var s struct {
			ID         string            `json:"id"`
			Name       string            `json:"name"`
			Location   string            `json:"location"`
			Tags       map[string]string `json:"tags"`
			Properties struct {
				KubernetesVersion string `json:"kubernetesVersion"`
				ProvisioningState string `json:"provisioningState"`
				APIServerAccess   *struct {
					EnablePrivateCluster bool `json:"enablePrivateCluster"`
				} `json:"apiServerAccessProfile"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		if s.ID == "" {
			return nil
		}
		mc := ManagedCluster{ResourceID: s.ID, Name: s.Name, Location: s.Location, KubernetesVersion: s.Properties.KubernetesVersion,
			State: s.Properties.ProvisioningState, Tags: armTags(s.Tags)}
		if s.Properties.APIServerAccess != nil {
			mc.PrivateCluster = s.Properties.APIServerAccess.EnablePrivateCluster
		}
		out = append(out, mc)
		return nil
	})
	return out, err
}

// VaultSecret is one Key Vault secret's metadata projection.
type VaultSecret struct {
	ResourceID string            `json:"resource_id"`
	Name       string            `json:"name"`
	Vault      string            `json:"vault"`
	Location   string            `json:"location"`
	Enabled    bool              `json:"enabled"`
	Tags       map[string]string `json:"tags,omitempty"`
}

// ListVaultSecrets lists every vault's secrets through the MANAGEMENT plane,
// which returns metadata and never a value.
func (c *Client) ListVaultSecrets(ctx context.Context) ([]VaultSecret, error) {
	type vault struct {
		ID, Name, Location string
	}
	var vaults []vault
	if err := c.armList(ctx, "providers/Microsoft.KeyVault/vaults", "2023-07-01", func(raw json.RawMessage) error {
		var v struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Location string `json:"location"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		if v.ID != "" {
			vaults = append(vaults, vault{v.ID, v.Name, v.Location})
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var out []VaultSecret
	for _, v := range vaults {
		rel := strings.TrimPrefix(v.ID, "/subscriptions/"+c.subscriptionID+"/")
		if rel == v.ID {
			continue
		}
		if err := c.armList(ctx, rel+"/secrets", "2023-07-01", func(raw json.RawMessage) error {
			var s struct {
				ID         string            `json:"id"`
				Name       string            `json:"name"`
				Tags       map[string]string `json:"tags"`
				Properties struct {
					Attributes *struct {
						Enabled bool `json:"enabled"`
					} `json:"attributes"`
				} `json:"properties"`
			}
			if err := json.Unmarshal(raw, &s); err != nil {
				return err
			}
			if s.ID == "" {
				return nil
			}
			vs := VaultSecret{ResourceID: s.ID, Name: s.Name, Vault: v.Name, Location: v.Location, Tags: armTags(s.Tags), Enabled: true}
			if s.Properties.Attributes != nil {
				vs.Enabled = s.Properties.Attributes.Enabled
			}
			out = append(out, vs)
			return nil
		}); err != nil {
			return out, err
		}
	}
	return out, nil
}

// DNSZone is an Azure DNS zone's projection.
type DNSZone struct {
	ResourceID  string            `json:"resource_id"`
	Name        string            `json:"name"`
	Private     bool              `json:"private"`
	RecordCount int               `json:"record_count"`
	Tags        map[string]string `json:"tags,omitempty"`
}

// ListDNSZones lists the subscription's public DNS zones.
func (c *Client) ListDNSZones(ctx context.Context) ([]DNSZone, error) {
	var out []DNSZone
	err := c.armList(ctx, "providers/Microsoft.Network/dnszones", "2018-05-01", func(raw json.RawMessage) error {
		var s struct {
			ID         string            `json:"id"`
			Name       string            `json:"name"`
			Tags       map[string]string `json:"tags"`
			Properties struct {
				NumberOfRecordSets int    `json:"numberOfRecordSets"`
				ZoneType           string `json:"zoneType"`
			} `json:"properties"`
		}
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		if s.ID == "" {
			return nil
		}
		out = append(out, DNSZone{ResourceID: s.ID, Name: s.Name, Private: strings.EqualFold(s.Properties.ZoneType, "Private"),
			RecordCount: s.Properties.NumberOfRecordSets, Tags: armTags(s.Tags)})
		return nil
	})
	return out, err
}
