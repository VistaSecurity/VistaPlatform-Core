package gcp

// Tier-1 cloud classes on GCP (asset-inventory ADR-0009 D2; DCIM row 4.6):
// Cloud Functions (v2), GKE clusters, Secret Manager secrets and Cloud DNS
// managed zones. Same projection boundary as compute.go: typed structs, and
// nothing decoded into a field the platform does not read.
//
// A function's environment variable VALUES arrive in its listing (Google has
// no narrower call); only the names are kept (envNames). A secret's value is
// never requested (`secrets.list` carries none; `versions.access` is never
// called). Permissions: roles/viewer covers all four.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

const (
	cloudFunctionsBaseURL = "https://cloudfunctions.googleapis.com/v2"
	containerBaseURL      = "https://container.googleapis.com/v1"
	secretManagerBaseURL  = "https://secretmanager.googleapis.com/v1"
	cloudDNSBaseURL       = "https://dns.googleapis.com/dns/v1"
	maxTier1Pages         = 200
)

// envNames keeps the names of an environment-variable map and drops the
// values on decode.
type envNames []string

func (e *envNames) UnmarshalJSON(b []byte) error {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	names := make([]string, 0, len(m))
	for k := range m {
		names = append(names, k)
	}
	sort.Strings(names)
	*e = names
	return nil
}

func labels(in map[string]string) map[string]string {
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

// pagedList GETs base and every nextPageToken after it.
func (c *Client) pagedList(ctx context.Context, base string, fn func([]byte) (string, error)) error {
	apiURL := base
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	for page := 0; page < maxTier1Pages && apiURL != ""; page++ {
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return err
		}
		next, err := fn(body)
		if err != nil {
			return err
		}
		apiURL = ""
		if next != "" {
			apiURL = base + sep + "pageToken=" + url.QueryEscape(next)
		}
	}
	return nil
}

// CloudFunction is a Cloud Function's projection.
type CloudFunction struct {
	Name               string            `json:"name"`
	Region             string            `json:"region"`
	State              string            `json:"state,omitempty"`
	Runtime            string            `json:"runtime,omitempty"`
	EntryPoint         string            `json:"entry_point,omitempty"`
	MemoryMB           int               `json:"memory_mb,omitempty"`
	ServiceAccount     string            `json:"service_account,omitempty"`
	EnvironmentVarKeys []string          `json:"environment_variable_names,omitempty"`
	Labels             map[string]string `json:"labels,omitempty"`
}

// ListCloudFunctions lists every function in every location.
func (c *Client) ListCloudFunctions(ctx context.Context) ([]CloudFunction, error) {
	var out []CloudFunction
	base := fmt.Sprintf("%s/projects/%s/locations/-/functions", c.apiBase(cloudFunctionsBaseURL), c.projectID)
	err := c.pagedList(ctx, base, func(body []byte) (string, error) {
		var resp struct {
			Functions []struct {
				Name        string            `json:"name"`
				State       string            `json:"state"`
				Labels      map[string]string `json:"labels"`
				BuildConfig struct {
					Runtime    string `json:"runtime"`
					EntryPoint string `json:"entryPoint"`
				} `json:"buildConfig"`
				ServiceConfig struct {
					AvailableMemory      string   `json:"availableMemory"`
					ServiceAccountEmail  string   `json:"serviceAccountEmail"`
					EnvironmentVariables envNames `json:"environmentVariables"`
				} `json:"serviceConfig"`
			} `json:"functions"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse functions response: %w", err)
		}
		for _, f := range resp.Functions {
			if f.Name == "" {
				continue
			}
			out = append(out, CloudFunction{
				Name: f.Name, Region: segmentAfter(f.Name, "locations"), State: f.State,
				Runtime: f.BuildConfig.Runtime, EntryPoint: f.BuildConfig.EntryPoint,
				MemoryMB: memoryMB(f.ServiceConfig.AvailableMemory), ServiceAccount: f.ServiceConfig.ServiceAccountEmail,
				EnvironmentVarKeys: []string(f.ServiceConfig.EnvironmentVariables), Labels: labels(f.Labels),
			})
		}
		return resp.NextPageToken, nil
	})
	return out, err
}

// memoryMB reads "256M" / "1Gi" style memory strings.
func memoryMB(s string) int {
	s = strings.TrimSpace(s)
	n, unit := 0, ""
	for i, r := range s {
		if r < '0' || r > '9' {
			unit = strings.ToLower(s[i:])
			break
		}
		n = n*10 + int(r-'0')
	}
	switch {
	case strings.HasPrefix(unit, "g"):
		return n * 1024
	case strings.HasPrefix(unit, "k"):
		return n / 1024
	}
	return n
}

func segmentAfter(path, key string) string {
	parts := strings.Split(path, "/")
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == key {
			return parts[i+1]
		}
	}
	return ""
}

// GKECluster is a GKE cluster's projection.
type GKECluster struct {
	SelfLink        string            `json:"self_link"`
	Name            string            `json:"name"`
	Location        string            `json:"location"`
	Version         string            `json:"version,omitempty"`
	Status          string            `json:"status,omitempty"`
	PrivateEndpoint bool              `json:"private_endpoint"`
	Labels          map[string]string `json:"labels,omitempty"`
	ResourceName    string            `json:"resource_name"`
}

// ListGKEClusters lists every cluster in every location.
func (c *Client) ListGKEClusters(ctx context.Context) ([]GKECluster, error) {
	body, err := c.doRequest(ctx, fmt.Sprintf("%s/projects/%s/locations/-/clusters", c.apiBase(containerBaseURL), c.projectID))
	if err != nil {
		return nil, err
	}
	var resp struct {
		Clusters []struct {
			Name                 string            `json:"name"`
			Location             string            `json:"location"`
			SelfLink             string            `json:"selfLink"`
			CurrentMasterVersion string            `json:"currentMasterVersion"`
			Status               string            `json:"status"`
			ResourceLabels       map[string]string `json:"resourceLabels"`
			PrivateClusterConfig *struct {
				EnablePrivateEndpoint bool `json:"enablePrivateEndpoint"`
			} `json:"privateClusterConfig"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse clusters response: %w", err)
	}
	var out []GKECluster
	for _, cl := range resp.Clusters {
		if cl.Name == "" {
			continue
		}
		g := GKECluster{SelfLink: cl.SelfLink, Name: cl.Name, Location: cl.Location, Version: cl.CurrentMasterVersion,
			Status: cl.Status, Labels: labels(cl.ResourceLabels),
			ResourceName: fmt.Sprintf("projects/%s/locations/%s/clusters/%s", c.projectID, cl.Location, cl.Name)}
		if cl.PrivateClusterConfig != nil {
			g.PrivateEndpoint = cl.PrivateClusterConfig.EnablePrivateEndpoint
		}
		out = append(out, g)
	}
	return out, nil
}

// ManagedSecret is a Secret Manager secret's metadata projection.
type ManagedSecret struct {
	Name         string            `json:"name"`
	Rotation     bool              `json:"rotation"`
	NextRotation string            `json:"next_rotation,omitempty"`
	KMSKeyName   string            `json:"kms_key_name,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
}

// ListSecrets lists the project's secrets (metadata; never a value).
func (c *Client) ListSecrets(ctx context.Context) ([]ManagedSecret, error) {
	var out []ManagedSecret
	base := fmt.Sprintf("%s/projects/%s/secrets", c.apiBase(secretManagerBaseURL), c.projectID)
	err := c.pagedList(ctx, base, func(body []byte) (string, error) {
		var resp struct {
			Secrets []struct {
				Name     string            `json:"name"`
				Labels   map[string]string `json:"labels"`
				Rotation *struct {
					NextRotationTime string `json:"nextRotationTime"`
				} `json:"rotation"`
				CustomerManagedEncryption *struct {
					KMSKeyName string `json:"kmsKeyName"`
				} `json:"customerManagedEncryption"`
			} `json:"secrets"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse secrets response: %w", err)
		}
		for _, s := range resp.Secrets {
			if s.Name == "" {
				continue
			}
			ms := ManagedSecret{Name: s.Name, Labels: labels(s.Labels)}
			if s.Rotation != nil {
				ms.Rotation, ms.NextRotation = true, s.Rotation.NextRotationTime
			}
			if s.CustomerManagedEncryption != nil {
				ms.KMSKeyName = s.CustomerManagedEncryption.KMSKeyName
			}
			out = append(out, ms)
		}
		return resp.NextPageToken, nil
	})
	return out, err
}

// ManagedZone is a Cloud DNS managed zone's projection.
type ManagedZone struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	DNSName    string            `json:"dns_name"`
	Visibility string            `json:"visibility,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

// ListManagedZones lists the project's Cloud DNS zones.
func (c *Client) ListManagedZones(ctx context.Context) ([]ManagedZone, error) {
	var out []ManagedZone
	base := fmt.Sprintf("%s/projects/%s/managedZones", c.apiBase(cloudDNSBaseURL), c.projectID)
	err := c.pagedList(ctx, base, func(body []byte) (string, error) {
		var resp struct {
			ManagedZones []struct {
				ID         string            `json:"id"`
				Name       string            `json:"name"`
				DNSName    string            `json:"dnsName"`
				Visibility string            `json:"visibility"`
				Labels     map[string]string `json:"labels"`
			} `json:"managedZones"`
			NextPageToken string `json:"nextPageToken"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse managed zones response: %w", err)
		}
		for _, z := range resp.ManagedZones {
			if z.Name == "" {
				continue
			}
			out = append(out, ManagedZone{ID: z.ID, Name: z.Name, DNSName: strings.TrimSuffix(z.DNSName, "."), Visibility: z.Visibility, Labels: labels(z.Labels)})
		}
		return resp.NextPageToken, nil
	})
	return out, err
}
