package gcp

// GCP enumeration: compute instances, networks, subnetworks and firewalls.
//
// This client is hand-rolled REST over typed structs, which means the
// projection boundary is STRUCTURAL: a field with no struct tag in this package
// is discarded by `encoding/json` before any platform code can see it. That is
// the strongest form of "don't collect it", and it is why the types below list
// only what is read.
//
// Three things the Compute API returns and this package deliberately has no
// field for:
//
//   - `instance.metadata.items` — GCP's user-data. It is where `startup-script`
//     and per-instance `ssh-keys` live, and it routinely carries credentials.
//   - `instance.disks[]` — carries `diskEncryptionKey`, which can hold a
//     customer-supplied key's `rsaEncryptedKey`/`sha256`, and `licenses`, which
//     is an image label rather than a statement about the running guest.
//   - `firewall.allowed` / `denied` / `sourceRanges` — the RULES. Only a
//     firewall's identity is collected, as membership; `cloud.security_groups`
//     is "the group the resource is IN, never the rules inside it"
//     (standards/fact-keys.yaml).
//
// `serviceAccounts[]` is likewise absent: a VM's service-account email and
// scopes describe what it is authorised to do, not what it is.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/redact"
)

// computeEndpoint is the Compute API base this client talks to.
//
// A method rather than the bare constant so a test can point one client at a
// recorded-response server without mutating a package-level variable that every
// other test in the package would then share. The override is empty in every
// non-test build, so production reads the constant.
func (c *Client) computeEndpoint() string {
	if strings.TrimSpace(c.computeBaseOverride) != "" {
		return strings.TrimRight(c.computeBaseOverride, "/")
	}
	return computeBaseURL
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

// ComputeInstance is a GCE instance. Fields are the allowlist; see the file
// comment for what is deliberately missing.
type ComputeInstance struct {
	ID                string                    `json:"id"`
	Name              string                    `json:"name"`
	SelfLink          string                    `json:"selfLink"`
	Status            string                    `json:"status,omitempty"`
	MachineType       string                    `json:"machineType,omitempty"`
	Zone              string                    `json:"zone,omitempty"`
	CPUPlatform       string                    `json:"cpuPlatform,omitempty"`
	CreationTimestamp string                    `json:"creationTimestamp,omitempty"`
	Hostname          string                    `json:"hostname,omitempty"`
	NetworkInterfaces []ComputeNetworkInterface `json:"networkInterfaces,omitempty"`
	Tags              *ComputeInstanceTags      `json:"tags,omitempty"`
	Labels            map[string]string         `json:"labels,omitempty"`
}

// ComputeInstanceTags is GCE's network-tag list — the strings firewall rules
// select instances by. Not to be confused with `labels`, which are the
// key/value pairs an operator uses for organisation.
type ComputeInstanceTags struct {
	Items []string `json:"items,omitempty"`
}

// ComputeNetworkInterface is one NIC of an instance.
//
// `accessConfigs` (the external/public address) is deliberately absent: an
// instance's internet exposure is a posture question answered by probing, and
// the ephemeral external address changes on every stop/start, so recording it
// as an identifier would mint a new asset each time.
type ComputeNetworkInterface struct {
	Name       string `json:"name,omitempty"`
	Network    string `json:"network,omitempty"`
	Subnetwork string `json:"subnetwork,omitempty"`
	NetworkIP  string `json:"networkIP,omitempty"`
	StackType  string `json:"stackType,omitempty"`
}

// ComputeNetwork is a VPC network. GCP networks are GLOBAL: they carry no
// region and, in the default (custom-mode) case, no CIDR of their own — the
// address space lives on the subnetworks.
type ComputeNetwork struct {
	ID                    string                       `json:"id"`
	Name                  string                       `json:"name"`
	SelfLink              string                       `json:"selfLink"`
	Description           string                       `json:"description,omitempty"`
	AutoCreateSubnetworks bool                         `json:"autoCreateSubnetworks,omitempty"`
	IPv4Range             string                       `json:"IPv4Range,omitempty"`
	Subnetworks           []string                     `json:"subnetworks,omitempty"`
	RoutingConfig         *ComputeNetworkRoutingConfig `json:"routingConfig,omitempty"`
}

// ComputeNetworkRoutingConfig is the network's routing mode (REGIONAL/GLOBAL).
type ComputeNetworkRoutingConfig struct {
	RoutingMode string `json:"routingMode,omitempty"`
}

// ComputeSubnetwork is a subnetwork. Unlike the network, it is regional and
// carries the CIDR.
type ComputeSubnetwork struct {
	ID                    string `json:"id"`
	Name                  string `json:"name"`
	SelfLink              string `json:"selfLink"`
	Network               string `json:"network,omitempty"`
	Region                string `json:"region,omitempty"`
	IPCidrRange           string `json:"ipCidrRange,omitempty"`
	GatewayAddress        string `json:"gatewayAddress,omitempty"`
	PrivateIPGoogleAccess bool   `json:"privateIpGoogleAccess,omitempty"`
	Purpose               string `json:"purpose,omitempty"`
	StackType             string `json:"stackType,omitempty"`
}

// ComputeFirewall is a firewall rule's IDENTITY and TARGETING, with no rule
// content.
//
// GCP has no security-group object: a firewall rule attaches to a network and
// selects instances by network tag (or by service account). The identity plus
// the targeting is what makes "which rules select this instance" answerable,
// which is the membership question `cloud.security_groups` asks. `allowed`,
// `denied`, `sourceRanges` and `destinationRanges` are the rule CONTENT and
// have no field here.
type ComputeFirewall struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	SelfLink              string   `json:"selfLink"`
	Network               string   `json:"network,omitempty"`
	Direction             string   `json:"direction,omitempty"`
	Disabled              bool     `json:"disabled,omitempty"`
	TargetTags            []string `json:"targetTags,omitempty"`
	TargetServiceAccounts []string `json:"targetServiceAccounts,omitempty"`
}

// Paged list responses.

type instanceAggregatedListResponse struct {
	Items         map[string]instanceScopedList `json:"items"`
	NextPageToken string                        `json:"nextPageToken"`
}

type instanceScopedList struct {
	Instances []ComputeInstance `json:"instances"`
}

type subnetworkAggregatedListResponse struct {
	Items         map[string]subnetworkScopedList `json:"items"`
	NextPageToken string                          `json:"nextPageToken"`
}

type subnetworkScopedList struct {
	Subnetworks []ComputeSubnetwork `json:"subnetworks"`
}

type networkListResponse struct {
	Items         []ComputeNetwork `json:"items"`
	NextPageToken string           `json:"nextPageToken"`
}

type firewallListResponse struct {
	Items         []ComputeFirewall `json:"items"`
	NextPageToken string            `json:"nextPageToken"`
}

// ---------------------------------------------------------------------------
// List calls
// ---------------------------------------------------------------------------

// ListInstances enumerates every Compute Engine instance in the project, in
// every zone, with ONE aggregated call per page.
//
// `instances.aggregatedList` rather than a per-zone `instances.list` loop: GCP
// has 100-odd zones and the per-zone form would be 100 calls to find a project
// with three VMs in it.
func (c *Client) ListInstances(ctx context.Context) ([]ComputeInstance, error) {
	base := fmt.Sprintf("%s/projects/%s/aggregated/instances", c.computeEndpoint(), c.projectID)
	var all []ComputeInstance
	err := c.paginate(ctx, base, func(body []byte) (string, error) {
		var resp instanceAggregatedListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse instances response: %w", err)
		}
		for _, scoped := range resp.Items {
			for i := range scoped.Instances {
				inst := scoped.Instances[i]
				if inst.Name == "" || inst.SelfLink == "" {
					continue
				}
				inst.Labels = redactStringMap(inst.Labels)
				all = append(all, inst)
			}
		}
		return resp.NextPageToken, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list compute instances: %w", err)
	}
	return all, nil
}

// ListNetworks enumerates every VPC network in the project.
func (c *Client) ListNetworks(ctx context.Context) ([]ComputeNetwork, error) {
	base := fmt.Sprintf("%s/projects/%s/global/networks", c.computeEndpoint(), c.projectID)
	var all []ComputeNetwork
	err := c.paginate(ctx, base, func(body []byte) (string, error) {
		var resp networkListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse networks response: %w", err)
		}
		for i := range resp.Items {
			if resp.Items[i].SelfLink == "" {
				continue
			}
			all = append(all, resp.Items[i])
		}
		return resp.NextPageToken, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list networks: %w", err)
	}
	return all, nil
}

// ListSubnetworks enumerates every subnetwork in the project, in every region.
func (c *Client) ListSubnetworks(ctx context.Context) ([]ComputeSubnetwork, error) {
	base := fmt.Sprintf("%s/projects/%s/aggregated/subnetworks", c.computeEndpoint(), c.projectID)
	var all []ComputeSubnetwork
	err := c.paginate(ctx, base, func(body []byte) (string, error) {
		var resp subnetworkAggregatedListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse subnetworks response: %w", err)
		}
		for _, scoped := range resp.Items {
			for i := range scoped.Subnetworks {
				if scoped.Subnetworks[i].SelfLink == "" {
					continue
				}
				all = append(all, scoped.Subnetworks[i])
			}
		}
		return resp.NextPageToken, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list subnetworks: %w", err)
	}
	return all, nil
}

// ListFirewalls enumerates every firewall rule in the project, identity and
// targeting only.
func (c *Client) ListFirewalls(ctx context.Context) ([]ComputeFirewall, error) {
	base := fmt.Sprintf("%s/projects/%s/global/firewalls", c.computeEndpoint(), c.projectID)
	var all []ComputeFirewall
	err := c.paginate(ctx, base, func(body []byte) (string, error) {
		var resp firewallListResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return "", fmt.Errorf("failed to parse firewalls response: %w", err)
		}
		for i := range resp.Items {
			if resp.Items[i].SelfLink == "" {
				continue
			}
			all = append(all, resp.Items[i])
		}
		return resp.NextPageToken, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list firewalls: %w", err)
	}
	return all, nil
}

// paginate walks a Compute list endpoint's pages, calling decode for each body
// and following the page token it returns.
//
// It is a helper rather than a repeated loop because the existing list methods
// each rebuilt the next-page URL by hand and one of them (ListGlobalForwarding
// Rules) reassigns the loop variable to the token before rebuilding, which is a
// shape that is one edit away from an infinite loop. This appends the token
// with url.Values so a token containing a `=` (they do) cannot corrupt the
// query string.
func (c *Client) paginate(ctx context.Context, baseURL string, decode func(body []byte) (string, error)) error {
	next := ""
	// A project with more pages than this is not a project, it is a runaway
	// loop. GCP's maxResults defaults to 500, so this is a 250,000-resource
	// ceiling per call — far past anything real, and finite.
	for page := 0; page < 500; page++ {
		apiURL := baseURL
		if next != "" {
			q := url.Values{}
			q.Set("pageToken", next)
			apiURL = baseURL + "?" + q.Encode()
		}
		body, err := c.doRequest(ctx, apiURL)
		if err != nil {
			return err
		}
		token, err := decode(body)
		if err != nil {
			return err
		}
		if token == "" || token == next {
			// An unchanged token means the server is repeating itself; stopping
			// is the only safe reading.
			return nil
		}
		next = token
	}
	return fmt.Errorf("gcp: %s returned more than 500 pages; stopping rather than looping", baseURL)
}

// ---------------------------------------------------------------------------
// Canonical ids and derived values
// ---------------------------------------------------------------------------

// ResourceName turns a Compute self link into the canonical partial resource
// name — `projects/<project>/zones/<zone>/instances/<name>` — which is what
// this platform stores as a GCP resource's `cloud_resource_id`.
//
// The SELF LINK is not used verbatim because its host is not stable: the
// Compute API echoes `https://www.googleapis.com/compute/v1/...` on some
// surfaces and `https://compute.googleapis.com/compute/v1/...` on others, and
// an identifier that changes with the endpoint would mint a second asset for
// one instance the first time Google moved a surface. The partial resource name
// is Google's own canonical form (it is what `--format='value(selfLink)'`
// trimming and Cloud Asset Inventory both reduce to) and is host-independent.
//
// A value that is already a partial resource name is returned unchanged, so
// this is idempotent and can be applied to a `network`/`subnetwork` reference
// on an interface as well as to a top-level self link.
func ResourceName(selfLink string) string {
	v := strings.TrimSpace(selfLink)
	if v == "" {
		return ""
	}
	if idx := strings.Index(v, "/compute/v1/"); idx >= 0 {
		return strings.TrimPrefix(v[idx+len("/compute/v1/"):], "/")
	}
	if idx := strings.Index(v, "/compute/beta/"); idx >= 0 {
		return strings.TrimPrefix(v[idx+len("/compute/beta/"):], "/")
	}
	// A bare `projects/...` reference, which is what several inline references
	// already are.
	return strings.TrimPrefix(v, "/")
}

// ResourceShortName returns the last path segment of a self link or resource
// reference — the machine type, zone or region name an operator recognises.
func ResourceShortName(ref string) string {
	v := strings.TrimSpace(ref)
	if v == "" {
		return ""
	}
	if idx := strings.LastIndex(v, "/"); idx >= 0 {
		return v[idx+1:]
	}
	return v
}

// ZoneRegion turns a zone name ("us-central1-a") into its region
// ("us-central1"), or "" when the value is not a zone.
//
// It trims the LAST hyphen-separated segment rather than matching a pattern:
// zone suffixes are single letters today but Google has never promised that,
// and a pattern that stopped matching would silently report no region at all.
func ZoneRegion(zone string) string {
	z := ResourceShortName(zone)
	idx := strings.LastIndex(z, "-")
	if idx <= 0 {
		return ""
	}
	return z[:idx]
}

// FirewallsForInstance returns the firewall rules that SELECT an instance, as
// membership references.
//
// GCP's targeting rules, implemented exactly:
//
//   - the rule and the instance must be on the same network;
//   - a rule with `targetTags` applies to instances carrying one of those tags;
//   - a rule with `targetServiceAccounts` applies to instances running as one
//     of those accounts — and this platform does not collect an instance's
//     service account, so such a rule is NOT claimed to apply. Guessing would
//     assert a membership that may be false, and a false membership is worse
//     than a missing one;
//   - a rule with neither applies to every instance on the network.
//
// Disabled rules are excluded: a disabled rule selects nothing.
func FirewallsForInstance(inst ComputeInstance, firewalls []ComputeFirewall) []ComputeFirewall {
	networks := map[string]bool{}
	for _, ni := range inst.NetworkInterfaces {
		if n := ResourceName(ni.Network); n != "" {
			networks[n] = true
		}
	}
	if len(networks) == 0 {
		return nil
	}
	tags := map[string]bool{}
	if inst.Tags != nil {
		for _, t := range inst.Tags.Items {
			if t = strings.TrimSpace(t); t != "" {
				tags[t] = true
			}
		}
	}

	var out []ComputeFirewall
	for _, fw := range firewalls {
		if fw.Disabled || !networks[ResourceName(fw.Network)] {
			continue
		}
		switch {
		case len(fw.TargetTags) > 0:
			matched := false
			for _, t := range fw.TargetTags {
				if tags[strings.TrimSpace(t)] {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		case len(fw.TargetServiceAccounts) > 0:
			// Targeted by service account, which we do not collect. Not claimed.
			continue
		}
		out = append(out, fw)
	}
	return out
}

// redactStringMap masks label VALUES whose key looks like a secret. GCP labels
// are lower-cased key/value pairs the customer chose, exactly as free-form as
// an AWS tag.
func redactStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		key := strings.TrimSpace(k)
		if key == "" {
			continue
		}
		out[key] = redact.String(key, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
