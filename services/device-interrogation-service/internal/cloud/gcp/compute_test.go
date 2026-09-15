package gcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The GCP enumeration's projection boundary is STRUCTURAL — a field with no tag
// on the types in compute.go is discarded by encoding/json before any platform
// code sees it. These tests serve the Compute API's REAL response shape,
// including the fields that carry secrets, and assert they do not survive the
// decode.
//
// The two that matter on GCE:
//
//   - `metadata.items` — startup-script and per-instance ssh-keys. This is
//     GCP's user-data, and it is where credentials live.
//   - `disks[].diskEncryptionKey` — a customer-supplied key's rsaEncryptedKey.

const poison = "MUST-NOT-BE-COLLECTED"

func assertNoPoison(t *testing.T, label string, v any) {
	t.Helper()
	blob, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("%s: marshal: %v", label, err)
	}
	if strings.Contains(string(blob), poison) {
		t.Errorf("%s: collected material that should have been projected away: %s", label, blob)
	}
}

// testClient returns a Client with a pre-warmed access token (so no OAuth round
// trip happens) pointed at srv.
func testClient(t *testing.T, srv *httptest.Server) *Client {
	t.Helper()
	return &Client{
		projectID:           "my-project",
		httpClient:          srv.Client(),
		computeBaseOverride: srv.URL,
		accessToken:         "test-token",
		// Far enough ahead that the 60s refresh buffer does not trip.
		tokenExpiry: time.Now().Add(time.Hour),
	}
}

const instancesPage1 = `{
  "items": {
    "zones/us-central1-a": {
      "instances": [ {
        "id": "8765",
        "name": "web-01",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/instances/web-01",
        "status": "RUNNING",
        "machineType": "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a/machineTypes/e2-medium",
        "zone": "https://www.googleapis.com/compute/v1/projects/my-project/zones/us-central1-a",
        "cpuPlatform": "Intel Broadwell",
        "labels": { "env": "prod", "db_password": "` + poison + `" },
        "tags": { "items": ["http-server"], "fingerprint": "abc" },
        "networkInterfaces": [ {
          "name": "nic0",
          "network": "https://www.googleapis.com/compute/v1/projects/my-project/global/networks/prod-vpc",
          "subnetwork": "https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1/subnetworks/app",
          "networkIP": "10.128.0.5",
          "accessConfigs": [ { "natIP": "` + poison + `" } ]
        } ],
        "metadata": {
          "items": [
            { "key": "startup-script", "value": "` + poison + `" },
            { "key": "ssh-keys", "value": "` + poison + `" }
          ]
        },
        "disks": [ {
          "deviceName": "persistent-disk-0",
          "source": "` + poison + `",
          "licenses": [ "` + poison + `" ],
          "diskEncryptionKey": { "rsaEncryptedKey": "` + poison + `", "sha256": "` + poison + `" }
        } ],
        "serviceAccounts": [ { "email": "` + poison + `", "scopes": [ "` + poison + `" ] } ]
      } ]
    },
    "zones/us-central1-b": { "warning": { "code": "NO_RESULTS_ON_PAGE" } }
  },
  "nextPageToken": "page-2"
}`

const instancesPage2 = `{
  "items": {
    "zones/europe-west4-a": {
      "instances": [ {
        "id": "8766",
        "name": "db-01",
        "selfLink": "https://compute.googleapis.com/compute/v1/projects/my-project/zones/europe-west4-a/instances/db-01",
        "status": "TERMINATED",
        "zone": "https://compute.googleapis.com/compute/v1/projects/my-project/zones/europe-west4-a",
        "networkInterfaces": [ { "name": "nic0", "networkIP": "10.164.0.9" } ]
      } ]
    }
  }
}`

const networksPage = `{
  "items": [ {
    "id": "1",
    "name": "prod-vpc",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/my-project/global/networks/prod-vpc",
    "autoCreateSubnetworks": false,
    "routingConfig": { "routingMode": "REGIONAL" },
    "peerings": [ { "name": "` + poison + `", "network": "` + poison + `" } ]
  } ]
}`

const subnetworksPage = `{
  "items": {
    "regions/us-central1": {
      "subnetworks": [ {
        "id": "2",
        "name": "app",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1/subnetworks/app",
        "network": "https://www.googleapis.com/compute/v1/projects/my-project/global/networks/prod-vpc",
        "region": "https://www.googleapis.com/compute/v1/projects/my-project/regions/us-central1",
        "ipCidrRange": "10.128.0.0/20",
        "privateIpGoogleAccess": true,
        "logConfig": { "aggregationInterval": "` + poison + `" }
      } ]
    }
  }
}`

const firewallsPage = `{
  "items": [ {
    "id": "3",
    "name": "allow-http",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/my-project/global/firewalls/allow-http",
    "network": "https://www.googleapis.com/compute/v1/projects/my-project/global/networks/prod-vpc",
    "direction": "INGRESS",
    "targetTags": ["http-server"],
    "allowed": [ { "IPProtocol": "tcp", "ports": ["` + poison + `"] } ],
    "sourceRanges": [ "` + poison + `" ],
    "denied": [ { "IPProtocol": "` + poison + `" } ]
  } ]
}`

func fixtureServer(t *testing.T, routes map[string][]string) *httptest.Server {
	t.Helper()
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("Authorization = %q, want the bearer token", got)
		}
		pages, ok := routes[r.URL.Path]
		if !ok {
			t.Errorf("unexpected path %q — the enumeration called an endpoint the test did not record", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		i := seen[r.URL.Path]
		if i >= len(pages) {
			t.Errorf("%s fetched %d times, only %d pages recorded", r.URL.Path, i+1, len(pages))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		seen[r.URL.Path] = i + 1
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(pages[i]))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestListInstances_ProjectsAndPaginates(t *testing.T) {
	srv := fixtureServer(t, map[string][]string{
		"/projects/my-project/aggregated/instances": {instancesPage1, instancesPage2},
	})
	got, err := testClient(t, srv).ListInstances(context.Background())
	if err != nil {
		t.Fatalf("ListInstances: %v", err)
	}
	assertNoPoison(t, "gcp instances", got)

	if len(got) != 2 {
		t.Fatalf("got %d instances across two pages, want 2: %+v", len(got), got)
	}
	var web ComputeInstance
	for _, inst := range got {
		if inst.Name == "web-01" {
			web = inst
		}
	}
	if web.Name == "" {
		t.Fatalf("web-01 missing: %+v", got)
	}
	if web.Status != "RUNNING" || web.CPUPlatform != "Intel Broadwell" {
		t.Errorf("posture lost: %+v", web)
	}
	if len(web.NetworkInterfaces) != 1 || web.NetworkInterfaces[0].NetworkIP != "10.128.0.5" {
		t.Errorf("internal address lost: %+v", web.NetworkInterfaces)
	}
	if web.Tags == nil || len(web.Tags.Items) != 1 || web.Tags.Items[0] != "http-server" {
		t.Errorf("network tags lost — they are what firewall membership is computed from: %+v", web.Tags)
	}
	if web.Labels["env"] != "prod" {
		t.Errorf("labels lost: %v", web.Labels)
	}
	if v := web.Labels["db_password"]; v == poison || v == "" {
		t.Errorf("db_password label = %q; the key must survive with the value masked", v)
	}
}

func TestListNetworksSubnetworksAndFirewalls(t *testing.T) {
	srv := fixtureServer(t, map[string][]string{
		"/projects/my-project/global/networks":        {networksPage},
		"/projects/my-project/aggregated/subnetworks": {subnetworksPage},
		"/projects/my-project/global/firewalls":       {firewallsPage},
	})
	c := testClient(t, srv)
	ctx := context.Background()

	networks, err := c.ListNetworks(ctx)
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	assertNoPoison(t, "gcp networks", networks)
	if len(networks) != 1 || networks[0].Name != "prod-vpc" {
		t.Fatalf("networks = %+v", networks)
	}

	subnets, err := c.ListSubnetworks(ctx)
	if err != nil {
		t.Fatalf("ListSubnetworks: %v", err)
	}
	assertNoPoison(t, "gcp subnetworks", subnets)
	if len(subnets) != 1 || subnets[0].IPCidrRange != "10.128.0.0/20" {
		t.Fatalf("subnetworks = %+v", subnets)
	}

	firewalls, err := c.ListFirewalls(ctx)
	if err != nil {
		t.Fatalf("ListFirewalls: %v", err)
	}
	// The rules are the point: `allowed`, `denied` and `sourceRanges` are an
	// attacker's map of the network and there is no field for them.
	assertNoPoison(t, "gcp firewalls", firewalls)
	if len(firewalls) != 1 || firewalls[0].Name != "allow-http" {
		t.Fatalf("firewalls = %+v", firewalls)
	}
	if len(firewalls[0].TargetTags) != 1 || firewalls[0].TargetTags[0] != "http-server" {
		t.Errorf("targeting lost — membership cannot be computed without it: %+v", firewalls[0])
	}
}

// The self link's HOST is not stable — the Compute API echoes
// www.googleapis.com on some surfaces and compute.googleapis.com on others —
// so the canonical id is the host-independent partial resource name.
func TestResourceName_IsHostIndependentAndIdempotent(t *testing.T) {
	want := "projects/my-project/zones/us-central1-a/instances/web-01"
	for _, in := range []string{
		"https://www.googleapis.com/compute/v1/" + want,
		"https://compute.googleapis.com/compute/v1/" + want,
		"https://compute.googleapis.com/compute/beta/" + want,
		want,
		"/" + want,
	} {
		if got := ResourceName(in); got != want {
			t.Errorf("ResourceName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := ResourceName("   "); got != "" {
		t.Errorf("ResourceName(blank) = %q", got)
	}
}

func TestZoneRegion(t *testing.T) {
	cases := map[string]string{
		"https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a": "us-central1",
		"europe-west4-b": "europe-west4",
		"":               "",
		"nohyphen":       "",
	}
	for in, want := range cases {
		if got := ZoneRegion(in); got != want {
			t.Errorf("ZoneRegion(%q) = %q, want %q", in, got, want)
		}
	}
}

// GCP's targeting rules, exactly. The service-account case is the one that
// matters: we do not collect an instance's service account, so a rule targeted
// that way must NOT be claimed to apply — a false membership is worse than a
// missing one.
func TestFirewallsForInstance(t *testing.T) {
	const net = "https://www.googleapis.com/compute/v1/projects/p/global/networks/prod"
	const other = "https://www.googleapis.com/compute/v1/projects/p/global/networks/dev"

	inst := ComputeInstance{
		NetworkInterfaces: []ComputeNetworkInterface{{Network: net}},
		Tags:              &ComputeInstanceTags{Items: []string{"http-server"}},
	}
	firewalls := []ComputeFirewall{
		{Name: "by-tag-match", SelfLink: net + "/fw1", Network: net, TargetTags: []string{"http-server"}},
		{Name: "by-tag-miss", SelfLink: net + "/fw2", Network: net, TargetTags: []string{"db"}},
		{Name: "network-wide", SelfLink: net + "/fw3", Network: net},
		{Name: "other-network", SelfLink: other + "/fw4", Network: other},
		{Name: "disabled", SelfLink: net + "/fw5", Network: net, Disabled: true},
		{Name: "by-service-account", SelfLink: net + "/fw6", Network: net, TargetServiceAccounts: []string{"sa@p.iam.gserviceaccount.com"}},
	}

	got := FirewallsForInstance(inst, firewalls)
	names := make([]string, 0, len(got))
	for _, fw := range got {
		names = append(names, fw.Name)
	}
	want := []string{"by-tag-match", "network-wide"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("FirewallsForInstance = %v, want %v", names, want)
	}

	// An instance with no interfaces is on no network and matches nothing.
	if got := FirewallsForInstance(ComputeInstance{}, firewalls); len(got) != 0 {
		t.Errorf("an instance on no network matched %d rules", len(got))
	}
}

// A server that keeps returning the same page token would loop forever. The
// paginator stops instead.
func TestPaginate_StopsOnRepeatedToken(t *testing.T) {
	const repeating = `{"items": [], "nextPageToken": "same"}`
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls > 10 {
			t.Fatal("paginator did not stop on a repeated token")
		}
		_, _ = w.Write([]byte(repeating))
	}))
	t.Cleanup(srv.Close)

	if _, err := testClient(t, srv).ListNetworks(context.Background()); err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if calls != 2 {
		t.Errorf("made %d calls, want 2 (the first page, then one that repeated its token)", calls)
	}
}
