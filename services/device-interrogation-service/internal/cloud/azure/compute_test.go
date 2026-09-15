package azure

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
)

// The Azure enumeration is a PROJECTION BOUNDARY. These tests build the SDK
// types from RECORDED ARM JSON — the generated models carry the wire
// unmarshallers, so a fixture here is the response an operator would see in
// `az vm list` — and assert the secret-bearing halves do not survive.
//
// `osProfile.adminPassword` and `osProfile.customData` are the two that matter:
// customData is Azure's user-data, base64 of whatever bootstrap script the
// customer wrote, and it routinely carries credentials.

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

const vmFixture = `{
  "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/web-01",
  "name": "web-01",
  "location": "westeurope",
  "tags": { "environment": "production", "db_password": "` + poison + `" },
  "zones": ["1"],
  "properties": {
    "vmId": "b0c1d2e3-4f56-7890-abcd-ef0123456789",
    "provisioningState": "Succeeded",
    "hardwareProfile": { "vmSize": "Standard_D2s_v5" },
    "storageProfile": {
      "osDisk": { "osType": "Linux", "name": "` + poison + `", "diskSizeGB": 64 },
      "imageReference": {
        "publisher": "Canonical",
        "offer": "0001-com-ubuntu-server-jammy",
        "sku": "22_04-lts-gen2",
        "version": "latest"
      }
    },
    "osProfile": {
      "computerName": "web-01",
      "adminUsername": "azureuser",
      "adminPassword": "` + poison + `",
      "customData": "` + poison + `",
      "linuxConfiguration": {
        "ssh": { "publicKeys": [ { "keyData": "` + poison + `", "path": "/home/azureuser/.ssh/authorized_keys" } ] }
      }
    },
    "networkProfile": {
      "networkInterfaces": [ { "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkInterfaces/nic-01" } ]
    },
    "diagnosticsProfile": { "bootDiagnostics": { "storageUri": "` + poison + `" } }
  }
}`

const nicFixture = `{
  "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkInterfaces/nic-01",
  "name": "nic-01",
  "properties": {
    "macAddress": "00-0D-3A-1B-2C-3D",
    "virtualMachine": { "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/web-01" },
    "networkSecurityGroup": { "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web" },
    "ipConfigurations": [ {
      "name": "ipconfig1",
      "properties": {
        "privateIPAddress": "10.10.1.20",
        "subnet": { "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/vnet-prod/subnets/app" },
        "publicIPAddress": { "id": "` + poison + `" }
      }
    } ]
  }
}`

const vnetFixture = `{
  "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/vnet-prod",
  "name": "vnet-prod",
  "location": "westeurope",
  "tags": { "owner": "platform" },
  "properties": {
    "addressSpace": { "addressPrefixes": ["10.10.0.0/16"] },
    "dhcpOptions": { "dnsServers": ["` + poison + `"] },
    "subnets": [ {
      "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/virtualNetworks/vnet-prod/subnets/app",
      "name": "app",
      "properties": {
        "addressPrefix": "10.10.1.0/24",
        "networkSecurityGroup": { "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web" }
      }
    } ]
  }
}`

const nsgFixture = `{
  "id": "/subscriptions/sub-1/resourceGroups/rg-prod/providers/Microsoft.Network/networkSecurityGroups/nsg-web",
  "name": "nsg-web",
  "location": "westeurope",
  "properties": {
    "securityRules": [ {
      "name": "` + poison + `",
      "properties": { "protocol": "Tcp", "destinationPortRange": "` + poison + `", "sourceAddressPrefix": "` + poison + `" }
    } ]
  }
}`

func unmarshal[T any](t *testing.T, raw string) *T {
	t.Helper()
	var out T
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return &out
}

func TestProjectVirtualMachine_DropsOSProfileAndCustomData(t *testing.T) {
	nic := projectNetworkInterface(unmarshal[armnetwork.Interface](t, nicFixture))
	nics := map[string]NetworkInterface{strings.ToLower(nic.ID): nic}

	got := projectVirtualMachine(unmarshal[armcompute.VirtualMachine](t, vmFixture), nics)

	assertNoPoison(t, "azure vm", got)

	if got.ResourceID == "" || got.Name != "web-01" || got.Location != "westeurope" {
		t.Errorf("identity lost: %+v", got)
	}
	if got.SubscriptionID != "sub-1" || got.ResourceGroup != "rg-prod" {
		t.Errorf("placement parsed from the resource id is wrong: %+v", got)
	}
	if got.VMSize != "Standard_D2s_v5" {
		t.Errorf("vm size lost: %q", got.VMSize)
	}
	if got.VMID != "b0c1d2e3-4f56-7890-abcd-ef0123456789" {
		t.Errorf("vmId lost: %q — it is the IMDS join to an agent inside the guest", got.VMID)
	}
	if got.OSType != "Linux" {
		t.Errorf("os type lost: %q", got.OSType)
	}
	if got.ImageReference != "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest" {
		t.Errorf("image reference = %q", got.ImageReference)
	}
	if len(got.PrivateIPs) != 1 || got.PrivateIPs[0] != "10.10.1.20" {
		t.Errorf("addresses from the NIC index lost: %v", got.PrivateIPs)
	}
	if len(got.SubnetIDs) != 1 || !strings.HasSuffix(got.SubnetIDs[0], "/subnets/app") {
		t.Errorf("subnet placement lost: %v", got.SubnetIDs)
	}
	if len(got.NSGs) != 1 || got.NSGs[0].Name != "nsg-web" {
		t.Errorf("NSG membership lost: %+v", got.NSGs)
	}
	if len(got.Interfaces) != 1 || got.Interfaces[0].MAC != "00:0d:3a:1b:2c:3d" {
		t.Errorf("MAC = %+v, want the lower-case colon form every other producer writes", got.Interfaces)
	}
	if got.Tags["environment"] != "production" {
		t.Errorf("ordinary tag lost: %v", got.Tags)
	}
	if v := got.Tags["db_password"]; v == poison || v == "" {
		t.Errorf("db_password tag = %q; key kept, value masked", v)
	}
}

func TestProjectNetworkSecurityGroup_DropsRules(t *testing.T) {
	got := projectNetworkSecurityGroup(unmarshal[armnetwork.SecurityGroup](t, nsgFixture))
	assertNoPoison(t, "azure nsg", got)
	if got.Name != "nsg-web" || got.ResourceGroup != "rg-prod" {
		t.Errorf("identity lost: %+v", got)
	}
}

func TestProjectVirtualNetwork_CarriesSubnetsInline(t *testing.T) {
	got := projectVirtualNetwork(unmarshal[armnetwork.VirtualNetwork](t, vnetFixture))
	assertNoPoison(t, "azure vnet", got)

	if len(got.AddressPrefixes) != 1 || got.AddressPrefixes[0] != "10.10.0.0/16" {
		t.Errorf("address space lost: %v", got.AddressPrefixes)
	}
	if len(got.Subnets) != 1 {
		t.Fatalf("subnets = %+v, want the one ARM returned inline", got.Subnets)
	}
	sn := got.Subnets[0]
	if sn.Name != "app" || len(sn.AddressPrefixes) != 1 || sn.AddressPrefixes[0] != "10.10.1.0/24" {
		t.Errorf("subnet = %+v", sn)
	}
	if sn.VNetID != got.ResourceID {
		t.Errorf("subnet does not name its VNet: %q vs %q", sn.VNetID, got.ResourceID)
	}
	if sn.Location != "westeurope" {
		t.Errorf("a subnet has no location of its own; it inherits the VNet's: %q", sn.Location)
	}
	if sn.NSG == nil || sn.NSG.Name != "nsg-web" {
		t.Errorf("subnet NSG membership lost: %+v", sn.NSG)
	}
}

func TestResourceIDSegment(t *testing.T) {
	id := "/subscriptions/SUB-1/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/web-01"
	if got := ResourceIDSegment(id, "subscriptions"); got != "SUB-1" {
		t.Errorf("subscription = %q", got)
	}
	// ARM echoes `resourceGroups` and `resourcegroups` for the same group
	// depending on which surface produced the reference.
	if got := ResourceIDSegment(id, "resourcegroups"); got != "rg-prod" {
		t.Errorf("resource group must match case-insensitively, got %q", got)
	}
	if got := ResourceIDSegment("not-a-resource-id", "subscriptions"); got != "" {
		t.Errorf("a non-id must answer empty, got %q", got)
	}
}
