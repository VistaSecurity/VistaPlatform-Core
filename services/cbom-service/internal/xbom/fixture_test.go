package xbom

import (
	"time"

	"github.com/google/uuid"
)

// The fixture tenant. Fixed UUIDs, not uuid.New(): every one of them ends up in
// a bom-ref, a property value or an OCSF `device.uid`, so a random id would
// make the golden files unrepeatable and the byte-stability assertion vacuous.
//
// Addresses are from the RFC 5737 documentation ranges, and MAC addresses from
// the IANA documentation OUI (00:53:00). Real lab addressing is rejected by the
// public-tree export's leak gate — including inside a comment, which has broken
// main more than once — and this file ships in the open-source tree.
var (
	fixtureTenant = uuid.MustParse("11111111-1111-4111-8111-111111111111")
	fixtureSerial = uuid.MustParse("22222222-2222-4222-8222-222222222222")

	assetServer   = uuid.MustParse("a0000000-0000-4000-8000-000000000001")
	assetSwitch   = uuid.MustParse("a0000000-0000-4000-8000-000000000002")
	assetService  = uuid.MustParse("a0000000-0000-4000-8000-000000000003")
	assetBucket   = uuid.MustParse("a0000000-0000-4000-8000-000000000004")
	productSSL    = uuid.MustParse("b0000000-0000-4000-8000-000000000001")
	productNginx  = uuid.MustParse("b0000000-0000-4000-8000-000000000002")
	endpointHTTPS = uuid.MustParse("c0000000-0000-4000-8000-000000000001")
	endpointSSH   = uuid.MustParse("c0000000-0000-4000-8000-000000000002")
	findingCVE    = uuid.MustParse("d0000000-0000-4000-8000-000000000001")
	findingNoCVE  = uuid.MustParse("d0000000-0000-4000-8000-000000000002")
)

func fixtureTime() time.Time { return time.Date(2026, 9, 12, 10, 30, 0, 0, time.UTC) }

// fixtureSnapshot is one of every shape the assembler has to handle:
//
//   - a Linux server with OS facts, software, two endpoints and a CVE
//   - a switch (hardware, no OS facts, one identifier) so the HBOM has two rows
//     and the OCSF device type mapping has a non-server case
//   - a business service, whose class maps to CycloneDX `service` rather than a
//     component — the split the class registry dictates
//   - an object-storage bucket, whose class maps to `data` and whose OCSF
//     device type is 0/Unknown — the "we do not know" case that must not become
//     99/Other
//   - a fact key with TWO sources, so the per-source property naming is
//     exercised rather than assumed
//   - a vulnerability finding WITHOUT a CVE id, so the "absent stays absent"
//     path is covered by a golden file and not only by a comment
func fixtureSnapshot() *Snapshot {
	t := fixtureTime()
	earlier := t.Add(-720 * time.Hour)
	published := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	score := 9.8

	return &Snapshot{
		Assets: []Asset{
			{
				ID: assetServer, ClassKey: "server", ClassPath: "hardware.computer.server",
				DisplayName: "web-01", Hostname: "web-01.example.com", PrimaryAddress: "192.0.2.10",
				Environment: "production", BusinessUnit: "Platform", OwnerEmail: "ops@example.com",
				Site: "dc1", Region: "us-east", Zone: "a",
				AssetStatus: "monitoring", AssetOwnership: "internal", RiskScore: 72,
				FirstSeenAt: earlier, LastSeenAt: t,
				Tags: map[string]string{"tier": "1", "pci": "in-scope"},
			},
			{
				ID: assetSwitch, ClassKey: "switch", ClassPath: "hardware.network_device.switch",
				DisplayName: "", Hostname: "", PrimaryAddress: "192.0.2.20",
				AssetStatus: "monitoring", AssetOwnership: "internal", RiskScore: 10,
				FirstSeenAt: earlier, LastSeenAt: t,
				Tags: map[string]string{},
			},
			{
				ID: assetService, ClassKey: "business_service", ClassPath: "service.business_service",
				DisplayName: "Checkout", Environment: "production",
				AssetStatus: "monitoring", AssetOwnership: "internal", RiskScore: 0,
				FirstSeenAt: earlier, LastSeenAt: t,
				Tags: map[string]string{},
			},
			{
				ID: assetBucket, ClassKey: "object_storage", ClassPath: "cloud_resource.object_storage",
				DisplayName: "reports-bucket",
				AssetStatus: "monitoring", AssetOwnership: "internal", RiskScore: 40,
				FirstSeenAt: earlier, LastSeenAt: t,
				Tags: map[string]string{},
			},
		},
		Identifiers: []Identifier{
			{AssetID: assetServer, Kind: "fqdn", Value: "web-01.example.com"},
			{AssetID: assetServer, Kind: "hostname", Value: "web-01"},
			{AssetID: assetServer, Kind: "ip_address", Value: "192.0.2.10"},
			{AssetID: assetServer, Kind: "mac_address", Value: "00:53:00:00:00:10"},
			{AssetID: assetSwitch, Kind: "ip_address", Value: "192.0.2.20"},
			{AssetID: assetSwitch, Kind: "serial_number", Value: "FOC2201X0AB"},
		},
		Endpoints: []Endpoint{
			{
				ID: endpointHTTPS, AssetID: assetServer, Address: "192.0.2.10",
				FQDN: "web-01.example.com", Port: 443, HasPort: true,
				Transport: "tcp", Protocol: "https", ServiceName: "nginx",
				ServiceVersion: "1.27.0", Status: "active",
			},
			{
				ID: endpointSSH, AssetID: assetServer, Address: "192.0.2.10",
				Port: 22, HasPort: true, Transport: "tcp", Protocol: "ssh",
				Status: "active",
			},
		},
		Facts: []Fact{
			// os.name from two sources — the disagreement the per-source
			// property naming exists to preserve.
			{AssetID: assetServer, Key: "os.name", Value: "Ubuntu", SourceKind: "measured", SourceRef: "agent:1", ObservedAt: t},
			{AssetID: assetServer, Key: "os.name", Value: "Ubuntu Linux", SourceKind: "imported", SourceRef: "cmdb", ObservedAt: t},
			{AssetID: assetServer, Key: "os.version", Value: "24.04.1 LTS", SourceKind: "measured", SourceRef: "agent:1", ObservedAt: t},
			{AssetID: assetServer, Key: "os.kernel", Value: "6.8.0-45-generic", SourceKind: "measured", SourceRef: "agent:1", ObservedAt: t},
			{AssetID: assetServer, Key: "hw.vendor", Value: "Dell Inc.", SourceKind: "measured", SourceRef: "agent:1", ObservedAt: t},
			{AssetID: assetServer, Key: "hw.model", Value: "PowerEdge R650", SourceKind: "measured", SourceRef: "agent:1", ObservedAt: t},
			{AssetID: assetSwitch, Key: "hw.vendor", Value: "Cisco Systems", SourceKind: "measured", SourceRef: "sensor:1", ObservedAt: t},
			{AssetID: assetSwitch, Key: "hw.model", Value: "Catalyst 9300-48P", SourceKind: "measured", SourceRef: "sensor:1", ObservedAt: t},
			{AssetID: assetSwitch, Key: "hw.firmware_version", Value: "17.09.04a", SourceKind: "measured", SourceRef: "sensor:1", ObservedAt: t},
		},
		Software: []SoftwareInstall{
			{
				AssetID: assetServer, ProductID: productSSL, InstallPath: "/usr/lib/x86_64-linux-gnu",
				Name: "openssl", Vendor: "OpenSSL", Version: "3.0.14",
				CPE:  "cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*",
				PURL: "pkg:deb/ubuntu/openssl@3.0.14", LicenseID: "Apache-2.0",
			},
			{
				AssetID: assetSwitch, ProductID: productSSL, InstallPath: "",
				Name: "openssl", Vendor: "OpenSSL", Version: "3.0.14",
				CPE:  "cpe:2.3:a:openssl:openssl:3.0.14:*:*:*:*:*:*:*",
				PURL: "pkg:deb/ubuntu/openssl@3.0.14", LicenseID: "Apache-2.0",
			},
			{
				AssetID: assetServer, ProductID: productNginx, InstallPath: "/usr/sbin/nginx",
				Name: "nginx", Vendor: "F5", Version: "1.27.0",
				PURL: "pkg:deb/ubuntu/nginx@1.27.0",
			},
		},
		Relationships: []Relationship{
			{FromAssetID: assetService, ToAssetID: assetServer, Type: "depends_on", Status: "active"},
			{FromAssetID: assetServer, ToAssetID: assetSwitch, Type: "connects_to", Status: "active"},
		},
		Vulns: []VulnerabilityFinding{
			{
				ID: findingCVE, Kind: "known_vulnerability", SubjectType: "asset",
				SubjectID: assetServer, SubjectLbl: "web-01", Severity: "critical",
				Score: 98, Summary: "openssl 3.0.14 is affected by CVE-2026-0001",
				FirstSeen: earlier, LastSeen: t, CVEID: "CVE-2026-0001",
				CVSSVersion: "3.1", CVSSScore: &score,
				CVSSVector:  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
				CVSSeverity: "critical",
				Description: "A flaw in the fixture library.",
				PublishedAt: &published,
			},
			{
				// No CVE id, no catalogue row. Emits an entry with no `id`, no
				// `source`, no rating — "absent stays absent", pinned by the
				// golden file rather than only asserted in prose.
				ID: findingNoCVE, Kind: "known_vulnerability", SubjectType: "asset",
				SubjectID: assetSwitch, SubjectLbl: "192.0.2.20", Severity: "medium",
				Score: 50, Summary: "Vendor advisory with no CVE assigned",
				FirstSeen: earlier, LastSeen: t,
			},
		},
	}
}

func fixtureInput() DocumentInput {
	return DocumentInput{
		SerialNumber: fixtureSerial,
		GeneratedAt:  fixtureTime(),
		ScopeName:    "Production",
		ToolVersion:  "1.0.0",
	}
}
