package xbom

// OCSF export — the SIEM-facing projection of an `inventory` artifact.
//
// Schema: OCSF **1.9.0**, pinned. Two classes:
//
//	Device Inventory Info  category_uid 5 (Discovery) · class_uid 5001
//	Vulnerability Finding  category_uid 2 (Findings)  · class_uid 2002
//
// The version is pinned rather than tracking "latest" because these events land
// in someone's SIEM, where a field that changes meaning between releases is a
// broken detection rule, not a deprecation notice. `metadata.version` states
// which version the reader is getting, on every event.
//
// Two rules govern what is written, and both are the same rule:
//
//  1. **No guessed fields.** Every value below comes from something the
//     platform measured or was told. Where OCSF has a field and we have no
//     answer, the field is ABSENT — not "", not 0, not "Unknown". The one
//     exception is `device.type_id`, which OCSF marks REQUIRED and whose
//     enumeration includes 0 = Unknown; an asset whose class has no OCSF
//     counterpart gets 0, which is the enumeration's own way of saying we do
//     not know.
//  2. **It is a projection of the artifact, not a fresh query.** The events are
//     built from the stored canonical bytes, so what a SIEM ingests is exactly
//     what the artifact's content hash covers and what an auditor verifying the
//     artifact would see. Re-querying the database at download time would
//     produce a stream that no longer matched the evidence it came from.
//
// The wire format is JSON Lines (`application/x-ndjson`) — one event per line,
// which is what every SIEM ingest path expects and what lets a large inventory
// stream instead of buffering as one array.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/cbom-service/internal/formatters"
)

// OCSFVersion is the OCSF schema version these events declare and conform to.
const OCSFVersion = "1.9.0"

// OCSF class and category identifiers (OCSF 1.9.0).
const (
	ocsfCategoryDiscovery = 5
	ocsfCategoryFindings  = 2

	ocsfClassDeviceInventoryInfo  = 5001
	ocsfClassVulnerabilityFinding = 2002

	// Discovery activity 2 = Collect: "the discovered information is via a
	// collection process", which is what a scope-driven inventory snapshot is.
	// 1 (Log) would claim the information came out of a log.
	ocsfActivityCollect = 2
	// Findings activity 1 = Create.
	ocsfActivityCreate = 1

	// severity_id 1 = Informational. An inventory record is not an alert; a
	// higher severity would make every asset in a fleet page someone.
	ocsfSeverityInformational = 1
)

// ocsfProductName / Vendor identify the producer on every event.
const (
	ocsfProductName = "Vista Platform"
	ocsfVendorName  = "Vista Security"
)

// RenderOCSF projects an inventory artifact's canonical CycloneDX bytes into an
// OCSF 1.9.0 NDJSON event stream.
//
// It returns the body and the content type. An artifact with no assets yields
// an EMPTY body, not an empty array and not an error — zero lines is what "no
// events" looks like in NDJSON, and every ingest path handles it.
func RenderOCSF(canonicalBytes []byte) ([]byte, string, error) {
	var doc formatters.CDXDocument
	if err := json.Unmarshal(canonicalBytes, &doc); err != nil {
		return nil, "", fmt.Errorf("xbom: unmarshal canonical cyclonedx: %w", err)
	}

	// The artifact's own timestamp, not now(): these events describe the moment
	// the snapshot was taken. Stamping them with the download time would tell a
	// SIEM the inventory was observed when someone happened to click Export.
	observed := parseRFC3339(docTimestamp(&doc))

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)

	for i := range doc.Components {
		event, ok := deviceInventoryEvent(&doc, &doc.Components[i], observed)
		if !ok {
			continue
		}
		if err := enc.Encode(event); err != nil {
			return nil, "", fmt.Errorf("xbom: encode device event: %w", err)
		}
	}
	for i := range doc.Vulnerabilities {
		event := vulnerabilityFindingEvent(&doc, &doc.Vulnerabilities[i], observed)
		if err := enc.Encode(event); err != nil {
			return nil, "", fmt.Errorf("xbom: encode vulnerability event: %w", err)
		}
	}

	return buf.Bytes(), "application/x-ndjson", nil
}

// ocsfEvent is the base-event envelope both classes share.
//
// OCSF requires exactly seven base fields: activity_id, category_uid, class_uid,
// metadata, severity_id, time, type_uid. Everything else here is `recommended`
// or `optional` and is omitempty, so an absent answer is an absent key.
type ocsfEvent struct {
	ActivityID   int    `json:"activity_id"`
	ActivityName string `json:"activity_name,omitempty"`
	CategoryUID  int    `json:"category_uid"`
	CategoryName string `json:"category_name,omitempty"`
	ClassUID     int    `json:"class_uid"`
	ClassName    string `json:"class_name,omitempty"`
	TypeUID      int    `json:"type_uid"`
	TypeName     string `json:"type_name,omitempty"`
	SeverityID   int    `json:"severity_id"`
	Severity     string `json:"severity,omitempty"`
	// Time is milliseconds since the Unix epoch — OCSF's `timestamp_t`.
	Time     int64                 `json:"time"`
	Metadata ocsfMetadata          `json:"metadata"`
	Device   *ocsfDevice           `json:"device,omitempty"`
	Finding  *ocsfFinding          `json:"finding_info,omitempty"`
	Vulns    []ocsfVuln            `json:"vulnerabilities,omitempty"`
	Resource []ocsfResourceDetails `json:"resources,omitempty"`
	StatusID int                   `json:"status_id,omitempty"`
	Status   string                `json:"status,omitempty"`
}

type ocsfMetadata struct {
	Version string      `json:"version"`
	Product ocsfProduct `json:"product"`
	// LogName names the producing surface so a SIEM can route on it without
	// parsing the class.
	LogName string `json:"log_name,omitempty"`
	// OriginalTime is the artifact's own generation timestamp in text form —
	// OCSF `original_time` is "the original event time as reported by the
	// source", and for a snapshot that is when the snapshot was taken.
	OriginalTime string `json:"original_time,omitempty"`
	// Correlation is the artifact's serial number: every event from one
	// artifact shares it, so a SIEM can group a whole snapshot.
	CorrelationUID string `json:"correlation_uid,omitempty"`
}

type ocsfProduct struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version,omitempty"`
}

// ocsfDevice is the OCSF Device object. `type_id` is the only required field.
type ocsfDevice struct {
	TypeID     int     `json:"type_id"`
	Type       string  `json:"type,omitempty"`
	UID        string  `json:"uid,omitempty"`
	Name       string  `json:"name,omitempty"`
	Hostname   string  `json:"hostname,omitempty"`
	IP         string  `json:"ip,omitempty"`
	MAC        string  `json:"mac,omitempty"`
	Domain     string  `json:"domain,omitempty"`
	VendorName string  `json:"vendor_name,omitempty"`
	Model      string  `json:"model,omitempty"`
	Region     string  `json:"region,omitempty"`
	Zone       string  `json:"zone,omitempty"`
	Desc       string  `json:"desc,omitempty"`
	OS         *ocsfOS `json:"os,omitempty"`
	RiskScore  *int    `json:"risk_score,omitempty"`
	// FirstSeenTime / LastSeenTime are epoch milliseconds.
	FirstSeenTime *int64 `json:"first_seen_time,omitempty"`
	LastSeenTime  *int64 `json:"last_seen_time,omitempty"`
}

// ocsfOS is the OCSF OS object. `name` and `type_id` are both required, so the
// object is emitted ONLY when an os.name fact exists — an OS object with no
// name would be an assertion that the device has an operating system we did not
// observe.
type ocsfOS struct {
	Name    string `json:"name"`
	TypeID  int    `json:"type_id"`
	Type    string `json:"type,omitempty"`
	Version string `json:"version,omitempty"`
	// KernelRelease is OCSF's own field name for what we call os.kernel.
	KernelRelease string `json:"kernel_release,omitempty"`
	CPEName       string `json:"cpe_name,omitempty"`
}

// ocsfFinding is the OCSF Finding Info object. `uid` is required.
type ocsfFinding struct {
	UID           string   `json:"uid"`
	Title         string   `json:"title,omitempty"`
	Desc          string   `json:"desc,omitempty"`
	Types         []string `json:"types,omitempty"`
	SrcURL        string   `json:"src_url,omitempty"`
	CreatedTime   *int64   `json:"created_time,omitempty"`
	FirstSeenTime *int64   `json:"first_seen_time,omitempty"`
	LastSeenTime  *int64   `json:"last_seen_time,omitempty"`
}

// ocsfVuln is the OCSF Vulnerability object.
type ocsfVuln struct {
	CVE           *ocsfCVE `json:"cve,omitempty"`
	Title         string   `json:"title,omitempty"`
	Desc          string   `json:"desc,omitempty"`
	Severity      string   `json:"severity,omitempty"`
	VendorName    string   `json:"vendor_name,omitempty"`
	FirstSeenTime *int64   `json:"first_seen_time,omitempty"`
	LastSeenTime  *int64   `json:"last_seen_time,omitempty"`
}

// ocsfCVE is the OCSF CVE object. `uid` is required, which is why a finding
// naming no CVE carries no `cve` at all.
type ocsfCVE struct {
	UID          string     `json:"uid"`
	Title        string     `json:"title,omitempty"`
	Desc         string     `json:"desc,omitempty"`
	CVSS         []ocsfCVSS `json:"cvss,omitempty"`
	CreatedTime  *int64     `json:"created_time,omitempty"`
	ModifiedTime *int64     `json:"modified_time,omitempty"`
}

// ocsfCVSS is the OCSF CVSS object. `version` and `base_score` are both
// required, so the array is emitted only when the catalogue has both.
type ocsfCVSS struct {
	Version      string  `json:"version"`
	BaseScore    float64 `json:"base_score"`
	VectorString string  `json:"vector_string,omitempty"`
	Severity     string  `json:"severity,omitempty"`
	VendorName   string  `json:"vendor_name,omitempty"`
}

// ocsfResourceDetails names the affected resource on a vulnerability finding.
type ocsfResourceDetails struct {
	UID      string `json:"uid,omitempty"`
	Name     string `json:"name,omitempty"`
	Type     string `json:"type,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	IP       string `json:"ip,omitempty"`
}

// deviceInventoryEvent projects one CycloneDX component into a 5001 event.
//
// Returns ok=false for a component that is not an asset — the document's own
// metadata.component, for one, which describes the BOM rather than anything
// inventoried. The `vista:asset:uid` property is the test: it is present on
// every asset component this package emits and on nothing else.
func deviceInventoryEvent(doc *formatters.CDXDocument, c *formatters.CDXComponent, observed time.Time) (*ocsfEvent, bool) {
	assetUID := propertyValue(c.Properties, propAssetUID)
	if assetUID == "" {
		return nil, false
	}

	classKey := propertyValue(c.Properties, propAssetClass)
	device := &ocsfDevice{
		TypeID: ocsfDeviceTypeID(classKey),
		Type:   ocsfDeviceTypeName(classKey),
		UID:    assetUID,
		Name:   c.Name,
		Desc:   c.Description,
	}
	device.Hostname = firstNonEmpty(
		propertyValue(c.Properties, propIDPrefix+"fqdn"),
		propertyValue(c.Properties, propIDPrefix+"hostname"),
	)
	device.IP = propertyValue(c.Properties, propIDPrefix+"ip_address")
	device.MAC = propertyValue(c.Properties, propIDPrefix+"mac_address")
	device.VendorName = factProperty(c.Properties, "hw.vendor")
	device.Model = factProperty(c.Properties, "hw.model")
	device.Region = propertyValue(c.Properties, propAssetRegn)
	device.Zone = propertyValue(c.Properties, propAssetZone)
	// `domain` is the FQDN's parent, and only when the FQDN actually has one.
	// Deriving it from a bare hostname would invent a domain.
	if fqdn := propertyValue(c.Properties, propIDPrefix+"fqdn"); strings.Contains(fqdn, ".") {
		device.Domain = fqdn[strings.Index(fqdn, ".")+1:]
	}
	if score, err := strconv.Atoi(propertyValue(c.Properties, propAssetRisk)); err == nil {
		device.RiskScore = &score
	}
	device.FirstSeenTime = epochMillisPtr(propertyValue(c.Properties, propAssetFirst))
	device.LastSeenTime = epochMillisPtr(propertyValue(c.Properties, propAssetLast))
	device.OS = ocsfOSObject(c.Properties)

	return &ocsfEvent{
		ActivityID:   ocsfActivityCollect,
		ActivityName: "Collect",
		CategoryUID:  ocsfCategoryDiscovery,
		CategoryName: "Discovery",
		ClassUID:     ocsfClassDeviceInventoryInfo,
		ClassName:    "Device Inventory Info",
		TypeUID:      ocsfClassDeviceInventoryInfo*100 + ocsfActivityCollect,
		TypeName:     "Device Inventory Info: Collect",
		SeverityID:   ocsfSeverityInformational,
		Severity:     "Informational",
		Time:         epochMillis(observed),
		Metadata:     ocsfMetadataFor(doc, observed),
		Device:       device,
	}, true
}

// vulnerabilityFindingEvent projects one CycloneDX vulnerability into a 2002
// event.
func vulnerabilityFindingEvent(doc *formatters.CDXDocument, v *formatters.CDXVulnerability, observed time.Time) *ocsfEvent {
	findingUID := propertyValue(v.Properties, propVulnFind)
	if findingUID == "" {
		// `finding_info.uid` is required. The bom-ref is the artifact's own
		// handle for this entry and is unique within the document, so it is a
		// true identifier even when the finding id property is missing.
		findingUID = v.BOMRef
	}

	finding := &ocsfFinding{
		UID:           findingUID,
		Title:         firstNonEmpty(v.ID, v.Detail),
		Desc:          firstNonEmpty(v.Description, v.Detail),
		CreatedTime:   epochMillisPtr(v.Created),
		FirstSeenTime: epochMillisPtr(propertyValue(v.Properties, propVulnFirst)),
		LastSeenTime:  epochMillisPtr(propertyValue(v.Properties, propVulnLast)),
	}
	if kind := propertyValue(v.Properties, propVulnKind); kind != "" {
		finding.Types = []string{kind}
	}
	if v.Source != nil {
		finding.SrcURL = v.Source.URL
	}

	vuln := ocsfVuln{
		Title:         v.ID,
		Desc:          firstNonEmpty(v.Description, v.Detail),
		Severity:      ocsfSeverityLabel(propertyValue(v.Properties, propVulnSev)),
		FirstSeenTime: finding.FirstSeenTime,
		LastSeenTime:  finding.LastSeenTime,
	}
	if v.ID != "" {
		cve := &ocsfCVE{
			UID:          v.ID,
			Desc:         v.Description,
			CreatedTime:  epochMillisPtr(v.Published),
			ModifiedTime: epochMillisPtr(v.Updated),
		}
		if len(v.Ratings) > 0 && v.Ratings[0].Score != nil {
			r := v.Ratings[0]
			version := cvssVersionFromMethod(r.Method)
			// Both `version` and `base_score` are required on an OCSF CVSS
			// object. A rating whose method we could not map has no version to
			// state, and an invented one would be a claim about which scoring
			// system produced the number.
			if version != "" {
				cve.CVSS = []ocsfCVSS{{
					Version:      version,
					BaseScore:    *r.Score,
					VectorString: r.Vector,
					Severity:     r.Severity,
					VendorName:   ratingSourceName(r),
				}}
			}
		}
		vuln.CVE = cve
		if v.Source != nil {
			vuln.VendorName = v.Source.Name
		}
	}

	event := &ocsfEvent{
		ActivityID:   ocsfActivityCreate,
		ActivityName: "Create",
		CategoryUID:  ocsfCategoryFindings,
		CategoryName: "Findings",
		ClassUID:     ocsfClassVulnerabilityFinding,
		ClassName:    "Vulnerability Finding",
		TypeUID:      ocsfClassVulnerabilityFinding*100 + ocsfActivityCreate,
		TypeName:     "Vulnerability Finding: Create",
		SeverityID:   ocsfSeverityIDFor(propertyValue(v.Properties, propVulnSev)),
		Severity:     ocsfSeverityLabel(propertyValue(v.Properties, propVulnSev)),
		Time:         epochMillis(observed),
		Metadata:     ocsfMetadataFor(doc, observed),
		Finding:      finding,
		Vulns:        []ocsfVuln{vuln},
		// status_id 1 = New. The artifact records ACTIVE findings only, and
		// "new" is what an event stream calls one it is reporting for the first
		// time. Triage state lives in the platform, not in the export.
		StatusID: 1,
		Status:   "New",
	}

	if len(v.Affects) > 0 {
		if res := resourceForRef(doc, v.Affects[0].Ref); res != nil {
			event.Resource = []ocsfResourceDetails{*res}
		}
	}
	return event
}

// resourceForRef resolves an `affects` bom-ref back to the component it names,
// so the event says WHICH asset is affected rather than only naming a ref.
func resourceForRef(doc *formatters.CDXDocument, ref string) *ocsfResourceDetails {
	for i := range doc.Components {
		c := &doc.Components[i]
		if c.BOMRef != ref {
			continue
		}
		return &ocsfResourceDetails{
			UID:      propertyValue(c.Properties, propAssetUID),
			Name:     c.Name,
			Type:     propertyValue(c.Properties, propAssetClass),
			Hostname: propertyValue(c.Properties, propIDPrefix+"hostname"),
			IP:       propertyValue(c.Properties, propIDPrefix+"ip_address"),
		}
	}
	return nil
}

func ocsfMetadataFor(doc *formatters.CDXDocument, observed time.Time) ocsfMetadata {
	return ocsfMetadata{
		Version: OCSFVersion,
		Product: ocsfProduct{
			Name:       ocsfProductName,
			VendorName: ocsfVendorName,
		},
		LogName:        "vista.inventory_artifact",
		OriginalTime:   utcRFC3339(observed),
		CorrelationUID: strings.TrimPrefix(doc.SerialNumber, "urn:uuid:"),
	}
}

// ocsfOSObject builds the OS object from os.* facts, or nothing.
//
// Nothing when there is no os.name: `name` and `type_id` are both required, and
// an OS object carrying only a version would assert that the device runs an
// operating system whose name we did not observe.
func ocsfOSObject(props []formatters.CDXProperty) *ocsfOS {
	name := factProperty(props, "os.name")
	if name == "" {
		return nil
	}
	// The hardware the OS runs on is the only Apple signal a bare "IOS 15.2"
	// can have. See [isAppleIOS] for why it is needed at all.
	typeID, typeName := ocsfOSTypeFor(name, factProperty(props, "hw.vendor"), factProperty(props, "hw.model"))
	return &ocsfOS{
		Name:          name,
		TypeID:        typeID,
		Type:          typeName,
		Version:       factProperty(props, "os.version"),
		KernelRelease: factProperty(props, "os.kernel"),
		CPEName:       factProperty(props, "sw.cpe"),
	}
}

// ocsfDeviceTypeID maps an asset class key onto the OCSF device `type_id`
// enumeration (OCSF 1.9.0: 0 Unknown, 1 Server, 2 Desktop, 3 Laptop, 4 Tablet,
// 5 Mobile, 6 Virtual, 7 IOT, 8 Browser, 9 Firewall, 10 Switch, 11 Hub,
// 12 Router, 13 IDS, 14 IPS, 15 Load Balancer, 99 Other).
//
// A class with no OCSF counterpart maps to 0 (Unknown), NOT to 99 (Other). The
// difference matters: 99 says "a kind OCSF does not model", which would be a
// claim about OCSF; 0 says "we do not know", which is a claim about us, and it
// is the true one — an object-storage bucket is a real kind of thing, OCSF's
// device enumeration simply is not where it belongs.
func ocsfDeviceTypeID(classKey string) int {
	switch classKey {
	case "server", "compute_instance", "managed_database", "database_instance":
		return 1
	case "workstation":
		return 2
	case "laptop":
		return 3
	case "mobile":
		return 5
	case "virtual", "virtual_machine", "container", "hypervisor", "cluster":
		return 6
	case "iot_device", "ot_device", "plc", "rtu", "hmi", "ied", "printer", "access_point", "bmc":
		return 7
	case "firewall", "vpn_gateway":
		return 9
	case "switch":
		return 10
	case "router":
		return 12
	case "load_balancer", "cloud_load_balancer":
		return 15
	default:
		return 0
	}
}

func ocsfDeviceTypeName(classKey string) string {
	return map[int]string{
		0:  "Unknown",
		1:  "Server",
		2:  "Desktop",
		3:  "Laptop",
		5:  "Mobile",
		6:  "Virtual",
		7:  "IOT",
		9:  "Firewall",
		10: "Switch",
		12: "Router",
		15: "Load Balancer",
	}[ocsfDeviceTypeID(classKey)]
}

// ocsfOSTypeFor maps an OS product name onto the OCSF OS `type_id` enumeration
// (0 Unknown, 99 Other, 100 Windows, 101 Windows Mobile, 200 Linux,
// 201 Android, 300 macOS, 301 iOS, 302 iPadOS, 400 Solaris, 401 AIX,
// 402 HP-UX).
//
// The match is on the vendor's own product name, which is what `os.name` holds.
// An unrecognised name is 0 (Unknown) — a firewall running PAN-OS or FortiOS
// has an operating system, and guessing at one from a substring would be a
// fabricated platform attribution in a document a SIEM correlates on.
// The `hints` are other things known about the same device — `hw.vendor` and
// `hw.model` — consulted only by [isAppleIOS], which is the one mapping a
// product name cannot settle on its own.
func ocsfOSTypeFor(name string, hints ...string) (int, string) {
	lower := strings.ToLower(name)
	switch {
	case strings.Contains(lower, "windows"):
		return 100, "Windows"
	case strings.Contains(lower, "android"):
		return 201, "Android"
	case strings.Contains(lower, "ipados"):
		return 302, "iPadOS"
	case isAppleIOS(lower, hints...):
		return 301, "iOS"
	case strings.Contains(lower, "macos"), strings.Contains(lower, "mac os"), strings.Contains(lower, "darwin"):
		return 300, "macOS"
	case strings.Contains(lower, "solaris"):
		return 400, "Solaris"
	case strings.Contains(lower, "aix"):
		return 401, "AIX"
	case strings.Contains(lower, "hp-ux"), strings.Contains(lower, "hpux"):
		return 402, "HP-UX"
	case strings.Contains(lower, "linux"),
		strings.Contains(lower, "ubuntu"),
		strings.Contains(lower, "debian"),
		strings.Contains(lower, "rhel"),
		strings.Contains(lower, "red hat"),
		strings.Contains(lower, "centos"),
		strings.Contains(lower, "alpine"),
		strings.Contains(lower, "suse"),
		strings.Contains(lower, "fedora"),
		strings.Contains(lower, "rocky"),
		strings.Contains(lower, "almalinux"),
		strings.Contains(lower, "amazon linux"):
		return 200, "Linux"
	default:
		return 0, "Unknown"
	}
}

// isAppleIOS decides whether an os.name means Apple's iOS.
//
// A `strings.Contains(name, "ios")` test is wrong and was: **FortiOS**,
// PAN-OS's neighbours, Cisco's IOS-XE and IOS-XR all carry those three letters,
// and every one of them would have been reported to a SIEM as an Apple mobile
// device. A test caught it, which is the only reason this function exists as
// something other than one clause of a switch.
//
// So the rule is a whole-name one, not a substring one: the name IS "ios", or
// it begins "ios " followed by a version digit ("iOS 17.4"). Everything else —
// including every network OS that merely ends in "OS" — falls through to
// Unknown, which is the honest answer for a platform we have no mapping for.
//
// # Why the name alone is not enough
//
// The whole-name rule still gets "IOS 15.2" wrong, and that spelling is the
// COMMON one: `show version` on a Catalyst prints "IOS 15.2(4)E10" with no
// vendor word anywhere in it, because the device is not telling you who made
// it — it already knows. Cisco IOS releases 12.x–15.x predate iOS 15 by a
// decade and overlap it numerically, so there is no version range to split them
// on either. Name-only, the shapes are identical.
//
// So an Apple signal is REQUIRED, not merely an absence of Cisco ones: either
// the name itself carries one (iPhone, iPad, iPadOS, Apple) or one of the
// `hints` — the device's own `hw.vendor` / `hw.model` facts — does. With no
// such signal the answer is Unknown, which for a SIEM correlating on
// `os.type_id` is the difference between "we did not identify this platform"
// and "this is an Apple handset", asserted about a core switch.
func isAppleIOS(lower string, hints ...string) bool {
	// Cisco spells its own product with the same three letters, and unlike the
	// others it also puts them FIRST ("IOS-XE 17.9"), so the prefix rule alone
	// would not exclude it.
	for _, marker := range []string{"cisco", "ios-xe", "ios xe", "ios-xr", "ios xr"} {
		if strings.Contains(lower, marker) {
			return false
		}
	}
	return mentionsIOS(lower) && hasAppleSignal(append([]string{lower}, hints...))
}

// mentionsIOS reports whether the name names iOS at all, as a WORD.
//
// A token comparison rather than a substring one, which is the whole point:
// "fortios" contains "ios" and is not it, while "iOS 17.4" and "Apple iOS" both
// carry it as a word of its own. "iPhone OS" is the same product under its
// original name and is spelled out because no tokenisation would find "ios" in
// it.
func mentionsIOS(lower string) bool {
	if strings.Contains(lower, "iphone os") {
		return true
	}
	notAlnum := func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9')
	}
	for _, token := range strings.FieldsFunc(lower, notAlnum) {
		if token == "ios" {
			return true
		}
	}
	return false
}

// appleSignals are the words that mean the device is Apple's. Deliberately
// short: every one of them is a word no network-OS vendor uses, and a longer
// list bought with looser words would put the fabrication back.
var appleSignals = []string{"apple", "iphone", "ipad", "ipod", "watchos", "tvos"}

// hasAppleSignal reports whether any of the given strings names Apple.
func hasAppleSignal(values []string) bool {
	for _, v := range values {
		lower := strings.ToLower(v)
		for _, signal := range appleSignals {
			if strings.Contains(lower, signal) {
				return true
			}
		}
	}
	return false
}

// ocsfSeverityIDFor maps the findings registry's lowercase ladder onto the OCSF
// `severity_id` enumeration (0 Unknown, 1 Informational, 2 Low, 3 Medium,
// 4 High, 5 Critical, 6 Fatal, 99 Other).
func ocsfSeverityIDFor(severity string) int {
	switch strings.ToLower(severity) {
	case "info":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	default:
		return 0
	}
}

func ocsfSeverityLabel(severity string) string {
	return map[int]string{
		0: "Unknown",
		1: "Informational",
		2: "Low",
		3: "Medium",
		4: "High",
		5: "Critical",
	}[ocsfSeverityIDFor(severity)]
}

func ratingSourceName(r formatters.CDXVulnerabilityRating) string {
	if r.Source == nil {
		return ""
	}
	return r.Source.Name
}

// cvssVersionFromMethod inverts the CycloneDX scoreMethod enumeration back to
// the version string OCSF's CVSS object wants. An unmapped method yields empty,
// which suppresses the whole CVSS object — see the caller.
func cvssVersionFromMethod(method string) string {
	switch method {
	case "CVSSv2":
		return "2.0"
	case "CVSSv3":
		return "3.0"
	case "CVSSv31":
		return "3.1"
	case "CVSSv4":
		return "4.0"
	default:
		return ""
	}
}

func docTimestamp(doc *formatters.CDXDocument) string {
	if doc.Metadata == nil {
		return ""
	}
	return doc.Metadata.Timestamp
}

func parseRFC3339(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// epochMillis is OCSF's `timestamp_t`: milliseconds since the Unix epoch.
//
// A zero time yields 0, and `time` is a required field so it is emitted either
// way. That is not a guessed value — the document always carries a
// metadata.timestamp, so a zero here means the bytes were malformed, and 0
// (1970) is conspicuous rather than plausible.
func epochMillis(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// epochMillisPtr parses an RFC 3339 string into an optional epoch-millis
// pointer. An unparseable or absent value yields nil, so the field is ABSENT
// rather than 1970.
func epochMillisPtr(s string) *int64 {
	t := parseRFC3339(s)
	if t.IsZero() {
		return nil
	}
	ms := t.UnixMilli()
	return &ms
}
