package registrycatalog

import "github.com/vistasecurity/vistaplatform/shared/dcim"

// The closed value sets the validator enforces on first-class fields.
//
// Every list here is a COPY of something the database declares — a Postgres
// enum type, or the ARRAY of a CHECK constraint — and every one of them is
// pinned to `scripts/database/schema.sql` by TestEnumsMatchSchema, which parses
// the file and fails on any difference in either direction. That test is the
// only thing that makes these copies safe: a value added to the schema and not
// here would validate as `unknown_value` for a row the column happily holds,
// and a value here that the column cannot hold would validate and then return
// no rows forever.
//
// The lists are NOT read out of schema.sql at build or run time. A shared
// library cannot depend on a file two directories above the module root being
// present at runtime, and a catalogue that fails to construct when a deployment
// omits the SQL would be worse than a copy with a test.
//
// What is NOT here: anything a generated Go registry already holds. Identifier
// kinds come from shared/assetclass, fact keys from shared/facts, finding
// producers/kinds/subject types from shared/findings, relationship types from
// shared/query/ast. Copying those would be the same mistake one layer up.

// environmentValues is `public.environment_type`.
//
// §12 amendment 1 settled the contradiction this list used to sit in the middle
// of: §4.3 typed `environment` as the enum while §8 and §9 example 18 wrote
// `prod`, which is not a member. THE ENUM WINS — and it is not a close call
// here, because the column IS the Postgres type: a row holding `prod` cannot
// exist, so leaving the set open would turn a typo into an empty result instead
// of a diagnostic with a suggestion.
var environmentValues = []string{"production", "staging", "development", "test"}

// protocolValues is `public.protocol_type`.
//
// Note the five OT protocols after OPC_UA. The static test catalogue stops at
// OPC_UA and has been missing EtherNet_IP, BACnet, BACnet_SC, HART_IP and S7
// since they were added to the enum — which is exactly the drift a hand-copied
// list acquires, and exactly what TestEnumsMatchSchema now prevents.
var protocolValues = []string{
	"TLS", "SSH", "IPSec", "VPN", "Database", "API", "SMB", "Kerberos",
	"QUIC", "PPTP", "IKE",
	"Modbus", "DNP3", "MMS", "ICCP", "IEC62351", "OPC_UA",
	"EtherNet_IP", "BACnet", "BACnet_SC", "HART_IP", "S7",
}

// sourceKindValues is the provenance vocabulary of ADR-0005 D2, carried by a
// `*_source_kind_check` CHECK on assets, asset_endpoints, asset_identifiers,
// asset_facts, asset_relationships, software_installs and findings alike. It is
// also the precedence order the fact reconciliation reads (§13 A4), highest
// first, which is why it is ordered rather than sorted.
var sourceKindValues = []string{"measured", "declared", "imported", "inferred"}

// classSourceKindValues is `assets_class_source_kind_check`, which is
// sourceKindValues PLUS `rule` (asset-inventory workstream 2.10b).
//
// A separate list and not an append to the one above, because the difference is
// the point: `class_source_kind` is the ONLY column that accepts `rule`. A class
// argued from a curated classification_rules row is not `measured` — the MAC was
// measured, the MAC-to-class mapping was not — and not `inferred`, which
// ADR-0008 D4.2 defines as a model's proposal. Widening the shared list would
// make the query language accept `source=rule` on facts, endpoints,
// relationships, software installs and findings, whose CHECKs all refuse it:
// the predicate would validate and then return no rows for ever, which is the
// silent wrong answer this parity file exists to prevent.
var classSourceKindValues = []string{"measured", "declared", "imported", "inferred", "rule"}

// assetStatusValues is `assets_asset_status_check`.
var assetStatusValues = []string{"pending_approval", "monitoring", "denied", "archived"}

// identityStatusValues is `assets_identity_status_check`.
//
// `provisional` ( D1) is a real inventory row whose identity nothing has
// corroborated yet. It is in the column's CHECK, so it must be here too: a
// value the column holds but the catalogue omits makes `identity_status:provisional`
// answer "not a value of identity_status" for rows that exist — which is how
// the one filter a tenant needs to find their provisional items would 400.
var identityStatusValues = []string{"legacy", "established", "provisional", "operator_confirmed"}

// assetOwnershipValues is `assets_asset_ownership_check`.
var assetOwnershipValues = []string{"internal", "third_party", "unknown"}

// staleStatusValues is `assets_stale_status_check`.
var staleStatusValues = []string{"active", "stale", "archived"}

// interfaceModeValues is `interfaces_mode_check`.
var interfaceModeValues = []string{"access", "tagged", "tagged-all", "q-in-q"}

// rackFaceValues is `assets_face_check` (DCIM row 2.3): the face of a rack a
// placed asset is mounted on.
var rackFaceValues = []string{"front", "rear"}

// interfaceStatusValues is `interfaces_status_check` (the asset lifecycle).
var interfaceStatusValues = []string{"pending", "active", "rejected", "stale", "archived"}

// interfaceOperStatusValues is `interfaces_operational_status_check`.
var interfaceOperStatusValues = []string{"up", "down", "testing", "unknown"}

// endpointTransportValues is `asset_endpoints_transport_check`.
var endpointTransportValues = []string{"tcp", "udp", "none"}

// endpointStatusValues is `asset_endpoints_status_check`.
var endpointStatusValues = []string{"active", "stale", "closed"}

// softwareInstallStatusValues is `software_installs_status_check`.
var softwareInstallStatusValues = []string{"active", "stale", "removed"}

// relationshipStatusValues is `asset_relationships_status_check`.
var relationshipStatusValues = []string{"pending", "active", "rejected", "stale"}

// findingDetectionStateValues is `findings_detection_state_check`.
var findingDetectionStateValues = []string{"ACTIVE", "INACTIVE", "ARCHIVED"}

// findingWorkflowStatusValues is `findings_workflow_status_check`.
var findingWorkflowStatusValues = []string{"NEW", "NOTIFIED", "RESOLVED", "SUPPRESSED"}

// certificateStateValues is `valid_certificate_state` on `certificates`.
var certificateStateValues = []string{
	"pre-activation", "active", "suspended", "deactivated", "revoked", "expired", "destroyed",
}

// certificateTrustStatusValues is `certificates_trust_status_check`.
// NULL — not yet evaluated — is not a value; `trust_status:*` / `exists`
// distinguish it.
var certificateTrustStatusValues = []string{
	"public", "private_trusted", "self_signed", "untrusted", "distrusted", "incomplete",
}

// certTrustAssetValues is the asset's derived `cert_trust`: the worst of its
// certificates' statuses, plus unevaluated and none (shared/query/sql
// CertTrustValues, which the translator's expression produces).
var certTrustAssetValues = []string{
	"public", "private_trusted", "incomplete", "self_signed", "untrusted", "distrusted", "unevaluated", "none",
}

// cryptoStrengthValues is §4.3's vocabulary for the derived `strength` field:
// the `algorithms.strength` catalogue column, read through the shared helper.
// It has no CHECK of its own, so it is not in the schema-parity test; the
// authority is the catalogue table and CLAUDE.md's "Crypto Assessment Source of
// Truth".
var cryptoStrengthValues = []string{"weak", "acceptable", "strong", "recommended"}

// observationSourceValues is the producer vocabulary of an in-flight
// discovery. The `observation` target has no table (§4.1), so there is no
// constraint to pin this to — it is the set of things that can present an
// observation to the identification engine.
var observationSourceValues = []string{"sensor", "cloud", "interrogation", "import", "manual", "agent"}

// observationKindValues says what an in-flight observation IS, as distinct from
// who produced it.
//
// The two are independent and both are needed: `source:sensor` covers a passive
// capture, an uploaded PCAP and an active scan alike, and until now there was no
// way to write a rule about the passive HOST-PRESENCE rows specifically — which
// is the thing a tenant most plausibly wants to auto-approve on a segment they
// own, and least plausibly wants to auto-approve everywhere.
//
//   - `crypto` — a cryptographic measurement: a negotiated protocol version, a
//     cipher suite, a certificate. Every finding the discovery pipeline produced
//     before asset-inventory workstream 2.5.
//   - `host_observation` — a passive statement that a host exists, with whatever
//     identity the frame carried (ARP, DHCP, mDNS, NetBIOS, LLDP, CDP). It
//     measured no cryptography; see
//     docsv4/internal/developer/architecture/discovery-host-observation.md.
//
// The set is deliberately NOT widened to cover the declared and imported intake
// paths. A spreadsheet row is neither a cryptographic measurement nor a passive
// host observation, and those paths leave the field ABSENT — which by §5.2 makes
// any predicate over `kind` Unknown for them, so a rule about kinds cannot fire
// on a thing whose kind nobody stated. Inventing a third value to cover them
// would be naming something the platform does not measure.
var observationKindValues = []string{"crypto", "host_observation"}

// observationNetworkOwnershipValues and observationNetworkTypeValues are the
// LIVE classifier's vocabulary — shared/approval's Classification.
//
// Ownership is internal/third_party/unknown and has no table to pin against:
// the classifier computes it, and those three values are its whole range.
//
// Type is the matching prefix's `network_type` when it is one of the four
// values the auto-approval generator and the scan-consent rules read (DCIM row
// 1.6; inventory-service prefix_context.go), else the address class
// (private/public). Four values, not two: it was once written here as
// {private, public} on the strength of the field's NAME, and a rule for a
// `cloud` or `vpn` network was refused outright, so every cloud network
// silently stopped generating one.
//
// §13 A8 is the same mistake in the other direction: §8 used to map
// `conditions.network_type` to `network.type:corporate`, and nothing in the
// platform has ever emitted "corporate". A rule written against the spec's word
// would have validated and then matched nothing. A closed set here has to come
// from what the platform WRITES, never from what a field sounds like.
var (
	observationNetworkOwnershipValues = []string{"internal", "third_party", "unknown"}
	observationNetworkTypeValues      = []string{"private", "public", "vpn", "cloud"}
)

// The IPAM closed sets (DCIM DATA_MODEL §5), equal to the schema's CHECKs on
// ip_addresses.operational_status / role and prefixes.operational_status.
var (
	ipStatusValues     = []string{"active", "reserved", "deprecated", "dhcp", "slaac"}
	ipRoleValues       = []string{"loopback", "secondary", "anycast", "vip", "vrrp", "hsrp", "glbp", "carp"}
	prefixStatusValues = []string{"container", "active", "reserved", "deprecated"}
	// wireless_lans.auth_type (row 4.4), shared/dcim/wireless.AuthTypes.
	wirelessAuthTypeValues = []string{"open", "wep", "wpa-personal", "wpa-enterprise"}
)

// virtualCircuitRoleValues is `virtual_circuit_terminations_role_check` (DCIM
// gap 10; NetBox VirtualCircuitTerminationRoleChoices).
var virtualCircuitRoleValues = []string{"peer", "hub", "spoke"}

// tunnelEncapsulationValues is `tunnels_encapsulation_check` (DCIM row 4.3).
var tunnelEncapsulationValues = []string{"ipsec-transport", "ipsec-tunnel", "ip-ip", "gre", "wireguard", "l2tp", "pptp", "openvpn"}

// cableTypeValues and cableStatusValues come from the generated DCIM type
// registry (standards/cable-types.yaml → shared/dcim), not a copy.
func cableTypeValues() []string {
	var out []string
	for _, t := range dcim.AllCableTypes() {
		out = append(out, string(t))
	}
	return out
}

func cableStatusValues() []string {
	var out []string
	for _, t := range dcim.AllCableStatuses() {
		out = append(out, string(t))
	}
	return out
}

// The power-feed choice sets (NetBox 4.3 PowerFeed*Choices; DCIM row 6.1).
// Not in standards/netbox-choices.v4.3.5.json; the schema CHECKs on
// power_feeds hold the same lists (schema_parity_test.go).
var (
	powerFeedStatusValues = []string{"offline", "active", "planned", "failed"}
	powerFeedTypeValues   = []string{"primary", "redundant"}
	powerFeedSupplyValues = []string{"ac", "dc"}
	powerFeedPhaseValues  = []string{"single-phase", "three-phase"}
)

// The inventory item stock states (DCIM gap 8; inventory_items_stock_state_check,
// schema_parity_test.go). Device42-style stock, so not a NetBox choice set.
var inventoryItemStockStateValues = []string{"installed", "in_stock", "reserved", "rma", "retired"}
