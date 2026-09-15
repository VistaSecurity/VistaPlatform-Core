package services

// The measurement SHAPES — the whitelist of FROM/JOIN skeletons a registry row
// may name (ADR-0005 D5, workstream 3.6).
//
// This file is to measurement extraction what shared/query/sql/shapes.go is to
// the query language: the join chains live in code, reviewed, rather than in the
// registry, so adding a way to reach the data is a deliberate act and not a
// YAML entry that silently starts generating queries. A shape owns
//
//   - the tables and how they join;
//   - the tenant predicate and the per-asset filter every extraction carries;
//   - the SOFT-DELETE predicates (see below — this is load-bearing);
//   - what the subject of a measurement is, and which column holds its id;
//   - the whole set of expressions a registry row may select, each with the
//     type it scans as.
//
// # Deleted inventory is not in scope, and forgetting that resurrects findings
//
// Asset deletion is a SOFT delete: inventory-service's DeleteAsset only stamps
// assets.deleted_at, and deliberately leaves the asset's crypto_implementations
// rows alone. FindingsService.OnAssetDeleted then flips that asset's findings to
// INACTIVE.
//
// Every asset-rooted shape therefore carries BOTH `deleted_at IS NULL`
// predicates where they exist. Without them a whole-tenant reconcile
// re-extracts the deleted asset, recomputes the same violation, and
// upsertFindings flips the INACTIVE rows straight back to ACTIVE — with
// workflow_status reset to NEW and resurfaced_at stamped, so the tenant loses
// triage state and their score drops again for an asset that no longer exists.
// The two predicates are independent: an asset delete sets only
// assets.deleted_at, while a crypto-implementation delete sets only
// crypto_implementations.deleted_at.
//
// The `certificates` shape needs no equivalent — that table has no deleted_at
// column; a certificate is either present or gone.

import (
	"database/sql"

	"github.com/google/uuid"
)

// scanKind names how a selectable's value is read out of a row.
const (
	scanText     = "text"     // nullable text
	scanTextNN   = "text_nn"  // NOT NULL text (a COALESCE or CASE expression)
	scanInt      = "int"      // nullable integer
	scanFloat    = "float"    // nullable double
	scanBool     = "bool"     // nullable boolean
	scanTime     = "time"     // nullable timestamptz
	scanUUIDList = "uuidlist" // a uuid published as a one-element list
)

// selectable is one expression a shape offers. The SQL is written here, never
// in the registry; `Dynamic` marks the one value a shape composes at extraction
// time from a compiled predicate.
type selectable struct {
	SQL  string
	Kind string
	// EmptyIsAbsent drops an empty string from the evidence instead of writing
	// `""`. It is set on the COALESCEd expressions, whose "absent" IS the empty
	// string; a plain nullable column says absent with NULL.
	EmptyIsAbsent bool
	// Dynamic names a value the executor builds rather than reads from this
	// map. Only the finding shape has one.
	Dynamic string
}

// measurementShape is a whitelisted extraction skeleton.
type measurementShape struct {
	Name string
	// Subject is the findings subject type a measurement over this shape is
	// about. The registry's own `subject` is checked against it.
	Subject string
	// Target and Alias: the query-language target a registry row's `where` is
	// compiled against, and the alias the compiled clause must use.
	Target string
	Alias  string
	// SubjectTarget and SubjectAlias: the same, for `subject_where`. Empty when
	// the shape does not offer one.
	SubjectTarget string
	SubjectAlias  string

	From string
	// Base predicates, in order. $1 is the tenant id and $2 the optional
	// single-asset filter for every shape.
	Base []string

	SubjectIDExpr  string
	TenantExpr     string
	MeasuredAt     map[string]string // name → expression; "" is the default
	OrderBy        map[string]string // name → expression; "" is the default
	Selectables    map[string]selectable
	EvidenceGroups map[string][]EvidenceProjection

	// NeedsFactKey / NeedsAssessedBy declare the extra bound parameter the
	// shape requires, which the generator checks the registry row supplies.
	NeedsFactKey    bool
	NeedsAssessedBy bool
}

// endpointEvidence is the "where was this measured" projection every
// crypto-configuration measurement carries, so the question is answered one way
// rather than eleven.
//
// A configuration names the endpoint it was observed on
// (crypto_implementations.endpoint_id, phase 1), so address and port come from
// THAT endpoint and nowhere else. The asset's own primary_address is read only
// when the configuration names no endpoint at all — an asset-level or at-rest
// observation, which correspondingly has no port. The two are deliberately not
// COALESCEd together: an endpoint identified only by FQDN carries address NULL,
// and substituting the asset's primary_address there would report the
// measurement as taken at an address nobody measured — the same fabrication the
// retired `AT-REST` port sentinel used to commit.
//
// `crypto_implementation_ids` is the one entry that is not about WHERE. A
// configuration measurement's SUBJECT is the asset — that is what the query
// selects and what the per-asset reconcile keys on — so the configuration the
// value was read from would otherwise be lost, and the inspector would have no
// way to link a finding to the thing that actually failed. It is a LIST because
// one asset routinely has several configurations while the reconcile keeps one
// finding per (control, asset): the ids union as the representative finding
// absorbs its siblings (mergeSubjectEvidence).
//
// It is NOT the finding's subject. `crypto_configuration` is reserved for the
// phase-3 configuration producer (workstream 3.5), which measures ONE
// configuration and will carry `crypto_implementations.id` in `subject_id`.
var endpointEvidence = []EvidenceProjection{
	{Key: "hostname", From: "hostname"},
	{Key: "ip_address", From: "ip_address"},
	{Key: "endpoint_fqdn", From: "endpoint_fqdn"},
	{Key: "port", From: "port"},
	{Key: EvidenceCryptoImplementationIDs, From: "crypto_implementation_id"},
}

// assetEvidence names the asset a hygiene or lifecycle measurement is about.
// hostname and ip_address are what subjectLabelFrom reads, so a finding whose
// subject has since been archived still reads as a name rather than a uuid.
var assetEvidence = []EvidenceProjection{
	{Key: "hostname", From: "hostname"},
	{Key: "ip_address", From: "ip_address"},
	{Key: "display_name", From: "display_name"},
	{Key: "class", From: "class_key"},
}

// measurementShapes is the whitelist, keyed by name.
var measurementShapes = map[string]measurementShape{

	// ---------------------------------------------------------- certificate
	"certificate": {
		Name:    "certificate",
		Subject: SubjectCertificate,
		Target:  "certificate",
		Alias:   "c",
		From:    "certificates c",
		// is_ca_certificate = false is part of the SHAPE, not of any one
		// measurement: every certificate control here describes the leaf
		// certificates a tenant serves, and a CA certificate judged against a
		// 398-day validity rule or a days-to-expiry threshold produces a
		// finding about somebody else's root.
		Base: []string{
			"c.tenant_id = $1",
			"($2::uuid IS NULL OR c.id = $2)",
			"c.is_ca_certificate = false",
		},
		SubjectIDExpr: "c.id",
		TenantExpr:    "c.tenant_id",
		MeasuredAt: map[string]string{
			"":    "c.updated_at",
			"now": "now()",
		},
		OrderBy: map[string]string{
			"":              "c.updated_at DESC",
			"not_after_asc": "c.not_after ASC",
		},
		Selectables: map[string]selectable{
			"expiration_days":      {SQL: "EXTRACT(EPOCH FROM (c.not_after - NOW())) / 86400.0", Kind: scanFloat},
			"validity_days":        {SQL: "EXTRACT(EPOCH FROM (c.not_after - c.not_before)) / 86400.0", Kind: scanFloat},
			"public_key_size":      {SQL: "c.public_key_size", Kind: scanInt},
			"public_key_algorithm": {SQL: "c.public_key_algorithm", Kind: scanText},
			"signature_algorithm":  {SQL: "c.signature_algorithm", Kind: scanText},
			"is_self_signed":       {SQL: "c.is_self_signed", Kind: scanBool},
			"common_name":          {SQL: "c.common_name", Kind: scanText},
			"issuer_dn":            {SQL: "c.issuer_dn", Kind: scanText},
			"not_after":            {SQL: "c.not_after", Kind: scanTime},
			"not_before":           {SQL: "c.not_before", Kind: scanTime},
		},
	},

	// ------------------------------------------------- crypto_configuration
	"crypto_configuration": {
		Name:    "crypto_configuration",
		Subject: SubjectAsset,
		Target:  "crypto_configuration",
		Alias:   "ci",
		// tenant_id appears in BOTH join conditions, which is not
		// belt-and-braces. `assets` and `asset_endpoints` are hash-partitioned
		// by tenant_id and keyed on (tenant_id, id) — neither has an index on
		// `id` alone. A join written `ON na.id = ci.asset_id` cannot use the
		// primary key at all and degenerates into a sequential scan of all
		// eight partitions per probe. Carrying ci.tenant_id into the condition
		// is what lets the planner prune to the one partition and seek.
		From: "crypto_implementations ci" +
			"\n\t\t\tJOIN assets na ON na.tenant_id = ci.tenant_id AND na.id = ci.asset_id" +
			"\n\t\t\tLEFT JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id",
		Base: []string{
			"ci.tenant_id = $1",
			"na.deleted_at IS NULL",
			"ci.deleted_at IS NULL",
			"($2::uuid IS NULL OR na.id = $2)",
		},
		SubjectIDExpr: "na.id",
		TenantExpr:    "ci.tenant_id",
		MeasuredAt: map[string]string{
			"":    "ci.last_verified_at",
			"now": "now()",
		},
		OrderBy: map[string]string{"": "ci.last_verified_at DESC"},
		Selectables: map[string]selectable{
			"protocol_version":       {SQL: "ci.protocol_version", Kind: scanText},
			"cipher_suite":           {SQL: "ci.cipher_suite", Kind: scanText},
			"key_exchange_algorithm": {SQL: "ci.key_exchange_algorithm", Kind: scanText},
			"signature_algorithm":    {SQL: "ci.signature_algorithm", Kind: scanText},
			"symmetric_encryption":   {SQL: "ci.symmetric_encryption", Kind: scanText},
			"hash_algorithm":         {SQL: "ci.hash_algorithm", Kind: scanText},
			"protocol":               {SQL: "ci.protocol::text", Kind: scanTextNN},
			"raw_data":               {SQL: "ci.raw_data", Kind: scanText},
			// TLS compression as the probe recorded it, three-valued. A
			// configuration whose raw_data carries no `compression` key, or
			// carries something that is not a boolean, yields NULL — and a NULL
			// value yields NO measurement, so the asset is reported as not
			// assessed for compression rather than as "compression disabled".
			//
			// The predecessor of this selectable answered `false` for every
			// configuration in existence. It uppercased raw_data and then
			// searched it for the lowercase literal `"compression":true`, which
			// no uppercased string can contain; jsonb also renders a space after
			// the colon, so even the same-case search would have missed. Two
			// independent reasons the check could not fire, in four lines.
			"tls_compression": {SQL: "CASE WHEN jsonb_typeof(ci.raw_data -> 'compression') = 'boolean'" +
				" THEN (ci.raw_data ->> 'compression')::boolean ELSE NULL END", Kind: scanBool},
			"cipher_suite_coalesced": {SQL: "COALESCE(NULLIF(ci.cipher_suite, ''), '')", Kind: scanTextNN, EmptyIsAbsent: true},
			// "Encrypted" means the row carries either a cipher_suite or a
			// non-empty symmetric_encryption — anything the sensor would record
			// only when actual crypto was negotiated. Plaintext OT (Modbus
			// without TLS, plaintext DNP3, plaintext S7, plaintext HART-IP)
			// leaves both empty. BACnet/SC always carries a TLS handshake so it
			// reads as "present" via cipher_suite.
			"ot_encryption_state": {SQL: "CASE WHEN COALESCE(NULLIF(ci.cipher_suite, ''), '') <> ''" +
				" OR COALESCE(NULLIF(ci.symmetric_encryption, ''), '') <> ''" +
				" THEN 'present' ELSE 'absent' END", Kind: scanTextNN},
			"hostname": {SQL: "na.hostname", Kind: scanText},
			"ip_address": {SQL: "host(CASE WHEN ci.endpoint_id IS NULL THEN na.primary_address ELSE e.address END)",
				Kind: scanText},
			"endpoint_fqdn":            {SQL: "e.fqdn", Kind: scanText},
			"port":                     {SQL: "e.port", Kind: scanInt},
			"crypto_implementation_id": {SQL: "ci.id", Kind: scanUUIDList},
		},
		EvidenceGroups: map[string][]EvidenceProjection{"endpoint": endpointEvidence},
	},

	// ----------------------------------------------------------------- asset
	"asset": {
		Name:          "asset",
		Subject:       SubjectAsset,
		Target:        "asset",
		Alias:         "a",
		SubjectTarget: "asset",
		SubjectAlias:  "a",
		From:          "assets a",
		Base: []string{
			"a.tenant_id = $1",
			"a.deleted_at IS NULL",
			"($2::uuid IS NULL OR a.id = $2)",
		},
		SubjectIDExpr: "a.id",
		TenantExpr:    "a.tenant_id",
		MeasuredAt: map[string]string{
			"":    "a.updated_at",
			"now": "now()",
		},
		OrderBy: map[string]string{"": "a.updated_at DESC"},
		Selectables: map[string]selectable{
			// Accountability is either a person or a group; the hygiene
			// producer's no_owner finding is "no owner_email AND no
			// support_group", and a column holding only whitespace is not an
			// answer.
			"owner_present": {SQL: "(COALESCE(NULLIF(btrim(a.owner_email), ''), NULLIF(btrim(a.support_group), '')) IS NOT NULL)", Kind: scanBool},
			"location_present": {SQL: "(COALESCE(NULLIF(btrim(a.site), ''), NULLIF(btrim(a.region), ''), NULLIF(btrim(a.zone), ''), a.location_id::text) IS NOT NULL)",
				Kind: scanBool},
			"class_key":      {SQL: "a.class_key", Kind: scanTextNN},
			"last_seen_days": {SQL: "EXTRACT(EPOCH FROM (now() - a.last_seen_at)) / 86400.0", Kind: scanFloat},
			"last_seen_at":   {SQL: "a.last_seen_at", Kind: scanTime},
			"owner_email":    {SQL: "a.owner_email", Kind: scanText},
			"support_group":  {SQL: "a.support_group", Kind: scanText},
			"site":           {SQL: "a.site", Kind: scanText},
			"region":         {SQL: "a.region", Kind: scanText},
			"hostname":       {SQL: "a.hostname", Kind: scanText},
			"display_name":   {SQL: "a.display_name", Kind: scanText},
			"ip_address":     {SQL: "host(a.primary_address)", Kind: scanText},
		},
		EvidenceGroups: map[string][]EvidenceProjection{"asset": assetEvidence},
	},

	// ------------------------------------------------------------------ fact
	// One row per asset_facts row with the declared key. An asset with no such
	// fact yields NO row at all, which is the entire point: a control over an
	// absent fact is NOT ASSESSED, and rule_evaluator reports it as such
	// (reasonNothingInScope) rather than scoring it 100.
	"fact": {
		Name:          "fact",
		Subject:       SubjectAsset,
		Target:        "asset",
		Alias:         "a",
		SubjectTarget: "asset",
		SubjectAlias:  "a",
		From: "asset_facts af" +
			"\n\t\t\tJOIN assets a ON a.tenant_id = af.tenant_id AND a.id = af.asset_id",
		Base: []string{
			"af.tenant_id = $1",
			"a.deleted_at IS NULL",
			"($2::uuid IS NULL OR a.id = $2)",
			"af.key = $3",
			// An expired fact is not a current statement about the asset.
			"(af.expires_at IS NULL OR af.expires_at > now())",
		},
		SubjectIDExpr: "a.id",
		TenantExpr:    "af.tenant_id",
		MeasuredAt: map[string]string{
			"":    "af.observed_at",
			"now": "now()",
		},
		OrderBy:      map[string]string{"": "af.observed_at DESC"},
		NeedsFactKey: true,
		Selectables: map[string]selectable{
			// `#>> '{}'` unwraps a jsonb SCALAR to text without the quotes
			// `->>` would leave on a string, so a stored "" arrives
			// as a date and not as `""`.
			"fact_value":       {SQL: "af.value #>> '{}'", Kind: scanText},
			"fact_source_ref":  {SQL: "NULLIF(af.source_ref, '')", Kind: scanText},
			"fact_source_kind": {SQL: "af.source_kind", Kind: scanTextNN},
			"observed_at":      {SQL: "af.observed_at", Kind: scanTime},
			"hostname":         {SQL: "a.hostname", Kind: scanText},
			"display_name":     {SQL: "a.display_name", Kind: scanText},
			"class_key":        {SQL: "a.class_key", Kind: scanTextNN},
			"ip_address":       {SQL: "host(a.primary_address)", Kind: scanText},
		},
		EvidenceGroups: map[string][]EvidenceProjection{"asset": assetEvidence},
	},

	// --------------------------------------------------------------- finding
	// One row per live asset the declared producer has completed a pass over,
	// valued with the count of that producer's matching ACTIVE, non-suppressed
	// findings.
	//
	// The producer gate is the honest half. Counting findings alone would
	// report every asset as "0 findings, therefore compliant" — including every
	// asset the producer has never looked at, and including every asset in a
	// deployment where the producer does not run at all. A count of 0 for an
	// asset nobody evaluated is not assessed; a count of 0 for an asset the
	// producer DID evaluate is assessed clean.
	//
	// The gate reads `producer_assessments` (workstream 3.2), not
	// `assets.risk_assessed_by`. They are not the same set and the difference
	// is deliberate: the array is the RISK-feeding subset, so an asset only the
	// `hygiene` producer has visited is correctly NOT ASSESSED for risk — and
	// `assessed_by: hygiene` rows (IH-005, IH-006) and `assessed_by:
	// configuration` rows would then be permanently unassessable if they read
	// the array. The coverage record covers every producer; the array is one
	// view of it. (Orchestrator decision,.)
	"finding": {
		Name:          "finding",
		Subject:       SubjectAsset,
		Target:        "finding",
		Alias:         "f",
		SubjectTarget: "asset",
		SubjectAlias:  "a",
		From:          "assets a",
		Base: []string{
			"a.tenant_id = $1",
			"a.deleted_at IS NULL",
			"($2::uuid IS NULL OR a.id = $2)",
			"EXISTS (SELECT 1 FROM producer_assessments pa" +
				" WHERE pa.tenant_id = a.tenant_id AND pa.asset_id = a.id AND pa.producer = $3)",
		},
		SubjectIDExpr:   "a.id",
		TenantExpr:      "a.tenant_id",
		MeasuredAt:      map[string]string{"": "a.updated_at", "now": "now()"},
		OrderBy:         map[string]string{"": "a.updated_at DESC"},
		NeedsAssessedBy: true,
		Selectables: map[string]selectable{
			"finding_count": {Kind: scanInt, Dynamic: "finding_count"},
			"hostname":      {SQL: "a.hostname", Kind: scanText},
			"display_name":  {SQL: "a.display_name", Kind: scanText},
			"class_key":     {SQL: "a.class_key", Kind: scanTextNN},
			"ip_address":    {SQL: "host(a.primary_address)", Kind: scanText},
		},
		EvidenceGroups: map[string][]EvidenceProjection{"asset": assetEvidence},
	},
}

// findingCountSQL composes the finding shape's one dynamic value: the count of
// a producer's open findings for this asset, narrowed by the registry row's
// compiled query-language predicate.
//
// `via` selects what the finding is ABOUT. The default counts findings whose
// subject IS the asset. "relationship" counts findings on the edges the asset
// takes part in — the hygiene producer records an orphan edge against the
// RELATIONSHIP (that is the subject type its registry entry declares), so a
// control that asks "does this asset have dangling edges" has to reach them
// through asset_relationships or it would count nothing, forever and silently.
// "asset_or_endpoint" counts BOTH subject types at once, for a kind a producer
// raises at either granularity: the `configuration` producer records plaintext
// management on the ASSET when the interrogation facts say the device is
// managed that way, and on the ENDPOINT when one socket is the plaintext
// service. A control over that kind that read only one of them would report a
// device with a Telnet listener as compliant.
//
// ACTIVE and non-SUPPRESSED is the house definition of an open finding
// (framework_score.go): a suppressed finding is a decision somebody made, not a
// gap in the inventory.
func findingCountSQL(via, predicate string) string {
	open := "f.detection_state = 'ACTIVE'" +
		" AND (f.workflow_status <> 'SUPPRESSED' OR f.workflow_status IS NULL)"
	if predicate == "" {
		predicate = "TRUE"
	}
	switch via {
	case "asset_or_endpoint":
		return "(SELECT count(*) FROM findings f" +
			" WHERE f.tenant_id = a.tenant_id" +
			" AND " + open +
			" AND (" + predicate + ")" +
			" AND ((f.subject_type = 'asset' AND f.subject_id = a.id)" +
			" OR (f.subject_type = 'endpoint' AND f.subject_id IN (" +
			"SELECT e.id FROM asset_endpoints e" +
			" WHERE e.tenant_id = a.tenant_id AND e.asset_id = a.id))))"
	case "relationship":
		return "(SELECT count(*) FROM findings f" +
			" JOIN asset_relationships r ON r.id = f.subject_id AND r.tenant_id = f.tenant_id" +
			" WHERE f.tenant_id = a.tenant_id" +
			" AND f.subject_type = 'relationship'" +
			" AND (r.from_asset_id = a.id OR r.to_asset_id = a.id)" +
			" AND " + open +
			" AND (" + predicate + "))"
	default:
		return "(SELECT count(*) FROM findings f" +
			" WHERE f.tenant_id = a.tenant_id" +
			" AND f.subject_type = 'asset'" +
			" AND f.subject_id = a.id" +
			" AND " + open +
			" AND (" + predicate + "))"
	}
}

// measurementFindingVias is the whitelist for `source.via`.
var measurementFindingVias = map[string]bool{"": true, "relationship": true, "asset_or_endpoint": true}

// ------------------------------------------------------------ scanned values

// scannedValue is one column of one row, already typed by its selectable's
// Kind. It exists so the transforms and the evidence writer can ask questions
// ("is it present?", "as text", "as a number") without each of them knowing
// which of six sql.Null* types the column came back in.
type scannedValue struct {
	kind          string
	str           sql.NullString
	num           sql.NullInt64
	flt           sql.NullFloat64
	bl            sql.NullBool
	tm            sql.NullTime
	id            uuid.UUID
	emptyIsAbsent bool
}

// dest returns the scan destination for this value's kind.
func (v *scannedValue) dest() interface{} {
	switch v.kind {
	case scanInt:
		return &v.num
	case scanFloat:
		return &v.flt
	case scanBool:
		return &v.bl
	case scanTime:
		return &v.tm
	case scanUUIDList:
		return &v.id
	default: // scanText, scanTextNN
		return &v.str
	}
}

// text returns the value as a string, empty when absent.
func (v scannedValue) text() string {
	if v.kind == scanText || v.kind == scanTextNN {
		return v.str.String
	}
	return ""
}

// number returns the value as a float64 and whether it was present.
func (v scannedValue) number() (float64, bool) {
	switch v.kind {
	case scanFloat:
		return v.flt.Float64, v.flt.Valid
	case scanInt:
		return float64(v.num.Int64), v.num.Valid
	}
	return 0, false
}

// boolean returns the value as a bool and whether it was present.
func (v scannedValue) boolean() (bool, bool) { return v.bl.Bool, v.bl.Valid }

// publish returns the value as the scalar a rule judges, or errNoMeasurement
// when the column is NULL. A NULL is not a zero: a certificate with no recorded
// key size has not got a key size of 0, and publishing one would invent a
// violation.
func (v scannedValue) publish() (interface{}, error) {
	switch v.kind {
	case scanInt:
		if !v.num.Valid {
			return nil, errNoMeasurement
		}
		return int(v.num.Int64), nil
	case scanFloat:
		if !v.flt.Valid {
			return nil, errNoMeasurement
		}
		return v.flt.Float64, nil
	case scanBool:
		if !v.bl.Valid {
			return nil, errNoMeasurement
		}
		return v.bl.Bool, nil
	case scanTime:
		if !v.tm.Valid {
			return nil, errNoMeasurement
		}
		return v.tm.Time, nil
	case scanTextNN:
		return v.str.String, nil
	default:
		if !v.str.Valid {
			return nil, errNoMeasurement
		}
		return v.str.String, nil
	}
}

// evidence returns the value as it should appear in a finding's metadata, and
// whether it should appear at all.
func (v scannedValue) evidence() (interface{}, bool) {
	switch v.kind {
	case scanInt:
		if !v.num.Valid {
			return nil, false
		}
		return v.num.Int64, true
	case scanFloat:
		if !v.flt.Valid {
			return nil, false
		}
		return v.flt.Float64, true
	case scanBool:
		if !v.bl.Valid {
			return nil, false
		}
		return v.bl.Bool, true
	case scanTime:
		if !v.tm.Valid {
			return nil, false
		}
		return v.tm.Time, true
	case scanUUIDList:
		if v.id == uuid.Nil {
			return nil, false
		}
		return []string{v.id.String()}, true
	case scanTextNN:
		if v.emptyIsAbsent && v.str.String == "" {
			return nil, false
		}
		return v.str.String, true
	default:
		if !v.str.Valid {
			return nil, false
		}
		if v.emptyIsAbsent && v.str.String == "" {
			return nil, false
		}
		return v.str.String, true
	}
}
