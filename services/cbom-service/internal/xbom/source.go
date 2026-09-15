package xbom

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
)

// Source reads the inventory tables an xBOM is assembled from.
//
// Every read is scoped BOTH by `app.tenant_id` (the RLS session variable, set
// by WithTenantTx) and by an explicit `tenant_id = $1` predicate. Neither alone
// is sufficient here: the services connect as the table owner, which makes RLS
// inert, and a pooled connection carries whatever session state the last
// borrower left, which makes the session variable alone unreliable. Both, and
// the tenant is passed explicitly rather than inferred, the same way
// AttestationBuilder takes it.
type Source struct {
	db *sql.DB
}

// NewSource constructs a Source over the given connection pool. It takes the
// pool, not a connection: each read owns its own tenant-scoped transaction.
func NewSource(db *sql.DB) *Source { return &Source{db: db} }

// Load reads everything the kinds need for one asset set, in one transaction.
//
// One transaction for all seven reads is deliberate: an artifact is a snapshot
// of a MOMENT, and seven autocommit reads spread across a busy ingest would
// produce a document whose software list postdates its asset list. Postgres's
// default READ COMMITTED gives each statement its own snapshot, so this is not
// a serialisable guarantee — but it does keep the reads on one connection with
// one tenant context, and it is where a stricter isolation level would go if
// the drift ever proves to matter.
//
// An empty asset set short-circuits: the scope matched nothing, which is a
// legitimate answer (an artifact with zero components), and every query below
// would otherwise run with an empty ANY() for no rows.
func (s *Source) Load(ctx context.Context, tenantID uuid.UUID, assetIDs []uuid.UUID) (*Snapshot, error) {
	snap := &Snapshot{
		Assets:        []Asset{},
		Identifiers:   []Identifier{},
		Endpoints:     []Endpoint{},
		Facts:         []Fact{},
		Software:      []SoftwareInstall{},
		Relationships: []Relationship{},
		Vulns:         []VulnerabilityFinding{},
	}
	if len(assetIDs) == 0 {
		return snap, nil
	}

	ids := pq.Array(uuidStrings(assetIDs))

	err := shareddatabase.WithTenantTx(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		if err := s.loadAssets(ctx, tx, tenantID, ids, snap); err != nil {
			return err
		}
		if err := s.loadIdentifiers(ctx, tx, tenantID, ids, snap); err != nil {
			return err
		}
		if err := s.loadEndpoints(ctx, tx, tenantID, ids, snap); err != nil {
			return err
		}
		if err := s.loadFacts(ctx, tx, tenantID, ids, snap); err != nil {
			return err
		}
		if err := s.loadSoftware(ctx, tx, tenantID, ids, snap); err != nil {
			return err
		}
		if err := s.loadRelationships(ctx, tx, tenantID, ids, snap); err != nil {
			return err
		}
		return s.loadVulnerabilities(ctx, tx, tenantID, ids, snap)
	})
	if err != nil {
		return nil, err
	}
	return snap, nil
}

func (s *Source) loadAssets(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, ids interface{}, snap *Snapshot) error {
	// The correlated subselect resolves the class's OWN CycloneDX component
	// type. `assetclass.Get` — the generated registry — knows only the fixed
	// top of the taxonomy, and a tenant may add leaf subclasses at runtime
	// (ADR-0002 D2), so without this an HBOM admitted every tenant subclass as
	// hardware and an inventory typed them all `device`.
	//
	// The tenant's row wins over the platform copy of the same key:
	// `(tenant_id IS NULL)` sorts false before true. Same tie-break, spelled
	// the same way, as shared/identity/postgres's classPathFor.
	rows, err := tx.QueryContext(ctx, `
		SELECT id, class_key, class_path,
		       COALESCE((
		           SELECT ac.cyclonedx_type
		             FROM public.asset_classes ac
		            WHERE ac.key = assets.class_key
		              AND (ac.tenant_id = $1 OR ac.tenant_id IS NULL)
		            ORDER BY (ac.tenant_id IS NULL)
		            LIMIT 1
		       ), ''),
		       COALESCE(display_name, ''), COALESCE(hostname, ''),
		       COALESCE(host(primary_address), ''),
		       COALESCE(environment::text, ''), COALESCE(business_unit, ''),
		       COALESCE(owner_email, ''), COALESCE(site, ''),
		       COALESCE(region, ''), COALESCE(zone, ''),
		       asset_status, asset_ownership, risk_score,
		       first_discovered_at, last_seen_at, tags
		FROM public.assets
		WHERE tenant_id = $1 AND id = ANY($2) AND deleted_at IS NULL
		ORDER BY id
	`, tenantID, ids)
	if err != nil {
		return fmt.Errorf("xbom: query assets: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			a        Asset
			tagsJSON []byte
		)
		if err := rows.Scan(
			&a.ID, &a.ClassKey, &a.ClassPath, &a.CycloneDXType,
			&a.DisplayName, &a.Hostname, &a.PrimaryAddress,
			&a.Environment, &a.BusinessUnit,
			&a.OwnerEmail, &a.Site,
			&a.Region, &a.Zone,
			&a.AssetStatus, &a.AssetOwnership, &a.RiskScore,
			&a.FirstSeenAt, &a.LastSeenAt, &tagsJSON,
		); err != nil {
			return fmt.Errorf("xbom: scan asset: %w", err)
		}
		a.Tags = flattenStringMap(tagsJSON)
		snap.Assets = append(snap.Assets, a)
	}
	return rows.Err()
}

func (s *Source) loadIdentifiers(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, ids interface{}, snap *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT asset_id, kind, value, COALESCE(scope, '')
		FROM public.asset_identifiers
		WHERE tenant_id = $1 AND asset_id = ANY($2)
		ORDER BY asset_id, kind, value, COALESCE(scope, '')
	`, tenantID, ids)
	if err != nil {
		return fmt.Errorf("xbom: query identifiers: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var i Identifier
		if err := rows.Scan(&i.AssetID, &i.Kind, &i.Value, &i.Scope); err != nil {
			return fmt.Errorf("xbom: scan identifier: %w", err)
		}
		snap.Identifiers = append(snap.Identifiers, i)
	}
	return rows.Err()
}

func (s *Source) loadEndpoints(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, ids interface{}, snap *Snapshot) error {
	rows, err := tx.QueryContext(ctx, `
		SELECT id, asset_id,
		       COALESCE(host(address), ''), COALESCE(fqdn, ''),
		       port, transport, COALESCE(protocol::text, ''),
		       COALESCE(service_name, ''), COALESCE(service_version, ''),
		       status
		FROM public.asset_endpoints
		WHERE tenant_id = $1 AND asset_id = ANY($2) AND status <> 'closed'
		ORDER BY asset_id, COALESCE(host(address), ''), COALESCE(fqdn, ''), COALESCE(port, -1), transport
	`, tenantID, ids)
	if err != nil {
		return fmt.Errorf("xbom: query endpoints: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			e    Endpoint
			port sql.NullInt64
		)
		if err := rows.Scan(
			&e.ID, &e.AssetID, &e.Address, &e.FQDN,
			&port, &e.Transport, &e.Protocol,
			&e.ServiceName, &e.ServiceVersion, &e.Status,
		); err != nil {
			return fmt.Errorf("xbom: scan endpoint: %w", err)
		}
		// A NULL port is an at-rest face, not port 0. Recording it as 0 would
		// publish a listening socket that does not exist.
		if port.Valid {
			e.Port = int(port.Int64)
			e.HasPort = true
		}
		snap.Endpoints = append(snap.Endpoints, e)
	}
	return rows.Err()
}

func (s *Source) loadFacts(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, ids interface{}, snap *Snapshot) error {
	// Expired facts are excluded. A fact past its expires_at is one the
	// producer said it would no longer stand behind, and an artifact is exactly
	// the document that must not restate a retracted measurement.
	rows, err := tx.QueryContext(ctx, `
		SELECT asset_id, key, value, source_kind, source_ref, observed_at
		FROM public.asset_facts
		WHERE tenant_id = $1 AND asset_id = ANY($2)
		  AND (expires_at IS NULL OR expires_at > now())
		ORDER BY asset_id, key, source_ref
	`, tenantID, ids)
	if err != nil {
		return fmt.Errorf("xbom: query facts: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			f   Fact
			raw []byte
		)
		if err := rows.Scan(&f.AssetID, &f.Key, &raw, &f.SourceKind, &f.SourceRef, &f.ObservedAt); err != nil {
			return fmt.Errorf("xbom: scan fact: %w", err)
		}
		f.Value = renderJSONScalar(raw)
		snap.Facts = append(snap.Facts, f)
	}
	return rows.Err()
}

func (s *Source) loadSoftware(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, ids interface{}, snap *Snapshot) error {
	// Removed installs are excluded; stale ones are kept. "Stale" means nobody
	// has re-observed it lately, which is a freshness statement about our
	// collection, not a statement that the software is gone — dropping it would
	// silently shrink an SBOM every time a collector missed a sweep.
	rows, err := tx.QueryContext(ctx, `
		SELECT i.asset_id, p.id, COALESCE(i.install_path, ''),
		       p.name, COALESCE(p.vendor, ''), COALESCE(p.version, ''),
		       COALESCE(p.cpe, ''), COALESCE(p.purl, ''), COALESCE(p.license_id, '')
		FROM public.software_installs i
		JOIN public.software_products p
		  ON p.tenant_id = i.tenant_id AND p.id = i.product_id
		WHERE i.tenant_id = $1 AND i.asset_id = ANY($2) AND i.status <> 'removed'
		ORDER BY p.id, i.asset_id, COALESCE(i.install_path, '')
	`, tenantID, ids)
	if err != nil {
		return fmt.Errorf("xbom: query software: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var si SoftwareInstall
		if err := rows.Scan(
			&si.AssetID, &si.ProductID, &si.InstallPath,
			&si.Name, &si.Vendor, &si.Version,
			&si.CPE, &si.PURL, &si.LicenseID,
		); err != nil {
			return fmt.Errorf("xbom: scan software: %w", err)
		}
		snap.Software = append(snap.Software, si)
	}
	return rows.Err()
}

func (s *Source) loadRelationships(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, ids interface{}, snap *Snapshot) error {
	// Both ends must be in scope. An edge to an asset outside the boundary
	// would be a dangling `dependsOn` in the emitted graph — CycloneDX
	// `dependsOn` is a refLinkType, so a reader resolves it to nothing — and an
	// artifact that points outside the boundary it names is lying about its
	// boundary either way.
	//
	// Only ACTIVE edges. A `pending` edge is a proposal awaiting a human
	// (ADR-0003), and signed evidence is not the place a proposal becomes a
	// fact.
	rows, err := tx.QueryContext(ctx, `
		SELECT from_asset_id, to_asset_id, type, status
		FROM public.asset_relationships
		WHERE tenant_id = $1
		  AND from_asset_id = ANY($2) AND to_asset_id = ANY($2)
		  AND status = 'active'
		ORDER BY from_asset_id, to_asset_id, type
	`, tenantID, ids)
	if err != nil {
		return fmt.Errorf("xbom: query relationships: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var r Relationship
		if err := rows.Scan(&r.FromAssetID, &r.ToAssetID, &r.Type, &r.Status); err != nil {
			return fmt.Errorf("xbom: scan relationship: %w", err)
		}
		snap.Relationships = append(snap.Relationships, r)
	}
	return rows.Err()
}

func (s *Source) loadVulnerabilities(ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, ids interface{}, snap *Snapshot) error {
	// Subject types: `asset` (the id IS an asset id) and `software_install`
	// (the id is an install's). The registry allows both for
	// vulnerability/known_vulnerability. The software_install arm resolves
	// through the installs table so an install-subject finding still lands on
	// an in-scope asset — without it, every install-scoped CVE would be
	// silently absent from an inventory artifact.
	//
	// ARCHIVED rows are excluded and INACTIVE ones are too: an INACTIVE finding
	// is a condition that STOPPED being detected, and restating it in a dated
	// snapshot would assert a vulnerability we no longer observe.
	rows, err := tx.QueryContext(ctx, `
		SELECT f.id, f.kind, f.subject_type, f.subject_id,
		       COALESCE(f.subject_label, ''), f.severity, f.score, f.summary,
		       f.first_seen, f.last_seen, f.evidence,
		       c.cvss_version, c.cvss_score, c.cvss_vector, c.severity,
		       c.description, c.published_at, c.modified_at
		FROM public.findings f
		LEFT JOIN public.software_installs si
		       ON f.subject_type = 'software_install'
		      AND si.tenant_id = f.tenant_id
		      AND si.id = f.subject_id
		LEFT JOIN public.vulnerability_catalogue c
		       ON c.cve_id = COALESCE(
		            f.evidence ->> 'cve_id',
		            f.evidence -> 'cve_ids' ->> 0
		          )
		WHERE f.tenant_id = $1
		  AND f.producer = $3
		  AND f.detection_state = 'ACTIVE'
		  AND (
		        (f.subject_type = 'asset' AND f.subject_id = ANY($2))
		     OR (f.subject_type = 'software_install' AND si.asset_id = ANY($2))
		      )
		ORDER BY f.id
	`, tenantID, ids, sharedfindings.ProducerVulnerability)
	if err != nil {
		return fmt.Errorf("xbom: query vulnerability findings: %w", err)
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var (
			v            VulnerabilityFinding
			evidenceJSON []byte
			cvssVersion  sql.NullString
			cvssScore    sql.NullFloat64
			cvssVector   sql.NullString
			cvssSeverity sql.NullString
			description  sql.NullString
			publishedAt  sql.NullTime
			modifiedAt   sql.NullTime
		)
		if err := rows.Scan(
			&v.ID, &v.Kind, &v.SubjectType, &v.SubjectID,
			&v.SubjectLbl, &v.Severity, &v.Score, &v.Summary,
			&v.FirstSeen, &v.LastSeen, &evidenceJSON,
			&cvssVersion, &cvssScore, &cvssVector, &cvssSeverity,
			&description, &publishedAt, &modifiedAt,
		); err != nil {
			return fmt.Errorf("xbom: scan vulnerability finding: %w", err)
		}
		v.CVEID = cveIDFromEvidence(evidenceJSON)
		v.CVSSVersion = cvssVersion.String
		if cvssScore.Valid {
			score := cvssScore.Float64
			v.CVSSScore = &score
		}
		v.CVSSVector = cvssVector.String
		v.CVSSeverity = cvssSeverity.String
		v.Description = description.String
		if publishedAt.Valid {
			t := publishedAt.Time
			v.PublishedAt = &t
		}
		if modifiedAt.Valid {
			t := modifiedAt.Time
			v.ModifiedAt = &t
		}
		snap.Vulns = append(snap.Vulns, v)
	}
	return rows.Err()
}

// cveIDFromEvidence reads the CVE id a vulnerability finding names.
//
// Two spellings are accepted because the `vulnerability` producer is not built
// yet (BUILD_PLAN 3.4 part 2) and this is the reader arriving first: a finding
// about ONE advisory is expected to carry `evidence.cve_id`, and one that
// matched several is expected to carry `evidence.cve_ids`. Reading the first of
// the array rather than expanding it keeps one finding to one vulnerability
// entry; when the producer lands and settles the shape, this is the one place
// to change.
//
// An absent id yields empty, and empty means the emitted vulnerability has no
// `id` — not a placeholder, not "CVE-UNKNOWN".
func cveIDFromEvidence(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var evidence struct {
		CVEID  string   `json:"cve_id"`
		CVEIDs []string `json:"cve_ids"`
	}
	if err := json.Unmarshal(raw, &evidence); err != nil {
		return ""
	}
	if evidence.CVEID != "" {
		return evidence.CVEID
	}
	if len(evidence.CVEIDs) > 0 {
		return evidence.CVEIDs[0]
	}
	return ""
}

// renderJSONScalar turns a jsonb value into the string a CycloneDX property
// carries. A JSON string loses its quotes; everything else keeps its JSON text.
//
// Without the unquoting, `os.name` — stored as the JSON string `"Ubuntu"` —
// would reach the document as the five-character-longer `"Ubuntu"`, quotes
// included, in every property of every asset.
func renderJSONScalar(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var any interface{}
	if err := json.Unmarshal(raw, &any); err != nil {
		return string(raw)
	}
	switch v := any.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case float64:
		// 'g' with -1 precision round-trips without printing 22 as 22.000000.
		return strconv.FormatFloat(v, 'g', -1, 64)
	case nil:
		return ""
	default:
		compact, err := json.Marshal(v)
		if err != nil {
			return string(raw)
		}
		return string(compact)
	}
}

// flattenStringMap reads a jsonb object into a string map, keeping only the
// string-valued entries. A nested object or array is SKIPPED rather than
// stringified: "map[a:1]" in a published document is noise, and a tag whose
// value is a structure is not a tag.
func flattenStringMap(raw []byte) map[string]string {
	out := map[string]string{}
	if len(raw) == 0 {
		return out
	}
	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return out
	}
	for k, v := range decoded {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func uuidStrings(ids []uuid.UUID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}

// utcRFC3339 formats a timestamp the way every date in an emitted document is
// formatted: UTC, RFC 3339, second precision.
//
// UTC is not cosmetic. The canonical bytes are the content hash, and a
// timestamp rendered in the server's local zone would make the same snapshot
// hash differently depending on which pod produced it and whether the host had
// crossed a DST boundary.
func utcRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
