package producers

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/cryptoassess"
	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/findings/producer"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
	"github.com/vistasecurity/vistaplatform/shared/riskbands"
)

// CryptoProducer is the `crypto` finding producer (ADR-0005 D3, workstream
// 3.2).
//
// It judges the cryptographic posture already materialised in the inventory —
// it does not probe, parse handshakes or classify algorithms itself. Three
// kinds:
//
//	crypto configuration + its catalogue components → crypto/weak_configuration
//	certificate key / size / signature             → crypto/weak_certificate
//	any of those, or an inventoried KEY, using a
//	Shor-breakable primitive                       → crypto/pqc_vulnerable
//
// # Where every number comes from
//
// Nothing here invents a score. The three sources, in the order they are
// consulted:
//
//  1. the `algorithms` catalogue, through the junction roles named in
//     [cryptoassess.CatalogueRiskRoles] — worst component wins, exactly as
//     ingest computes it;
//  2. `crypto_implementations.risk_score`, the verdict ingest already persisted
//     (itself the worse of the catalogue and the weak-crypto detector, which is
//     where key SIZE enters for a configuration);
//  3. for a certificate, [cryptoparse.WeakKeySizeSeverity] and
//     [cryptoparse.WeakHashSeverity] — the two rules a per-algorithm catalogue
//     row cannot express, shared with the detector rather than restated.
//
// Taking the worst of (1) and (2) means the producer's score for a
// configuration can never be LOWER than the number the product showed before
// this producer existed, which is what makes the cutover a parity change rather
// than a rescoring. `TestIntegration_CryptoProducer_MatchesTheLegacyCryptoRollup`
// pins that.
//
// # Score 0 is NOT ASSESSED, and no finding is written for it
//
// A configuration whose components resolve to nothing has not been judged
// clean; it has not been judged. It raises no finding — and it also does not,
// on its own, make its asset "assessed by crypto". Coverage is claimed only for
// an asset where something actually resolved: at least one catalogue component
// on one of its configurations, or a certificate carrying enough to measure.
// Marking generously is the failure mode here, because an over-claimed asset
// reads "assessed clean" and is silent about it.
type CryptoProducer struct {
	repo   *pgidentity.Repository
	writer *producer.Writer
}

// NewCryptoProducer builds the producer over the RLS-subject handle.
//
// Unlike the eol and vulnerability producers it takes no second handle: every
// table it reads (`crypto_implementations`, `certificates`,
// `crypto_implementation_algorithms`, `algorithms`) is either tenant-scoped or
// a global catalogue with no policy, and both are reachable from the tenant's
// own session.
func NewCryptoProducer(appDB *sql.DB) (*CryptoProducer, error) {
	w, err := producer.New(findings.ProducerCrypto)
	if err != nil {
		return nil, err
	}
	return &CryptoProducer{repo: pgidentity.New(appDB), writer: w}, nil
}

// CryptoRun is what one pass did.
type CryptoRun struct {
	// Raised is how many findings were upserted (created or re-observed).
	Raised int
	// Resolved is how many the sweep moved to INACTIVE.
	Resolved int
	// Configurations, Certificates and Keys are how many subjects were read.
	Configurations int
	Certificates   int
	Keys           int
	// Assessed is how many assets the pass claimed coverage of, and
	// Unassessable how many it read but could not judge — no catalogue
	// component on any configuration and no measurable certificate. The two are
	// reported separately because "this tenant has no crypto risk" and "nothing
	// about this tenant's crypto could be assessed" are different answers and
	// only one of them is reassuring.
	Assessed      int
	Unassessable  int
	PQCVulnerable int
}

// configSubject is one crypto configuration and everything judged about it.
type configSubject struct {
	id       uuid.UUID
	assetID  uuid.UUID
	label    string
	protocol string
	version  string
	suite    string

	// storedRisk is crypto_implementations.risk_score, ingest's persisted
	// verdict; catalogueRisk is recomputed here from the junction so a catalogue
	// row edited since ingest takes effect without re-observing the service.
	storedRisk    int
	catalogueRisk int
	linked        int
	components    []byte // jsonb array, worst first

	pqcVulnerable bool
	pqcCodes      []string
}

// certSubject is one certificate and everything judged about it.
type certSubject struct {
	id uuid.UUID
	// assetIDs is EVERY asset the certificate is reachable from, not one of
	// them. A wildcard certificate deployed across a fleet is linked to a
	// configuration on each host, and `findings.AssetSubjects` walks the
	// junction from all of them — so the one finding written about it raises
	// every one of those assets' risk. Claiming coverage for a single asset
	// would leave the others SCORED by a producer their coverage record says
	// never looked at them, which reads as "not assessed" beside a non-zero
	// number: the exact pair this workstream exists to keep honest.
	assetIDs  []uuid.UUID
	label     string
	keyAlg    string
	keyBits   int
	sigAlg    string
	catalogue []catalogueHit
}

// keySubject is one row of the cryptographic-key inventory and the catalogue
// row its algorithm resolves to.
//
// The key inventory (`keys`, produced from certificate public keys — metadata
// only, never material) is the third place a Shor-breakable primitive can be
// recorded, and until this existed it was the only one that raised nothing. A
// key is an especially poor thing to leave unreported: it is the subject the
// PQC migration is actually ABOUT — one RSA key deployed on forty hosts is one
// migration, not forty — and NIST IR 8547's "long-lived data protected by this
// key is the part to prioritise" is advice that needs a key to attach to.
type keySubject struct {
	id uuid.UUID
	// assetIDs is EVERY asset the key is reachable from, for the same reason
	// certSubject.assetIDs is: one key row is shared across every certificate
	// and configuration presenting that public key, the finding on it raises
	// all of their assets through findings.AssetSubjects, and coverage that
	// named only one would leave the rest SCORED by a producer their coverage
	// record says never looked.
	assetIDs []uuid.UUID
	label    string
	keyType  string
	sizeBits int

	// The catalogue row keys.algorithm_id points at. Empty code means the key
	// resolved to nothing: UNCLASSIFIED, never assumed safe, no finding, and no
	// coverage claimed for it.
	catalogue catalogueHit
}

// pqcVulnerableCode names the key's classical asymmetric algorithm, or "".
//
// Same denylist as the configuration and certificate classifiers —
// cryptoassess.QuantumVulnerablePrimitives, which is a DENYLIST on purpose
// (pqc_readiness.go: an allowlist silently treats everything it forgot as
// needing migration, and the previous {ae, hash, mac} allowlist misclassified
// plain AES). A key whose algorithm resolves to no catalogue row, or to one with
// no primitive, is unclassified and raises nothing.
func (k keySubject) pqcVulnerableCode() string {
	if k.catalogue.Code == "" || k.catalogue.IsPQC || k.catalogue.Primitive == "" {
		return ""
	}
	for _, vuln := range cryptoassess.QuantumVulnerablePrimitives {
		if k.catalogue.Primitive == vuln {
			return k.catalogue.Code
		}
	}
	return ""
}

// measurable is whether anything about this key could be judged at all — which
// is whether its algorithm resolved to a catalogue row. A key whose algorithm
// is a string nothing recognises contributes NO coverage: "we could not tell"
// must not be recorded as "we checked".
func (k keySubject) measurable() bool { return k.catalogue.Code != "" }

func (k keySubject) evidence(code string) map[string]any {
	e := map[string]any{
		"vulnerable_algorithms": []string{code},
		"key_algorithm":         orUnknown(k.keyType),
		"authority":             pqcAuthority,
	}
	if k.sizeBits > 0 {
		e["key_size"] = k.sizeBits
	}
	return e
}

// catalogueHit is one algorithms-table row a certificate's algorithm string
// resolved to.
type catalogueHit struct {
	Field             string `json:"field"`
	Observed          string `json:"observed"`
	Code              string `json:"code"`
	RiskScore         int    `json:"risk_score"`
	Strength          string `json:"strength"`
	DeprecationStatus string `json:"deprecation_status"`
	Primitive         string `json:"primitive"`
	IsPQC             bool   `json:"is_pqc"`
}

// Run executes one pass over one tenant.
//
// Read, judge, write — separate phases for the reason the eol producer states:
// an error before the write phase returns WITHOUT sweeping, because a run that
// died half way has not made a full statement about what it sees and sweeping
// on a partial answer inactivates live findings and re-raises them tomorrow.
func (p *CryptoProducer) Run(ctx context.Context, tenantID uuid.UUID) (CryptoRun, error) {
	var run CryptoRun

	configs, certs, keys, err := p.read(ctx, tenantID)
	if err != nil {
		return CryptoRun{}, fmt.Errorf("crypto producer: reading tenant %s: %w", tenantID, err)
	}
	run.Configurations = len(configs)
	run.Certificates = len(certs)
	run.Keys = len(keys)

	planned, assessed := p.judge(configs, certs, keys, &run)

	if err := p.write(ctx, tenantID, planned, assessed, &run); err != nil {
		return CryptoRun{}, fmt.Errorf("crypto producer: writing tenant %s: %w", tenantID, err)
	}
	return run, nil
}

// liveConfigurationsSQL is the population this producer judges: live
// configurations on an asset the tenant is still tracking.
//
// `asset_status <> 'archived'` rather than `= 'monitoring'`, matching the eol
// and vulnerability producers: an asset awaiting approval is one the tenant has
// not yet decided about, and withholding its findings until it is approved
// means the approval decision is taken without them. An ARCHIVED asset is
// excluded because the tenant has decided to stop tracking it, and raising
// fresh findings would put work back in the queue they took it out of.
//
// The asset a configuration belongs to is resolved by
// [findings.ConfigurationAssetSQL] — the SAME fragment findings.AssetSubjects
// splices — and selected as `asset_id`, so the coverage rows this producer
// writes name the assets its findings are actually reachable from. It used to
// read bare `ci.asset_id`: a configuration whose endpoint had moved to another
// host was then recorded as coverage of its old asset while the finding hung off
// the new one.
//
// $1 is the tenant.
var liveConfigurationsSQL = `
    SELECT ci.id, ci.tenant_id, ` + findings.ConfigurationAssetSQL("ci", "lce") + ` AS asset_id
      FROM crypto_implementations ci
      LEFT JOIN asset_endpoints lce ON lce.tenant_id = ci.tenant_id AND lce.id = ci.endpoint_id
      JOIN assets a ON a.tenant_id = ci.tenant_id
           AND a.id = ` + findings.ConfigurationAssetSQL("ci", "lce") + `
           AND a.deleted_at IS NULL AND a.asset_status <> 'archived'
     WHERE ci.tenant_id = $1 AND ci.deleted_at IS NULL`

// read loads the configurations and certificates, already scored by the
// catalogue and already classified for PQC.
//
// One statement each. The alternative — a per-subject lookup — is the shape
// that turns a tenant with twenty thousand configurations into an overnight
// job, and both judgements are pure SQL over rows the database already has.
func (p *CryptoProducer) read(ctx context.Context, tenantID uuid.UUID) ([]configSubject, []certSubject, []keySubject, error) {
	var configs []configSubject
	var certs []certSubject
	var keys []keySubject

	err := p.repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		tx := r.Tx()

		// The configuration read. `cryptoassess.PQCClassCTE` is the SAME
		// classification `/pqc/progress` aggregates over — same roles, same
		// denylist, same precedence — so a configuration the two both see gets
		// the same verdict from both.
		//
		// The POPULATIONS are not identical and deliberately so: the PQC page
		// counts `asset_status = 'monitoring'` (MonitoredConfigurationsSQL,
		// because its denominator has to match the Dashboard's Configs count and
		// the Configuration lens total), while this producer judges every
		// non-archived asset for the reason liveConfigurationsSQL gives — an
		// approval decision taken without the findings is a decision taken
		// blind. So a pending-approval asset can carry a pqc_vulnerable finding
		// that the PQC page does not yet count. Same verdict, different
		// denominator; do not "fix" one to match the other without deciding
		// which question is being asked.
		cfgQuery := `
			WITH cfg AS (` + liveConfigurationsSQL + `),
			` + cryptoassess.PQCClassCTE("SELECT id, tenant_id FROM cfg", "$2", "$3") + `,
			cat AS (
			    SELECT cia.crypto_implementation_id AS impl_id,
			           MAX(COALESCE(a.risk_score, 0)) AS max_risk,
			           COUNT(*)                       AS linked,
			           jsonb_agg(
			               jsonb_build_object(
			                   'code', a.code,
			                   'role', cia.algorithm_type,
			                   'risk_score', COALESCE(a.risk_score, 0),
			                   'strength', COALESCE(a.strength, ''),
			                   'deprecation_status', COALESCE(a.deprecation_status, '')
			               )
			               ORDER BY COALESCE(a.risk_score, 0) DESC, a.code
			           ) AS components
			      FROM crypto_implementation_algorithms cia
			      JOIN algorithms a ON a.id = cia.algorithm_id
			     WHERE cia.crypto_implementation_id IN (SELECT id FROM cfg)
			       AND cia.algorithm_type = ANY($4)
			     GROUP BY cia.crypto_implementation_id
			)
			SELECT ci.id,
			       cfg.asset_id,
			       ci.protocol::text,
			       COALESCE(ci.protocol_version, ''),
			       COALESCE(ci.cipher_suite, ''),
			       COALESCE(ci.risk_score, 0),
			       COALESCE(cat.max_risk, 0),
			       COALESCE(cat.linked, 0),
			       COALESCE(cat.components, '[]'::jsonb)::text,
			       COALESCE(k.vulnerable, false),
			       COALESCE(k.vulnerable_codes, ARRAY[]::text[]),
			       COALESCE(host(e.address), ''),
			       COALESCE(e.port, 0)
			  FROM cfg
			  JOIN crypto_implementations ci ON ci.id = cfg.id
			  LEFT JOIN cat ON cat.impl_id = cfg.id
			  LEFT JOIN impl_class k ON k.impl_id = cfg.id
			  LEFT JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
			 ORDER BY ci.id`

		rows, err := tx.QueryContext(ctx, cfgQuery, tenantID,
			pq.Array(cryptoassess.PQCComponentRoles),
			pq.Array(cryptoassess.QuantumVulnerablePrimitives),
			pq.Array(cryptoassess.CatalogueRiskRoles))
		if err != nil {
			return fmt.Errorf("query crypto configurations: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var c configSubject
			var components string
			var codes pq.StringArray
			var addr string
			var port int
			if err := rows.Scan(&c.id, &c.assetID, &c.protocol, &c.version, &c.suite,
				&c.storedRisk, &c.catalogueRisk, &c.linked, &components,
				&c.pqcVulnerable, &codes, &addr, &port); err != nil {
				return fmt.Errorf("scan crypto configuration: %w", err)
			}
			c.components = []byte(components)
			c.pqcCodes = codes
			c.label = configurationLabel(c.protocol, c.version, addr, port)
			configs = append(configs, c)
		}
		if err := rows.Err(); err != nil {
			return err
		}

		// Certificates reachable from a live asset, with the catalogue rows
		// their two algorithm strings resolve to.
		//
		// Reachable, not "every certificate the tenant holds": a certificate
		// linked to no configuration belongs to no asset, so a finding on it
		// could not be reached from any asset by findings.AssetSubjects, could
		// not raise anyone's risk and could not be counted by the has_findings
		// facet. Judging it would create a row nothing leads to. Stated in the
		// PR as a known gap rather than papered over.
		//
		// The catalogue resolution is an exact match on `algorithms.code`, in
		// upper case, against the raw string and against
		// cryptoparse.NormalizeComponentCode's fold of it — the first two steps
		// AlgorithmService.ClassifyAlgorithm takes, over the same table. Its
		// third step (unambiguous substring) is deliberately NOT reproduced:
		// "md5WithRSAEncryption" matches both MD5 and RSA, which that rule calls
		// ambiguous and declines to resolve, and a certificate signed with MD5
		// must not go unreported because of a tie. The broken-hash reading of
		// that string is made by cryptoparse.WeakHashSeverity instead, which is
		// the detector's own rule.
		certQuery := `
			WITH reachable AS (
			    SELECT DISTINCT cic.certificate_id,
			           ` + findings.ConfigurationAssetSQL("ci", "rce") + ` AS asset_id
			      FROM crypto_implementation_certificates cic
			      JOIN crypto_implementations ci ON ci.id = cic.crypto_implementation_id
			           AND ci.deleted_at IS NULL
			      LEFT JOIN asset_endpoints rce ON rce.tenant_id = ci.tenant_id AND rce.id = ci.endpoint_id
			      JOIN assets a ON a.tenant_id = ci.tenant_id
			           AND a.id = ` + findings.ConfigurationAssetSQL("ci", "rce") + `
			           AND a.deleted_at IS NULL AND a.asset_status <> 'archived'
			     WHERE ci.tenant_id = $1
			)
			SELECT c.id,
			       -- EVERY asset it is reachable from. See certSubject.assetIDs:
			       -- the finding raises all of them, so all of them are covered.
			       array_agg(DISTINCT reachable.asset_id::text),
			       COALESCE(NULLIF(c.common_name, ''), c.subject_dn),
			       COALESCE(c.public_key_algorithm, ''),
			       COALESCE(c.public_key_size, 0),
			       COALESCE(c.signature_algorithm, '')
			  FROM certificates c
			  JOIN reachable ON reachable.certificate_id = c.id
			 WHERE c.tenant_id = $1
			 GROUP BY c.id, c.common_name, c.subject_dn, c.public_key_algorithm,
			          c.public_key_size, c.signature_algorithm
			 ORDER BY c.id`
		cRows, err := tx.QueryContext(ctx, certQuery, tenantID)
		if err != nil {
			return fmt.Errorf("query certificates: %w", err)
		}
		defer func() { _ = cRows.Close() }()
		for cRows.Next() {
			var c certSubject
			var assetIDs pq.StringArray
			if err := cRows.Scan(&c.id, &assetIDs, &c.label, &c.keyAlg, &c.keyBits, &c.sigAlg); err != nil {
				return fmt.Errorf("scan certificate: %w", err)
			}
			for _, raw := range assetIDs {
				parsed, err := uuid.Parse(raw)
				if err != nil {
					return fmt.Errorf("certificate %s has an unreadable asset id %q: %w", c.id, raw, err)
				}
				c.assetIDs = append(c.assetIDs, parsed)
			}
			certs = append(certs, c)
		}
		if err := cRows.Err(); err != nil {
			return err
		}

		// The cryptographic-key inventory, reachable from a live asset.
		//
		// `implementation_keys` is the junction the Keys lens's "used by N
		// assets" count already walks, so "linked to an asset" means here
		// exactly what it means on screen. findings.ConfigurationAssetSQL is the
		// same fragment findings.AssetSubjects' key path splices, so the assets
		// this claims coverage of are the assets the finding actually raises — an endpoint that moved to another host takes its
		// keys with it, in both readers.
		//
		// A key linked to NO configuration belongs to no asset: a finding on it
		// could not be reached from any asset, could not raise anyone's risk and
		// could not be counted by the has_findings facet, exactly as for an
		// unlinked certificate above. Those keys are read by nothing here.
		//
		// Only the key's own catalogue row is consulted — never its material,
		// which this table has never held (key_producer.go stores fingerprint,
		// algorithm, size, curve and lifecycle dates, and nothing else).
		keyQuery := `
			WITH reachable AS (
			    SELECT DISTINCT ik.key_id,
			           ` + findings.ConfigurationAssetSQL("ci", "e") + ` AS asset_id
			      FROM implementation_keys ik
			      JOIN crypto_implementations ci ON ci.id = ik.implementation_id
			           AND ci.deleted_at IS NULL AND ci.tenant_id = $1
			      LEFT JOIN asset_endpoints e ON e.tenant_id = ci.tenant_id AND e.id = ci.endpoint_id
			      JOIN assets a ON a.tenant_id = ci.tenant_id
			           AND a.id = ` + findings.ConfigurationAssetSQL("ci", "e") + `
			           AND a.deleted_at IS NULL AND a.asset_status <> 'archived'
			)
			SELECT k.id,
			       array_agg(DISTINCT reachable.asset_id::text),
			       COALESCE(k.key_type, ''),
			       COALESCE(k.size_bits, 0),
			       COALESCE(alg.code, ''),
			       COALESCE(alg.primitive, ''),
			       COALESCE(alg.is_pqc, false)
			  FROM keys k
			  JOIN reachable ON reachable.key_id = k.id
			  LEFT JOIN algorithms alg ON alg.id = k.algorithm_id
			 WHERE k.tenant_id = $1
			 GROUP BY k.id, k.key_type, k.size_bits, alg.code, alg.primitive, alg.is_pqc
			 ORDER BY k.id`
		kRows, err := tx.QueryContext(ctx, keyQuery, tenantID)
		if err != nil {
			return fmt.Errorf("query keys: %w", err)
		}
		defer func() { _ = kRows.Close() }()
		for kRows.Next() {
			var k keySubject
			var assetIDs pq.StringArray
			if err := kRows.Scan(&k.id, &assetIDs, &k.keyType, &k.sizeBits,
				&k.catalogue.Code, &k.catalogue.Primitive, &k.catalogue.IsPQC); err != nil {
				return fmt.Errorf("scan key: %w", err)
			}
			for _, raw := range assetIDs {
				parsed, err := uuid.Parse(raw)
				if err != nil {
					return fmt.Errorf("key %s has an unreadable asset id %q: %w", k.id, raw, err)
				}
				k.assetIDs = append(k.assetIDs, parsed)
			}
			k.catalogue.Field = "key_algorithm"
			k.catalogue.Observed = k.keyType
			k.label = keyLabel(k.keyType, k.catalogue.Code, k.sizeBits)
			keys = append(keys, k)
		}
		if err := kRows.Err(); err != nil {
			return err
		}

		certs, err = p.resolveCertificateAlgorithms(ctx, tx, certs)
		return err
	})
	if err != nil {
		return nil, nil, nil, err
	}
	return configs, certs, keys, nil
}

// resolveCertificateAlgorithms looks the certificates' algorithm strings up in
// the catalogue, in ONE query for the whole run.
func (p *CryptoProducer) resolveCertificateAlgorithms(ctx context.Context, tx *sql.Tx, certs []certSubject) ([]certSubject, error) {
	if len(certs) == 0 {
		return certs, nil
	}
	// Every spelling worth asking about: the raw upper-case string and the
	// normalized fold, for both fields.
	needles := map[string]bool{}
	add := func(s string) {
		if s = strings.ToUpper(strings.TrimSpace(s)); s != "" {
			needles[s] = true
			if n := cryptoparse.NormalizeComponentCode(s); n != "" {
				needles[n] = true
			}
		}
	}
	for _, c := range certs {
		add(c.keyAlg)
		add(c.sigAlg)
	}
	if len(needles) == 0 {
		return certs, nil
	}
	list := make([]string, 0, len(needles))
	for n := range needles {
		list = append(list, n)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT UPPER(code), code, COALESCE(risk_score, 0), COALESCE(strength, ''),
		       COALESCE(deprecation_status, ''), COALESCE(primitive, ''), COALESCE(is_pqc, false)
		FROM algorithms
		WHERE UPPER(code) = ANY($1::text[])`, pq.Array(list))
	if err != nil {
		return nil, fmt.Errorf("resolve certificate algorithms: %w", err)
	}
	defer func() { _ = rows.Close() }()

	byCode := map[string]catalogueHit{}
	for rows.Next() {
		var upper string
		var h catalogueHit
		if err := rows.Scan(&upper, &h.Code, &h.RiskScore, &h.Strength, &h.DeprecationStatus, &h.Primitive, &h.IsPQC); err != nil {
			return nil, fmt.Errorf("scan algorithm: %w", err)
		}
		byCode[upper] = h
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	lookup := func(field, observed string) (catalogueHit, bool) {
		s := strings.ToUpper(strings.TrimSpace(observed))
		if s == "" {
			return catalogueHit{}, false
		}
		if h, ok := byCode[s]; ok {
			h.Field, h.Observed = field, observed
			return h, true
		}
		if h, ok := byCode[cryptoparse.NormalizeComponentCode(s)]; ok {
			h.Field, h.Observed = field, observed
			return h, true
		}
		return catalogueHit{}, false
	}

	for i := range certs {
		if h, ok := lookup("public_key_algorithm", certs[i].keyAlg); ok {
			certs[i].catalogue = append(certs[i].catalogue, h)
		}
		if h, ok := lookup("signature_algorithm", certs[i].sigAlg); ok {
			certs[i].catalogue = append(certs[i].catalogue, h)
		}
	}
	return certs, nil
}

// plannedCrypto is one finding the judge phase decided on.
//
// It carries no asset id: a finding names its SUBJECT, and which assets that
// subject belongs to is `findings.AssetSubjects`'s answer, not this producer's
// — a certificate belongs to every asset that serves it. Coverage travels
// separately, in the assessed set.
type plannedCrypto struct {
	finding producer.Finding
}

// judge turns the read rows into findings and into a coverage claim.
//
// No database access: everything it needs is already in the structs, which is
// what lets the whole decision layer be unit-tested without Postgres.
func (p *CryptoProducer) judge(configs []configSubject, certs []certSubject, keys []keySubject, run *CryptoRun) ([]plannedCrypto, []uuid.UUID) {
	var planned []plannedCrypto
	assessed := map[uuid.UUID]bool{}
	seenAsset := map[uuid.UUID]bool{}

	for _, c := range configs {
		seenAsset[c.assetID] = true

		// Assessed when the catalogue actually resolved something, or when
		// ingest's own verdict is non-zero. A configuration whose components
		// resolved to nothing and whose stored score is 0 has not been judged
		// clean — it has not been judged.
		if c.linked > 0 || c.storedRisk > 0 {
			assessed[c.assetID] = true
		}

		if score := c.score(); score > 0 {
			planned = append(planned, plannedCrypto{
				finding: producer.Finding{
					Kind:         findings.KindWeakConfiguration,
					Subject:      producer.Subject{Type: findings.SubjectCryptoConfiguration, ID: c.id},
					SubjectLabel: c.label,
					Severity:     severityForScore(score),
					Score:        score,
					Summary:      summary(findings.KindWeakConfiguration, c.label, ""),
					Evidence:     c.evidence(score),
				},
			})
		}

		if c.pqcVulnerable {
			run.PQCVulnerable++
			planned = append(planned, plannedCrypto{
				finding: pqcFinding(
					producer.Subject{Type: findings.SubjectCryptoConfiguration, ID: c.id},
					c.label,
					map[string]any{
						"vulnerable_algorithms": c.pqcCodes,
						"protocol":              c.protocol,
						"authority":             pqcAuthority,
					}),
			})
		}
	}

	for _, c := range certs {
		score, factors, measurable := c.assess()
		for _, assetID := range c.assetIDs {
			seenAsset[assetID] = true
			if measurable {
				assessed[assetID] = true
			}
		}
		if score > 0 {
			planned = append(planned, plannedCrypto{
				finding: producer.Finding{
					Kind:         findings.KindWeakCertificate,
					Subject:      producer.Subject{Type: findings.SubjectCertificate, ID: c.id},
					SubjectLabel: c.label,
					Severity:     severityForScore(score),
					Score:        score,
					Summary:      summary(findings.KindWeakCertificate, c.label, ""),
					Evidence:     c.evidence(score, factors),
				},
			})
		}
		if codes := c.pqcVulnerableCodes(); len(codes) > 0 {
			run.PQCVulnerable++
			planned = append(planned, plannedCrypto{
				finding: pqcFinding(
					producer.Subject{Type: findings.SubjectCertificate, ID: c.id},
					c.label,
					map[string]any{
						"vulnerable_algorithms": codes,
						"key_algorithm":         c.keyAlg,
						"authority":             pqcAuthority,
					}),
			})
		}
	}

	for _, k := range keys {
		for _, assetID := range k.assetIDs {
			seenAsset[assetID] = true
			if k.measurable() {
				assessed[assetID] = true
			}
		}
		code := k.pqcVulnerableCode()
		if code == "" {
			continue
		}
		run.PQCVulnerable++
		planned = append(planned, plannedCrypto{
			finding: pqcFinding(
				producer.Subject{Type: findings.SubjectKey, ID: k.id},
				k.label,
				k.evidence(code)),
		})
	}

	out := make([]uuid.UUID, 0, len(assessed))
	for id := range assessed {
		out = append(out, id)
	}
	run.Assessed = len(out)
	run.Unassessable = len(seenAsset) - len(out)
	return planned, out
}

// pqcAuthority is the citation every pqc_vulnerable finding carries. A date in
// 2030 that the product asserts without saying who set it is an opinion.
const pqcAuthority = "NIST IR 8547: classical asymmetric primitives deprecated after 2030, disallowed after 2035"

func pqcFinding(subject producer.Subject, label string, evidence map[string]any) producer.Finding {
	k, _ := findings.Get(findings.ProducerCrypto, findings.KindPQCVulnerable)
	return producer.Finding{
		Kind:         findings.KindPQCVulnerable,
		Subject:      subject,
		SubjectLabel: label,
		Severity:     k.DefaultSeverity,
		Score:        k.Score,
		Summary:      summary(findings.KindPQCVulnerable, label, ""),
		Evidence:     evidence,
	}
}

// score is the configuration's risk: the worse of the catalogue's current
// verdict and the one ingest persisted.
//
// Both, not one. The catalogue alone would drop the key-SIZE half of the
// judgement, which no per-algorithm row can express; the stored value alone
// would ignore a catalogue row corrected since the configuration was last
// observed, which is the whole promise of "edit the catalogue row, not Go
// code". Taking the worse means adding the producer can only ever raise a
// score relative to the rollup it replaces, never silently lower one.
func (c configSubject) score() int {
	if c.catalogueRisk > c.storedRisk {
		return c.catalogueRisk
	}
	return c.storedRisk
}

func (c configSubject) evidence(score int) map[string]any {
	e := map[string]any{
		"score":                  score,
		"catalogue_score":        c.catalogueRisk,
		"stored_score":           c.storedRisk,
		"protocol":               c.protocol,
		"linked_component_count": c.linked,
		// The components that produced the number, worst first, straight from
		// the catalogue rows. Algorithm CODES and their assessments only: a
		// cipher suite name and a protocol version are posture, and nothing
		// here is or derives from key material.
		"components": rawJSON(c.components),
	}
	if c.version != "" {
		e["protocol_version"] = c.version
	}
	if c.suite != "" {
		e["cipher_suite"] = c.suite
	}
	return e
}

// assess scores one certificate.
//
// Returns measurable=false when nothing about the certificate could be judged:
// no catalogue row for either algorithm string, no readable key size and no
// recognisable hash. That certificate contributes no coverage — "we could not
// tell" must not be recorded as "we checked".
func (c certSubject) assess() (score int, factors []string, measurable bool) {
	for _, h := range c.catalogue {
		measurable = true
		if h.RiskScore > score {
			score = h.RiskScore
		}
		if h.RiskScore > 0 {
			factors = append(factors, fmt.Sprintf("%s (%s) is rated %s by the algorithm catalogue (risk %d)",
				h.Code, h.Field, orUnrated(h.Strength), h.RiskScore))
		}
	}

	if sev := cryptoparse.WeakHashSeverity(c.sigAlg); sev != "" {
		measurable = true
		if s := cryptoparse.WeakCryptoSeverityScore(sev); s > score {
			score = s
		}
		factors = append(factors, fmt.Sprintf("signature algorithm %q uses a broken or deprecated hash", c.sigAlg))
	}

	// The key-size floor. `KeyAlgorithmFamily` answering Unknown is what makes
	// "measurable" false here rather than "fine": a bare size with no family is
	// a number nobody can place.
	if c.keyBits > 0 && cryptoparse.KeyAlgorithmFamily(c.keyAlg) != cryptoparse.KexFamilyUnknown {
		measurable = true
		if sev := cryptoparse.WeakKeySizeSeverity(c.keyAlg, c.keyBits); sev != "" {
			if s := cryptoparse.WeakCryptoSeverityScore(sev); s > score {
				score = s
			}
			factors = append(factors, fmt.Sprintf("%s key of %d bits is below the SP 800-131A floor",
				orUnknown(c.keyAlg), c.keyBits))
		}
	}
	return score, factors, measurable
}

// pqcVulnerableCodes names the certificate's classical asymmetric algorithms,
// or nothing.
//
// Same denylist as the configuration classifier — `cryptoassess`
// .QuantumVulnerablePrimitives — applied to the catalogue rows the
// certificate's own algorithm strings resolved to. A certificate whose
// algorithm resolves to nothing is UNCLASSIFIED, never assumed safe, and raises
// no finding.
func (c certSubject) pqcVulnerableCodes() []string {
	var out []string
	for _, h := range c.catalogue {
		if h.IsPQC || h.Primitive == "" {
			continue
		}
		for _, vuln := range cryptoassess.QuantumVulnerablePrimitives {
			if h.Primitive == vuln {
				out = append(out, h.Code)
				break
			}
		}
	}
	return out
}

func (c certSubject) evidence(score int, factors []string) map[string]any {
	e := map[string]any{
		"score":                score,
		"risk_factors":         factors,
		"public_key_algorithm": c.keyAlg,
		"signature_algorithm":  c.sigAlg,
		"catalogue_matches":    c.catalogue,
	}
	if c.keyBits > 0 {
		e["public_key_size"] = c.keyBits
	}
	return e
}

// write commits the run: the findings, the coverage claim, then the sweep — one
// transaction, because a sweep that lands without the upserts that justify it
// inactivates live findings, and a coverage claim that lands without them
// asserts an assessment that did not happen.
func (p *CryptoProducer) write(ctx context.Context, tenantID uuid.UUID, planned []plannedCrypto, assessed []uuid.UUID, run *CryptoRun) error {
	seen := map[string][]producer.Subject{}
	for _, kind := range cryptoKinds {
		seen[kind] = nil
	}

	return p.repo.RunInTx(ctx, tenantID.String(), func(r *pgidentity.Repository) error {
		tx := r.Tx()

		for _, plan := range planned {
			if _, err := p.writer.Upsert(ctx, tx, tenantID, plan.finding); err != nil {
				return err
			}
			run.Raised++
			seen[plan.finding.Kind] = append(seen[plan.finding.Kind], plan.finding.Subject)
		}

		if _, err := p.writer.MarkAssessed(ctx, tx, tenantID, assessed); err != nil {
			return err
		}

		for _, kind := range cryptoKinds {
			n, err := p.writer.Sweep(ctx, tx, tenantID, kind, seen[kind])
			if err != nil {
				return err
			}
			run.Resolved += n
		}
		return nil
	})
}

// cryptoKinds is every kind this producer emits, which is also every kind it
// sweeps. Derived from the registry rather than listed, so a kind added to the
// `crypto` producer without a sweep here is impossible.
var cryptoKinds = func() []string {
	var out []string
	for _, k := range findings.All {
		if k.Producer == findings.ProducerCrypto {
			out = append(out, k.Key)
		}
	}
	return out
}()

// severityForScore bands a score and spells the band the way
// findings_severity_check does.
//
// models.RiskBands (shared/riskbands) is the single CVSS-anchored ladder; this
// does not re-band, it renames. "Informational" has no severity below `info`
// and is unreachable here because the caller only raises a finding for a
// positive score — which is the three-valued rule: 0 is not assessed, and not
// assessed raises nothing.
func severityForScore(score int) string {
	switch riskbands.GetRiskLevel(score) {
	case "Critical":
		return producer.SeverityCritical
	case "High":
		return producer.SeverityHigh
	case "Medium":
		return producer.SeverityMedium
	case "Low":
		return producer.SeverityLow
	}
	return producer.SeverityInfo
}

// summary renders the registry's title_template.
func summary(kind, subject, detail string) string {
	k, ok := findings.Get(findings.ProducerCrypto, kind)
	if !ok {
		return subject
	}
	s := strings.ReplaceAll(k.TitleTemplate, "{subject}", subject)
	return strings.ReplaceAll(s, "{detail}", detail)
}

// configurationLabel names a configuration the way somebody reading a finding
// list needs it named: the protocol it speaks and where it speaks it.
func configurationLabel(protocol, version, address string, port int) string {
	name := protocol
	if version != "" {
		name += " " + version
	}
	if address != "" && port > 0 {
		return fmt.Sprintf("%s on %s:%d", name, address, port)
	}
	if address != "" {
		return name + " on " + address
	}
	return name
}

// keyLabel names a key the way somebody reading a finding list needs it named:
// what it is and how big, not which one.
//
// The catalogue CODE when the algorithm resolved (it is the precise name — the
// thing the migration is from), the raw key_type otherwise. Deliberately NOT the
// public fingerprint: a finding title is read in lists, digests and tickets, and
// a 64-character hex string there is noise. The id in the subject is how a
// reader gets to the exact row.
func keyLabel(keyType, code string, sizeBits int) string {
	name := code
	if name == "" {
		name = orUnknown(keyType)
	}
	if sizeBits > 0 {
		return fmt.Sprintf("%s %d-bit key", name, sizeBits)
	}
	return name + " key"
}

func orUnrated(s string) string {
	if s == "" {
		return "unrated"
	}
	return s
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown-algorithm"
	}
	return s
}

// rawJSON carries an already-encoded JSON document into the evidence map
// without decoding and re-encoding it.
type rawJSON []byte

func (r rawJSON) MarshalJSON() ([]byte, error) {
	if len(r) == 0 {
		return []byte("[]"), nil
	}
	return r, nil
}
