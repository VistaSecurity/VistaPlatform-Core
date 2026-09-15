package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/findings"
)

// RemediationDraftService resolves a finding into the allowlisted projection the
// Remediator seam is given (seams.FindingRef).
//
// # Why the resolution lives here and not in the seam
//
// ADR-0008 D4.6 keeps tenant isolation out of the seam layer: a seam gets no
// database handle and no tenant context, so the thing that holds both — a
// request-scoped service, inside the tenant's RLS transaction — is what reads
// the row and decides what may leave. The projection it produces IS the boundary
// allowlist (D4.5), and it is written here so a reviewer can read one function
// and know what crosses.
//
// Nothing about the projection is generic. It deliberately drops every
// identifier except the subject LABEL the tenant already sees on the finding, and
// it fills the subject context from an explicit list of facts — class, OS,
// hardware vendor and model, and a one-line summary of the cryptographic
// configuration where there is one. A vendor and a model name a product, which
// is what lets a step say "on PAN-OS 10.1"; a serial or an address names a thing
// and buys nothing a plan needs.
type RemediationDraftService struct {
	db *sqlx.DB
}

// NewRemediationDraftService creates the resolver.
func NewRemediationDraftService(db *sqlx.DB) *RemediationDraftService {
	return &RemediationDraftService{db: db}
}

// subjectFactKeys are the asset facts that may cross the provider boundary.
//
// A closed list, matched exactly. The fact store is extensible by design, so a
// prefix match or a "everything under os.*" rule would export whatever a future
// producer decides to write there — which is the "never assign a vendor response
// into Metadata" mistake with an extra step.
var subjectFactKeys = []string{"os.name", "os.version", "hw.vendor", "hw.model"}

// ResolveFinding reads one finding and projects it for the seam.
//
// The guidance comes from the findings REGISTRY rather than from the row: it is
// a property of the kind, generated from standards/findings-registry.yaml, and a
// per-row copy would be 21 sentences duplicated across every finding a tenant
// has. A kind with no registry entry resolves to empty guidance, which the
// endpoint treats as "there is nothing to degrade to" rather than sending a
// finding with no deterministic answer behind it.
func (s *RemediationDraftService) ResolveFinding(ctx context.Context, tenantID, findingID uuid.UUID) (seams.FindingRef, error) {
	var (
		ref          seams.FindingRef
		subjectLabel sql.NullString
		evidenceRaw  []byte
		subjectID    uuid.UUID
	)

	err := shareddatabase.WithTenantTx(ctx, s.db.DB, tenantID, func(tx *sql.Tx) error {
		row := tx.QueryRowContext(ctx, `
			SELECT producer, kind, severity, subject_type, subject_id, subject_label, summary, evidence
			  FROM findings
			 WHERE id = $1 AND tenant_id = $2`, findingID, tenantID)
		if err := row.Scan(&ref.Producer, &ref.Kind, &ref.Severity, &ref.SubjectType,
			&subjectID, &subjectLabel, &ref.Summary, &evidenceRaw); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrFindingNotFound
			}
			return fmt.Errorf("read finding: %w", err)
		}
		ref.SubjectLabel = subjectLabel.String

		subject, err := s.resolveSubject(ctx, tx, tenantID, ref.SubjectType, subjectID)
		if err != nil {
			// A subject that cannot be resolved is not a reason to refuse the
			// draft: the finding, its evidence and its guidance are all still
			// there, and the plan is simply less specific. Failing the whole
			// request over a missing join would turn a partial answer into no
			// answer, which is the wrong direction on a surface whose entire
			// premise is that something honest can always be returned.
			//
			// Logged, never silent — an operator debugging "why are the plans
			// suddenly generic" needs the cause named — and the zero
			// SubjectContext is carried forward deliberately: a half-filled one
			// would be worse than none, because a step naming the wrong vendor
			// reads exactly like a step naming the right one.
			log.Printf("[remediation-draft] subject context for finding %s (%s) unavailable, drafting without it: %v",
				findingID, ref.SubjectType, err)
			ref.Subject = seams.SubjectContext{}
			return nil
		}
		ref.Subject = subject
		return nil
	})
	if err != nil {
		if errors.Is(err, ErrFindingNotFound) {
			return seams.FindingRef{}, err
		}
		return seams.FindingRef{}, err
	}

	ref.FindingID = findingID.String()
	ref.TenantID = tenantID.String()
	ref.Evidence = decodeEvidence(evidenceRaw)
	if g, ok := findings.GuidanceFor(ref.Producer, ref.Kind); ok {
		ref.Guidance = g
	}
	return ref, nil
}

// resolveSubject fills the allowlisted subject context for whatever the finding
// is about.
//
// Every subject type resolves to an ASSET where it has one — an endpoint and a
// crypto configuration both belong to one — because the facts that make a step
// specific (which OS, whose hardware) are the asset's. A certificate has no
// asset of its own and contributes only what is already in its label.
func (s *RemediationDraftService) resolveSubject(
	ctx context.Context, tx *sql.Tx, tenantID uuid.UUID, subjectType string, subjectID uuid.UUID,
) (seams.SubjectContext, error) {
	var out seams.SubjectContext

	assetID := uuid.Nil
	switch subjectType {
	case findings.SubjectAsset:
		assetID = subjectID

	case findings.SubjectEndpoint:
		if err := tx.QueryRowContext(ctx,
			`SELECT asset_id FROM asset_endpoints WHERE id = $1 AND tenant_id = $2`,
			subjectID, tenantID).Scan(&assetID); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return out, err
		}

	case findings.SubjectCryptoConfiguration:
		var (
			protocolVersion, cipherSuite, keyExchange, signature sql.NullString
		)
		err := tx.QueryRowContext(ctx, `
			SELECT asset_id, protocol_version, cipher_suite, key_exchange_algorithm, signature_algorithm
			  FROM crypto_implementations
			 WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
			subjectID, tenantID).Scan(&assetID, &protocolVersion, &cipherSuite, &keyExchange, &signature)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return out, err
		}
		out.Configuration = configurationSummary(protocolVersion, cipherSuite, keyExchange, signature)

	default:
		// Certificates, keys, software installs, relationships, controls,
		// frameworks. No asset join and no extra context — the label is what a
		// person sees and it is what the seam gets.
		return out, nil
	}

	if assetID == uuid.Nil {
		return out, nil
	}

	// Both key columns: `assets` is hash-partitioned by tenant_id and keyed on
	// (tenant_id, id), with no index on id alone, so naming only id scans all
	// eight partitions.
	var classKey sql.NullString
	if err := tx.QueryRowContext(ctx,
		`SELECT class_key FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
		tenantID, assetID).Scan(&classKey); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}
	out.ClassKey = classKey.String

	rows, err := tx.QueryContext(ctx, `
		SELECT key, value
		  FROM asset_facts
		 WHERE tenant_id = $1 AND asset_id = $2 AND key = ANY($3)`,
		// pq.Array, not a bare []string: lib/pq does not implement driver.Valuer
		// for a Go slice, so the bare form is a runtime "unsupported type" on
		// every call — the kind of failure that only shows up on the one code
		// path a unit test with no database never reaches.
		tenantID, assetID, pq.Array(subjectFactKeys))
	if err != nil {
		return out, err
	}
	defer func() { _ = rows.Close() }()

	for rows.Next() {
		var key string
		var raw []byte
		if err := rows.Scan(&key, &raw); err != nil {
			return out, err
		}
		v := factString(raw)
		if v == "" {
			continue
		}
		switch key {
		case "os.name":
			out.OSName = v
		case "os.version":
			out.OSVersion = v
		case "hw.vendor":
			out.HWVendor = v
		case "hw.model":
			out.HWModel = v
		}
	}
	return out, rows.Err()
}

// configurationSummary renders the one-line description of a cryptographic
// configuration a step needs to be specific about it.
//
// A summary, never the row. The row carries raw_data, a certificate id, a
// sensor id and a compliance_status blob, none of which a remediation step reads
// and all of which would be exported by a "just send the record" projection.
func configurationSummary(parts ...sql.NullString) string {
	var out []string
	for _, p := range parts {
		if p.Valid && strings.TrimSpace(p.String) != "" {
			out = append(out, strings.TrimSpace(p.String))
		}
	}
	return strings.Join(out, " / ")
}

// factString reads a fact value as a display string.
//
// `asset_facts.value` is jsonb, so a string fact arrives quoted. Anything that
// is not a JSON string — a number, an object — is rendered as its raw JSON
// rather than dropped: `os.version` written as a number is still a version, and
// dropping it would silently make the plan less specific for a reason nobody
// could see.
func factString(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(string(raw))
}

// decodeEvidence reads the finding's evidence jsonb into a map.
//
// A decode failure yields an EMPTY map rather than an error: the evidence is
// grounding, the guidance and the finding are not, and a malformed blob should
// cost specificity rather than the whole answer. It also yields an empty map for
// `null`, which is what the column holds when a producer wrote nothing — and
// nil would marshal back into the prompt as `null`, reading as a value rather
// than as the absence of one.
func decodeEvidence(raw []byte) map[string]any {
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return map[string]any{}
	}
	return out
}
