package certtrust

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// MaxNoteLength mirrors the API contract's maxLength on note.
const MaxNoteLength = 1000

// MaxPEMBytes caps a certificate_pem body: a CA chain is a few kilobytes.
const MaxPEMBytes = 1 << 20

// maxBackfillPerChange bounds how many never-evaluated certificates a decision
// change also evaluates, so the request stays short on a large tenant.
const maxBackfillPerChange = 2000

// ErrInvalid is a request the caller must fix (400). The message is safe to
// show.
type ErrInvalid struct{ Msg string }

func (e *ErrInvalid) Error() string { return e.Msg }

// ErrConflict is returned when a decision already exists for the CA (409).
type ErrConflict struct{ ExistingID uuid.UUID }

func (e *ErrConflict) Error() string {
	return fmt.Sprintf("a trust decision already exists for this CA (id %s); change it with PUT /trust-anchors/%s", e.ExistingID, e.ExistingID)
}

// ErrAnchorNotFound is returned when the decision does not exist for the tenant.
var ErrAnchorNotFound = errors.New("trust anchor not found")

// AnchorCertificate is the CA a decision is about (TrustAnchorCertificate).
type AnchorCertificate struct {
	ID                uuid.UUID  `json:"id"`
	SubjectDN         string     `json:"subject_dn"`
	IssuerDN          string     `json:"issuer_dn"`
	CommonName        *string    `json:"common_name,omitempty"`
	FingerprintSHA256 string     `json:"fingerprint_sha256"`
	NotBefore         *time.Time `json:"not_before,omitempty"`
	NotAfter          *time.Time `json:"not_after,omitempty"`
	IsSelfSigned      bool       `json:"is_self_signed"`
	IsCACertificate   bool       `json:"is_ca_certificate"`
}

// Anchor is one recorded decision (TrustAnchor).
type Anchor struct {
	ID                   uuid.UUID         `json:"id"`
	TenantID             uuid.UUID         `json:"tenant_id"`
	CertificateID        uuid.UUID         `json:"certificate_id"`
	Decision             string            `json:"decision"`
	Note                 *string           `json:"note,omitempty"`
	DecidedBy            *uuid.UUID        `json:"decided_by,omitempty"`
	DecidedAt            time.Time         `json:"decided_at"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
	Certificate          AnchorCertificate `json:"certificate"`
	AffectedCertificates int               `json:"affected_certificates"`
	AffectedAssets       int               `json:"affected_assets"`
}

// CreateRequest names the CA by CertificateID or CertificatePEM (exactly one).
type CreateRequest struct {
	CertificateID  *uuid.UUID
	CertificatePEM string
	Decision       string
	Note           string
	DecidedBy      uuid.UUID
}

// UpdateRequest changes the decision, the note, or both. A nil field is left
// as it is; an empty Note clears it.
type UpdateRequest struct {
	Decision  *string
	Note      *string
	DecidedBy uuid.UUID
}

// CertificateWriter is the slice of CertificateService a PEM decision needs to
// put CA certificates into inventory through the ordinary create path (so
// they get history, events and their own trust evaluation like any other).
type CertificateWriter interface {
	FindOrCreateCertificate(tenantID uuid.UUID, certData models.CertificateData) (*models.Certificate, error)
	LinkCertificateIssuer(tenantID, certID, issuerCertID uuid.UUID) error
}

// Store reads and writes a tenant's trust decisions and keeps trust_status
// current when they change.
type Store struct {
	db    *database.DB
	eval  *Evaluator
	certs CertificateWriter
	// reconcile asks compliance-engine to re-evaluate the tenant after a
	// decision changes (the cert-hygiene control reads trust_status). Nil:
	// nothing is published.
	reconcile ReconcilePublisher
}

// ReconcileReason is the reason a trust decision's reconcile job carries.
const ReconcileReason = "certificate_trust_changed"

// ReconcilePublisher publishes compliance-engine's per-tenant reconcile job
// (services.EventPublisherService in production).
type ReconcilePublisher interface {
	PublishComplianceReconcile(ctx context.Context, tenantID uuid.UUID, reason string) error
}

// SetReconcilePublisher wires the compliance reconcile publish.
func (s *Store) SetReconcilePublisher(p ReconcilePublisher) { s.reconcile = p }

// publishReconcile asks for ONE compliance reconcile of the tenant after a
// decision request changed what it trusts — once per request, not once per
// re-evaluated certificate: the reconcile re-reads every certificate anyway.
// A failure is logged; the decision is already recorded and the nightly
// reconcile converges it.
func (s *Store) publishReconcile(ctx context.Context, tenantID uuid.UUID) {
	if s.reconcile == nil {
		return
	}
	if err := s.reconcile.PublishComplianceReconcile(ctx, tenantID, ReconcileReason); err != nil {
		log.Printf("[certtrust] tenant %s: publish compliance reconcile: %v", tenantID, err)
	}
}

// NewStore returns a Store. certs may be nil only if PEM decisions are never
// made (tests of the id path).
func NewStore(db *database.DB, eval *Evaluator, certs CertificateWriter) *Store {
	return &Store{db: db, eval: eval, certs: certs}
}

const anchorSelect = `
	SELECT a.id, a.tenant_id, a.certificate_id, a.decision, a.note, a.decided_by,
	       a.decided_at, a.created_at, a.updated_at,
	       c.subject_dn, c.issuer_dn, c.common_name, c.fingerprint_sha256,
	       c.not_before, c.not_after,
	       COALESCE(c.is_self_signed, false), COALESCE(c.is_ca_certificate, false),
	       (SELECT COUNT(*)
	          FROM certificates x
	         WHERE x.tenant_id = a.tenant_id
	           AND x.trust_anchor_certificate_id = a.certificate_id
	           AND x.id <> a.certificate_id) AS affected_certificates,
	       (SELECT COUNT(DISTINCT ci.asset_id)
	          FROM crypto_implementations ci
	          JOIN assets na ON na.tenant_id = ci.tenant_id AND na.id = ci.asset_id
	          JOIN certificates x ON x.id = ci.certificate_id AND x.tenant_id = ci.tenant_id
	         WHERE ci.tenant_id = a.tenant_id
	           AND ci.deleted_at IS NULL
	           AND na.deleted_at IS NULL
	           AND x.trust_anchor_certificate_id = a.certificate_id
	           AND x.id <> a.certificate_id) AS affected_assets
	  FROM tenant_trust_anchors a
	  JOIN certificates c ON c.id = a.certificate_id AND c.tenant_id = a.tenant_id
	 WHERE a.tenant_id = $1`

type rowScanner interface {
	Scan(dest ...interface{}) error
}

func scanAnchor(r rowScanner) (Anchor, error) {
	var a Anchor
	var note, commonName sql.NullString
	var decidedBy uuid.NullUUID
	var notBefore, notAfter sql.NullTime
	err := r.Scan(&a.ID, &a.TenantID, &a.CertificateID, &a.Decision, &note, &decidedBy,
		&a.DecidedAt, &a.CreatedAt, &a.UpdatedAt,
		&a.Certificate.SubjectDN, &a.Certificate.IssuerDN, &commonName, &a.Certificate.FingerprintSHA256,
		&notBefore, &notAfter, &a.Certificate.IsSelfSigned, &a.Certificate.IsCACertificate,
		&a.AffectedCertificates, &a.AffectedAssets)
	if err != nil {
		return a, err
	}
	a.Certificate.ID = a.CertificateID
	if note.Valid && note.String != "" {
		v := note.String
		a.Note = &v
	}
	if decidedBy.Valid && decidedBy.UUID != uuid.Nil {
		v := decidedBy.UUID
		a.DecidedBy = &v
	}
	if commonName.Valid && commonName.String != "" {
		v := commonName.String
		a.Certificate.CommonName = &v
	}
	if notBefore.Valid {
		v := notBefore.Time
		a.Certificate.NotBefore = &v
	}
	if notAfter.Valid {
		v := notAfter.Time
		a.Certificate.NotAfter = &v
	}
	return a, nil
}

// ListAnchors returns the tenant's decisions, newest first.
func (s *Store) ListAnchors(ctx context.Context, tenantID uuid.UUID) ([]Anchor, error) {
	out := make([]Anchor, 0)
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, anchorSelect+` ORDER BY a.decided_at DESC, a.created_at DESC, a.id`, tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			a, err := scanAnchor(rows)
			if err != nil {
				return err
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("list trust anchors: %w", err)
	}
	return out, nil
}

// GetAnchor returns one decision, or ErrAnchorNotFound.
func (s *Store) GetAnchor(ctx context.Context, tenantID, id uuid.UUID) (*Anchor, error) {
	var a Anchor
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		var err error
		a, err = scanAnchor(tx.QueryRowContext(ctx, anchorSelect+` AND a.id = $2`, tenantID, id))
		return err
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAnchorNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get trust anchor: %w", err)
	}
	return &a, nil
}

func validDecision(d string) bool { return d == DecisionTrusted || d == DecisionDistrusted }

func checkNote(note string) error {
	if utf8.RuneCountInString(note) > MaxNoteLength {
		return &ErrInvalid{Msg: fmt.Sprintf("note exceeds %d characters", MaxNoteLength)}
	}
	return nil
}

func nullable(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func nullableUser(id uuid.UUID) interface{} {
	if id == uuid.Nil {
		return nil
	}
	return id
}

// CreateAnchor records a decision and re-evaluates every certificate that
// chains through the CA, synchronously.
func (s *Store) CreateAnchor(ctx context.Context, tenantID uuid.UUID, req CreateRequest) (*Anchor, error) {
	if !validDecision(req.Decision) {
		return nil, &ErrInvalid{Msg: "decision must be 'trusted' or 'distrusted'"}
	}
	if err := checkNote(req.Note); err != nil {
		return nil, err
	}
	hasID := req.CertificateID != nil && *req.CertificateID != uuid.Nil
	hasPEM := strings.TrimSpace(req.CertificatePEM) != ""
	if hasID == hasPEM {
		return nil, &ErrInvalid{Msg: "give exactly one of certificate_id or certificate_pem"}
	}

	var caID uuid.UUID
	if hasID {
		caID = *req.CertificateID
		if err := s.requireCA(ctx, tenantID, caID); err != nil {
			return nil, err
		}
	} else {
		id, err := s.storePEMChain(ctx, tenantID, req.CertificatePEM)
		if err != nil {
			return nil, err
		}
		caID = id
	}

	var anchorID uuid.UUID
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		err := tx.QueryRowContext(ctx, `
			INSERT INTO tenant_trust_anchors (tenant_id, certificate_id, decision, note, decided_by)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (tenant_id, certificate_id) DO NOTHING
			RETURNING id`,
			tenantID, caID, req.Decision, nullable(req.Note), nullableUser(req.DecidedBy)).Scan(&anchorID)
		if errors.Is(err, sql.ErrNoRows) {
			var existing uuid.UUID
			if e := tx.QueryRowContext(ctx,
				`SELECT id FROM tenant_trust_anchors WHERE tenant_id = $1 AND certificate_id = $2`,
				tenantID, caID).Scan(&existing); e != nil {
				return fmt.Errorf("find existing decision: %w", e)
			}
			return &ErrConflict{ExistingID: existing}
		}
		return err
	})
	if err != nil {
		var conflict *ErrConflict
		if errors.As(err, &conflict) {
			return nil, conflict
		}
		return nil, fmt.Errorf("record trust decision: %w", err)
	}

	if err := s.recompute(ctx, tenantID, caID); err != nil {
		return nil, err
	}
	s.publishReconcile(ctx, tenantID)
	return s.GetAnchor(ctx, tenantID, anchorID)
}

// requireCA is the certificate_id path's check: the certificate must exist for
// the tenant and be a CA certificate.
func (s *Store) requireCA(ctx context.Context, tenantID, certID uuid.UUID) error {
	var isCA bool
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT COALESCE(is_ca_certificate, false) FROM certificates WHERE tenant_id = $1 AND id = $2`,
			tenantID, certID).Scan(&isCA)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return &ErrInvalid{Msg: "certificate_id does not name a certificate in this organisation's inventory"}
	}
	if err != nil {
		return fmt.Errorf("look up certificate: %w", err)
	}
	if !isCA {
		return &ErrInvalid{Msg: "only a CA certificate can be trusted or distrusted"}
	}
	return nil
}

// storePEMChain parses every CERTIFICATE block, requires each to be a CA,
// stores the ones not yet in inventory (chain_source 'upload'), links each to
// its issuer among them, and returns the id of the LAST certificate in the
// file — the one the decision is recorded against.
func (s *Store) storePEMChain(ctx context.Context, tenantID uuid.UUID, pemText string) (uuid.UUID, error) {
	if len(pemText) > MaxPEMBytes {
		return uuid.Nil, &ErrInvalid{Msg: "certificate_pem exceeds the 1 MiB limit"}
	}
	if s.certs == nil {
		return uuid.Nil, errors.New("certtrust: store has no certificate writer")
	}
	var parsed []*x509.Certificate
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return uuid.Nil, &ErrInvalid{Msg: "certificate_pem holds a certificate that does not parse"}
		}
		parsed = append(parsed, c)
	}
	if len(parsed) == 0 {
		return uuid.Nil, &ErrInvalid{Msg: "certificate_pem holds no PEM CERTIFICATE block"}
	}
	for _, c := range parsed {
		if !c.BasicConstraintsValid || !c.IsCA {
			return uuid.Nil, &ErrInvalid{Msg: fmt.Sprintf("%q is not a CA certificate; only CA certificates can be trusted or distrusted", c.Subject.String())}
		}
	}

	ids := make([]uuid.UUID, len(parsed))
	for i, c := range parsed {
		data := CertificateDataFromX509(c)
		data.DataSource = "manual"
		data.ChainSource = ChainSourceUpload
		stored, err := s.certs.FindOrCreateCertificate(tenantID, data)
		if err != nil {
			return uuid.Nil, fmt.Errorf("store CA certificate %q: %w", c.Subject.String(), err)
		}
		ids[i] = stored.ID
	}
	if err := s.linkBySignature(tenantID, parsed, ids); err != nil {
		return uuid.Nil, fmt.Errorf("link uploaded CA certificates: %w", err)
	}
	return ids[len(ids)-1], nil
}

// linkBySignature links each stored certificate to its issuer among the
// others — by signature, not by position: a file may list the chain in either
// order. ids[i] is the stored row of parsed[i].
func (s *Store) linkBySignature(tenantID uuid.UUID, parsed []*x509.Certificate, ids []uuid.UUID) error {
	for i, c := range parsed {
		if c.Subject.String() == c.Issuer.String() {
			continue
		}
		for j, issuer := range parsed {
			if i == j || ids[i] == ids[j] {
				continue
			}
			if c.CheckSignatureFrom(issuer) == nil {
				if err := s.certs.LinkCertificateIssuer(tenantID, ids[i], ids[j]); err != nil {
					return err
				}
				break
			}
		}
	}
	return nil
}

// UpdateAnchor changes a decision or its note and re-evaluates.
func (s *Store) UpdateAnchor(ctx context.Context, tenantID, id uuid.UUID, req UpdateRequest) (*Anchor, error) {
	if req.Decision == nil && req.Note == nil {
		return nil, &ErrInvalid{Msg: "nothing to change: give decision, note, or both"}
	}
	if req.Decision != nil && !validDecision(*req.Decision) {
		return nil, &ErrInvalid{Msg: "decision must be 'trusted' or 'distrusted'"}
	}
	if req.Note != nil {
		if err := checkNote(*req.Note); err != nil {
			return nil, err
		}
	}
	var decision, note interface{}
	if req.Decision != nil {
		decision = *req.Decision
	}
	setNote := req.Note != nil
	if setNote {
		note = nullable(*req.Note)
	}
	var caID uuid.UUID
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		// A changed decision is a new decision: decided_at / decided_by move
		// with it. A note-only edit keeps who decided and when.
		return tx.QueryRowContext(ctx, `
			UPDATE tenant_trust_anchors
			   SET decided_at = CASE WHEN $3::varchar IS NOT NULL AND $3::varchar <> decision THEN NOW() ELSE decided_at END,
			       decided_by = CASE WHEN $3::varchar IS NOT NULL AND $3::varchar <> decision THEN $6::uuid ELSE decided_by END,
			       decision   = COALESCE($3::varchar, decision),
			       note       = CASE WHEN $4 THEN $5::text ELSE note END,
			       updated_at = NOW()
			 WHERE tenant_id = $1 AND id = $2
			RETURNING certificate_id`,
			tenantID, id, decision, setNote, note, nullableUser(req.DecidedBy)).Scan(&caID)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAnchorNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("update trust decision: %w", err)
	}
	if err := s.recompute(ctx, tenantID, caID); err != nil {
		return nil, err
	}
	if req.Decision != nil {
		// A note-only edit changes no verdict, so it asks for no reconcile.
		s.publishReconcile(ctx, tenantID)
	}
	return s.GetAnchor(ctx, tenantID, id)
}

// DeleteAnchor removes a decision. The CA stays in inventory; certificates
// chaining to it are re-evaluated (untrusted, or public for a public root).
func (s *Store) DeleteAnchor(ctx context.Context, tenantID, id uuid.UUID) error {
	var caID uuid.UUID
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx,
			`DELETE FROM tenant_trust_anchors WHERE tenant_id = $1 AND id = $2 RETURNING certificate_id`,
			tenantID, id).Scan(&caID)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return ErrAnchorNotFound
	}
	if err != nil {
		return fmt.Errorf("delete trust decision: %w", err)
	}
	if err := s.recompute(ctx, tenantID, caID); err != nil {
		return err
	}
	s.publishReconcile(ctx, tenantID)
	return nil
}

// recompute runs after every decision change, synchronously: every certificate
// whose chain runs through the CA (the exact set a decision on it can change),
// then a bounded backfill of certificates never evaluated at all.
func (s *Store) recompute(ctx context.Context, tenantID, caID uuid.UUID) error {
	start := time.Now()
	// LocalOnly: the request does not wait on AIA fetches; chains that need
	// one are completed in the background.
	ctx = LocalOnly(ctx)
	n, err := s.eval.EvaluateSubtree(ctx, tenantID, caID)
	if err != nil {
		return fmt.Errorf("re-evaluate certificates under %s: %w", caID, err)
	}
	m, err := s.eval.RecomputeUnevaluated(ctx, tenantID, maxBackfillPerChange)
	if err != nil {
		return fmt.Errorf("evaluate unevaluated certificates: %w", err)
	}
	// 3rd-party connections read the same decisions (their hygiene flags and
	// trust_status); bounded like the certificate recompute.
	if _, err := s.eval.RecomputeExternalConnections(ctx, tenantID); err != nil {
		return fmt.Errorf("re-classify 3rd-party connections: %w", err)
	}
	if d := time.Since(start); n+m > 1000 || d > 5*time.Second {
		log.Printf("[certtrust] tenant %s: decision on %s re-evaluated %d certificate(s) and backfilled %d in %s", tenantID, caID, n, m, d.Round(time.Millisecond))
	}
	return nil
}
