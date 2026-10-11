package certtrust

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/certificates/chainfetch"
	"github.com/vistasecurity/vistaplatform/shared/certificates/publicroots"
	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

// ErrCertificateNotFound is returned when the certificate does not exist for
// the tenant.
var ErrCertificateNotFound = errors.New("certificate not found")

// maxChainDepth bounds the issuer walk. Real chains are 2-4 long; the bound is
// what stops a corrupt issuer cycle from walking forever.
const maxChainDepth = 16

// recomputeBatch is how many certificate ids a tenant recompute reads at once.
const recomputeBatch = 500

// maxSubtreeSize bounds the certificates re-evaluated under one CA after a
// decision or a link change. A CA with more descendants than this is logged and
// the rest are picked up by the next tenant recompute.
const maxSubtreeSize = 20000

// RootStore is the public root bundle as the evaluator uses it. The production
// value is the embedded Mozilla bundle; tests substitute a generated root.
type RootStore interface {
	Lookup(fingerprintSHA256 string) *x509.Certificate
	FindIssuer(cert *x509.Certificate) *x509.Certificate
}

type embeddedRoots struct{}

func (embeddedRoots) Lookup(fp string) *x509.Certificate { return publicroots.Lookup(fp) }
func (embeddedRoots) FindIssuer(c *x509.Certificate) *x509.Certificate {
	return publicroots.FindIssuer(c)
}

// EmbeddedRoots is the RootStore backed by shared/certificates/publicroots.
func EmbeddedRoots() RootStore { return embeddedRoots{} }

// Evaluator computes and stores certificates.trust_status.
type Evaluator struct {
	db    *database.DB
	roots RootStore
	// aia completes chains from caIssuers URLs; nil disables AIA.
	aia *aiaPolicy
}

// NewEvaluator returns an evaluator over the embedded public root bundle that
// completes chains by AIA through the platform's fetch guard.
func NewEvaluator(db *database.DB) *Evaluator {
	return &Evaluator{db: db, roots: EmbeddedRoots(), aia: platformAIAPolicy()}
}

// WithAIAGuard returns a copy of e whose AIA fetches go through guard, with
// fresh failure and rate-limit state. For tests, whose AIA server listens on
// loopback, which the platform guard refuses. A nil guard disables AIA.
func (e *Evaluator) WithAIAGuard(guard discovery.AddressGuard) *Evaluator {
	c := *e
	c.aia = nil
	if guard != nil {
		c.aia = newAIAPolicy(guard)
	}
	return &c
}

// WithRoots returns a copy of e that consults roots instead of the embedded
// bundle. For tests: a generated root cannot be in Mozilla's store.
func (e *Evaluator) WithRoots(roots RootStore) *Evaluator {
	c := *e
	c.roots = roots
	return &c
}

type chainRow struct {
	Link
	issuerID *uuid.UUID
	pem      string
}

// loadChain walks issuer_certificate_id from certID to the top, inside the
// tenant's RLS context, with each certificate's recorded decision.
func (e *Evaluator) loadChain(ctx context.Context, tenantID, certID uuid.UUID) ([]chainRow, error) {
	const q = `
		WITH RECURSIVE chain AS (
			SELECT c.id, c.issuer_certificate_id, c.fingerprint_sha256,
			       (COALESCE(c.is_self_signed, false) OR c.subject_dn = c.issuer_dn) AS self_signed,
			       c.certificate_pem, 0 AS depth, ARRAY[c.id] AS path
			  FROM certificates c
			 WHERE c.tenant_id = $1 AND c.id = $2
			UNION ALL
			SELECT p.id, p.issuer_certificate_id, p.fingerprint_sha256,
			       (COALESCE(p.is_self_signed, false) OR p.subject_dn = p.issuer_dn),
			       p.certificate_pem, ch.depth + 1, ch.path || p.id
			  FROM chain ch
			  JOIN certificates p ON p.id = ch.issuer_certificate_id AND p.tenant_id = $1
			 WHERE NOT ch.self_signed
			   AND NOT (p.id = ANY(ch.path))
			   AND ch.depth < $3
		)
		SELECT ch.id, ch.issuer_certificate_id, ch.fingerprint_sha256, ch.self_signed,
		       COALESCE(ch.certificate_pem, ''), COALESCE(a.decision, '')
		  FROM chain ch
		  LEFT JOIN tenant_trust_anchors a ON a.tenant_id = $1 AND a.certificate_id = ch.id
		 ORDER BY ch.depth`
	var out []chainRow
	err := database.WithTenantTx(ctx, e.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, q, tenantID, certID, maxChainDepth)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var r chainRow
			var issuer uuid.NullUUID
			if err := rows.Scan(&r.ID, &issuer, &r.FingerprintSHA256, &r.SelfSigned, &r.pem, &r.Decision); err != nil {
				return err
			}
			if issuer.Valid {
				id := issuer.UUID
				r.issuerID = &id
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("load chain for certificate %s: %w", certID, err)
	}
	// Stored links include the order supplied by a scanned server. That order
	// is not proof of issuance: a server can append an unrelated trusted CA.
	// Only a signature-verified edge may propagate an issuer's trust verdict.
	for i := 1; i < len(out); i++ {
		child, issuer := parseLeafPEM(out[i-1].pem), parseLeafPEM(out[i].pem)
		if !chainfetch.IsIssuer(child, issuer) {
			return out[:i], nil
		}
	}
	return out, nil
}

func links(chain []chainRow) []Link {
	out := make([]Link, len(chain))
	for i, r := range chain {
		out[i] = r.Link
	}
	return out
}

func (e *Evaluator) isPublicRoot(fp string) bool {
	return e.roots != nil && e.roots.Lookup(fp) != nil
}

// Evaluate classifies one certificate and stores the verdict. When the chain
// stops at a certificate that is not self-signed and has no issuer in
// inventory, the chain is completed (completeChain: the tenant's inventory,
// the public bundle, then — unless ctx is LocalOnly — the top's AIA caIssuers
// URLs); every issuer found is stored for the tenant with its chain_source,
// linked, and the chain is classified again.
func (e *Evaluator) Evaluate(ctx context.Context, tenantID, certID uuid.UUID) (Verdict, error) {
	return e.evaluate(ctx, tenantID, certID, true)
}

func (e *Evaluator) evaluate(ctx context.Context, tenantID, certID uuid.UUID, complete bool) (Verdict, error) {
	chain, err := e.loadChain(ctx, tenantID, certID)
	if err != nil {
		return Verdict{}, err
	}
	if len(chain) == 0 {
		return Verdict{}, ErrCertificateNotFound
	}
	v := Classify(links(chain), e.isPublicRoot)
	if v.NeedsIssuer && complete {
		completed, err := e.completeChain(ctx, tenantID, certID, chain[len(chain)-1])
		if err != nil {
			return Verdict{}, err
		}
		if completed {
			if chain, err = e.loadChain(ctx, tenantID, certID); err != nil {
				return Verdict{}, err
			}
			v = Classify(links(chain), e.isPublicRoot)
		}
	}
	if err := e.store(ctx, tenantID, certID, v); err != nil {
		return Verdict{}, err
	}
	return v, nil
}

// store writes the verdict. It writes only when the verdict differs from what
// is stored (or nothing is): the certificates update trigger bumps updated_at
// and last_data_update on every write, and a tenant recompute that rewrote
// every row would make every certificate look freshly changed to anything
// that reads those columns. trust_evaluated_at therefore records when the
// current verdict was reached.
func (e *Evaluator) store(ctx context.Context, tenantID, certID uuid.UUID, v Verdict) error {
	var anchor interface{}
	if v.Anchor != uuid.Nil {
		anchor = v.Anchor
	}
	return database.WithTenantTx(ctx, e.db, tenantID, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE certificates
			   SET trust_status = $3, trust_anchor_certificate_id = $4, trust_evaluated_at = NOW()
			 WHERE tenant_id = $1 AND id = $2
			   AND (trust_status IS DISTINCT FROM $3
			        OR trust_anchor_certificate_id IS DISTINCT FROM $4::uuid
			        OR trust_evaluated_at IS NULL)`,
			tenantID, certID, v.Status, anchor)
		if err != nil {
			return fmt.Errorf("store trust verdict for certificate %s: %w", certID, err)
		}
		return nil
	})
}

// completeChain finds the missing issuers above top (chainfetch), stores each
// one the tenant does not already hold, links top to the first and each to the
// next, and evaluates the stored issuers. It returns true when top gained an
// issuer link.
//
// The tenant-anchor source is not passed: an anchor is a certificates row of
// the tenant, so the inventory lookup already finds it.
func (e *Evaluator) completeChain(ctx context.Context, tenantID, certID uuid.UUID, top chainRow) (bool, error) {
	if top.pem == "" {
		return false, nil
	}
	block, _ := pem.Decode([]byte(top.pem))
	if block == nil {
		return false, nil
	}
	topCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, nil
	}
	opts := chainfetch.Options{Inventory: e.inventoryLookup(tenantID, top.ID)}
	if e.roots != nil {
		opts.Bundle = e.roots.FindIssuer
	} else {
		opts.NoBundle = true
	}
	network := e.aia != nil && !isLocalOnly(ctx)
	if network {
		opts.Guard = e.aia.guard
		opts.AllowFetch = func(url string) bool { return e.aia.allow(tenantID, url) }
		opts.OnFetchFailure = e.aia.recordFailure
	}
	found, sources, ferr := chainfetch.Resolve(ctx, []*x509.Certificate{topCert}, opts)
	if ctxErr := ctx.Err(); ctxErr != nil {
		return false, ctxErr
	}
	if len(found) == 0 {
		if !network && e.aia != nil && errors.Is(ferr, chainfetch.ErrIssuerNotFound) && hasHTTPAIA(topCert) {
			// Ingest and decision paths never wait on the network: the
			// fetch runs in the background and re-evaluates what chains
			// through top when it lands.
			e.aia.enqueue(e, tenantID, certID, top.ID)
		}
		return false, nil
	}

	prev := top.ID
	var stored []uuid.UUID
	for i, issuer := range found {
		id, created, err := e.ensureIssuer(ctx, tenantID, issuer, sources[i])
		if err != nil {
			return false, err
		}
		if id == uuid.Nil || id == prev {
			break
		}
		if err := e.linkIssuer(ctx, tenantID, prev, id); err != nil {
			return false, err
		}
		if created {
			stored = append(stored, id)
		}
		prev = id
	}
	// Top-down, so each stored issuer is classified over the links above it.
	for i := len(stored) - 1; i >= 0; i-- {
		if _, err := e.evaluate(ctx, tenantID, stored[i], false); err != nil {
			return false, err
		}
	}
	return true, nil
}

// linkIssuer sets child's issuer_certificate_id when it has none: a row that
// already names an issuer keeps the one chain rebuild or ingest gave it.
func (e *Evaluator) linkIssuer(ctx context.Context, tenantID, child, issuer uuid.UUID) error {
	err := database.WithTenantTx(ctx, e.db, tenantID, func(tx *sqlx.Tx) error {
		_, err := tx.ExecContext(ctx,
			`UPDATE certificates SET issuer_certificate_id = $3
			  WHERE tenant_id = $1 AND id = $2 AND issuer_certificate_id IS NULL`,
			tenantID, child, issuer)
		return err
	})
	if err != nil {
		return fmt.Errorf("link certificate %s to its issuer %s: %w", child, issuer, err)
	}
	return nil
}

// maxInventoryCandidates bounds the same-subject rows the inventory lookup
// signature-checks (re-issued CAs share a subject; dozens never do).
const maxInventoryCandidates = 20

// inventoryLookup returns chainfetch's inventory source for one tenant: a
// certificate the tenant holds whose subject is the child's issuer DN (the
// signature check that makes it the issuer is chainfetch's).
func (e *Evaluator) inventoryLookup(tenantID, exclude uuid.UUID) chainfetch.Lookup {
	return func(ctx context.Context, child *x509.Certificate) *x509.Certificate {
		issuerDN := CertificateDataFromX509(child).IssuerDN
		var pems []string
		err := database.WithTenantTx(ctx, e.db, tenantID, func(tx *sqlx.Tx) error {
			return tx.SelectContext(ctx, &pems, `
				SELECT certificate_pem FROM certificates
				 WHERE tenant_id = $1 AND subject_dn = $2 AND id <> $3
				   AND certificate_pem IS NOT NULL AND certificate_pem <> ''
				 ORDER BY created_at
				 LIMIT $4`, tenantID, issuerDN, exclude, maxInventoryCandidates)
		})
		if err != nil {
			log.Printf("[certtrust] tenant %s: inventory issuer lookup: %v", tenantID, err)
			return nil
		}
		for _, p := range pems {
			block, _ := pem.Decode([]byte(p))
			if block == nil {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err == nil && chainfetch.IsIssuer(child, c) {
				return c
			}
		}
		return nil
	}
}

// Data sources for certificates the platform stored without anybody observing
// or uploading them (certificates.data_source).
const (
	// DataSourceBundle is a root copied from the embedded public bundle.
	DataSourceBundle = "bundle"
	// DataSourceAIA is a CA certificate fetched from an AIA caIssuers URL.
	DataSourceAIA = "aia"
)

// ensureIssuer returns the tenant's certificate row for an issuer chainfetch
// found, storing it first when the tenant does not have it (chain_source and
// data_source say where it came from). created reports a new row.
func (e *Evaluator) ensureIssuer(ctx context.Context, tenantID uuid.UUID, cert *x509.Certificate, src chainfetch.Source) (uuid.UUID, bool, error) {
	data := CertificateDataFromX509(cert)
	chainSource, dataSource := ChainSourceAIA, DataSourceAIA
	switch src {
	case chainfetch.SourceBundle:
		chainSource, dataSource = ChainSourceBundle, DataSourceBundle
	case chainfetch.SourceTenantAnchor:
		chainSource = ChainSourceTenantAnchor
	}
	state := "active"
	if cert.NotAfter.Before(time.Now()) {
		state = "expired"
	}
	var id uuid.UUID
	created := false
	err := database.WithTenantTx(ctx, e.db, tenantID, func(tx *sqlx.Tx) error {
		err := tx.QueryRowContext(ctx,
			`SELECT id FROM certificates WHERE tenant_id = $1 AND fingerprint_sha256 = $2 ORDER BY created_at LIMIT 1`,
			tenantID, data.FingerprintSHA256).Scan(&id)
		if err == nil {
			return nil
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if src == chainfetch.SourceInventory {
			// Found by subject in inventory but not by fingerprint: the row
			// was removed in between. Nothing to link to (id stays Nil).
			return nil
		}
		created = true
		return tx.QueryRowContext(ctx, `
			INSERT INTO certificates (
				tenant_id, serial_number, subject_dn, issuer_dn, common_name,
				subject_alternative_names, signature_algorithm, public_key_algorithm,
				public_key_size, not_before, not_after, fingerprint_sha1, fingerprint_sha256,
				certificate_pem, is_self_signed, is_ca_certificate, key_usage, extended_key_usage,
				certificate_state, data_completeness, data_source, chain_source
			) VALUES ($1,$2,$3,$4,NULLIF($5,''),$6,$7,$8,NULLIF($9,0),$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,'complete',$20,$21)
			RETURNING id`,
			tenantID, data.SerialNumber, data.SubjectDN, data.IssuerDN, data.CommonName,
			pq.Array(data.SubjectAlternativeNames), data.SignatureAlgorithm, data.PublicKeyAlgorithm,
			data.PublicKeySize, data.NotBefore, data.NotAfter, data.FingerprintSHA1, data.FingerprintSHA256,
			data.CertificatePEM, chainfetch.SelfSigned(cert), cert.IsCA,
			pq.Array(data.KeyUsage), pq.Array(data.ExtendedKeyUsage),
			state, dataSource, chainSource,
		).Scan(&id)
	})
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("store issuer %q (%s): %w", cert.Subject.String(), src, err)
	}
	return id, created, nil
}

// EvaluateSubtree re-evaluates certID and every certificate whose chain runs
// through it — what a decision on a CA, or a new issuer link, can change.
// It returns how many certificates were evaluated.
func (e *Evaluator) EvaluateSubtree(ctx context.Context, tenantID, certID uuid.UUID) (int, error) {
	if _, err := e.Evaluate(ctx, tenantID, certID); err != nil {
		return 0, err
	}
	var ids []uuid.UUID
	err := database.WithTenantTx(ctx, e.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.SelectContext(ctx, &ids, `
			WITH RECURSIVE sub AS (
				SELECT c.id, 1 AS depth
				  FROM certificates c
				 WHERE c.tenant_id = $1 AND c.issuer_certificate_id = $2 AND c.id <> $2
				UNION
				SELECT c.id, s.depth + 1
				  FROM certificates c
				  JOIN sub s ON c.issuer_certificate_id = s.id
				 WHERE c.tenant_id = $1 AND c.id <> c.issuer_certificate_id AND s.depth < $3
			)
			SELECT id FROM (SELECT DISTINCT id FROM sub) d ORDER BY id LIMIT $4`,
			tenantID, certID, maxChainDepth, maxSubtreeSize+1)
	})
	if err != nil {
		return 1, fmt.Errorf("list certificates under %s: %w", certID, err)
	}
	if len(ids) > maxSubtreeSize {
		log.Printf("[certtrust] tenant %s: more than %d certificates chain through %s; re-evaluating the first %d, the rest on the next tenant recompute",
			tenantID, maxSubtreeSize, certID, maxSubtreeSize)
		ids = ids[:maxSubtreeSize]
	}
	n := 1
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return n, err
		}
		if _, err := e.Evaluate(ctx, tenantID, id); err != nil && !errors.Is(err, ErrCertificateNotFound) {
			return n, err
		}
		n++
	}
	return n, nil
}

// RecomputeTenant re-evaluates every certificate of the tenant, reading ids in
// batches of recomputeBatch. It returns how many were evaluated.
func (e *Evaluator) RecomputeTenant(ctx context.Context, tenantID uuid.UUID) (int, error) {
	return e.recompute(ctx, tenantID, selectAll, 0)
}

// RecomputeUnevaluated evaluates up to limit certificates of the tenant that
// have never been evaluated (trust_status NULL) — the rows stored before trust
// evaluation existed. It returns how many were evaluated.
func (e *Evaluator) RecomputeUnevaluated(ctx context.Context, tenantID uuid.UUID, limit int) (int, error) {
	return e.recompute(ctx, tenantID, selectUnevaluated, limit)
}

// RetryIncomplete re-evaluates up to limit certificates of the tenant whose
// chain was incomplete, completing chains with the network allowed unless ctx
// is LocalOnly — the periodic backfill's second half. It returns how many were
// evaluated.
func (e *Evaluator) RetryIncomplete(ctx context.Context, tenantID uuid.UUID, limit int) (int, error) {
	return e.recompute(ctx, tenantID, selectIncomplete, limit)
}

// Which certificates a recompute pass selects.
const (
	selectAll         = "all"
	selectUnevaluated = "unevaluated"
	selectIncomplete  = "incomplete"
)

func (e *Evaluator) recompute(ctx context.Context, tenantID uuid.UUID, which string, limit int) (int, error) {
	cursor := uuid.Nil
	n := 0
	for {
		batch := recomputeBatch
		if limit > 0 && limit-n < batch {
			batch = limit - n
		}
		if batch <= 0 {
			log.Printf("[certtrust] tenant %s: evaluated the limit of %d certificates in this pass; any remaining are evaluated on a later one", tenantID, n)
			return n, nil
		}
		var ids []uuid.UUID
		err := database.WithTenantTx(ctx, e.db, tenantID, func(tx *sqlx.Tx) error {
			return tx.SelectContext(ctx, &ids, `
				SELECT id FROM certificates
				 WHERE tenant_id = $1 AND id > $2
				   AND ($3 = 'all'
				        OR ($3 = 'unevaluated' AND trust_status IS NULL)
				        OR ($3 = 'incomplete' AND trust_status = 'incomplete'))
				 ORDER BY id
				 LIMIT $4`, tenantID, cursor, which, batch)
		})
		if err != nil {
			return n, fmt.Errorf("list certificates to evaluate: %w", err)
		}
		for _, id := range ids {
			if err := ctx.Err(); err != nil {
				return n, err
			}
			if _, err := e.Evaluate(ctx, tenantID, id); err != nil && !errors.Is(err, ErrCertificateNotFound) {
				return n, err
			}
			n++
		}
		if len(ids) < batch {
			return n, nil
		}
		cursor = ids[len(ids)-1]
	}
}
