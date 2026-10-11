package certtrust

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/certificates/chainfetch"
)

// 3rd-party connections ( slice 3). external_connections keeps only the
// LEAF a server presented (cert_pem, cert_issuer, cert_fingerprint_sha256) —
// not the intermediates — so a connection's trust is decided from the leaf's
// issuer: the tenant's inventory (by subject and signature; its chain and any
// decision on it then apply), else the embedded public bundle, else the leaf
// itself if self-signed. No AIA fetch is made for a connection: ingesting a
// 3rd-party observation does not reach out to that party's CA repository.
// A leaf whose issuer is in neither place is incomplete — the probe's own
// verdict (cert_validation_status) still stands for it.

// Hygiene flag texts that depend on the tenant's trust decisions, on
// external_connections.cert_hygiene_flags.
const (
	HygieneUntrustedCA  = "Certificate signed by an untrusted certificate authority (not in the system trust store — may be a private or pinned CA)"
	HygieneDistrustedCA = "Certificate chains to a certificate authority this organisation has distrusted"
)

// ApplyTrustToHygiene rewrites the two trust-dependent hygiene flags of a
// 3rd-party connection from the tenant's verdict:
//
//   - the probe said untrusted_ca, but the chain reaches a CA the tenant
//     trusted or a public root of the embedded bundle -> no untrusted flag
//     (the platform decides trust, not the probing runtime's OS store);
//   - the chain reaches a CA the tenant distrusted -> the distrusted flag,
//     replacing the untrusted one;
//   - otherwise the probe's untrusted_ca verdict stands.
//
// Every other flag is kept in order. trustStatus "" means not evaluated.
func ApplyTrustToHygiene(flags []string, validationStatus, trustStatus string) []string {
	out := make([]string, 0, len(flags)+1)
	for _, f := range flags {
		if f != HygieneUntrustedCA && f != HygieneDistrustedCA {
			out = append(out, f)
		}
	}
	switch trustStatus {
	case StatusDistrusted:
		return append(out, HygieneDistrustedCA)
	case StatusPrivateTrusted, StatusPublic:
		return out
	}
	if strings.EqualFold(strings.TrimSpace(validationStatus), "untrusted_ca") {
		out = append(out, HygieneUntrustedCA)
	}
	return out
}

// PresentedVerdict classifies the leaf a 3rd-party server presented, against
// the tenant's inventory, decisions and the public bundle. It writes nothing.
// A nil leaf, or one that does not parse, has no verdict ("").
func (e *Evaluator) PresentedVerdict(ctx context.Context, tenantID uuid.UUID, leafPEM string) (string, error) {
	leaf := parseLeafPEM(leafPEM)
	if leaf == nil {
		return "", nil
	}
	return newPresentedClassifier(e, tenantID).verdict(ctx, leaf)
}

func parseLeafPEM(p string) *x509.Certificate {
	block, _ := pem.Decode([]byte(p))
	if block == nil {
		return nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return c
}

// presentedClassifier caches per-issuer answers for one pass: a tenant's
// thousands of 3rd-party connections share a few dozen issuers.
type presentedClassifier struct {
	e        *Evaluator
	tenantID uuid.UUID
	byIssuer map[string]issuerAnswer
}

type issuerAnswer struct {
	issuer *x509.Certificate // every leaf must verify against this cached issuer
	chain  []Link            // the issuer's chain, from the issuer up; nil = not in inventory
	err    error
}

func newPresentedClassifier(e *Evaluator, tenantID uuid.UUID) *presentedClassifier {
	return &presentedClassifier{e: e, tenantID: tenantID, byIssuer: map[string]issuerAnswer{}}
}

func (p *presentedClassifier) verdict(ctx context.Context, leaf *x509.Certificate) (string, error) {
	leafLink := Link{FingerprintSHA256: fingerprintHex(leaf), SelfSigned: chainfetch.SelfSigned(leaf)}

	// The leaf itself in inventory (a connection to an asset the tenant
	// also holds): its own chain and decisions.
	if id, ok, err := p.e.certIDByFingerprint(ctx, p.tenantID, leafLink.FingerprintSHA256); err != nil {
		return "", err
	} else if ok {
		chain, err := p.e.loadChain(ctx, p.tenantID, id)
		if err != nil {
			return "", err
		}
		if len(chain) > 0 {
			if v := Classify(links(chain), p.e.isPublicRoot); !v.NeedsIssuer {
				return v.Status, nil
			}
		}
	}
	if leafLink.SelfSigned {
		return Classify([]Link{leafLink}, p.e.isPublicRoot).Status, nil
	}

	key := string(leaf.RawIssuer) + "\x00" + hex.EncodeToString(leaf.AuthorityKeyId)
	ans, ok := p.byIssuer[key]
	if !ok || ans.issuer == nil || !chainfetch.IsIssuer(leaf, ans.issuer) {
		ans = p.issuerChain(ctx, leaf)
		p.byIssuer[key] = ans
	}
	if ans.err != nil {
		return "", ans.err
	}
	if ans.chain != nil {
		return Classify(append([]Link{leafLink}, ans.chain...), p.e.isPublicRoot).Status, nil
	}
	if p.e.roots != nil {
		if root := p.e.roots.FindIssuer(leaf); root != nil {
			return StatusPublic, nil
		}
	}
	return StatusIncomplete, nil
}

// issuerChain finds the leaf's issuer in the tenant's inventory and loads its
// chain with the recorded decisions.
func (p *presentedClassifier) issuerChain(ctx context.Context, leaf *x509.Certificate) issuerAnswer {
	issuer := p.e.inventoryLookup(p.tenantID, uuid.Nil)(ctx, leaf)
	if issuer == nil || !chainfetch.IsIssuer(leaf, issuer) {
		return issuerAnswer{}
	}
	id, ok, err := p.e.certIDByFingerprint(ctx, p.tenantID, fingerprintHex(issuer))
	if err != nil || !ok {
		return issuerAnswer{err: err}
	}
	chain, err := p.e.loadChain(ctx, p.tenantID, id)
	if err != nil {
		return issuerAnswer{err: err}
	}
	return issuerAnswer{issuer: issuer, chain: links(chain)}
}

func fingerprintHex(c *x509.Certificate) string {
	return CertificateDataFromX509(c).FingerprintSHA256
}

func (e *Evaluator) certIDByFingerprint(ctx context.Context, tenantID uuid.UUID, fp string) (uuid.UUID, bool, error) {
	var id uuid.UUID
	err := database.WithTenantTx(ctx, e.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.QueryRowContext(ctx,
			`SELECT id FROM certificates WHERE tenant_id = $1 AND fingerprint_sha256 = $2 ORDER BY created_at LIMIT 1`,
			tenantID, fp).Scan(&id)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, false, fmt.Errorf("look up certificate by fingerprint: %w", err)
	}
	return id, true, nil
}

// maxExternalRecompute bounds the 3rd-party connections re-classified after a
// decision change; the rest are re-classified as they are next observed.
const maxExternalRecompute = 20000

// RecomputeExternalConnections re-classifies the tenant's 3rd-party
// connections that carry a leaf certificate, and rewrites trust_status and the
// trust-dependent hygiene flags where they changed. It returns how many rows
// changed.
func (e *Evaluator) RecomputeExternalConnections(ctx context.Context, tenantID uuid.UUID) (int, error) {
	type row struct {
		ID         uuid.UUID      `db:"id"`
		CertPEM    string         `db:"cert_pem"`
		Validation sql.NullString `db:"cert_validation_status"`
		Trust      sql.NullString `db:"trust_status"`
		Flags      pq.StringArray `db:"cert_hygiene_flags"`
	}
	var rows []row
	err := database.WithTenantTx(ctx, e.db, tenantID, func(tx *sqlx.Tx) error {
		return tx.SelectContext(ctx, &rows, `
			SELECT id, cert_pem, cert_validation_status, trust_status,
			       COALESCE(cert_hygiene_flags, '{}'::text[]) AS cert_hygiene_flags
			  FROM external_connections
			 WHERE tenant_id = $1 AND cert_pem IS NOT NULL AND cert_pem <> ''
			 ORDER BY id
			 LIMIT $2`, tenantID, maxExternalRecompute+1)
	})
	if err != nil {
		return 0, fmt.Errorf("list 3rd-party connections: %w", err)
	}
	if len(rows) > maxExternalRecompute {
		log.Printf("[certtrust] tenant %s: more than %d 3rd-party connections carry a certificate; re-classifying the first %d, the rest when next observed",
			tenantID, maxExternalRecompute, maxExternalRecompute)
		rows = rows[:maxExternalRecompute]
	}
	pc := newPresentedClassifier(e, tenantID)
	changed := 0
	for _, r := range rows {
		if err := ctx.Err(); err != nil {
			return changed, err
		}
		leaf := parseLeafPEM(r.CertPEM)
		if leaf == nil {
			continue
		}
		status, err := pc.verdict(ctx, leaf)
		if err != nil {
			return changed, err
		}
		flags := []string(r.Flags)
		next := ApplyTrustToHygiene(flags, r.Validation.String, status)
		if r.Trust.String == status && equalStrings(flags, next) {
			continue
		}
		err = database.WithTenantTx(ctx, e.db, tenantID, func(tx *sqlx.Tx) error {
			_, err := tx.ExecContext(ctx,
				`UPDATE external_connections SET trust_status = NULLIF($3, ''), cert_hygiene_flags = $4
				  WHERE tenant_id = $1 AND id = $2`,
				tenantID, r.ID, status, pq.StringArray(next))
			return err
		})
		if err != nil {
			return changed, fmt.Errorf("store 3rd-party connection trust: %w", err)
		}
		changed++
	}
	return changed, nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
