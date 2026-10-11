package certtrust

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/certificates/publicroots"
)

// FromChainRequest is POST /trust-anchors/from-chain: the chain a server
// presented in a TLS handshake (an integration's test-connection returns it
// as presented_chain), leaf first, and the decision to record on its top CA.
type FromChainRequest struct {
	ChainPEM  string
	Decision  string
	Note      string
	DecidedBy uuid.UUID
}

// DataSourcePresented is certificates.data_source for a CA certificate stored
// from a chain a server presented to an integration test, on a person's say-so.
const DataSourcePresented = "presented_chain"

// CreateAnchorFromChain stores every CA certificate of the presented chain the
// tenant does not already hold (chain_source 'served'), links issuers, and
// records the decision against the TOP CA of the chain. The leaf (any
// non-CA certificate) is never stored and never becomes an anchor. A decision
// already recorded for that CA is a conflict (*ErrConflict), as for
// CreateAnchor.
func (s *Store) CreateAnchorFromChain(ctx context.Context, tenantID uuid.UUID, req FromChainRequest) (*Anchor, error) {
	if !validDecision(req.Decision) {
		return nil, &ErrInvalid{Msg: "decision must be 'trusted' or 'distrusted'"}
	}
	if err := checkNote(req.Note); err != nil {
		return nil, err
	}
	if len(req.ChainPEM) > MaxPEMBytes {
		return nil, &ErrInvalid{Msg: "chain_pem exceeds the 1 MiB limit"}
	}
	if strings.TrimSpace(req.ChainPEM) == "" {
		return nil, &ErrInvalid{Msg: "chain_pem is required"}
	}
	if s.certs == nil {
		return nil, errors.New("certtrust: store has no certificate writer")
	}

	var all []*x509.Certificate
	rest := []byte(req.ChainPEM)
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
			return nil, &ErrInvalid{Msg: "chain_pem holds a certificate that does not parse"}
		}
		all = append(all, c)
	}
	if len(all) == 0 {
		return nil, &ErrInvalid{Msg: "chain_pem holds no PEM CERTIFICATE block"}
	}
	var cas []*x509.Certificate
	for _, c := range all {
		if c.BasicConstraintsValid && c.IsCA {
			cas = append(cas, c)
		}
	}
	if len(cas) == 0 {
		return nil, &ErrInvalid{Msg: "chain_pem holds no CA certificate: the server presented only its own certificate, so there is no authority to trust — add the CA certificate itself on the Trusted CAs page"}
	}
	top := topOfChain(all, cas)

	ids := make([]uuid.UUID, len(cas))
	var topID uuid.UUID
	for i, c := range cas {
		data := CertificateDataFromX509(c)
		data.DataSource = DataSourcePresented
		data.ChainSource = ChainSourceServed
		stored, err := s.certs.FindOrCreateCertificate(tenantID, data)
		if err != nil {
			return nil, fmt.Errorf("store CA certificate %q: %w", c.Subject.String(), err)
		}
		ids[i] = stored.ID
		if c == top {
			topID = stored.ID
		}
	}
	if err := s.linkBySignature(tenantID, cas, ids); err != nil {
		return nil, fmt.Errorf("link presented CA certificates: %w", err)
	}
	return s.CreateAnchor(ctx, tenantID, CreateRequest{
		CertificateID: &topID, Decision: req.Decision, Note: req.Note, DecidedBy: req.DecidedBy,
	})
}

// topOfChain returns the top-most CA: walking up from the first certificate
// by signature (servers do not always send the chain in order), the last CA
// reached; if the walk reaches none of the CAs, the last CA in the list —
// the contract's "last CA certificate when ordered leaf -> root".
func topOfChain(all, cas []*x509.Certificate) *x509.Certificate {
	var top *x509.Certificate
	cur := all[0]
	if cur.BasicConstraintsValid && cur.IsCA {
		top = cur
	}
	seen := map[*x509.Certificate]bool{cur: true}
	for {
		var next *x509.Certificate
		for _, c := range cas {
			if !seen[c] && cur.Subject.String() != cur.Issuer.String() && cur.CheckSignatureFrom(c) == nil {
				next = c
				break
			}
		}
		if next == nil {
			break
		}
		seen[next] = true
		top, cur = next, next
	}
	if top == nil {
		top = cas[len(cas)-1]
	}
	return top
}

// InternalAnchors is GET /internal/trust/anchors (InternalTrustAnchors): what
// a service building a TLS trust pool for the tenant needs. Public roots are
// not listed — the caller has the system store and the embedded bundle.
type InternalAnchors struct {
	TrustedPEM                   []string `json:"trusted_pem"`
	DistrustedFingerprintsSHA256 []string `json:"distrusted_fingerprints_sha256"`
	BundleVersion                string   `json:"bundle_version"`
}

// InternalAnchors returns the tenant's decisions for a trust pool: the PEM of
// every CA it trusted (a trusted CA stored without PEM cannot join a pool and
// is left out) and the lower-case SHA-256 fingerprint of every CA it
// distrusted.
func (s *Store) InternalAnchors(ctx context.Context, tenantID uuid.UUID) (InternalAnchors, error) {
	out := InternalAnchors{TrustedPEM: []string{}, DistrustedFingerprintsSHA256: []string{}, BundleVersion: publicroots.Version()}
	err := database.WithTenantTx(ctx, s.db, tenantID, func(tx *sqlx.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT a.decision, COALESCE(c.certificate_pem, ''), lower(c.fingerprint_sha256)
			  FROM tenant_trust_anchors a
			  JOIN certificates c ON c.id = a.certificate_id AND c.tenant_id = a.tenant_id
			 WHERE a.tenant_id = $1
			 ORDER BY a.decided_at, a.id`, tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var decision, pemText, fp string
			if err := rows.Scan(&decision, &pemText, &fp); err != nil {
				return err
			}
			switch decision {
			case DecisionTrusted:
				if strings.TrimSpace(pemText) != "" {
					out.TrustedPEM = append(out.TrustedPEM, pemText)
				}
			case DecisionDistrusted:
				out.DistrustedFingerprintsSHA256 = append(out.DistrustedFingerprintsSHA256, fp)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return InternalAnchors{}, fmt.Errorf("list trust anchors for a trust pool: %w", err)
	}
	return out, nil
}
