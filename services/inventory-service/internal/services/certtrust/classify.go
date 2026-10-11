// Package certtrust decides, centrally and per tenant, where each certificate's
// chain ends: a public root, a CA the organisation trusted or distrusted, a
// self-signed certificate, a CA nobody trusted, or an issuer that is not in the
// inventory yet (feature).
//
// Agents observe; the platform decides (owner decision D4). The verdict is
// written to certificates.trust_status and recomputed whenever a decision or a
// chain link changes. A certificate never evaluated keeps a NULL status, which
// the UI shows as "not yet evaluated" — never as trusted.
package certtrust

import (
	"github.com/google/uuid"
)

// Trust statuses, as stored in certificates.trust_status and documented by the
// TrustStatus schema in api/openapi/inventory-service.openapi.yaml.
const (
	StatusPublic         = "public"
	StatusPrivateTrusted = "private_trusted"
	StatusSelfSigned     = "self_signed"
	StatusUntrusted      = "untrusted"
	StatusDistrusted     = "distrusted"
	StatusIncomplete     = "incomplete"
)

// Decisions a tenant can record against a CA certificate.
const (
	DecisionTrusted    = "trusted"
	DecisionDistrusted = "distrusted"
)

// Chain sources, as stored in certificates.chain_source.
const (
	ChainSourceServed       = "served"
	ChainSourceAIA          = "aia"
	ChainSourceBundle       = "bundle"
	ChainSourceTenantAnchor = "tenant_anchor"
	ChainSourceUpload       = "upload"
)

// Link is one certificate of a chain as the classifier sees it. A chain is
// ordered from the certificate being evaluated (index 0) to the top: the last
// certificate reached by following issuer_certificate_id.
type Link struct {
	ID                uuid.UUID
	FingerprintSHA256 string
	// SelfSigned: the certificate is its own issuer (is_self_signed, or its
	// subject and issuer DNs are equal — the same test chain rebuild uses).
	SelfSigned bool
	// Decision is the tenant's recorded decision on this certificate:
	// DecisionTrusted, DecisionDistrusted, or "" for none.
	Decision string
}

// Verdict is the classifier's answer.
type Verdict struct {
	Status string
	// Anchor is the certificate the status was decided on: the distrusted or
	// trusted CA, the public root, the self-signed top, the top nobody
	// trusted, or the last issuer found when the chain is incomplete.
	Anchor uuid.UUID
	// NeedsIssuer is set with StatusIncomplete: the top is not self-signed and
	// has no issuer in inventory, so the caller may try to complete the chain
	// (the embedded public bundle, in this slice) and classify again.
	NeedsIssuer bool
}

// Classify applies the precedence pinned by TestClassify_Precedence:
//
//  1. any certificate in the chain the tenant DISTRUSTED -> distrusted
//     (explicit distrust overrides everything, including the public bundle);
//  2. any certificate in the chain the tenant TRUSTED -> private_trusted
//     (the nearest trusted CA is the anchor);
//  3. the top is a root of the embedded public bundle -> public;
//  4. the top is self-signed and is the certificate itself -> self_signed;
//  5. the top is self-signed but neither anchored nor bundled -> untrusted;
//  6. the top is not self-signed: its issuer is missing -> incomplete.
//
// isPublicRoot reports whether a fingerprint is in the public bundle. An empty
// chain classifies as incomplete with a nil anchor.
func Classify(chain []Link, isPublicRoot func(fingerprintSHA256 string) bool) Verdict {
	if len(chain) == 0 {
		return Verdict{Status: StatusIncomplete, NeedsIssuer: true}
	}
	for _, l := range chain {
		if l.Decision == DecisionDistrusted {
			return Verdict{Status: StatusDistrusted, Anchor: l.ID}
		}
	}
	for _, l := range chain {
		if l.Decision == DecisionTrusted {
			return Verdict{Status: StatusPrivateTrusted, Anchor: l.ID}
		}
	}
	top := chain[len(chain)-1]
	if isPublicRoot != nil && top.FingerprintSHA256 != "" && isPublicRoot(top.FingerprintSHA256) {
		return Verdict{Status: StatusPublic, Anchor: top.ID}
	}
	if top.SelfSigned {
		if len(chain) == 1 {
			return Verdict{Status: StatusSelfSigned, Anchor: top.ID}
		}
		return Verdict{Status: StatusUntrusted, Anchor: top.ID}
	}
	return Verdict{Status: StatusIncomplete, Anchor: top.ID, NeedsIssuer: true}
}
