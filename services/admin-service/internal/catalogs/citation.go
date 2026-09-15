package catalogs

// What makes a URL a CITATION (ADR-0008 D4.4), and the one security rule that
// comes with accepting a URL from a model.
//
// This lives in Core, beside the store, rather than in `ee/enrich` where it was
// written, for a reason that is not tidiness: the rule has to bind every path
// that can put a URL into `eol_catalogue_proposals` or `eol_catalogue`, and
// `ee/enrich` is only the first of those. The generative proposer applies it
// before it ever builds a proposal; [validateNewProposal] applies it at the
// last door before storage, so a future second proposal source cannot skip it;
// and [SQLStore.AcceptProposal] applies it AGAIN before writing the catalogue
// row, because accept is the moment a claim becomes data every tenant is
// evaluated against and "it was checked when it was written" is a promise about
// code that may since have changed.
//
// Every check answers one question — *could a person open this and check the
// claim?* Nothing here can tell a right date from a wrong one and nothing
// pretends to.

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/network"
)

// maxCitationURL bounds the stored citation. Past this it is not a URL.
const maxCitationURL = 2000

// ValidateCitationURL reports whether raw can serve as the citation on an
// end-of-life proposal or catalogue row, and says why not when it cannot.
//
// The returned error is written for the operator debugging an empty proposal
// queue, so it names the rule that fired and the value that fired it.
//
// https only — not because http is insecure here (nothing fetches this URL) but
// because a citation is a thing a REVIEWER opens, and a vendor lifecycle page
// available only over plaintext in 2026 is a sign the URL was invented. The
// private-address and internal-hostname refusals are the real guard: a model
// that answers with `https://169.254.169.254/…` or `https://wiki.internal/…`
// has produced something that is not a citation of anything public, and a
// reviewer clicking it from inside a corporate network is the second half of
// that problem.
func ValidateCitationURL(raw string) error {
	s := strings.TrimSpace(raw)
	if s == "" {
		// Cite or refuse. This is the check the whole seam exists around: an
		// enrichment fact without a source URL is commentary, and commentary is
		// never persisted as data.
		return fmt.Errorf("no source_url in the answer")
	}
	if len(s) > maxCitationURL {
		return fmt.Errorf("source_url is %d bytes, which is not a URL", len(s))
	}
	u, err := url.Parse(s)
	if err != nil {
		return fmt.Errorf("source_url %q does not parse: %v", s, err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return fmt.Errorf("source_url %q is not https", s)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("source_url %q names no host", s)
	}
	if network.IsPrivateAddressLiteral(host) {
		return fmt.Errorf("source_url %q points at a private address", s)
	}
	if isInternalName(host) {
		return fmt.Errorf("source_url %q points at an internal hostname", s)
	}
	if !strings.Contains(host, ".") {
		// A single-label host ("intranet", "docs") is not a public page. It is
		// also the shape a search-domain lookup resolves inside a corporate
		// network, which is exactly the case the private-address literal check
		// cannot see.
		return fmt.Errorf("source_url %q has no public domain", s)
	}
	if isNumericHost(host) {
		return fmt.Errorf("source_url %q is an IP address rather than a vendor page", s)
	}
	return nil
}

// isInternalName lists the hostnames that are internal by NAME rather than by
// address, which no IP check can catch because they are resolved by the
// reviewer's resolver and not by ours.
//
// The list is the one shared/network's webhook validator already uses, restated
// here rather than imported because that function's other half is a DNS lookup:
// this validator deliberately resolves nothing (see
// network.IsPrivateAddressLiteral), so that it stays pure, its tests stay
// offline, and a resolver outage cannot silently start dropping every proposal.
func isInternalName(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	switch h {
	case "localhost", "host.docker.internal", "metadata.google.internal",
		"kubernetes.default", "kubernetes.default.svc":
		return true
	}
	return strings.HasSuffix(h, ".localhost") ||
		strings.HasSuffix(h, ".local") ||
		strings.HasSuffix(h, ".internal") ||
		strings.HasSuffix(h, ".cluster.local")
}

// isNumericHost reports whether a host's last label is all digits — i.e. the
// host is an IP address in SOME notation rather than a domain name.
//
// It exists because [network.IsPrivateAddressLiteral] answers with net.ParseIP,
// which is strict: `0177.0.0.1` has a leading zero and parses as nothing, so it
// returned false, contains a dot, and sailed through as a "domain". Browsers
// and curl read it as 127.0.0.1. The same is true of `2130706433` and
// `0x7f.1` — the notations differ, the destination does not.
//
// Testing the last label rather than enumerating notations is what makes the
// rule closed: no public domain's TLD is numeric (ICANN forbids it, precisely
// so that a hostname can never be mistaken for an address), so "the last label
// is a number" means "this is an address". It therefore also refuses PUBLIC
// IPv4 literals, which is the right answer for a different reason: a raw
// address is not a vendor's lifecycle page, and this field is a citation.
func isNumericHost(host string) bool {
	h := strings.TrimSuffix(host, ".")
	last := h
	if i := strings.LastIndexByte(h, '.'); i >= 0 {
		last = h[i+1:]
	}
	if last == "" {
		return false
	}
	for _, r := range last {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
