package discovery

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"time"
)

// TLS key exchange: which named group a handshake negotiated, and whether the
// server will also agree to a classical-only or a post-quantum-hybrid-only
// offer.
//
// For a TLS 1.3 endpoint this is the ONLY place its key exchange is visible:
// the 1.3 suite names (TLS_AES_128_GCM_SHA256) carry no key exchange at all, so
// before this was recorded a TLS 1.3 endpoint's key exchange was never
// measured. Ingest filled the gap by assuming classical ECDHE from the suite
// shape, which reported every TLS 1.3 endpoint as needing PQC migration —
// including the ones already negotiating a hybrid ML-KEM group.
//
// Every live-handshake site (the shared prober both sensor runtimes use, the
// standalone sensor's TLS enricher, the device-interrogation TLS prober and the
// cloud collectors' handshake) records the group through MeasureTLSKeyExchange
// and ApplyTo, so they emit one vocabulary under one set of keys.

// Metadata keys written by TLSKeyExchange.ApplyTo.
//
// key_exchange_algorithm is the key every TLS key-exchange producer already
// uses (passive capture, device interrogation) and the one the ingest reads;
// the group is a more precise answer to the same question, not a new field.
// key_exchange_group_raw follows the tls_version_raw / cipher_suite_raw
// convention in probeTLS: the numeric wire value, under a name no consumer
// could mistake for the canonical string.
const (
	MetaKeyExchangeAlgorithm = "key_exchange_algorithm"
	MetaKeyExchangeGroupRaw  = "key_exchange_group_raw"
	// MetaKeyExchangeKeySize is the size in bits of the key exchange itself —
	// the named group's, or a custom finite-field prime's. It is a separate
	// key from the generic key_size, which producers use for certificate and
	// cipher bits as well; the external-connection ingest accepts only this
	// one as an exchange size.
	MetaKeyExchangeKeySize      = "key_exchange_key_size"
	MetaTLSSupportsClassicalKex = "tls_supports_classical_kex"
	MetaTLSSupportsPQCHybridKex = "tls_supports_pqc_hybrid_kex"
	// MetaTLSPQCHybridKexGroup names the hybrid group the server was seen to
	// accept: the negotiated group when the main handshake was hybrid,
	// otherwise the one the server chose from the hybrid-only offer. Written
	// only beside tls_supports_pqc_hybrid_kex=true, and only for a group this
	// package can name. It is ONE group the server accepts — the one it
	// preferred among the three offered — not the full set it supports.
	MetaTLSPQCHybridKexGroup = "tls_pqc_hybrid_kex_group"
)

// tlsGroupCatalogueCodes maps a TLS NamedGroup onto the code of its row in the
// algorithms catalogue, so ingest resolves it by exact code match. The NIST
// curves are the DH-ECP-* rows (P-256/P-384/P-521 ECDH); X25519 and the three
// hybrids are catalogued under their IANA names. Every name here must resolve
// to a key_exchange catalogue row, which
// TestIntegration_TLSKeyExchangeGroup_EveryRecordedNameIsCatalogued enforces.
//
// Only groups crypto/tls can negotiate appear here: the probe never offers any
// other, so a server cannot select one.
var tlsGroupCatalogueCodes = map[tls.CurveID]string{
	tls.X25519:             "X25519",
	tls.CurveP256:          "DH-ECP-256",
	tls.CurveP384:          "DH-ECP-384",
	tls.CurveP521:          "DH-ECP-521",
	tls.X25519MLKEM768:     "X25519MLKEM768",
	tls.SecP256r1MLKEM768:  "SecP256r1MLKEM768",
	tls.SecP384r1MLKEM1024: "SecP384r1MLKEM1024",
}

// tlsGroupKeyBits is the key size of each classical IANA TLS named group: the
// curve's field size or the finite-field prime's length (RFC 8422, RFC 7919,
// RFC 7027). It is a property of the group's definition, not an opinion about
// it — whether that size is adequate stays with the catalogue and the
// SP 800-131A floors in shared/cryptoparse. X25519 is recorded as 256, the
// convention this codebase already uses for Ed25519 keys.
//
// It is wider than tlsGroupCatalogueCodes on purpose: passive capture reports
// whatever a third party's server selected, including groups crypto/tls never
// offers. The hybrid post-quantum groups are absent — their sizes are not
// comparable to a classical floor and nothing gates on them.
var tlsGroupKeyBits = map[tls.CurveID]int{
	19: 192, 20: 224, 21: 224, 22: 256, // secp192r1, secp224k1, secp224r1, secp256k1
	tls.CurveP256: 256, tls.CurveP384: 384, tls.CurveP521: 521,
	26: 256, 27: 384, 28: 512, // brainpoolP256r1, brainpoolP384r1, brainpoolP512r1
	tls.X25519: 256, 30: 448, // x448
	31: 256, 32: 384, 33: 512, // brainpool*tls13
	256: 2048, 257: 3072, 258: 4096, 259: 6144, 260: 8192, // ffdhe2048..ffdhe8192
}

// TLSKeyExchangeGroupKeyBits returns the key size in bits of a classical TLS
// named group, or 0 when the id is not one whose size this package knows.
// Unknown stays unknown: the caller records no size rather than a guess.
func TLSKeyExchangeGroupKeyBits(id tls.CurveID) int {
	return tlsGroupKeyBits[id]
}

// ClassicalTLSGroups and PQCHybridTLSGroups are the two disjoint offers the
// support probe makes. Together they are every group crypto/tls implements.
var (
	ClassicalTLSGroups = []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521}
	PQCHybridTLSGroups = []tls.CurveID{tls.X25519MLKEM768, tls.SecP256r1MLKEM768, tls.SecP384r1MLKEM1024}
)

// TLSKeyExchangeGroupName returns the catalogue code for a negotiated group, or
// "" when the id is 0 (no named group — legacy RSA key transport) or one this
// table does not know. Unknown stays unknown: the caller records the raw id and
// no name rather than a guess.
func TLSKeyExchangeGroupName(id tls.CurveID) string {
	return tlsGroupCatalogueCodes[id]
}

// IsTLSKeyExchangeGroupName reports whether name is one of the group names
// TLSKeyExchangeGroupName records (compared case-insensitively) — i.e. a key
// exchange a live handshake MEASURED, as opposed to a family label such as
// "ECDHE" that a cipher-suite parse derives.
func IsTLSKeyExchangeGroupName(name string) bool {
	for _, code := range tlsGroupCatalogueCodes {
		if strings.EqualFold(code, strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

// IsPQCHybridTLSGroup reports whether id is one of the hybrid post-quantum
// groups (a classical ECDH combined with ML-KEM).
func IsPQCHybridTLSGroup(id tls.CurveID) bool {
	return containsGroup(PQCHybridTLSGroups, id)
}

// IsPQCHybridTLSGroupName reports whether name is the recorded name of one of
// the hybrid post-quantum groups (compared case-insensitively). For a reader of
// tls_pqc_hybrid_kex_group that wants to show only a name this package would
// have written.
func IsPQCHybridTLSGroupName(name string) bool {
	for _, id := range PQCHybridTLSGroups {
		if strings.EqualFold(tlsGroupCatalogueCodes[id], strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

func isClassicalTLSGroup(id tls.CurveID) bool {
	return containsGroup(ClassicalTLSGroups, id)
}

func containsGroup(groups []tls.CurveID, id tls.CurveID) bool {
	for _, g := range groups {
		if g == id {
			return true
		}
	}
	return false
}

// TLSKeyExchange is what one probe learned about an endpoint's key exchange.
//
// The two support flags are tri-state on purpose. nil means the question could
// not be answered — the extra handshake could not be attempted, or failed for a
// reason that says nothing about the offer (timeout, reset, a close with no
// alert). An error is not "false": only the server refusing the offer with a
// handshake alert is.
type TLSKeyExchange struct {
	GroupID           tls.CurveID
	Group             string
	SupportsClassical *bool
	SupportsPQCHybrid *bool
	// PQCHybridGroup is the catalogue code of the hybrid group a handshake
	// with this server negotiated — the main handshake's when it was hybrid,
	// else the hybrid-only support handshake's. "" when no handshake proved
	// hybrid support.
	PQCHybridGroup string
	// KeyBits is a MEASURED exchange size for a key exchange that used no
	// named group: the length of the custom prime in a TLS <= 1.2 DHE
	// ServerKeyExchange. 0 otherwise; a named group's size comes from the
	// group.
	KeyBits int
}

// TLSDialFunc opens a fresh TCP connection to the endpoint the main handshake
// used, within timeout. Callers pass the same dial they used for the main
// handshake, so the support probe reaches exactly the same target and nothing
// else.
type TLSDialFunc func(timeout time.Duration) (net.Conn, error)

// MeasureTLSKeyExchange records the group a completed handshake negotiated and
// works out whether the server supports classical and hybrid post-quantum key
// exchange.
//
// Whatever the main handshake already proves is taken from it rather than asked
// again: a negotiated hybrid proves hybrid support, a negotiated classical group
// proves classical support, and a server that answered a TLS 1.3 offer with TLS
// 1.2 cannot do hybrid key exchange at all (the hybrid groups exist only in TLS
// 1.3). Each question still open is asked with one extra handshake offering only
// that kind of group — so at most two, sequentially, sharing ONE deadline of
// `budget` from now. base is the main handshake's config; each extra handshake
// is a clone of it with only the group offer (and, for the hybrid probe, the
// minimum version) changed, so SNI and client-certificate behaviour are
// identical and a refusal can only be about the groups.
//
// dial nil, or a non-positive budget, skips the extra handshakes and leaves the
// open questions nil.
func MeasureTLSKeyExchange(state tls.ConnectionState, base *tls.Config, dial TLSDialFunc, budget time.Duration) TLSKeyExchange {
	kx := TLSKeyExchange{GroupID: state.CurveID, Group: TLSKeyExchangeGroupName(state.CurveID)}

	switch {
	case IsPQCHybridTLSGroup(state.CurveID):
		kx.SupportsPQCHybrid = boolPtr(true)
		kx.PQCHybridGroup = kx.Group
	case isClassicalTLSGroup(state.CurveID):
		kx.SupportsClassical = boolPtr(true)
	}
	if state.Version != 0 && state.Version < tls.VersionTLS13 {
		kx.SupportsPQCHybrid = boolPtr(false)
	}

	if dial == nil || base == nil || budget <= 0 {
		return kx
	}
	deadline := time.Now().Add(budget)
	if kx.SupportsClassical == nil {
		kx.SupportsClassical, _ = offerOnly(base, dial, deadline, ClassicalTLSGroups, 0)
	}
	if kx.SupportsPQCHybrid == nil {
		var accepted tls.CurveID
		kx.SupportsPQCHybrid, accepted = offerOnly(base, dial, deadline, PQCHybridTLSGroups, tls.VersionTLS13)
		if kx.SupportsPQCHybrid != nil && *kx.SupportsPQCHybrid && IsPQCHybridTLSGroup(accepted) {
			kx.PQCHybridGroup = TLSKeyExchangeGroupName(accepted)
		}
	}
	return kx
}

// offerOnly runs one handshake offering only groups and reports whether the
// server accepted it: true on success, false when the server refused it with a
// handshake alert, nil for anything else. On success it also returns the group
// the handshake negotiated (0 for legacy RSA key transport).
func offerOnly(base *tls.Config, dial TLSDialFunc, deadline time.Time, groups []tls.CurveID, minVersion uint16) (*bool, tls.CurveID) {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return nil, 0
	}
	conn, err := dial(remaining)
	if err != nil {
		return nil, 0
	}
	defer func() { _ = conn.Close() }()

	cfg := base.Clone()
	cfg.CurvePreferences = append([]tls.CurveID(nil), groups...)
	if minVersion != 0 {
		cfg.MinVersion = minVersion
	}

	tlsConn := tls.Client(conn, cfg)
	defer func() { _ = tlsConn.Close() }()
	if err := tlsConn.SetDeadline(deadline); err != nil {
		return nil, 0
	}
	if err := tlsConn.Handshake(); err != nil {
		if isGroupRefusal(err) {
			return boolPtr(false), 0
		}
		return nil, 0
	}
	// crypto/tls rejects a server that selects a group it did not offer, so a
	// completed handshake negotiated one of groups (or, for the classical
	// offer, legacy RSA key transport — which is classical too).
	return boolPtr(true), tlsConn.ConnectionState().CurveID
}

// isGroupRefusal reports whether err is the server rejecting the offer with a
// fatal handshake_failure or insufficient_security alert — what servers send
// when they share no group with the client. crypto/tls surfaces a received
// alert as a *net.OpError with Op "remote error" wrapping its unexported alert
// type, whose text is the same as tls.AlertError's for the same code.
//
// Anything else — a local error, EOF, a reset, an unrelated alert — is not
// evidence about the groups, and the caller records it as unknown.
func isGroupRefusal(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) || opErr.Op != "remote error" || opErr.Err == nil {
		return false
	}
	msg := opErr.Err.Error()
	return msg == tls.AlertError(alertHandshakeFailure).Error() ||
		msg == tls.AlertError(alertInsufficientSecurity).Error()
}

// RFC 8446 §6 alert codes.
const (
	alertHandshakeFailure     = 40
	alertInsufficientSecurity = 71
)

// ObservedTLSKeyExchange is the key exchange a passively captured handshake
// shows in clear: the group the server selected (the TLS 1.3 ServerHello
// key_share, or the TLS <= 1.2 ECDHE ServerKeyExchange named_curve), or the
// length of a custom DHE prime. The support flags stay nil — a capture answers
// what one connection negotiated, not what else the server would accept.
func ObservedTLSKeyExchange(groupID uint16, dhPrimeBits int) TLSKeyExchange {
	id := tls.CurveID(groupID)
	return TLSKeyExchange{GroupID: id, Group: TLSKeyExchangeGroupName(id), KeyBits: dhPrimeBits}
}

// ApplyTo writes the measurement into a discovery metadata map. Nothing is
// written for a question with no answer: no group name for an unknown id, no
// raw id when no named group was used, no size for a group whose size is not
// known, no flag that is nil.
func (k TLSKeyExchange) ApplyTo(meta map[string]interface{}) {
	if meta == nil {
		return
	}
	if k.GroupID != 0 {
		meta[MetaKeyExchangeGroupRaw] = uint16(k.GroupID)
	}
	if k.Group != "" {
		meta[MetaKeyExchangeAlgorithm] = k.Group
	}
	// The exchange size is what lets ingest finish a strength assessment: an
	// elliptic-curve or finite-field exchange with no size stays unrated.
	if bits := TLSKeyExchangeGroupKeyBits(k.GroupID); bits > 0 {
		meta[MetaKeyExchangeKeySize] = bits
	} else if k.GroupID == 0 && k.KeyBits > 0 {
		meta[MetaKeyExchangeKeySize] = k.KeyBits
	}
	if k.SupportsClassical != nil {
		meta[MetaTLSSupportsClassicalKex] = *k.SupportsClassical
	}
	if k.SupportsPQCHybrid != nil {
		meta[MetaTLSSupportsPQCHybridKex] = *k.SupportsPQCHybrid
		if *k.SupportsPQCHybrid && k.PQCHybridGroup != "" {
			meta[MetaTLSPQCHybridKexGroup] = k.PQCHybridGroup
		}
	}
}

func boolPtr(b bool) *bool { return &b }
