package matcher

// The identifier-kind vocabulary, as strings.
//
// It is a restatement of shared/identity's [identity.Kind] constants, not a
// second opinion: this package cannot import shared/identity (see the package
// doc — it would close an import cycle through shared/ai/seams), and
// TestMatcherKindVocabularyMatchesIdentity in shared/identity fails if these
// lists and identity's ever disagree. A comment claiming they agree would be
// worth nothing; the test is the mechanism.
const (
	KindAgentID               = "agent_id"
	KindCloudResourceID       = "cloud_resource_id"
	KindSerialNumber          = "serial_number"
	KindCMDBSysID             = "cmdb_sys_id"
	KindSSHHostKeyFingerprint = "ssh_host_key_fingerprint"
	KindMACAddress            = "mac_address"
	KindFQDN                  = "fqdn"
	KindHostname              = "hostname"
	KindIPAddress             = "ip_address"
	KindName                  = "name"
)

// allKinds is the whole vocabulary, default-precedence order first and `name`
// last — the order [identity.AllKinds] returns.
var allKinds = []string{
	KindAgentID,
	KindCloudResourceID,
	KindSerialNumber,
	KindCMDBSysID,
	KindSSHHostKeyFingerprint,
	KindMACAddress,
	KindFQDN,
	KindHostname,
	KindIPAddress,
	KindName,
}

// AllKinds returns a copy of the identifier vocabulary this model knows.
func AllKinds() []string {
	out := make([]string, len(allKinds))
	copy(out, allKinds)
	return out
}

// singletonKinds are the four kinds an asset may hold at most ONE of per scope
// (ADR-0002 D3, singleton erratum of. A disagreement on one of
// these is not an ambiguity a score can settle: two ARNs are two resources
// whatever a model thinks of the pair.
var singletonKinds = map[string]bool{
	KindAgentID:         true,
	KindCloudResourceID: true,
	KindSerialNumber:    true,
	KindCMDBSysID:       true,
}

// SingletonKinds returns the singleton kinds, in vocabulary order.
func SingletonKinds() []string {
	out := make([]string, 0, len(singletonKinds))
	for _, k := range allKinds {
		if singletonKinds[k] {
			out = append(out, k)
		}
	}
	return out
}

// IsSingleton reports whether a kind is one per asset per scope.
func IsSingleton(kind string) bool { return singletonKinds[kind] }

// strongKinds are the non-singleton kinds that are unique across the tenant by
// construction: a matching one is real evidence, short of a singleton's.
var strongKinds = map[string]bool{
	KindSSHHostKeyFingerprint: true,
	KindMACAddress:            true,
	KindFQDN:                  true,
}

// weakKinds identify only within a scope, so a match on one is evidence only
// alongside agreement about the scope. `name` is here because a person typed
// it.
var weakKinds = map[string]bool{
	KindHostname:  true,
	KindIPAddress: true,
	KindName:      true,
}

// nameLikeKinds are the kinds whose VALUE is a name a human would recognise,
// and so are worth comparing for similarity rather than only for equality.
var nameLikeKinds = []string{KindFQDN, KindHostname, KindName}
