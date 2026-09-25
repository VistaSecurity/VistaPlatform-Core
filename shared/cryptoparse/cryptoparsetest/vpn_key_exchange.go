package cryptoparsetest

// VPN key exchange: the cross-service contract for an interrogated tunnel.
//
// An interrogated VPN crosses three Go modules before anything scores it:
// device-interrogation-service writes sensor_discoveries.metadata,
// discovery-processor-service converts that into an ingest finding, and
// inventory-service links the finding's components to the algorithms
// catalogue and classifies it for PQC. The key exchange was lost at the second
// hop — the writer said `key_exchange_algorithm`, the converter read three
// other names — and no single module's tests could see it, because each was
// consistent with itself.
//
// So the expected outcome at every hop is written down once, here, and each
// module's tests hold themselves to it: one edit governs all three, and no hop
// can quietly weaken its own copy.

// VPNKeyExchangeCase is one tunnel as a collector reports it, and what each
// stage of the pipeline must make of it.
type VPNKeyExchangeCase struct {
	Name string

	// What the collector reports.
	Protocol    string
	CipherSuite string
	Hash        string
	// DHGroup is metadata["dh_group"] in the vendor's own spelling; empty
	// when the protocol has no negotiable group (WireGuard).
	DHGroup string
	// PFSGroup is metadata["pfs_dh_group"]: the phase-2 (PFS) group of an
	// IPsec SA or crypto map. It is a Diffie-Hellman exchange too, so it is
	// offered and scored, but it is never THE key exchange of the tunnel —
	// that is the IKE SA's group.
	PFSGroup string
	// CollectorKex is the key exchange the collector itself states (WireGuard's
	// protocol constant); empty when it comes from DHGroup.
	CollectorKex string
	// CipherKeyBits is the symmetric key length a collector (or an agent built
	// before this contract) may still have put in key_size.
	CipherKeyBits int

	// sensor_discoveries.metadata, as device-interrogation-service writes it.
	WantKex     string   // key_exchange_algorithm — also the converter's scalar; "" = absent
	WantOffered []string // kex_algorithms; nil means the key is absent
	WantKeySize int      // key_size: the size of the key beside WantKex; 0 = absent

	// inventory-service.
	WantLinkedKex []string // key_exchange catalogue codes linked to the configuration
	WantPQC       string   // the classifier's category for the configuration
}

// PQC categories, spelled as the classifier's partition names them.
const (
	PQCNeedsMigration = "needs_migration"
	PQCReady          = "pqc_ready"
	PQCSymmetricSafe  = "symmetric_safe"
	PQCUnclassified   = "unclassified"
)

// VPNKeyExchangeCases are the shapes the VPN collectors produce.
var VPNKeyExchangeCases = []VPNKeyExchangeCase{
	{
		// UniFi site-to-site IPsec: ipsec_dh_group 14, AES-256/SHA-256.
		Name: "unifi-ipsec-group14", Protocol: "IPSec", CipherSuite: "aes256-sha256", Hash: "SHA256",
		DHGroup: "14", CipherKeyBits: 256,
		WantKex: "DH-MODP-2048", WantOffered: []string{"DH-MODP-2048"}, WantKeySize: 2048,
		WantLinkedKex: []string{"DH-MODP-2048"}, WantPQC: PQCNeedsMigration,
	},
	{
		// FortiOS phase1 dhgrp "14 5": the whole offer is scored, so group 5
		// (1536-bit, under the 112-bit floor) is not hidden behind group 14.
		Name: "fortinet-phase1-14-5", Protocol: "IPSec", CipherSuite: "aes256-sha256", Hash: "SHA256",
		DHGroup: "14 5", CipherKeyBits: 256,
		WantKex: "DH-MODP-2048", WantOffered: []string{"DH-MODP-2048", "DH-MODP-1536"}, WantKeySize: 2048,
		WantLinkedKex: []string{"DH-MODP-1536", "DH-MODP-2048"}, WantPQC: PQCNeedsMigration,
	},
	{
		// WireGuard: no negotiation; the key exchange is the protocol constant
		// Curve25519, stated by the collector itself.
		Name: "unifi-wireguard", Protocol: "WireGuard", CipherSuite: "ChaCha20-Poly1305", Hash: "BLAKE2s",
		CollectorKex: "Curve25519", CipherKeyBits: 256,
		WantKex: "Curve25519", WantKeySize: 256,
		WantLinkedKex: []string{"CURVE25519"}, WantPQC: PQCNeedsMigration,
	},
	{
		// An ML-KEM-only key exchange (IKEv2 transform 36).
		Name: "ike-mlkem768-only", Protocol: "IPSec", CipherSuite: "aes256-sha256", Hash: "SHA256",
		DHGroup: "36", CipherKeyBits: 256,
		// key_size absent: ML-KEM has no size comparable to either floor, and
		// the AES length must not stand in for it.
		WantKex: "ML-KEM-768", WantOffered: []string{"ML-KEM-768"},
		WantLinkedKex: []string{"ML-KEM-768"}, WantPQC: PQCReady,
	},
	{
		// ALTERNATIVES, not a hybrid: "19 36" offers ECP-256 OR ML-KEM-768,
		// and a peer that only speaks ECP-256 gets a purely classical
		// exchange. Any classical alternative makes the tunnel vulnerable, so
		// needs_migration is simply correct here.
		//
		// A real RFC 9370 hybrid — an ADDITIONAL key exchange that runs as
		// well as the main one (strongSwan "ecp256-ke1_mlkem768", FortiOS
		// addke1..addke7) — is a different thing and is NOT collected yet.
		// When it is, it must go under a key of its own (never dh_group /
		// kex_algorithms): read as alternatives it would be misclassified.
		// cryptoparse.ParseIKEGroups deliberately answers nothing for it.
		Name: "ike-alternatives-ecp256-or-mlkem768", Protocol: "IPSec", CipherSuite: "aes256-sha256", Hash: "SHA256",
		DHGroup: "19 36", CipherKeyBits: 256,
		WantKex: "DH-ECP-256", WantOffered: []string{"DH-ECP-256", "ML-KEM-768"}, WantKeySize: 256,
		WantLinkedKex: []string{"DH-ECP-256", "ML-KEM-768"}, WantPQC: PQCNeedsMigration,
	},
	{
		// The preferred group has no catalogue row (GOST, 33). The key
		// exchange is unknown — it is NOT the second choice — and key_size
		// must not be left holding the AES length, which beside any key
		// exchange reads as a 256-bit finite-field key (Critical). The
		// assessable alternative is still offered and scored.
		Name: "ike-unassessable-first-gost-then-14", Protocol: "IPSec", CipherSuite: "aes256-sha256", Hash: "SHA256",
		DHGroup: "33 14", CipherKeyBits: 256,
		WantOffered:   []string{"DH-MODP-2048"},
		WantLinkedKex: []string{"DH-MODP-2048"}, WantPQC: PQCNeedsMigration,
	},
	{
		// A Cisco crypto map that states only its PFS group. The collector
		// does not read the isakmp policy, so the IKE group — the tunnel's
		// key exchange — is unknown; the PFS group is offered and scored, and
		// is not promoted to the key exchange.
		Name: "cisco-crypto-map-pfs-only", Protocol: "IPSec", CipherSuite: "AES-256", Hash: "SHA256",
		PFSGroup: "group14", CipherKeyBits: 256,
		WantOffered:   []string{"DH-MODP-2048"},
		WantLinkedKex: []string{"DH-MODP-2048"}, WantPQC: PQCNeedsMigration,
	},
	{
		// IKE group and a weaker PFS group: the IKE group is the key
		// exchange; the PFS group is offered, so the tunnel scores on it.
		Name: "ike-group19-pfs-group5", Protocol: "IPSec", CipherSuite: "aes256-sha256", Hash: "SHA256",
		DHGroup: "19", PFSGroup: "5", CipherKeyBits: 256,
		WantKex: "DH-ECP-256", WantOffered: []string{"DH-ECP-256", "DH-MODP-1536"}, WantKeySize: 256,
		WantLinkedKex: []string{"DH-ECP-256", "DH-MODP-1536"}, WantPQC: PQCNeedsMigration,
	},
}
