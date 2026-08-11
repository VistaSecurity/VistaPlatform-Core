// Command generator writes the DemoCorp discovery findings consumed by
// load-democorp.sh.
//
// # WHY THIS IS GENERATED RATHER THAN HAND-WRITTEN
//
// The findings carry real X.509 certificates. Real certificates are what make
// two of the platform's capabilities visible at all:
//
//   - The cryptographic-key inventory derives a key row from each certificate's
//     SubjectPublicKeyInfo, deduplicated by its SPKI fingerprint. Showing that
//     one key can be deployed on many hosts (and survive a renewal) requires
//     certificates that genuinely share a public key — which means issuing them,
//     not typing them.
//   - Certificate expiry, chains and self-signing are properties of the encoded
//     certificate, not of a JSON field.
//
// Regenerating also keeps validity windows relative to today, so "expires in
// three weeks" stays true instead of decaying into "expired two years ago".
//
// EVERY ALGORITHM STRING HERE MUST EXIST IN THE CATALOGUE. The ingest path
// resolves algorithm strings against the `algorithms` table and CREATES A NEW
// ROW when it cannot find a match, so an invented cipher name would silently
// pollute the catalogue the whole product treats as authoritative. The codes
// below are taken from scripts/database/seed.sql.
//
// Usage: go run ./generator -out ../data/findings
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ---------------------------------------------------------------- findings

// finding mirrors services.IngestFinding — the contract of
// POST /api/v1/inventory-service/discovery/jobs/:id/import.
type finding struct {
	Hostname             string                 `json:"hostname"`
	IPAddress            string                 `json:"ip_address"`
	Port                 int                    `json:"port"`
	AssetType            string                 `json:"asset_type"`
	Protocol             string                 `json:"protocol"`
	ProtocolVersion      string                 `json:"protocol_version,omitempty"`
	CipherSuite          string                 `json:"cipher_suite,omitempty"`
	KeyExchangeAlgorithm string                 `json:"key_exchange_algorithm,omitempty"`
	KeySize              int                    `json:"key_size,omitempty"`
	HashAlgorithm        string                 `json:"hash_algorithm,omitempty"`
	OperatingSystem      string                 `json:"operating_system,omitempty"`
	RawData              map[string]interface{} `json:"raw_data,omitempty"`
}

// certJSON is one entry of raw_data.certificates. Keys match what
// AssetService.extractCertificateData reads.
type certJSON struct {
	SubjectDN               string   `json:"subject_dn"`
	IssuerDN                string   `json:"issuer_dn"`
	SerialNumber            string   `json:"serial_number"`
	CommonName              string   `json:"common_name"`
	SubjectAlternativeNames []string `json:"subject_alternative_names,omitempty"`
	NotBefore               string   `json:"not_before"`
	NotAfter                string   `json:"not_after"`
	FingerprintSHA256       string   `json:"fingerprint_sha256"`
	CertificatePEM          string   `json:"certificate_pem"`
	PublicKeyAlgorithm      string   `json:"public_key_algorithm"`
	PublicKeySize           int      `json:"public_key_size"`
	SignatureAlgorithm      string   `json:"signature_algorithm"`
	IsSelfSigned            bool     `json:"is_self_signed"`
	IsCACertificate         bool     `json:"is_ca_certificate"`
	KeyUsage                []string `json:"key_usage,omitempty"`
	ExtendedKeyUsage        []string `json:"extended_key_usage,omitempty"`
}

// ---------------------------------------------------------------- PKI

// issuer is a signing certificate plus its key.
type issuer struct {
	cert *x509.Certificate
	key  interface{}
	pem  string
}

func signerOf(k interface{}) interface{} { return k }

func publicOf(k interface{}) interface{} {
	switch v := k.(type) {
	case *rsa.PrivateKey:
		return &v.PublicKey
	case *ecdsa.PrivateKey:
		return &v.PublicKey
	}
	return nil
}

func newRSA(bits int) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		log.Fatalf("rsa %d: %v", bits, err)
	}
	return k
}

func newECDSA() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("ecdsa: %v", err)
	}
	return k
}

// sigFor picks a signature algorithm compatible with the key actually in hand.
func sigFor(key interface{}, weak bool) x509.SignatureAlgorithm {
	if _, ok := key.(*rsa.PrivateKey); ok {
		if weak {
			return x509.SHA1WithRSA
		}
		return x509.SHA256WithRSA
	}
	if weak {
		return x509.ECDSAWithSHA1
	}
	return x509.ECDSAWithSHA256
}

var serial int64 = 4096

func nextSerial() *big.Int { serial++; return big.NewInt(serial) }

func encodePEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// makeCA builds a self-signed root.
func makeCA(cn string) *issuer {
	key := newRSA(3072)
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"DemoCorp"}, Country: []string{"US"}},
		NotBefore:             time.Now().AddDate(-4, 0, 0),
		NotAfter:              time.Now().AddDate(6, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		log.Fatalf("ca: %v", err)
	}
	c, _ := x509.ParseCertificate(der)
	return &issuer{cert: c, key: key, pem: encodePEM(der)}
}

// leafSpec describes one certificate to issue.
type leafSpec struct {
	cn       string
	sans     []string
	key      interface{} // reuse a key to demonstrate SPKI dedup; nil = fresh
	notdays  int         // days until expiry (negative = already expired)
	rsaBits  int         // >0 issues an RSA key of this size; 0 issues ECDSA P-256
	weakSig  bool        // sign with SHA-1, so the certificate lens has weak-signature rows
	selfSign bool
}

// issueLeaf issues (or self-signs) a leaf and returns the JSON form plus the key
// it used, so callers can deploy the same key elsewhere.
func issueLeaf(ca *issuer, s leafSpec) (certJSON, interface{}) {
	key := s.key
	if key == nil {
		if s.rsaBits > 0 {
			key = newRSA(s.rsaBits)
		} else {
			key = newECDSA()
		}
	}
	// The signature algorithm must match the key that SIGNS the certificate —
	// the CA's key for an issued leaf, the leaf's own key when self-signed. Not
	// the subject key, which is a different thing and the mistake that is easy
	// to make here once a shared key is injected for the SPKI-dedup demo.
	signingKey := ca.key
	if s.selfSign {
		signingKey = key
	}
	sigAlg := sigFor(signingKey, s.weakSig)
	tmpl := &x509.Certificate{
		SerialNumber:          nextSerial(),
		Subject:               pkix.Name{CommonName: s.cn, Organization: []string{"DemoCorp"}, Country: []string{"US"}},
		DNSNames:              append([]string{s.cn}, s.sans...),
		NotBefore:             time.Now().AddDate(-1, 0, 0),
		NotAfter:              time.Now().AddDate(0, 0, s.notdays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SignatureAlgorithm:    sigAlg,
	}
	parent, signKey := ca.cert, signingKey
	if s.selfSign {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, publicOf(key), signerOf(signKey))
	if err != nil {
		log.Fatalf("leaf %s: %v", s.cn, err)
	}
	c, _ := x509.ParseCertificate(der)
	sum := sha256.Sum256(der)

	alg, size := "ECDSA", 256
	if rk, ok := key.(*rsa.PrivateKey); ok {
		alg, size = "RSA", rk.N.BitLen()
	}
	issuerDN := ca.cert.Subject.String()
	if s.selfSign {
		issuerDN = c.Subject.String()
	}
	return certJSON{
		SubjectDN:               c.Subject.String(),
		IssuerDN:                issuerDN,
		SerialNumber:            c.SerialNumber.String(),
		CommonName:              s.cn,
		SubjectAlternativeNames: c.DNSNames,
		NotBefore:               c.NotBefore.Format(time.RFC3339),
		NotAfter:                c.NotAfter.Format(time.RFC3339),
		FingerprintSHA256:       hex.EncodeToString(sum[:]),
		CertificatePEM:          encodePEM(der),
		PublicKeyAlgorithm:      alg,
		PublicKeySize:           size,
		SignatureAlgorithm:      c.SignatureAlgorithm.String(),
		IsSelfSigned:            s.selfSign,
		IsCACertificate:         false,
		KeyUsage:                []string{"digitalSignature", "keyEncipherment"},
		ExtendedKeyUsage:        []string{"serverAuth"},
	}, key
}

// ---------------------------------------------------------------- profiles

// cryptoProfile is a named bundle of algorithm strings, every one of which is a
// real code in the algorithm catalogue. The comment on each records which risk
// band it is there to populate, so the spread stays deliberate.
type cryptoProfile struct {
	name     string
	version  string // protocol_version
	suite    string // cipher_suite
	kex      string // key_exchange_algorithm
	hash     string
	keySize  int
	rsaBits  int  // certificate key: >0 = RSA of this size, 0 = ECDSA P-256
	weakSig  bool // SHA-1 signature
	certDays int
}

var profiles = map[string]cryptoProfile{
	// Critical band — catalogue risk 90+.
	"legacy-ssl": {"legacy-ssl", "SSLv3", "TLS_RSA_WITH_RC4_128_SHA", "STATIC-RSA", "MD5", 1024, 1024, true, 200},
	// High band — 70-89.
	"legacy-tls": {"legacy-tls", "TLS1.0", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "RSA-1024", "SHA1", 1024, 1024, true, 120},
	"tls11":      {"tls11", "TLS1.1", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "DH-1024", "SHA1", 1024, 1024, true, 400},
	// Medium band — 40-69.
	"rsa-kex": {"rsa-kex", "TLS1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "RSA-2048", "SHA256", 2048, 2048, false, 300},
	// Low band — 1-39. The healthy majority.
	"modern":    {"modern", "TLS1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "SHA384", 2048, 2048, false, 500},
	"modern-ec": {"modern-ec", "TLS1.3", "TLS_AES_256_GCM_SHA384", "X25519", "SHA384", 256, 0, false, 600},
	"chacha":    {"chacha", "TLS1.3", "TLS_CHACHA20_POLY1305_SHA256", "X25519", "SHA256", 256, 0, false, 450},
	"expiring":  {"expiring", "TLS1.2", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE", "SHA384", 2048, 2048, false, 21},
	"expired":   {"expired", "TLS1.2", "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "ECDHE", "SHA256", 2048, 2048, false, -30},
	// Post-quantum: pure and hybrid. These make the PQC lens non-empty.
	"pqc-pure":   {"pqc-pure", "TLS1.3", "TLS_AES_256_GCM_SHA384", "ML-KEM-768", "SHA384", 256, 0, false, 700},
	"pqc-hybrid": {"pqc-hybrid", "TLS1.3", "TLS_AES_256_GCM_SHA384", "X25519MLKEM768", "SHA384", 256, 0, false, 700},
	"pqc-hqc":    {"pqc-hqc", "TLS1.3", "TLS_AES_128_GCM_SHA256", "HQC-128", "SHA256", 256, 0, false, 650},
}

// nonTLS are services whose crypto is not a TLS handshake. They exercise the
// non-TLS side of the inventory and, where they use no asymmetric algorithm at
// all, populate the "quantum-safe symmetric" PQC category.
type nonTLS struct {
	proto, version, suite, kex, hash string
	port                             int
}

var nonTLSKinds = []nonTLS{
	{"SSH", "2.0", "", "ECDHE", "SHA256", 22},
	{"SSH", "2.0", "", "X25519", "SHA512", 22},
	{"IPSec", "IKEv2", "", "DH-MODP-2048", "AUTH-HMAC-SHA2-256-128", 500},
	{"SMB", "3.1.1", "SMB-AES-256-GCM", "", "SHA512", 445},
	{"Kerberos", "", "AES256-CTS-HMAC-SHA1-96", "", "SHA1", 88},
}

// otKinds exercise operational-technology discovery — a differentiator with its
// own catalogue entries, and the most alarming risk rows in the dataset.
var otKinds = []nonTLS{
	{"Modbus", "MODBUS-NO-SECURITY", "", "", "", 502},
	{"DNP3", "DNP3-PLAINTEXT", "", "", "", 20000},
	{"DNP3", "DNP3-SAv5", "", "", "DNP3-SA-HMAC-SHA256-16", 20000},
	{"OPC-UA", "OPC-UA-Basic128Rsa15", "", "RSA-2048", "SHA1", 4840},
	{"OPC-UA", "OPC-UA-Aes256Sha256RsaPss", "", "RSA-3072", "SHA256", 4840},
	{"S7", "S7-NO-SECURITY", "", "", "", 102},
	{"EtherNet/IP", "ENIP-NO-SECURITY", "", "", "", 44818},
	{"BACnet", "BACNET-SC-TLS-WRAPPER", "", "ECDHE", "SHA256", 47808},
}

// ---------------------------------------------------------------- segments

type segment struct {
	file    string
	tag     string // short, unique host prefix — env alone collided across data centres
	cidr    string
	env     string
	profile []string // TLS profiles to cycle through
	tls     int      // how many TLS findings
	other   int      // how many non-TLS findings
	ot      int      // how many OT findings
	stale   bool     // last_seen_at backdated, to drive the stale lens
}

var segments = []segment{
	{"datacenter1-production", "dc1p", "172.20.10", "production",
		[]string{"modern", "modern-ec", "chacha", "rsa-kex", "expiring", "modern"}, 22, 4, 0, false},
	{"datacenter1-staging", "dc1s", "172.20.20", "staging",
		[]string{"modern", "rsa-kex", "legacy-tls", "modern-ec"}, 12, 2, 0, false},
	{"datacenter1-lab", "dc1l", "172.20.30", "lab",
		[]string{"legacy-ssl", "legacy-tls", "tls11", "expired", "modern"}, 12, 2, 0, true},
	{"datacenter2-production", "dc2p", "172.21.10", "production",
		[]string{"modern-ec", "modern", "chacha", "expiring", "modern"}, 18, 3, 0, false},
	{"datacenter2-development", "dc2d", "172.21.20", "development",
		[]string{"modern", "expired", "rsa-kex", "tls11"}, 12, 3, 0, true},
	{"corporate-network", "corp", "10.50.1", "production",
		[]string{"modern", "modern-ec", "rsa-kex", "legacy-tls"}, 14, 4, 0, false},
	{"pqc-pilot", "pqc", "172.22.10", "production",
		[]string{"pqc-pure", "pqc-hybrid", "pqc-hqc", "pqc-hybrid"}, 10, 0, 0, false},
	{"ot-plant-floor", "ot", "10.90.1", "production",
		nil, 0, 0, 14, false},
}

var roles = []string{"web", "api", "app", "db", "cache", "queue", "proxy", "gw", "svc", "node"}

func main() {
	out := flag.String("out", "../data/findings", "directory to write findings JSON into")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		log.Fatal(err)
	}

	ca := makeCA("DemoCorp Internal Issuing CA")

	// A single wildcard key deployed across the load-balancer fleet, plus its
	// renewal. Both certificates carry the SAME public key, so the key inventory
	// must collapse them into ONE key row used by many assets — that is the
	// deployment-count story, and it is only visible with shared keys.
	sharedKey := newRSA(2048)
	total, certCount := 0, 0

	for _, seg := range segments {
		var fs []finding

		for i := 0; i < seg.tls; i++ {
			p := profiles[seg.profile[i%len(seg.profile)]]
			host := fmt.Sprintf("%s-%s%02d.democorp.example", seg.tag, roles[i%len(roles)], i+1)
			ip := fmt.Sprintf("%s.%d", seg.cidr, 10+i)

			spec := leafSpec{cn: host, notdays: p.certDays, rsaBits: p.rsaBits, weakSig: p.weakSig}
			// Every third host in a production segment reuses the wildcard key.
			if seg.env == "production" && i%3 == 0 {
				spec.key = sharedKey
				spec.cn = "*.democorp.example"
				spec.sans = []string{host}
			}
			// One self-signed certificate per lab segment.
			if seg.env == "lab" && i == 1 {
				spec.selfSign = true
			}
			cj, _ := issueLeaf(ca, spec)
			certCount++

			f := finding{
				Hostname: host, IPAddress: ip, Port: 443, AssetType: "server",
				Protocol: "TLS", ProtocolVersion: p.version, CipherSuite: p.suite,
				KeyExchangeAlgorithm: p.kex, HashAlgorithm: p.hash, KeySize: p.keySize,
				OperatingSystem: pick(i, "Ubuntu 24.04", "RHEL 9", "Debian 12", "Windows Server 2022"),
				RawData: map[string]interface{}{
					"source":       "democorp-seed",
					"environment":  seg.env,
					"certificates": []interface{}{cj},
				},
			}
			if seg.stale {
				// Backdated so the lifecycle job ages these into warning/archived.
				f.RawData["last_seen_at"] = time.Now().AddDate(0, 0, -(45 + i*4)).Format(time.RFC3339)
			}
			fs = append(fs, f)
		}

		for i := 0; i < seg.other; i++ {
			k := nonTLSKinds[i%len(nonTLSKinds)]
			host := fmt.Sprintf("%s-%s%02d.democorp.example", seg.tag, strings.ToLower(k.proto), i+1)
			fs = append(fs, finding{
				Hostname: host, IPAddress: fmt.Sprintf("%s.%d", seg.cidr, 100+i), Port: k.port,
				AssetType: "server", Protocol: k.proto, ProtocolVersion: k.version,
				CipherSuite: k.suite, KeyExchangeAlgorithm: k.kex, HashAlgorithm: k.hash,
				RawData: map[string]interface{}{"source": "democorp-seed", "environment": seg.env},
			})
		}

		for i := 0; i < seg.ot; i++ {
			k := otKinds[i%len(otKinds)]
			host := fmt.Sprintf("%s-plc-%s%02d.democorp.example", seg.tag, strings.ToLower(strings.ReplaceAll(k.proto, "/", "")), i+1)
			fs = append(fs, finding{
				Hostname: host, IPAddress: fmt.Sprintf("%s.%d", seg.cidr, 20+i), Port: k.port,
				AssetType: "appliance", Protocol: k.proto, ProtocolVersion: k.version,
				CipherSuite: k.suite, KeyExchangeAlgorithm: k.kex, HashAlgorithm: k.hash,
				RawData: map[string]interface{}{"source": "democorp-seed", "environment": seg.env, "ot": true},
			})
		}

		body, err := json.MarshalIndent(map[string]interface{}{"findings": fs}, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		path := filepath.Join(*out, seg.file+".json")
		if err := os.WriteFile(path, append(body, '\n'), 0o644); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("  %-28s %3d findings\n", seg.file, len(fs))
		total += len(fs)
	}

	// The CA itself, so the certificate lens has a chain root to show.
	caJSON := certJSON{
		SubjectDN: ca.cert.Subject.String(), IssuerDN: ca.cert.Subject.String(),
		SerialNumber: ca.cert.SerialNumber.String(), CommonName: ca.cert.Subject.CommonName,
		NotBefore: ca.cert.NotBefore.Format(time.RFC3339), NotAfter: ca.cert.NotAfter.Format(time.RFC3339),
		FingerprintSHA256: fingerprintOf(ca.pem), CertificatePEM: ca.pem,
		PublicKeyAlgorithm: "RSA", PublicKeySize: 3072,
		SignatureAlgorithm: ca.cert.SignatureAlgorithm.String(),
		IsSelfSigned:       true, IsCACertificate: true,
		KeyUsage: []string{"keyCertSign", "cRLSign"},
	}
	caBody, _ := json.MarshalIndent(map[string]interface{}{"certificates": []certJSON{caJSON}}, "", "  ")
	_ = os.WriteFile(filepath.Join(*out, "..", "ca.json"), append(caBody, '\n'), 0o644)

	fmt.Printf("\n  total: %d findings, %d leaf certificates (+1 CA)\n", total, certCount)
}

func fingerprintOf(pemStr string) string {
	b, _ := pem.Decode([]byte(pemStr))
	if b == nil {
		return ""
	}
	s := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(s[:])
}

func pick(i int, opts ...string) string { return opts[i%len(opts)] }

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
