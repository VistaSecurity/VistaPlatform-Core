package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// The field names below are the real ones observed in a UniFi UDR interrogation
// whose result was persisted verbatim, secrets and all.
func TestIsSecretName_RedactsRealVendorSecrets(t *testing.T) {
	secret := []string{
		"x_mesh_psk", "x_authkey", "x_vwirekey", "syslog_key", "x_password",
		"password", "passwd", "passphrase", "x_shared_secret", "radius_secret",
		"api_key", "apiKey", "private_key", "privateKey", "auth_token",
		"bearer_token", "session_key", "master_key", "signing_key",
		"encryption_key", "x_ssh_password", "pre_shared_key", "credential",
		"host_key", "wpa_key",
	}
	for _, name := range secret {
		if !IsSecretName(name) {
			t.Errorf("field %q should be treated as secret material but was not", name)
		}
	}
}

// The matcher also backstops tenant integration credentials (the
// inventory-service integrations list runs auth_config through Map), and that
// domain names its secrets differently from a network device: an integration's
// credential is as likely to sit under `authorization`, a bare `auth`, or
// inside a webhook URL as under `api_key`. Those three leaked until the
// fragment list was extended; this pins them.
func TestIsSecretName_RedactsIntegrationCredentialNames(t *testing.T) {
	secret := []string{
		"authorization", "Authorization", "auth", "AUTH",
		"webhook_url", "webhook_uri", "slack_webhook", "incoming_webhook",
		"client_secret", "secret_access_key", "credentials",
	}
	for _, name := range secret {
		if !IsSecretName(name) {
			t.Errorf("field %q should be treated as secret material but was not", name)
		}
	}
}

// `auth` is a whole-name match, never a fragment: these are crypto posture that
// a fragment rule would have eaten. Guarding the scoping decision, not just its
// effect.
func TestIsSecretName_AuthIsWholeNameOnly(t *testing.T) {
	safe := []string{
		"auth_type", "auth_style", "auth_method", "authmethod",
		"authentication", "authentication_algorithm", "authenticated",
	}
	for _, name := range safe {
		if IsSecretName(name) {
			t.Errorf("posture/shape field %q was redacted; `auth` over-matched as a fragment", name)
		}
	}
}

// The inverse polarity: an over-strict scrubber that eats the posture fields is
// the same bug pointed the other way. These are exactly what we are in business
// to inventory and they must survive.
func TestIsSecretName_KeepsCryptoPostureFields(t *testing.T) {
	safe := []string{
		"key_algorithm", "key_size", "key_length", "key_exchange",
		"key_exchange_algorithm", "key_types", "key_usage",
		"extended_key_usage", "public_key_algorithm", "host_key_type",
		"host_key_fingerprint", "cipher_suite", "protocol_version",
		"signature_alg", "fingerprint_sha256", "not_after", "mac_address",
		"model", "firmware_version", "serial", "subject_dn", "issuer_dn",
	}
	for _, name := range safe {
		if IsSecretName(name) {
			t.Errorf("posture field %q was redacted; the scrubber is over-strict", name)
		}
	}
}

// Separator folding is what lets one fragment cover every spelling a vendor
// might return. Without it the list would have to enumerate all of them and
// would silently miss the next one.
func TestIsSecretName_FoldsSeparatorSpellings(t *testing.T) {
	for _, name := range []string{
		"private-key", "private_key", "privateKey", "Private Key", "private.key",
		"  PRIVATE-KEY  ",
	} {
		if !IsSecretName(name) {
			t.Errorf("spelling %q escaped the fragment list; separator folding is broken", name)
		}
	}
}

func TestIsSecretName_EmptyNameIsNotSecret(t *testing.T) {
	if IsSecretName("") || IsSecretName("   ") {
		t.Error("an empty field name was treated as secret")
	}
}

func TestMap_RecursesThroughNestedStructures(t *testing.T) {
	in := map[string]any{
		"name":      "Dream Router",
		"key_size":  2048,
		"x_authkey": "6c44255cfd1ae2c09ea2c20aa79538cd",
		"connectivity": map[string]any{
			"uplink_type": "gateway",
			"x_mesh_psk":  "76cb7a67a0650c263bd78635193fc1b2",
		},
		"settings": []any{
			map[string]any{"key": "super_smtp", "x_password": "hunter2"},
		},
	}
	out := Map(in)

	if out["name"] != "Dream Router" || out["key_size"] != 2048 {
		t.Fatalf("non-secret fields were altered: %#v", out)
	}
	if out["x_authkey"] != Marker {
		t.Errorf("top-level secret not redacted: %v", out["x_authkey"])
	}
	nested := out["connectivity"].(map[string]any)
	if nested["x_mesh_psk"] != Marker {
		t.Errorf("nested secret not redacted: %v", nested["x_mesh_psk"])
	}
	if nested["uplink_type"] != "gateway" {
		t.Errorf("nested non-secret altered: %v", nested["uplink_type"])
	}
	inSlice := out["settings"].([]any)[0].(map[string]any)
	if inSlice["x_password"] != Marker {
		t.Errorf("secret inside slice not redacted: %v", inSlice["x_password"])
	}

	// The input must not be mutated — callers may still hold it.
	if in["x_authkey"] == Marker {
		t.Error("Map mutated its input")
	}
}

func TestMap_NilReturnsNil(t *testing.T) {
	if Map(nil) != nil {
		t.Error("Map(nil) should return nil")
	}
}

func TestAny_WalksSliceOfMaps(t *testing.T) {
	// []map[string]any is the shape a Go collector builds directly, as opposed
	// to the []any that comes out of encoding/json. Both have to be walked or
	// the redactor is blind to whichever one the next collector picks.
	in := []map[string]any{
		{"model": "U7LR", "x_authkey": "leak-me"},
	}
	out, ok := Any(in).([]map[string]any)
	if !ok {
		t.Fatalf("Any changed the type of []map[string]any: %T", Any(in))
	}
	if out[0]["x_authkey"] != Marker {
		t.Errorf("secret in []map[string]any not redacted: %v", out[0])
	}
	if out[0]["model"] != "U7LR" {
		t.Errorf("inventory field lost: %v", out[0])
	}
}

// A pasted private key has no field name to catch it by, so the one
// value-shaped rule in this package masks it wherever a string is walked. The
// same rule must NOT touch the public artefacts beside it: a certificate is
// exactly what the inventory exists to record.
func TestMap_MasksPEMPrivateKeysInValuesButNotCertificates(t *testing.T) {
	const (
		privateBody = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmU"
		certBody    = "MIIDdzCCAl+gAwIBAgIEAgAAuQ"
	)
	in := map[string]any{
		"banner":          "login as: root\n-----BEGIN OPENSSH PRIVATE KEY-----\n" + privateBody + "\n-----END OPENSSH PRIVATE KEY-----\nwelcome",
		"certificate_pem": "-----BEGIN CERTIFICATE-----\n" + certBody + "\n-----END CERTIFICATE-----",
	}
	out := Map(in)

	banner, _ := out["banner"].(string)
	if strings.Contains(banner, privateBody) {
		t.Errorf("a private key survived inside an innocently-named field: %q", banner)
	}
	if !strings.Contains(banner, Marker) {
		t.Errorf("the masked key left no marker; a scrubber you cannot observe is one you cannot trust: %q", banner)
	}
	// The prose around it is not a secret and is the reason the field exists.
	if !strings.Contains(banner, "login as: root") || !strings.Contains(banner, "welcome") {
		t.Errorf("masking the key swallowed the text around it: %q", banner)
	}

	cert, _ := out["certificate_pem"].(string)
	if cert != in["certificate_pem"] {
		t.Errorf("a CERTIFICATE block was altered; only PRIVATE KEY blocks are secret material: %q", cert)
	}
}

func TestTextPEM_EveryFlavourAndNeitherPolarity(t *testing.T) {
	for _, kind := range []string{"RSA", "EC", "OPENSSH", "ENCRYPTED", "DSA", ""} {
		header := strings.TrimSpace(kind + " PRIVATE KEY")
		block := "-----BEGIN " + header + "-----\nc2VjcmV0Ynl0ZXM=\n-----END " + header + "-----"
		if got := TextPEM(block); strings.Contains(got, "c2VjcmV0Ynl0ZXM=") {
			t.Errorf("%q private key survived: %q", kind, got)
		}
	}

	// The inverse polarity: public material passes through byte for byte.
	for _, keep := range []string{
		"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		"-----BEGIN PUBLIC KEY-----\nMIIB\n-----END PUBLIC KEY-----",
		"-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----",
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5 deploy@build01",
		"no pem here at all",
	} {
		if got := TextPEM(keep); got != keep {
			t.Errorf("TextPEM altered public material:\n got %q\nwant %q", got, keep)
		}
	}
}

func TestAny_WalksStringSlices(t *testing.T) {
	// []string is what a collector building banner lines or a cipher list
	// produces. It used to be returned as the same slice header — not a copy,
	// and never reaching TextPEM.
	in := []string{
		"cipher: TLS_AES_256_GCM_SHA384",
		"-----BEGIN EC PRIVATE KEY-----\nleak-me\n-----END EC PRIVATE KEY-----",
	}
	out, ok := Any(in).([]string)
	if !ok {
		t.Fatalf("Any changed the type of []string: %T", Any(in))
	}
	if strings.Contains(out[1], "leak-me") {
		t.Errorf("a private key in a []string survived: %q", out[1])
	}
	if out[0] != in[0] {
		t.Errorf("a posture line in a []string was altered: %q", out[0])
	}

	out[0] = "mutated"
	if in[0] == "mutated" {
		t.Error("Any returned the caller's own []string backing array")
	}
}

func TestAny_LeavesScalarsAlone(t *testing.T) {
	// A scalar reached with no field name has no name to judge. Documented
	// behaviour, pinned so a future "clever" value-sniffing change is deliberate.
	for _, v := range []any{"plain", 42, true, nil, 3.5} {
		if got := Any(v); got != v {
			t.Errorf("Any(%#v) = %#v, want unchanged", v, got)
		}
	}
}

func TestString_RedactsByFieldName(t *testing.T) {
	if got := String("api_key", "EXAMPLE-api-key-abc123"); got != Marker {
		t.Errorf("String on a secret field returned %q, want %q", got, Marker)
	}
	if got := String("key_size", "2048"); got != "2048" {
		t.Errorf("String on a posture field returned %q, want it unchanged", got)
	}
}

func TestMustNotRedact_IsTheAllowlistAndIsACopy(t *testing.T) {
	list := MustNotRedact()
	if len(list) == 0 {
		t.Fatal("the crypto-posture allowlist is empty")
	}
	for _, name := range list {
		if !IsMustNotRedact(name) {
			t.Errorf("%q is on the list returned by MustNotRedact but IsMustNotRedact says no", name)
		}
	}
	// Mutating the returned slice must not change the package's answer.
	list[0] = "mutated"
	if IsMustNotRedact("mutated") {
		t.Error("MustNotRedact handed out a reference to the live allowlist")
	}
}

// Which allowlist entries actually DO anything.
//
// Looping over the allowlist asserting !IsSecretName(entry) proves nothing:
// IsSecretName consults this very list first, so the assertion is the
// definition read back to itself. It passes for an entry that does nothing and
// it would pass for an entry nobody has ever needed.
//
// The question worth asking is which entries are LOAD-BEARING — which names the
// fragment list and the "ends in key" catch-all would redact if the allowlist
// were not there to stop them. This test answers it by removing each entry and
// asking the real predicate, then pins the answer, so that adding a fragment
// which starts eating a posture field shows up here as a new load-bearing entry
// rather than silently.
func TestMustNotRedact_LoadBearingEntries(t *testing.T) {
	loadBearing := map[string]bool{}

	for _, name := range MustNotRedact() {
		delete(safeFieldNames, name)
		if IsSecretName(name) {
			loadBearing[name] = true
		}
		safeFieldNames[name] = true // restore immediately; the list must survive this test
	}

	// Today exactly one entry earns its place: "public_key" ends in "key" and
	// the catch-all would eat it, and a public key is publishable by
	// definition — redacting it would destroy inventory we exist to record.
	//
	// The other fifteen (key_algorithm, key_size, key_length, key_strength,
	// key_exchange, key_exchange_algorithm, key_types, key_usage,
	// extended_key_usage, key_agreement, key_id, keyid, public_key_algorithm,
	// host_key_type, host_key_fingerprint) are DEFENSIVE: they contain "key"
	// but do not end in it and match no fragment, so nothing currently redacts
	// them. They are kept deliberately — they state the intent, and they are
	// the guard rail for the day someone adds a fragment like "key" or widens
	// the suffix rule. This test is what would notice that day.
	want := map[string]bool{"public_key": true}

	for name := range want {
		if !loadBearing[name] {
			t.Errorf("%q is no longer load-bearing: with the allowlist entry removed it is not "+
				"redacted anyway. Either a fragment/suffix rule changed, or the entry can go.", name)
		}
	}
	for name := range loadBearing {
		if !want[name] {
			t.Errorf("%q has BECOME load-bearing: some fragment or suffix rule now matches it, so "+
				"the allowlist is the only thing keeping this posture field out of the redactor. "+
				"That is worth knowing about deliberately.", name)
		}
	}

	// The allowlist survived the surgery above.
	if got := len(MustNotRedact()); got != len(safeFieldNames) {
		t.Fatalf("the allowlist was left with %d entries and the map has %d", got, len(safeFieldNames))
	}
	if !IsMustNotRedact("public_key") || IsSecretName("public_key") {
		t.Error("the allowlist was not restored after the test removed entries from it")
	}
}

func TestSecretNameFragmentsAccessors_AreCopiesAndMatch(t *testing.T) {
	frags := SecretNameFragments()
	if len(frags) == 0 {
		t.Fatal("the fragment list is empty")
	}
	for _, frag := range frags {
		// Every fragment must itself read as secret, or the list contains a
		// fragment that the matcher would never act on.
		if !IsSecretName(frag) {
			t.Errorf("fragment %q does not make a field name secret", frag)
		}
	}
	frags[0] = "mutated"
	if IsSecretName("mutated") {
		t.Error("SecretNameFragments handed out a reference to the live list")
	}

	exact := ExactSecretNames()
	if len(exact) == 0 {
		t.Fatal("the exact-name list is empty")
	}
	for _, name := range exact {
		if !IsSecretName(name) {
			t.Errorf("exact secret name %q is not treated as secret", name)
		}
	}
}

// The whole point of the exercise: no secret value survives anywhere in the
// serialized structure, at any nesting depth.
func TestMap_NoSecretValueSurvivesSerialization(t *testing.T) {
	const psk = "76cb7a67a0650c263bd78635193fc1b2"
	const authkey = "6c44255cfd1ae2c09ea2c20aa79538cd"

	in := map[string]any{
		"controller_name": "Dream Router",
		"super_mgmt":      map[string]any{"x_mesh_psk": psk},
		"devices": []any{
			map[string]any{"model": "U7LR", "x_authkey": authkey},
		},
	}

	blob, err := json.Marshal(Map(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, leaked := range []string{psk, authkey} {
		if strings.Contains(string(blob), leaked) {
			t.Errorf("secret %q survived Map in: %s", leaked, blob)
		}
	}
	if !strings.Contains(string(blob), "U7LR") {
		t.Error("Map dropped legitimate inventory data")
	}
}
