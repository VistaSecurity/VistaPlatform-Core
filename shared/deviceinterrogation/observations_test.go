package deviceinterrogation

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/redact"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// assertObservationsValid is the gate every collector's test runs its result
// through. It is deliberately one helper rather than a check per collector: the
// rules it enforces are properties of the RESULT, and a collector that opts out
// of one of them by not calling it is the failure mode this exists to prevent.
func assertObservationsValid(t *testing.T, label string, result *InterrogateResult) {
	t.Helper()
	if result == nil {
		t.Fatalf("%s: nil result", label)
	}

	for _, f := range result.Facts {
		if _, known := facts.Get(f.Key); !known {
			t.Errorf("%s: fact key %q is not registered in standards/fact-keys.yaml", label, f.Key)
			continue
		}
		if !facts.MayWrite(facts.ProducerDeviceInterrogation, f.Key) {
			t.Errorf("%s: fact key %q does not list %s as a producer", label, f.Key, facts.ProducerDeviceInterrogation)
		}
		if err := facts.ValidateValue(f.Key, f.Value); err != nil {
			t.Errorf("%s: fact %s: %v", label, f.Key, err)
		}
		if f.Confidence <= 0 || f.Confidence > 1 {
			t.Errorf("%s: fact %s: confidence %v is not in (0, 1]", label, f.Key, f.Confidence)
		}
		assertPeerValid(t, label+" fact "+f.Key+" subject", f.Subject, false)
	}

	// One subject may not hold two values for the same key: asset_facts is
	// unique on (asset, key, source_ref), so a collector emitting net.interfaces
	// twice for one device would have the second silently replace the first.
	seen := map[string]bool{}
	for _, f := range result.Facts {
		key := f.Key + "\x00" + peerFingerprint(f.Subject)
		if seen[key] {
			t.Errorf("%s: fact %s emitted twice for the same subject", label, f.Key)
		}
		seen[key] = true
	}

	for _, rel := range result.Relationships {
		relType := relationships.Type(rel.Type)
		if !relType.Valid() {
			t.Errorf("%s: relationship type %q is not one of the canonical ten %v", label, rel.Type, relationships.Strings())
			continue
		}
		if !relType.Measurable() {
			t.Errorf("%s: relationship type %q is declared or derived, not measurable", label, rel.Type)
		}
		if !rel.Direction.Valid() {
			t.Errorf("%s: relationship %s: direction %q is not a direction", label, rel.Type, rel.Direction)
		}
		assertPeerValid(t, label+" relationship "+rel.Type+" peer", rel.Peer, true)
		assertPeerValid(t, label+" relationship "+rel.Type+" subject", rel.Subject, false)
	}
}

// assertPeerValid checks a peer reference against the identifier-kind and
// class-key registries. requireIdentifier distinguishes the far end of an edge
// (which must be resolvable) from a fact's subject (which may be the zero value,
// meaning the interrogated device).
func assertPeerValid(t *testing.T, label string, peer PeerRef, requireIdentifier bool) {
	t.Helper()
	if peer.IsZero() {
		if requireIdentifier {
			t.Errorf("%s: peer is empty", label)
		}
		return
	}
	if requireIdentifier && len(peer.Identifiers) == 0 {
		t.Errorf("%s: peer carries no identifier, so nothing downstream can resolve it", label)
	}
	for _, id := range peer.Identifiers {
		if !identity.Kind(id.Kind).Valid() {
			t.Errorf("%s: identifier kind %q is not one of the nine of ADR-0002 D3", label, id.Kind)
			continue
		}
		normalized, err := identity.Normalize(identity.Kind(id.Kind), id.Value)
		if err != nil {
			t.Errorf("%s: identifier %s=%q is rejected by the identification engine: %v", label, id.Kind, id.Value, err)
			continue
		}
		if normalized != id.Value {
			t.Errorf("%s: identifier %s=%q is not normalised; the engine would store %q", label, id.Kind, id.Value, normalized)
		}
	}
	if peer.ClassHint != "" {
		if _, ok := assetclass.Get(peer.ClassHint); !ok {
			t.Errorf("%s: class hint %q is not a registered asset class", label, peer.ClassHint)
		}
	}
}

func peerFingerprint(peer PeerRef) string {
	parts := make([]string, 0, len(peer.Identifiers))
	for _, id := range peer.Identifiers {
		parts = append(parts, id.Kind+"="+id.Value)
	}
	return strings.Join(parts, ",")
}

// --- the structural redaction guard ----------------------------------------

// TestSanitize_CoversEveryCollectedMapInTheResultType walks the RESULT TYPE by
// reflection, plants a secret at every place a collector can put
// collector-controlled data — a map[string]any, a []map[string]any, or an
// `any` — and asserts Sanitize scrubs all of them.
//
// This is the gap the 0.5 review flagged. Sanitize was a hand-written list of
// two fields; adding a third field to the result would have shipped unredacted
// and nothing would have said so. The walker finds the sites rather than being
// told them, so a field added tomorrow is covered today.
//
// Mutation-tested, which for this test means: add
// `Extra map[string]any` to InterrogateResult (or to CryptoAsset, or to any
// struct reachable from them), do NOT add a line to Sanitize, and this test
// fails.
func TestSanitize_CoversEveryCollectedMapInTheResultType(t *testing.T) {
	result := &InterrogateResult{}
	sites := plantSecrets(t, reflect.ValueOf(result).Elem(), "InterrogateResult", 0)

	// A walker that finds nothing passes vacuously. The four known sites today
	// are DeviceInfo, Assets[].Metadata, Facts[].Value and
	// Relationships[].Attributes; if the count ever drops, the walker has
	// stopped walking, not the type stopped carrying maps.
	const knownSites = 4
	if len(sites) < knownSites {
		t.Fatalf("the type walker found only %d collected-data sites (%v); it found %d or more when written, so it has stopped testing what it claims to",
			len(sites), sites, knownSites)
	}

	Sanitize(result)

	blob, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), poison) {
		t.Errorf("a collected map survived Sanitize unredacted — a site below has no line in Sanitize.\nSites planted: %v\nLeaked near: %s", sites, excerptAround(string(blob), poison))
	}
	if strings.Contains(string(blob), "BEGIN RSA PRIVATE KEY") {
		t.Errorf("a PEM private key survived Sanitize.\nLeaked near: %s", excerptAround(string(blob), "BEGIN RSA PRIVATE KEY"))
	}
	// Inverse polarity: the scrubber must not eat the posture it walks past.
	if !strings.Contains(string(blob), "surviving-posture-value") {
		t.Errorf("Sanitize destroyed a non-secret value it walked over: %s", blob)
	}
}

// plantSecrets fills every collected-data site reachable from v with a secret,
// returning the paths it planted at.
//
// It plants only at the shapes Sanitize is responsible for: a map keyed by
// string, a slice of such maps, and an `any`. Plain string fields are
// deliberately out of scope — Sanitize does not walk them, by the same
// reasoning that keeps a reflection-based redactor out of shared/redact, and
// asserting on them here would demand a redactor nobody can reason about.
func plantSecrets(t *testing.T, v reflect.Value, path string, depth int) []string {
	t.Helper()
	if depth > 6 || !v.CanSet() {
		return nil
	}

	switch v.Kind() {
	case reflect.Map:
		if v.Type().Key().Kind() != reflect.String {
			return nil
		}
		v.Set(reflect.ValueOf(secretBearingMap()).Convert(v.Type()))
		return []string{path}

	case reflect.Interface:
		// A fact value is `any`; the widest hole in the result.
		v.Set(reflect.ValueOf(secretBearingMap()))
		return []string{path}

	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		return plantSecrets(t, v.Elem(), path, depth+1)

	case reflect.Slice:
		// One element is enough: Sanitize either walks the slice or it does
		// not.
		v.Set(reflect.MakeSlice(v.Type(), 1, 1))
		return plantSecrets(t, v.Index(0), path+"[0]", depth+1)

	case reflect.Struct:
		var planted []string
		for i := 0; i < v.NumField(); i++ {
			field := v.Type().Field(i)
			if !field.IsExported() {
				continue
			}
			planted = append(planted, plantSecrets(t, v.Field(i), path+"."+field.Name, depth+1)...)
		}
		return planted

	case reflect.String:
		// Not a secret site, but a marker: if the scrubber ever starts eating
		// ordinary strings, the inverse-polarity assertion above catches it.
		v.SetString("surviving-posture-value")
		return nil

	default:
		_ = elemKindNote
		return nil
	}
}

// elemKindNote documents why the default branch does nothing: ints, bools and
// times carry no field name and no secret, and a redactor that judged them by
// value is the heuristic shared/redact deliberately refuses.
const elemKindNote = "scalars have no field name to judge"

// secretBearingMap is what gets planted: a secret under a name the redactor
// must catch, a PEM private key in a value whose name is innocent, and a
// posture field that must survive.
func secretBearingMap() map[string]any {
	return map[string]any{
		"x_mesh_psk": poison,
		"key_size":   2048,
		"banner": "Authorized access only\n-----BEGIN RSA PRIVATE KEY-----\n" +
			"MIIEowIBAAKCAQEA" + poison + "\n-----END RSA PRIVATE KEY-----",
		"nested": map[string]any{"admin_password": poison},
	}
}

// --- the emit-time gates ----------------------------------------------------

func TestAddFact_RejectsUnregisteredAndMistypedFacts(t *testing.T) {
	cases := []struct {
		name string
		fact FactObservation
		want string
	}{
		{
			name: "unregistered key",
			fact: FactObservation{Key: "net.mtu", Value: 1500, Confidence: 1},
			want: "not registered",
		},
		{
			name: "wrong type for the registered key",
			fact: FactObservation{Key: factNetUptimeSeconds, Value: "8 days", Confidence: 1},
			want: "want integer",
		},
		{
			name: "producer not declared for the key",
			fact: FactObservation{Key: facts.KeyAgentID, Value: "agent-1", Confidence: 1},
			want: "does not list device-interrogation",
		},
		{
			name: "no confidence stated",
			fact: FactObservation{Key: factHWVendor, Value: "Cisco Systems"},
			want: "confidence",
		},
		{
			name: "nil value",
			fact: FactObservation{Key: factHWVendor, Value: nil, Confidence: 1},
			want: "value is nil",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &InterrogateResult{}
			err := result.AddFact(tc.fact)
			if err == nil {
				t.Fatalf("AddFact accepted %+v", tc.fact)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not explain the problem (%q)", err, tc.want)
			}
			if len(result.Facts) != 0 {
				t.Errorf("a rejected fact was appended anyway: %+v", result.Facts)
			}
		})
	}
}

func TestAddRelationship_RejectsNonCanonicalEdges(t *testing.T) {
	peer := PeerRef{}
	peer.AddIdentifier(IdentifierMACAddress, "00:11:22:33:44:55")

	cases := []struct {
		name string
		rel  RelationshipObservation
		want string
	}{
		{
			name: "type outside the vocabulary",
			rel:  RelationshipObservation{Type: "uplinks_to", Direction: SubjectToPeer, Peer: peer},
			want: "canonical",
		},
		{
			name: "a type a collector may never measure",
			rel:  RelationshipObservation{Type: string(relationships.Impacts), Direction: SubjectToPeer, Peer: peer},
			want: "never measured",
		},
		{
			name: "no direction",
			rel:  RelationshipObservation{Type: relTypeConnectsTo, Peer: peer},
			want: "direction",
		},
		{
			name: "peer with no identifier",
			rel:  RelationshipObservation{Type: relTypeConnectsTo, Direction: SubjectToPeer, Peer: PeerRef{DisplayName: "core-sw-1"}},
			want: "no identifier",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := &InterrogateResult{}
			if err := result.AddRelationship(tc.rel); err == nil {
				t.Fatalf("AddRelationship accepted %+v", tc.rel)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not explain the problem (%q)", err, tc.want)
			}
			if len(result.Relationships) != 0 {
				t.Errorf("a rejected edge was appended anyway: %+v", result.Relationships)
			}
		})
	}
}

// --- identifier normalisation ----------------------------------------------

// TestNormalizeIdentifierMatchesIdentityPackage pins this package's mirror of
// the identifier rules against shared/identity, which owns them.
//
// The mirror exists because shared/identity pulls in the platform AI seam and
// the config loader, and this package is vendored into a cross-compiled agent
// binary. A mirror that drifts is worse than the dependency it avoided: the
// collector would emit an identifier the identification engine then normalises
// differently, and the same device would match itself twice.
func TestNormalizeIdentifierMatchesIdentityPackage(t *testing.T) {
	accepted := []struct{ kind, value string }{
		{IdentifierMACAddress, "00:11:22:33:44:55"},
		{IdentifierMACAddress, "00-11-22-33-44-55"},
		{IdentifierMACAddress, "0011.2233.4455"},
		{IdentifierMACAddress, "AA:BB:CC:DD:EE:FF"},
		{IdentifierFQDN, "core-sw-1.example.net"},
		{IdentifierFQDN, "CORE-SW-1.Example.NET."},
		{IdentifierHostname, "core-sw-1"},
		{IdentifierHostname, "Core-SW-1"},
		{IdentifierIPAddress, "192.0.2.10"},
		{IdentifierIPAddress, "::ffff:192.0.2.10"},
		{IdentifierIPAddress, "2001:db8::1"},
		{IdentifierSerialNumber, "FGT60D4615007833"},
		{IdentifierAgentID, "6f1b6a1e-2f3c-4d5e-8a7b-9c0d1e2f3a4b"},
	}
	for _, tc := range accepted {
		mine, myErr := normalizeIdentifier(tc.kind, tc.value)
		theirs, theirErr := identity.Normalize(identity.Kind(tc.kind), tc.value)
		if myErr != nil || theirErr != nil {
			t.Errorf("%s %q: mine=%v theirs=%v (both should accept)", tc.kind, tc.value, myErr, theirErr)
			continue
		}
		if mine != theirs {
			t.Errorf("%s %q: this package normalises to %q, the identification engine to %q", tc.kind, tc.value, mine, theirs)
		}
	}

	// The rejections matter as much: these are the placeholders a device
	// returns for "nothing here", and storing one as an identity is how two
	// unrelated assets merge.
	rejected := []struct{ kind, value string }{
		{IdentifierMACAddress, "00:00:00:00:00:00"},
		{IdentifierMACAddress, "ff:ff:ff:ff:ff:ff"},
		{IdentifierMACAddress, ""},
		{IdentifierMACAddress, "not-a-mac"},
		{IdentifierFQDN, "localhost"},
		{IdentifierHostname, "AC LR"},
		{IdentifierHostname, "office switch #2"},
		{IdentifierIPAddress, "0.0.0.0"},
		{IdentifierIPAddress, "N/A"},
		{IdentifierAgentID, ""},
		{IdentifierAgentID, "   "},
	}
	for _, tc := range rejected {
		if _, err := normalizeIdentifier(tc.kind, tc.value); err == nil {
			t.Errorf("%s %q was accepted by this package", tc.kind, tc.value)
		}
		if _, err := identity.Normalize(identity.Kind(tc.kind), tc.value); err == nil {
			t.Errorf("%s %q was accepted by the identification engine; the mirror above is now wrong", tc.kind, tc.value)
		}
	}
}

func TestCanonicalHostnameOrEmpty(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"valid short hostname is kept", "office-switch-1", "office-switch-1"},
		{"valid fqdn is lowercased and dotstripped", "HOST.Corp.Example.", "host.corp.example"},
		{"UniFi-style display name with a space is rejected", "U6+ Living Room", ""},
		{"display name with a hash is rejected", "Back Porch #1", ""},
		{"F5 partition-qualified object name is rejected", "/Common/my-vip", ""},
		{"empty input is rejected", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := canonicalHostnameOrEmpty(tc.input); got != tc.want {
				t.Errorf("canonicalHostnameOrEmpty(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestPeerIdentifierKindsMatchIdentityRegistry(t *testing.T) {
	for _, kind := range []string{
		IdentifierSerialNumber, IdentifierMACAddress,
		IdentifierFQDN, IdentifierHostname, IdentifierIPAddress,
		IdentifierAgentID,
	} {
		if !identity.Kind(kind).Valid() {
			t.Errorf("identifier kind %q is not one of the ten of ADR-0002 D3", kind)
		}
	}
}

func TestAddIdentifier_DropsPlaceholdersAndDuplicates(t *testing.T) {
	peer := PeerRef{}
	if !peer.AddIdentifier(IdentifierMACAddress, "AA-BB-CC-DD-EE-FF") {
		t.Fatal("a valid MAC was dropped")
	}
	if peer.AddIdentifier(IdentifierMACAddress, "aa:bb:cc:dd:ee:ff") {
		t.Error("the same MAC in another spelling was added twice")
	}
	if peer.AddIdentifier(IdentifierMACAddress, "00:00:00:00:00:00") {
		t.Error("the all-zero MAC was stored as an identity")
	}
	if peer.AddIdentifier(IdentifierHostname, "  ") {
		t.Error("whitespace was stored as a hostname")
	}
	if got := peer.Identifier(IdentifierMACAddress); got != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("identifier not canonicalised: %q", got)
	}
	if len(peer.Identifiers) != 1 {
		t.Errorf("expected one identifier, got %+v", peer.Identifiers)
	}
}

// --- redaction reaches the new fields --------------------------------------

func TestSanitize_RedactsFactValuesAndEdgeAttributes(t *testing.T) {
	result := &InterrogateResult{
		Facts: []FactObservation{{
			Key:        factNetVlans,
			Confidence: 1,
			Value: []map[string]interface{}{{
				"id":              20,
				"name":            "IoT",
				"x_radius_secret": poison,
			}},
		}},
		Relationships: []RelationshipObservation{{
			Type:      relTypeConnectsTo,
			Direction: SubjectToPeer,
			Attributes: map[string]interface{}{
				"local_port":  "Port 5",
				"auth_key":    poison,
				"description": "-----BEGIN OPENSSH PRIVATE KEY-----\n" + poison + "\n-----END OPENSSH PRIVATE KEY-----",
			},
		}},
	}

	Sanitize(result)

	blob, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), poison) {
		t.Errorf("a secret survived in a fact value or an edge attribute: %s", blob)
	}
	if !strings.Contains(string(blob), "Port 5") || !strings.Contains(string(blob), "IoT") {
		t.Errorf("Sanitize destroyed the ops data it walked over: %s", blob)
	}
	if marker := redact.Marker; !strings.Contains(string(blob), marker) {
		t.Errorf("nothing was marked as redacted, so the scrub is not observable: %s", blob)
	}
}

// A peer's display name is the least trusted string in a result — an LLDP
// neighbour advertises it — and the SAME string reaches the result twice: once
// as `remote_name` inside the fact value, and once as the peer's display name.
// Both must be scrubbed, or the boundary is decided by which field a reader
// happens to look at.
//
// To mutation-test: delete the sanitizePeer calls from Sanitize and this fails;
// delete only the Identifiers loop inside sanitizePeer and the serial case
// fails.
func TestSanitize_ScrubsPeerFreeText(t *testing.T) {
	const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA" + poison + "\n-----END RSA PRIVATE KEY-----"
	// A single-line block is the shape that survives identifier normalisation,
	// which rejects control characters.
	const inlinePEM = "-----BEGIN EC PRIVATE KEY----- MHcCAQEEI" + poison + " -----END EC PRIVATE KEY-----"

	peer := PeerRef{DisplayName: pem}
	peer.AddIdentifier(IdentifierMACAddress, "00:1b:17:00:00:aa")
	peer.AddIdentifier(IdentifierSerialNumber, inlinePEM)

	result := &InterrogateResult{
		Facts: []FactObservation{{
			Key:        factNetNeighbors,
			Confidence: 1,
			Subject:    PeerRef{DisplayName: pem},
			Value: []map[string]interface{}{{
				"protocol":    "lldp",
				"remote_name": pem,
			}},
		}},
		Relationships: []RelationshipObservation{{
			Type:       relTypeConnectsTo,
			Direction:  SubjectToPeer,
			Subject:    PeerRef{DisplayName: pem},
			Peer:       peer,
			Attributes: map[string]interface{}{"local_port": "Gi1/0/1"},
		}},
	}

	Sanitize(result)

	blob, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(blob), "PRIVATE KEY") {
		t.Errorf("a PEM private key survived in a peer reference: %s", blob)
	}
	if strings.Contains(string(blob), poison) {
		t.Errorf("key material survived in a peer reference: %s", blob)
	}
	// Inverse polarity: an ordinary name and an ordinary identifier are the
	// identity the edge exists to carry, and must come through untouched.
	if got := result.Relationships[0].Peer.Identifier(IdentifierMACAddress); got != "00:1b:17:00:00:aa" {
		t.Errorf("a neighbour MAC was altered by the scrub: %q", got)
	}
	if !strings.Contains(string(blob), "Gi1/0/1") {
		t.Errorf("Sanitize destroyed the port attribute it walked over: %s", blob)
	}
}

// TestRelationshipVocabularyMatchesADR0003 pins the canonical list. It is
// spelled out rather than derived so that changing the vocabulary is a
// deliberate edit in two places, one of which cites the ADR.
func TestRelationshipVocabularyMatchesADR0003(t *testing.T) {
	want := map[string]string{
		"runs_on":        "runs",
		"hosted_on":      "hosts",
		"virtualized_by": "virtualizes",
		"depends_on":     "used_by",
		"connects_to":    "connected_from",
		"member_of":      "members",
		"contains":       "contained_by",
		"manages":        "managed_by",
		"sends_data_to":  "receives_data_from",
		"impacts":        "impacted_by",
	}
	got := relationships.All()
	if len(got) != len(want) {
		t.Fatalf("vocabulary has %d types, ADR-0003 D2 lists %d: %v", len(got), len(want), got)
	}
	for _, typ := range got {
		reverse, ok := want[string(typ)]
		if !ok {
			t.Errorf("%q is not in the ADR-0003 D2 table", typ)
			continue
		}
		if typ.Reverse() != reverse {
			t.Errorf("%q reverses to %q, the ADR says %q", typ, typ.Reverse(), reverse)
		}
	}
	if relationships.Type("uplinks_to").Valid() {
		t.Error("an invented type validated")
	}
	if fmt.Sprint(relationships.Type("connects_to").Reverse()) == "" {
		t.Error("a canonical type has no reverse label")
	}
}

// excerptAround returns a short window of the serialized result around a leak,
// so a failure names the field rather than printing the whole document.
func excerptAround(blob, needle string) string {
	i := strings.Index(blob, needle)
	if i < 0 {
		return ""
	}
	start := max(i-120, 0)
	end := min(i+len(needle)+40, len(blob))
	return "…" + blob[start:end] + "…"
}
