package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/software"
)

// The class a subject may become is decided by ONE property: whether the class
// identifies by `name`. These cases are the table of that decision, and the one
// below proves the property rather than restating the table.
func TestSBOMSubjectClass(t *testing.T) {
	for _, tc := range []struct {
		subjectType string
		want        string
		wantRefused bool
	}{
		{subjectType: "application", want: string(assetclass.KeyApplication)},
		{subjectType: "Application", want: string(assetclass.KeyApplication)},
		{subjectType: "  application  ", want: string(assetclass.KeyApplication)},
		{subjectType: "framework", want: string(assetclass.KeyApplication)},
		// Absent and unrecognised are the same answer for the same reason: the
		// document did not tell us, and a mis-classed application is repairable
		// where an unmatchable asset is not.
		{subjectType: "", want: string(assetclass.KeyApplication)},
		{subjectType: "widget-we-have-not-seen", want: string(assetclass.KeyApplication)},

		{subjectType: "library", wantRefused: true},
		{subjectType: "container", wantRefused: true},
		{subjectType: "operating-system", wantRefused: true},
		{subjectType: "platform", wantRefused: true},
		{subjectType: "device", wantRefused: true},
		{subjectType: "device-driver", wantRefused: true},
		{subjectType: "firmware", wantRefused: true},
		{subjectType: "file", wantRefused: true},
		{subjectType: "data", wantRefused: true},
		{subjectType: "machine-learning-model", wantRefused: true},
	} {
		got, err := sbomSubjectClass(tc.subjectType)
		switch {
		case tc.wantRefused && err == nil:
			t.Errorf("%q: want a refusal, got class %q", tc.subjectType, got)
		case tc.wantRefused && !errors.Is(err, ErrSBOMSubjectNotAnAsset):
			t.Errorf("%q: refusal does not wrap ErrSBOMSubjectNotAnAsset: %v", tc.subjectType, err)
		case !tc.wantRefused && err != nil:
			t.Errorf("%q: unexpected refusal: %v", tc.subjectType, err)
		case !tc.wantRefused && got != tc.want:
			t.Errorf("%q: class = %q, want %q", tc.subjectType, got, tc.want)
		}
	}
}

// The rule, not the table: every class this function is willing to produce MUST
// identify by `name`, because a declared name is the only identifier a bill of
// materials supplies.
//
// This is the guard that matters. Adding `container` to the accepted list would
// pass TestSBOMSubjectClass with a one-line edit to its table and fail here —
// which is the right way round, because the table is an opinion and this is the
// consequence.
func TestSBOMSubjectClassOnlyProducesNameIdentifiableClasses(t *testing.T) {
	// Every CycloneDX type the parser can hand us, plus the absent and
	// unrecognised cases.
	all := []string{
		"", "application", "framework", "library", "container", "platform", "device",
		"device-driver", "firmware", "file", "data", "machine-learning-model",
		"operating-system", "something-new",
	}
	for _, subjectType := range all {
		classKey, err := sbomSubjectClass(subjectType)
		if err != nil {
			continue
		}
		class, ok := assetclass.Get(classKey)
		if !ok {
			t.Fatalf("%q produced class %q, which is not in the registry", subjectType, classKey)
		}
		var identifiesByName bool
		for _, kind := range class.IdentifierPrecedence {
			if identity.Kind(kind) == identity.KindName {
				identifiesByName = true
			}
		}
		if !identifiesByName {
			t.Errorf("%q produced class %q, whose identifier precedence is %v and does NOT include `name`. "+
				"An SBOM subject supplies only a declared name, so every upload after the first would find that "+
				"name already owned, have nothing that may vote, hit the identity floor and open a merge proposal "+
				"against the asset it already was.", subjectType, classKey, class.IdentifierPrecedence)
		}
	}
}

// There is no `container_image` class, and `container` is not a substitute.
// Stated as its own test because "check the registry for the right leaf" is a
// question somebody will ask again.
func TestSBOMSubjectContainerHasNoLeafToLandOn(t *testing.T) {
	if _, ok := assetclass.Get("container_image"); ok {
		t.Fatal("a `container_image` class now exists; revisit sbomSubjectClass — the refusal was because there was none")
	}
	container, ok := assetclass.Get(string(assetclass.KeyContainer))
	if !ok {
		t.Fatal("the `container` class is missing from the registry")
	}
	for _, kind := range container.IdentifierPrecedence {
		if identity.Kind(kind) == identity.KindName {
			t.Fatal("`container` now identifies by name; sbomSubjectClass could accept a container subject — revisit it")
		}
	}
	_, err := sbomSubjectClass("container")
	if !errors.Is(err, ErrSBOMSubjectNotAnAsset) {
		t.Fatalf("a container subject must be refused while `container` cannot be identified by name; got %v", err)
	}
}

func TestSBOMSubjectIdentity(t *testing.T) {
	for _, tc := range []struct {
		name    string
		product software.Product
		want    string
	}{
		{
			name:    "a purl is the strongest identifier and wins",
			product: software.Product{Name: "billing", Version: "2.1.0", PURL: "pkg:maven/com.acme/billing@2.1.0", CPE: "cpe:2.3:a:acme:billing:2.1.0:*:*:*:*:*:*:*"},
			want:    sbomSubjectIdentityPrefix + "pkg:maven/com.acme/billing@2.1.0",
		},
		{
			name:    "a CPE wins over name@version",
			product: software.Product{Name: "billing", Version: "2.1.0", CPE: "cpe:2.3:a:acme:billing:2.1.0:*:*:*:*:*:*:*"},
			want:    sbomSubjectIdentityPrefix + "cpe:2.3:a:acme:billing:2.1.0:*:*:*:*:*:*:*",
		},
		{
			name:    "name@version is the fallback",
			product: software.Product{Name: "billing", Version: "2.1.0"},
			want:    sbomSubjectIdentityPrefix + "billing@2.1.0",
		},
		{
			// The trap software.Identity's inner coalesce exists to prevent,
			// restated here because this value becomes an identifier: an
			// unversioned product is `name@`, never "".
			name:    "an unversioned subject keys on name@ and not on the prefix alone",
			product: software.Product{Name: "billing"},
			want:    sbomSubjectIdentityPrefix + "billing@",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := sbomSubjectIdentity(tc.product)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("identity = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestSBOMSubjectIdentityRefusesANamelessSubject(t *testing.T) {
	// Without the Identifiable() check the answer would be "sbom-subject:@",
	// one key every nameless subject in the tenant would collide on.
	_, err := sbomSubjectIdentity(software.Product{Version: "1.0"})
	if !errors.Is(err, ErrSBOMSubjectNotAnAsset) {
		t.Fatalf("want ErrSBOMSubjectNotAnAsset, got %v", err)
	}
}

// The host-parented application key and the SBOM-subject key must live in
// disjoint namespaces. If they could collide, an application measured on a host
// and an unrelated artefact described by a document would be one asset, and
// nothing downstream could tell.
func TestSBOMSubjectIdentityCannotCollide(t *testing.T) {
	dependent, err := dependentApplicationIdentity("web-01", "nginx", "443")
	if err != nil {
		t.Fatalf("building the host-parented key: %v", err)
	}
	subject, err := sbomSubjectIdentity(software.Product{Name: "nginx", Version: "1.27.0"})
	if err != nil {
		t.Fatalf("building the subject key: %v", err)
	}

	if strings.HasPrefix(dependent.Canonical, sbomSubjectIdentityPrefix) {
		t.Fatalf("the host-parented key %q starts with the SBOM prefix; the two namespaces have merged", dependent.Canonical)
	}
	if strings.HasPrefix(subject, string(identity.DependentApplication)+":") {
		t.Fatalf("the subject key %q starts with the host-parented prefix; the two namespaces have merged", subject)
	}
	if dependent.Canonical == subject {
		t.Fatalf("both keys are %q", subject)
	}
}

func TestSBOMSubjectDisplayName(t *testing.T) {
	if got := sbomSubjectDisplayName(software.Product{Name: " openssl ", Version: " 3.0.13 "}); got != "openssl 3.0.13" {
		t.Errorf("display name = %q", got)
	}
	if got := sbomSubjectDisplayName(software.Product{Name: "openssl"}); got != "openssl" {
		t.Errorf("an unversioned subject must not gain a trailing space: %q", got)
	}
}

// The projection is an ALLOWLIST, and the allowlist has to be the class's own.
// The effective schema carries additionalProperties: false, so a key outside it
// is not a harmless extra — it is a write that fails validation.
func TestSubjectAttributesStayInsideTheApplicationSchema(t *testing.T) {
	declared, ok := assetclass.Attributes(string(assetclass.KeyApplication))
	if !ok {
		t.Fatal("the application class has no attribute schema")
	}
	attrs := subjectAttributes(software.Product{Name: "billing", Version: "2.1.0", Vendor: "Acme"})
	if len(attrs) != 3 {
		t.Fatalf("want product, version and vendor projected; got %v", attrs)
	}
	for key := range attrs {
		if _, declaredHere := declared[key]; !declaredHere {
			t.Errorf("projected %q, which the application class does not declare; the effective schema is "+
				"additionalProperties: false, so this write would be rejected", key)
		}
	}
	if subjectAttributes(software.Product{}) != nil {
		t.Error("a subject with nothing to project must produce nil, not an empty map that writes `attributes: {}`")
	}
}
