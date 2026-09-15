package services

// The subject half of SBOM ingestion (workstream 2.6b): turning a document's
// `metadata.component` / `DESCRIBES` package into an asset.
//
// Kept in its own file, with no database and no service receiver, because these
// two decisions are the ones that are easy to get quietly wrong and the ones a
// unit test can pin exactly: WHICH class an SBOM subject may become, and WHAT
// string identifies it afterwards.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/software"
)

// ErrSBOMSubjectNotAnAsset is returned for a subject this path refuses to
// create an asset from. It is a 422, not a 500: the document parsed, we read
// it, and the answer is "not this".
var ErrSBOMSubjectNotAnAsset = errors.New("this document's subject is not something the platform can create an asset from")

// sbomSubjectIdentityPrefix namespaces the `name` identifier an SBOM-created
// application is known by.
//
// It MUST differ from the `application:` prefix that
// identity.ResolveDependent's host-parented form produces (see
// applicationDependentIdentifier), and the two must never be able to collide:
// a host-observed application is identified by its position under a host, and
// this one has no host at all. Two different facts keyed on one string would
// silently merge a measured application with a document's claim about a
// completely different one. TestSBOMSubjectIdentityCannotCollide pins the
// separation.
const sbomSubjectIdentityPrefix = "sbom-subject:"

// sbomSubjectClass decides which asset class an SBOM subject may become.
//
// # Why the list is this short
//
// The only identifier an SBOM subject gives us is a DECLARED name (below), and
// `name` appears in the identifier precedence of exactly two branches of
// standards/asset-classes.yaml: `application` (application, web_application,
// database_instance, service_daemon, middleware) and `service`. Creating an
// asset in any other class from a document would attach a `name` identifier
// that class is not allowed to identify by — so the FIRST upload would create
// the asset, and every upload after it would find the name already owned, have
// nothing left that could vote, hit the identity floor and open a merge
// proposal against the asset it already was. That is not a hypothetical: it is
// the ninety-six-proposals-a-day defect applicationDependentIdentifier exists
// to describe.
//
// So a type that cannot be identified by name is REFUSED by name, with the
// remedy in the message, rather than mapped to the nearest-looking class.
//
//   - `container` deserves the specific note: the registry's `container` class
//     is a RUNNING container, "identified by its image and orchestration
//     identity, never by serial number, MAC or address", precedence
//     [agent_id, cloud_resource_id, cmdb_sys_id, hostname]. There is no
//     `container_image` class. A container-image SBOM says nothing about a
//     running container, and inventing one would claim a workload exists that
//     nobody observed.
//   - `library` is refused as a category error rather than an identity one: a
//     library is a component OF an asset, which is exactly what the components
//     of this document become.
//
// An ABSENT or UNRECOGNISED type maps to `application`. Those two are the same
// answer for the same reason — the document did not tell us — and the failure
// mode is bounded: a mis-classed application is one row a person can re-class,
// where an unmatchable asset is a queue that grows forever.
func sbomSubjectClass(componentType string) (string, error) {
	t := strings.ToLower(strings.TrimSpace(componentType))
	switch t {
	case "", "application", "framework":
		// `framework` sits with `application` deliberately: in the CycloneDX
		// vocabulary it is software that runs, distinguished from `library`
		// only by how it is called. The inventory has no separate class for it.
		return string(assetclass.KeyApplication), nil

	case "library":
		return "", fmt.Errorf("%w: a library is a component of an asset, not an asset. "+
			"Upload this document against the asset the library is installed on and it will appear in its Software tab",
			ErrSBOMSubjectNotAnAsset)

	case "container":
		return "", fmt.Errorf("%w: the `container` asset class is a RUNNING container, identified by its agent, "+
			"cloud resource id or hostname — a container-image bill of materials supplies none of those and says "+
			"nothing about a running workload. Upload it against the container or host asset it runs on",
			ErrSBOMSubjectNotAnAsset)

	case "operating-system", "platform", "device", "device-driver", "firmware", "file", "data", "machine-learning-model":
		return "", fmt.Errorf("%w: a %q subject is identified by hardware or platform facts (serial number, MAC, "+
			"cloud resource id, hostname) that a bill of materials does not carry. Upload it against the existing "+
			"asset it describes", ErrSBOMSubjectNotAnAsset, t)

	default:
		// A type outside the CycloneDX enum, kept verbatim by the parser. See
		// the doc comment: absent and unrecognised get the same answer.
		return string(assetclass.KeyApplication), nil
	}
}

// sbomSubjectIdentity is the `name` identifier value an SBOM-created
// application is matched on, so that re-uploading the same document — or a
// different document about the same artefact — lands on the ONE asset instead
// of minting another.
//
// The value is the subject's own software identity: its purl, else its CPE,
// else `name@version`. That is [software.Product.Identity], which is the same
// expression `software_products` deduplicates on, so "the same piece of
// software" means one thing in the catalogue and in the inventory rather than
// two.
//
// It carries NO host. ADR-0002 D3 identifies an application under its host, and
// this path has no host to put it under: a document uploaded with no target
// asset says what the artefact is and nothing about where it runs. Inventing a
// parent would be the fabricated identity the identity floor exists to refuse,
// and the honest consequence is stated rather than hidden — an application
// created from a document and the same application later measured on a host are
// TWO assets until a person merges them, because nothing we have seen says they
// are one.
//
// The identifier is scoped by the CLASS KEY, which is how every other `name`
// identifier in this service is scoped (see defaultScopeForKind): a name
// identifies within a class, not within a network segment.
func sbomSubjectIdentity(p software.Product) (string, error) {
	n, _ := p.Normalize()
	if !n.Identifiable() {
		// software_products.name is NOT NULL and Identity() would return the
		// bare "@" for a nameless product — a single key every nameless
		// subject in the tenant would collide on. Refusing is the only safe
		// answer.
		return "", fmt.Errorf("%w: the subject has no name, so nothing could identify it a second time",
			ErrSBOMSubjectNotAnAsset)
	}
	return sbomSubjectIdentityPrefix + n.Identity(), nil
}

// sbomSubjectDisplayName is what a person sees in the asset list. The version
// is appended when the document supplied one, because "openssl" and
// "openssl 3.0.13" are different answers to "what did I just import".
func sbomSubjectDisplayName(p software.Product) string {
	n, _ := p.Normalize()
	if n.Version == "" {
		return n.Name
	}
	return n.Name + " " + n.Version
}
