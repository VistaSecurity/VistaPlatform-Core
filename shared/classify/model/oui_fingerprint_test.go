package model

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ouiregistry"
)

// The OUI half of [FeatureSchemaID], pinned.
//
// `NamespaceOUI` hashes the canonical VENDOR the IEEE registry resolves a MAC
// to, so a weights file is only meaningful against the registry it was trained
// on. The fingerprint once carried a row COUNT and was blind to a renamed
// vendor — every device of that vendor silently moved to a different bucket
// while the shipped weights still loaded and scored. It now carries the
// registry's own content hash (ouiregistry.SnapshotID, which covers every
// prefix->vendor row) plus a hash of the canonical-name set, which decides
// whether a vendor sets its own bucket or the shared uncatalogued feature.
func TestFeatureSchemaIDCarriesTheRegistrySnapshot(t *testing.T) {
	id := FeatureSchemaID()
	for _, want := range []string{
		"ouiregistry=" + ouiregistry.SnapshotID(),
		"ouicanon=" + hashNames(ouiregistry.CanonicalVendors()),
	} {
		if !strings.Contains(id, want) {
			t.Errorf("FeatureSchemaID() = %q, which does not carry %q — a hash that is "+
				"computed and then not used is the same as not computing it", id, want)
		}
	}
	if strings.Contains(id, "ouirows") || strings.Contains(id, "ouihash") {
		t.Errorf("FeatureSchemaID() = %q still carries the retired per-prefix table fingerprint", id)
	}
}

// hashNames is the change detector over the canonical-name set. It must move
// when the set does, and must NOT move when nothing did.
func TestHashNamesTracksTheSetNotItsOrder(t *testing.T) {
	base := []string{"Cisco Systems", "Juniper Networks", "Fortinet"}
	want := hashNames(base)

	if got := hashNames([]string{"Cisco Systems, Inc.", "Juniper Networks", "Fortinet"}); got == want {
		t.Error("renaming one vendor left the hash unmoved")
	}
	if got := hashNames([]string{"Cisco Systems", "Juniper Networks", "Palo Alto Networks"}); got == want {
		t.Error("swapping one vendor for another (same count) left the hash unmoved")
	}
	if got := hashNames([]string{"Fortinet", "Cisco Systems", "Juniper Networks"}); got != want {
		t.Errorf("reordering the same set moved the hash (%s -> %s); a fingerprint that "+
			"changes between two runs of one build rejects the shipped weights at random", want, got)
	}
	if a, b := hashNames([]string{"ab", "c"}), hashNames([]string{"a", "bc"}); a == b {
		t.Errorf("two different sets hash alike (%s); the separator is not doing its job", a)
	}
	if hashNames(base) != want || base[0] != "Cisco Systems" {
		t.Error("hashNames mutated or depended on its input's order")
	}
}
