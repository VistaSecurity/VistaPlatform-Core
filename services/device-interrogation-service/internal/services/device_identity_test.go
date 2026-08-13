package services

import "testing"

// TestDeviceIdentitySetClauses_OnlyNonEmptyFields pins the L-7 fix's core rule:
// an interrogator field left blank must not generate a clause that would
// overwrite a previously-recorded value with an empty string.
func TestDeviceIdentitySetClauses_OnlyNonEmptyFields(t *testing.T) {
	clauses, args := deviceIdentitySetClauses("Ubiquiti", "", "6.6.65", "", 1)
	if len(clauses) != 2 {
		t.Fatalf("expected 2 clauses, got %d: %v", len(clauses), clauses)
	}
	if clauses[0] != "vendor = $1" || clauses[1] != "firmware_version = $2" {
		t.Fatalf("unexpected clauses: %v", clauses)
	}
	if len(args) != 2 || args[0] != "Ubiquiti" || args[1] != "6.6.65" {
		t.Fatalf("unexpected args: %v", args)
	}
}

// TestDeviceIdentitySetClauses_AllEmpty covers the no-op case: nothing to set,
// so the caller must skip the UPDATE entirely rather than run a bare
// "SET updated_at = NOW()".
func TestDeviceIdentitySetClauses_AllEmpty(t *testing.T) {
	clauses, args := deviceIdentitySetClauses("", "", "", "", 1)
	if len(clauses) != 0 || len(args) != 0 {
		t.Fatalf("expected no clauses/args, got %v / %v", clauses, args)
	}
}

// TestDeviceIdentitySetClauses_PlaceholderNumberingContinuesFromStartIdx
// ensures a caller that has already consumed placeholders (e.g. for a WHERE
// clause built before the SET clause) gets correctly numbered continuations.
func TestDeviceIdentitySetClauses_PlaceholderNumberingContinuesFromStartIdx(t *testing.T) {
	clauses, _ := deviceIdentitySetClauses("Vendor", "Model", "FW1", "SN1", 3)
	want := []string{"vendor = $3", "model = $4", "firmware_version = $5", "serial_number = $6"}
	if len(clauses) != len(want) {
		t.Fatalf("expected %d clauses, got %d: %v", len(want), len(clauses), clauses)
	}
	for i, c := range clauses {
		if c != want[i] {
			t.Fatalf("clause %d: expected %q, got %q", i, want[i], c)
		}
	}
}
