package deviceinterrogation

import (
	"reflect"
	"testing"
)

func TestInterfaceMACs_KeepsOnlyIdentityGradeMACs(t *testing.T) {
	value := []map[string]any{
		{"name": "eth0", "mac": "00:00:5e:00:53:a0"},
		{"name": "eth1", "mac": "00:00:5E:00:53:A2"},
		{"name": "eth2", "mac": "00-00-5e-00-53-a4"},
		{"name": "dup", "mac": "00:00:5e:00:53:a0"},
		{"name": "laa", "mac": "02:00:5e:00:53:a6"},
		{"name": "zero", "mac": "00:00:00:00:00:00"},
		{"name": "bcast", "mac": "ff:ff:ff:ff:ff:ff"},
		{"name": "empty", "mac": ""},
		{"name": "junk", "mac": "not-a-mac"},
		{"name": "nomac"},
	}
	want := []string{"00:00:5e:00:53:a0", "00:00:5e:00:53:a2", "00:00:5e:00:53:a4"}
	if got := InterfaceMACs(value); !reflect.DeepEqual(got, want) {
		t.Fatalf("InterfaceMACs = %v, want %v", got, want)
	}
	// The fact value may arrive decoded from JSON.
	generic := []any{map[string]any{"mac": "00:00:5e:00:53:a0"}}
	if got := InterfaceMACs(generic); len(got) != 1 {
		t.Fatalf("InterfaceMACs(generic) = %v", got)
	}
	if got := InterfaceMACs("nonsense"); got != nil {
		t.Fatalf("InterfaceMACs(string) = %v, want nil", got)
	}
}
