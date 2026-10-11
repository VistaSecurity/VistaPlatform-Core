package handlers

import (
	"reflect"
	"testing"
)

func TestParseTrustStatusFilter(t *testing.T) {
	got, err := parseTrustStatusFilter(" Untrusted, distrusted,,unevaluated,untrusted ")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"untrusted", "distrusted", "unevaluated"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for _, bad := range []string{"trusted", "public,nonsense", ",", ""} {
		if _, err := parseTrustStatusFilter(bad); err == nil {
			t.Errorf("%q was accepted; an unknown status must be refused, not ignored", bad)
		}
	}
}
