package gcp

import (
	"testing"
)

func TestMinTLSVersionToString(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"TLS_1_0", "TLS 1.0"},
		{"TLS_1_1", "TLS 1.1"},
		{"TLS_1_2", "TLS 1.2"},
		{"TLS_1_3", "TLS 1.3"},
		{"UNKNOWN", "UNKNOWN"},
		{"", ""},
	}

	for _, tt := range tests {
		result := MinTLSVersionToString(tt.input)
		if result != tt.expected {
			t.Errorf("MinTLSVersionToString(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
