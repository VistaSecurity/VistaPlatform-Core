package cache

import (
	"testing"
	"time"
)

func TestTTLConstants(t *testing.T) {
	// Verify TTL constants have expected values
	tests := []struct {
		name     string
		ttl      time.Duration
		expected time.Duration
	}{
		{"TTLStatic", TTLStatic, 5 * time.Minute},
		{"TTLSemiStatic", TTLSemiStatic, 30 * time.Second},
		{"TTLDynamic", TTLDynamic, 10 * time.Second},
		{"TTLShort", TTLShort, 1 * time.Minute},
		{"TTLRealtime", TTLRealtime, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ttl != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.ttl, tt.expected)
			}
		})
	}
}

func TestDefaultTTLConfig(t *testing.T) {
	config := DefaultTTLConfig()

	if config.Static != TTLStatic {
		t.Errorf("Static = %v, want %v", config.Static, TTLStatic)
	}
	if config.SemiStatic != TTLSemiStatic {
		t.Errorf("SemiStatic = %v, want %v", config.SemiStatic, TTLSemiStatic)
	}
	if config.Dynamic != TTLDynamic {
		t.Errorf("Dynamic = %v, want %v", config.Dynamic, TTLDynamic)
	}
	if config.Short != TTLShort {
		t.Errorf("Short = %v, want %v", config.Short, TTLShort)
	}
}
