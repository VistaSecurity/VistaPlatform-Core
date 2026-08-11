package codescan

import (
	"testing"
)

func TestDefaultRules(t *testing.T) {
	rules := DefaultRules()
	if len(rules) == 0 {
		t.Fatal("expected default rules to be non-empty")
	}

	// Verify all rules have required fields
	seen := make(map[string]bool)
	for _, r := range rules {
		if r.ID == "" {
			t.Error("rule has empty ID")
		}
		if seen[r.ID] {
			t.Errorf("duplicate rule ID: %s", r.ID)
		}
		seen[r.ID] = true

		if r.Pattern == nil {
			t.Errorf("rule %s has nil pattern", r.ID)
		}
		if r.FindingType == "" {
			t.Errorf("rule %s has empty finding type", r.ID)
		}
		if r.Severity == "" {
			t.Errorf("rule %s has empty severity", r.ID)
		}
	}
}

func TestScanContent_GoMD5(t *testing.T) {
	scanner := &Scanner{rules: DefaultRules()}
	content := `package main

import (
	"crypto/md5"
	"fmt"
)

func hash(data []byte) string {
	h := md5.Sum(data)
	return fmt.Sprintf("%x", h)
}
`
	findings, err := scanner.ScanContent(content, "main.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatal("expected at least one finding for MD5 import")
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "go-md5-import" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected severity 'high', got %q", f.Severity)
			}
			if f.Algorithm != "MD5" {
				t.Errorf("expected algorithm 'MD5', got %q", f.Algorithm)
			}
			if f.FindingType != "weak_algorithm" {
				t.Errorf("expected finding type 'weak_algorithm', got %q", f.FindingType)
			}
			if f.LineNumber != 4 {
				t.Errorf("expected line 4, got %d", f.LineNumber)
			}
		}
	}
	if !found {
		t.Error("go-md5-import rule did not match")
	}
}

func TestScanContent_GoInsecureSkipVerify(t *testing.T) {
	scanner := &Scanner{rules: DefaultRules()}
	content := `package main

import "crypto/tls"

func newClient() *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: true,
	}
}
`
	findings, err := scanner.ScanContent(content, "client.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "go-insecure-skip-verify" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("expected severity 'critical', got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Error("go-insecure-skip-verify rule did not match")
	}
}

func TestScanContent_PrivateKey(t *testing.T) {
	scanner := &Scanner{rules: DefaultRules()}
	content := `
const key = "-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn..."
`
	findings, err := scanner.ScanContent(content, "config.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "any-rsa-private-key" {
			found = true
			if f.Severity != "critical" {
				t.Errorf("expected severity 'critical', got %q", f.Severity)
			}
			if f.FindingType != "hardcoded_secret" {
				t.Errorf("expected finding type 'hardcoded_secret', got %q", f.FindingType)
			}
		}
	}
	if !found {
		t.Error("any-rsa-private-key rule did not match")
	}
}

func TestScanContent_PythonMD5(t *testing.T) {
	scanner := &Scanner{rules: DefaultRules()}
	content := `import hashlib

def compute_hash(data):
    return hashlib.md5(data).hexdigest()
`
	findings, err := scanner.ScanContent(content, "utils.py")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "py-md5-usage" {
			found = true
			if f.Algorithm != "MD5" {
				t.Errorf("expected algorithm 'MD5', got %q", f.Algorithm)
			}
		}
	}
	if !found {
		t.Error("py-md5-usage rule did not match")
	}
}

func TestScanContent_JavaScriptSHA1(t *testing.T) {
	scanner := &Scanner{rules: DefaultRules()}
	content := `const crypto = require('crypto');
const hash = crypto.createHash('sha1').update(data).digest('hex');
`
	findings, err := scanner.ScanContent(content, "hash.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "js-sha1-usage" {
			found = true
		}
	}
	if !found {
		t.Error("js-sha1-usage rule did not match")
	}
}

func TestScanContent_JavaECBMode(t *testing.T) {
	scanner := &Scanner{rules: DefaultRules()}
	content := `import javax.crypto.Cipher;

public class Encryptor {
    public byte[] encrypt(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        return cipher.doFinal(data);
    }
}
`
	findings, err := scanner.ScanContent(content, "Encryptor.java")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "java-ecb-mode" {
			found = true
			if f.Severity != "high" {
				t.Errorf("expected severity 'high', got %q", f.Severity)
			}
		}
	}
	if !found {
		t.Error("java-ecb-mode rule did not match")
	}
}

func TestScanContent_NoFalsePositives(t *testing.T) {
	scanner := &Scanner{rules: DefaultRules()}
	content := `package main

import (
	"crypto/sha256"
	"crypto/tls"
)

func secureHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func newSecureClient() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
	}
}
`
	findings, err := scanner.ScanContent(content, "secure.go")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("unexpected finding: %s at line %d", f.RuleID, f.LineNumber)
		}
	}
}

func TestScanContent_NodeTLSRejectUnauthorized(t *testing.T) {
	scanner := &Scanner{rules: DefaultRules()}
	content := `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
`
	findings, err := scanner.ScanContent(content, "app.js")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "js-tls-reject-unauthorized" {
			found = true
		}
	}
	if !found {
		t.Error("js-tls-reject-unauthorized rule did not match")
	}
}

func TestScanContent_DeprecatedLibrary(t *testing.T) {
	scanner := &Scanner{rules: DefaultRules()}
	content := `from Crypto import Random
from Crypto.Cipher import AES
`
	findings, err := scanner.ScanContent(content, "encrypt.py")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "py-pycrypto-import" {
			found = true
		}
	}
	if !found {
		t.Error("py-pycrypto-import rule did not match")
	}
}

func TestShouldSkipFile(t *testing.T) {
	tests := []struct {
		path string
		size int
		skip bool
	}{
		{"src/main.go", 1000, false},
		{"vendor/pkg/lib.go", 1000, true},
		{"node_modules/pkg/index.js", 500, true},
		{"image.png", 5000, true},
		{"dist/bundle.min.js", 100000, true},
		{"src/crypto.py", 500, false},
		{"huge_file.go", 2_000_000, true},
	}

	for _, tt := range tests {
		result := shouldSkipFile(tt.path, tt.size)
		if result != tt.skip {
			t.Errorf("shouldSkipFile(%q, %d) = %v, want %v", tt.path, tt.size, result, tt.skip)
		}
	}
}

func TestSeverityToRiskScore(t *testing.T) {
	tests := []struct {
		severity string
		expected int
	}{
		{"critical", 90},
		{"high", 75},
		{"medium", 50},
		{"low", 25},
		{"info", 10},
		{"unknown", 50},
	}

	for _, tt := range tests {
		result := severityToRiskScore(tt.severity)
		if result != tt.expected {
			t.Errorf("severityToRiskScore(%q) = %d, want %d", tt.severity, result, tt.expected)
		}
	}
}

func TestMatchesFileGlob(t *testing.T) {
	tests := []struct {
		path    string
		ext     string
		glob    string
		matches bool
	}{
		{"main.go", ".go", "*.go", true},
		{"main.py", ".py", "*.go", false},
		{"script.js", ".js", "*.{js,ts,mjs,cjs}", true},
		{"script.ts", ".ts", "*.{js,ts,mjs,cjs}", true},
		{"script.py", ".py", "*.{js,ts,mjs,cjs}", false},
		{"anything.txt", ".txt", "*", true},
	}

	for _, tt := range tests {
		result := matchesFileGlob(tt.path, tt.ext, tt.glob)
		if result != tt.matches {
			t.Errorf("matchesFileGlob(%q, %q, %q) = %v, want %v",
				tt.path, tt.ext, tt.glob, result, tt.matches)
		}
	}
}
