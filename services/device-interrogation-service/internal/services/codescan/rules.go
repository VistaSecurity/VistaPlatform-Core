package codescan

import "regexp"

// Rule defines a single crypto scanning rule
type Rule struct {
	ID          string         // Unique rule identifier
	Description string         // Human-readable description
	FindingType string         // 'weak_algorithm', 'insecure_pattern', 'hardcoded_secret', 'deprecated_library'
	Severity    string         // 'critical', 'high', 'medium', 'low', 'info'
	Language    string         // Target language: 'go', 'python', 'javascript', 'java', '*' (any)
	Pattern     *regexp.Regexp // Compiled regex
	Algorithm   string         // Algorithm code to link to algorithms table (empty if not algorithm-specific)
	FileGlob    string         // File pattern to match (e.g., "*.go", "*.py")
}

// DefaultRules returns the built-in set of crypto scanning rules.
// These are organized by category for clarity.
func DefaultRules() []Rule {
	rules := []Rule{}
	rules = append(rules, weakAlgorithmRules()...)
	rules = append(rules, insecurePatternRules()...)
	rules = append(rules, hardcodedSecretRules()...)
	rules = append(rules, deprecatedLibraryRules()...)
	return rules
}

// --- Weak Algorithm Usage ---

func weakAlgorithmRules() []Rule {
	return []Rule{
		// Go
		{
			ID:          "go-md5-import",
			Description: "MD5 import detected — MD5 is cryptographically broken",
			FindingType: "weak_algorithm",
			Severity:    "high",
			Language:    "go",
			Pattern:     regexp.MustCompile(`"crypto/md5"`),
			Algorithm:   "MD5",
			FileGlob:    "*.go",
		},
		{
			ID:          "go-sha1-import",
			Description: "SHA-1 import detected — SHA-1 is deprecated for security use",
			FindingType: "weak_algorithm",
			Severity:    "high",
			Language:    "go",
			Pattern:     regexp.MustCompile(`"crypto/sha1"`),
			Algorithm:   "SHA-1",
			FileGlob:    "*.go",
		},
		{
			ID:          "go-des-import",
			Description: "DES import detected — DES has insufficient key length",
			FindingType: "weak_algorithm",
			Severity:    "critical",
			Language:    "go",
			Pattern:     regexp.MustCompile(`"crypto/des"`),
			Algorithm:   "DES",
			FileGlob:    "*.go",
		},
		{
			ID:          "go-rc4-import",
			Description: "RC4 import detected — RC4 has known biases and is broken",
			FindingType: "weak_algorithm",
			Severity:    "critical",
			Language:    "go",
			Pattern:     regexp.MustCompile(`"crypto/rc4"`),
			Algorithm:   "RC4",
			FileGlob:    "*.go",
		},

		// Python
		{
			ID:          "py-md5-usage",
			Description: "MD5 usage detected — MD5 is cryptographically broken",
			FindingType: "weak_algorithm",
			Severity:    "high",
			Language:    "python",
			Pattern:     regexp.MustCompile(`hashlib\.(md5|new\s*\(\s*['"]md5['"]\s*\))`),
			Algorithm:   "MD5",
			FileGlob:    "*.py",
		},
		{
			ID:          "py-sha1-usage",
			Description: "SHA-1 usage detected — SHA-1 is deprecated for security use",
			FindingType: "weak_algorithm",
			Severity:    "high",
			Language:    "python",
			Pattern:     regexp.MustCompile(`hashlib\.(sha1|new\s*\(\s*['"]sha1['"]\s*\))`),
			Algorithm:   "SHA-1",
			FileGlob:    "*.py",
		},
		{
			ID:          "py-des-usage",
			Description: "DES cipher usage detected",
			FindingType: "weak_algorithm",
			Severity:    "critical",
			Language:    "python",
			Pattern:     regexp.MustCompile(`(DES\.new|algorithms\.TripleDES|DES3\.new)`),
			Algorithm:   "DES",
			FileGlob:    "*.py",
		},

		// JavaScript / TypeScript
		{
			ID:          "js-md5-usage",
			Description: "MD5 usage detected in crypto module",
			FindingType: "weak_algorithm",
			Severity:    "high",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`createHash\s*\(\s*['"]md5['"]\s*\)`),
			Algorithm:   "MD5",
			FileGlob:    "*.{js,ts,mjs,cjs}",
		},
		{
			ID:          "js-sha1-usage",
			Description: "SHA-1 usage detected in crypto module",
			FindingType: "weak_algorithm",
			Severity:    "high",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`createHash\s*\(\s*['"]sha1['"]\s*\)`),
			Algorithm:   "SHA-1",
			FileGlob:    "*.{js,ts,mjs,cjs}",
		},
		{
			ID:          "js-des-usage",
			Description: "DES cipher usage detected",
			FindingType: "weak_algorithm",
			Severity:    "critical",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`createCipher(iv)?\s*\(\s*['"](des|des-ede|des-ede3|des3)['"]\s*`),
			Algorithm:   "DES",
			FileGlob:    "*.{js,ts,mjs,cjs}",
		},
		{
			ID:          "js-rc4-usage",
			Description: "RC4 cipher usage detected",
			FindingType: "weak_algorithm",
			Severity:    "critical",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`createCipher(iv)?\s*\(\s*['"]rc4['"]\s*`),
			Algorithm:   "RC4",
			FileGlob:    "*.{js,ts,mjs,cjs}",
		},

		// Java
		{
			ID:          "java-md5-usage",
			Description: "MD5 MessageDigest usage detected",
			FindingType: "weak_algorithm",
			Severity:    "high",
			Language:    "java",
			Pattern:     regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)`),
			Algorithm:   "MD5",
			FileGlob:    "*.java",
		},
		{
			ID:          "java-sha1-usage",
			Description: "SHA-1 MessageDigest usage detected",
			FindingType: "weak_algorithm",
			Severity:    "high",
			Language:    "java",
			Pattern:     regexp.MustCompile(`MessageDigest\.getInstance\s*\(\s*"SHA-?1"\s*\)`),
			Algorithm:   "SHA-1",
			FileGlob:    "*.java",
		},
		{
			ID:          "java-des-usage",
			Description: "DES cipher usage detected",
			FindingType: "weak_algorithm",
			Severity:    "critical",
			Language:    "java",
			Pattern:     regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"DES[/"]\s*`),
			Algorithm:   "DES",
			FileGlob:    "*.java",
		},
		{
			ID:          "java-ecb-mode",
			Description: "ECB mode detected — ECB does not provide semantic security",
			FindingType: "weak_algorithm",
			Severity:    "high",
			Language:    "java",
			Pattern:     regexp.MustCompile(`Cipher\.getInstance\s*\(\s*"[^"]+/ECB/`),
			Algorithm:   "",
			FileGlob:    "*.java",
		},

		// General / multi-language
		{
			ID:          "any-insecure-random",
			Description: "Insecure random number generator used for potential security context",
			FindingType: "weak_algorithm",
			Severity:    "medium",
			Language:    "*",
			Pattern:     regexp.MustCompile(`(Math\.random\s*\(\)|random\.random\s*\(\)|rand\(\)|srand\()`),
			Algorithm:   "",
			FileGlob:    "*.{go,py,js,ts,java,rb,php}",
		},
	}
}

// --- Insecure Patterns ---

func insecurePatternRules() []Rule {
	return []Rule{
		// Go
		{
			ID:          "go-insecure-skip-verify",
			Description: "TLS certificate verification disabled — allows MITM attacks",
			FindingType: "insecure_pattern",
			Severity:    "critical",
			Language:    "go",
			Pattern:     regexp.MustCompile(`InsecureSkipVerify\s*:\s*true`),
			FileGlob:    "*.go",
		},
		{
			ID:          "go-tls-min-version-10",
			Description: "TLS minimum version set to 1.0 — TLS 1.0 is deprecated",
			FindingType: "insecure_pattern",
			Severity:    "high",
			Language:    "go",
			Pattern:     regexp.MustCompile(`MinVersion\s*:\s*tls\.VersionTLS10`),
			FileGlob:    "*.go",
		},
		{
			ID:          "go-tls-min-version-11",
			Description: "TLS minimum version set to 1.1 — TLS 1.1 is deprecated",
			FindingType: "insecure_pattern",
			Severity:    "medium",
			Language:    "go",
			Pattern:     regexp.MustCompile(`MinVersion\s*:\s*tls\.VersionTLS11`),
			FileGlob:    "*.go",
		},

		// Python
		{
			ID:          "py-verify-false",
			Description: "SSL verification disabled — allows MITM attacks",
			FindingType: "insecure_pattern",
			Severity:    "critical",
			Language:    "python",
			Pattern:     regexp.MustCompile(`verify\s*=\s*False`),
			FileGlob:    "*.py",
		},
		{
			ID:          "py-no-check-hostname",
			Description: "SSL hostname checking disabled",
			FindingType: "insecure_pattern",
			Severity:    "critical",
			Language:    "python",
			Pattern:     regexp.MustCompile(`check_hostname\s*=\s*False`),
			FileGlob:    "*.py",
		},

		// JavaScript / Node.js
		{
			ID:          "js-tls-reject-unauthorized",
			Description: "TLS certificate rejection disabled globally",
			FindingType: "insecure_pattern",
			Severity:    "critical",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*['"]?0['"]?`),
			FileGlob:    "*.{js,ts,mjs,cjs}",
		},
		{
			ID:          "js-reject-unauthorized-false",
			Description: "TLS certificate verification disabled in request options",
			FindingType: "insecure_pattern",
			Severity:    "critical",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`rejectUnauthorized\s*:\s*false`),
			FileGlob:    "*.{js,ts,mjs,cjs}",
		},

		// PHP
		{
			ID:          "php-curl-verify-peer-false",
			Description: "CURL SSL peer verification disabled",
			FindingType: "insecure_pattern",
			Severity:    "critical",
			Language:    "php",
			Pattern:     regexp.MustCompile(`CURLOPT_SSL_VERIFYPEER\s*[=,]\s*(false|0|FALSE)`),
			FileGlob:    "*.php",
		},

		// C# / .NET
		{
			ID:          "csharp-server-cert-callback",
			Description: "Server certificate validation callback always returns true",
			FindingType: "insecure_pattern",
			Severity:    "critical",
			Language:    "csharp",
			Pattern:     regexp.MustCompile(`ServerCertificateValidationCallback\s*=.*=>\s*true`),
			FileGlob:    "*.cs",
		},
	}
}

// --- Hardcoded Secrets ---

func hardcodedSecretRules() []Rule {
	return []Rule{
		{
			ID:          "any-rsa-private-key",
			Description: "RSA private key found in source code",
			FindingType: "hardcoded_secret",
			Severity:    "critical",
			Language:    "*",
			Pattern:     regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
			FileGlob:    "*",
		},
		{
			ID:          "any-ec-private-key",
			Description: "EC private key found in source code",
			FindingType: "hardcoded_secret",
			Severity:    "critical",
			Language:    "*",
			Pattern:     regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
			FileGlob:    "*",
		},
		{
			ID:          "any-private-key-generic",
			Description: "Private key found in source code",
			FindingType: "hardcoded_secret",
			Severity:    "critical",
			Language:    "*",
			Pattern:     regexp.MustCompile(`-----BEGIN (ENCRYPTED )?PRIVATE KEY-----`),
			FileGlob:    "*",
		},
		{
			ID:          "any-pgp-private-key",
			Description: "PGP private key block found in source code",
			FindingType: "hardcoded_secret",
			Severity:    "critical",
			Language:    "*",
			Pattern:     regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
			FileGlob:    "*",
		},
	}
}

// --- Deprecated Libraries ---

func deprecatedLibraryRules() []Rule {
	return []Rule{
		// Python
		{
			ID:          "py-pycrypto-import",
			Description: "pycrypto library imported — unmaintained, use pycryptodome instead",
			FindingType: "deprecated_library",
			Severity:    "high",
			Language:    "python",
			Pattern:     regexp.MustCompile(`from\s+Crypto\s+import|import\s+Crypto\.`),
			FileGlob:    "*.py",
		},
		{
			ID:          "py-pycrypto-requirement",
			Description: "pycrypto in requirements — unmaintained, use pycryptodome",
			FindingType: "deprecated_library",
			Severity:    "high",
			Language:    "python",
			Pattern:     regexp.MustCompile(`(?i)^pycrypto[=<>!~]`),
			FileGlob:    "requirements*.txt",
		},

		// JavaScript
		{
			ID:          "js-crypto-js-legacy",
			Description: "crypto-js detected — check version, older versions have vulnerabilities",
			FindingType: "deprecated_library",
			Severity:    "medium",
			Language:    "javascript",
			Pattern:     regexp.MustCompile(`["']crypto-js["']\s*:\s*["'][0-3]\.`),
			FileGlob:    "package.json",
		},

		// Java
		{
			ID:          "java-bouncy-castle-old",
			Description: "Old BouncyCastle provider name detected — use org.bouncycastle",
			FindingType: "deprecated_library",
			Severity:    "low",
			Language:    "java",
			Pattern:     regexp.MustCompile(`import\s+org\.bouncycastle\.jce\.provider\.BouncyCastleProvider`),
			FileGlob:    "*.java",
		},
	}
}
