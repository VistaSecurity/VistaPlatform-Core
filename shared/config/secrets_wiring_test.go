package config

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// platformSecrets are the three secrets EnforceProductionSecrets governs.
var platformSecrets = map[string]bool{"INTERNAL_AUTH_SECRET": true, "ENCRYPTION_MASTER_KEY": true, "JWT_SECRET": true}

// repoRoot walks up from the test's directory to the go.work that marks the
// repository (or exported tree) root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.work found above " + dir)
		}
		dir = parent
	}
}

var (
	specLiteral = regexp.MustCompile(`(?s)(?:sharedconfig|config)\.EnforceProductionSecrets(?:Err)?\([^{]*?SecretSpec\{(.*?)\n\t+\}\)`)
	requiredRe  = regexp.MustCompile(`Required:\s*\[\]string\{([^}]*)\}`)
	nameRe      = regexp.MustCompile(`"([A-Z_]+)"`)
	verifiesRe  = regexp.MustCompile(`VerifiesJWT:\s*true`)
)

// declaredSecrets scans a service's non-test, non-ee Go sources for its
// EnforceProductionSecrets call and returns the platform secrets it declares
// (JWT_SECRET included when VerifiesJWT is set), and whether a call was found.
func declaredSecrets(t *testing.T, serviceDir string) (map[string]bool, bool) {
	t.Helper()
	declared := map[string]bool{}
	found := false
	err := filepath.WalkDir(serviceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "ee" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range specLiteral.FindAllStringSubmatch(string(src), -1) {
			found = true
			if r := requiredRe.FindStringSubmatch(m[1]); r != nil {
				for _, n := range nameRe.FindAllStringSubmatch(r[1], -1) {
					declared[n[1]] = true
				}
			}
			if verifiesRe.MatchString(m[1]) {
				declared["JWT_SECRET"] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return declared, found
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Every service must call EnforceProductionSecrets at startup, and what it
// declares must equal the platform secrets the registry says the chart injects
// into it. A service that declared a secret the chart does not inject would
// crash-loop in production; one that omitted a secret it receives would keep
// running with it missing or weak. Mutation-check by deleting a call or an entry.
func TestEveryServiceEnforcesItsRegistryDeclaredSecrets(t *testing.T) {
	root := repoRoot(t)

	registry := map[string]map[string]bool{} // service dir name -> required platform secrets
	if raw, err := os.ReadFile(filepath.Join(root, "standards", "service-registry.yaml")); err == nil {
		var doc struct {
			Services []struct {
				Dir             string   `yaml:"dir"`
				RequiredSecrets []string `yaml:"required_secrets"`
			} `yaml:"services"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse registry: %v", err)
		}
		for _, s := range doc.Services {
			set := map[string]bool{}
			for _, n := range s.RequiredSecrets {
				if platformSecrets[n] {
					set[n] = true
				}
			}
			registry[filepath.Base(s.Dir)] = set
		}
	} else {
		t.Fatalf("read registry: %v", err)
	}

	entries, err := os.ReadDir(filepath.Join(root, "services"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, e := range entries {
		dir := filepath.Join(root, "services", e.Name())
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
			continue
		}
		checked++
		declared, found := declaredSecrets(t, dir)
		if !found {
			t.Errorf("services/%s never calls EnforceProductionSecrets: it would start in production with missing or weak platform secrets", e.Name())
			continue
		}
		want, ok := registry[e.Name()]
		if !ok {
			t.Errorf("services/%s is not in standards/service-registry.yaml", e.Name())
			continue
		}
		if got, wantS := strings.Join(sortedKeys(declared), ","), strings.Join(sortedKeys(want), ","); got != wantS {
			t.Errorf("services/%s declares secrets [%s] but the registry's required_secrets give [%s]; keep them equal (the chart injects exactly the registry's set)", e.Name(), got, wantS)
		}
	}
	if checked < 10 {
		t.Fatalf("only %d services found under %s; the scan is inert", checked, root)
	}
}

var (
	healthyStatus = regexp.MustCompile(`"status":\s*"healthy"`)
	newCipherCall = regexp.MustCompile(`credentials\.NewCipher\(`)
)

// ginLiterals returns the text of every gin.H{...} literal in src, outermost
// first, with nested braces balanced.
func ginLiterals(src string) []string {
	var out []string
	for from := 0; ; {
		i := strings.Index(src[from:], "gin.H{")
		if i < 0 {
			return out
		}
		start := from + i
		depth, end := 0, -1
		for j := start + len("gin.H"); j < len(src); j++ {
			switch src[j] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = j + 1
				}
			}
			if end >= 0 {
				break
			}
		}
		if end < 0 {
			return out
		}
		out = append(out, src[start:end])
		from = start + len("gin.H{")
	}
}

// A service that stores credentials must say in /health whether it can encrypt
// them: with ENCRYPTION_MASTER_KEY unset outside production it runs with
// encryption disabled, and /health is where an operator or monitor looks. Every
// service that builds a credentials.Cipher must put credentials.HealthField in
// each healthy payload it serves (the main router and the plaintext probe
// listener are separate handlers).
func TestCredentialStoringServicesReportEncryptionInHealth(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(filepath.Join(root, "services"))
	if err != nil {
		t.Fatal(err)
	}
	storing := 0
	for _, e := range entries {
		dir := filepath.Join(root, "services", e.Name())
		if !e.IsDir() {
			continue
		}
		usesCipher, payloads, withField := false, 0, 0
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			src, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			if newCipherCall.Match(src) {
				usesCipher = true
			}
			for _, p := range ginLiterals(string(src)) {
				// A /health payload: healthy status plus the version block the
				// About-page aggregator reads. Dashboard payloads that merely
				// contain a "healthy" string are not it.
				if !healthyStatus.MatchString(p) || !strings.Contains(p, "version.Get()") {
					continue
				}
				payloads++
				if strings.Contains(p, "credentials.HealthField") {
					withField++
				}
			}
			return nil
		})
		if !usesCipher {
			continue
		}
		storing++
		if payloads == 0 {
			t.Errorf("services/%s builds credential ciphers but serves no recognisable healthy /health payload", e.Name())
		}
		if withField != payloads {
			t.Errorf("services/%s: %d of %d healthy /health payloads include credentials.HealthField", e.Name(), withField, payloads)
		}
	}
	if storing < 5 {
		t.Fatalf("only %d credential-storing services found; the scan is inert", storing)
	}
}
