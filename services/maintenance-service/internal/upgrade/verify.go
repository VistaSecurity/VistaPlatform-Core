package upgrade

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/services/maintenance-service/internal/updates"
)

// OIDCIssuer is the issuer every Vista Platform release signature is
// certified by: GitHub Actions' token service (keyless cosign).
const OIDCIssuer = "https://token.actions.githubusercontent.com"

// verifyTimeout bounds one `cosign verify` (registry reads plus the Sigstore
// trust root and transparency-log lookups).
const verifyTimeout = 60 * time.Second

// Verifier checks the signature of the chart at ref (registry/repo:version).
type Verifier interface {
	Verify(ctx context.Context, ref string) error
}

// ChartRef turns an oci:// chart source and a version into the reference
// cosign verifies: registry/repository:version.
func ChartRef(source, version string) (string, error) {
	src, err := updates.ParseSource(source)
	if err != nil {
		return "", err
	}
	return src.Registry + "/" + src.Repository + ":" + version, nil
}

// Cosign is the production Verifier: the pinned cosign binary in this image
// (Dockerfile `tools` stage), run in-process with a 60s bound.
type Cosign struct {
	// Binary defaults to "cosign" on PATH.
	Binary string
	// IdentityRegexp is verification.certificateIdentityRegexp
	// (MAINTENANCE_VERIFICATION_IDENTITY_REGEXP).
	IdentityRegexp string
	// DockerConfig returns a dockerconfigjson for the registry, or nil
	// (anonymous). Read per call so a rotated pull secret needs no restart.
	DockerConfig func(ctx context.Context) []byte
	// TempDir is where the per-call HOME (Sigstore's TUF cache) and docker
	// config go; defaults to os.TempDir() — the pod's /tmp emptyDir, the only
	// writable path under readOnlyRootFilesystem.
	TempDir string
}

// ErrNoIdentity: no identity regexp was rendered, so nothing could be
// verified against — fail closed.
var ErrNoIdentity = errors.New("no signing identity is configured (verification.certificateIdentityRegexp)")

// Verify implements Verifier.
func (c Cosign) Verify(ctx context.Context, ref string) error {
	if strings.TrimSpace(c.IdentityRegexp) == "" {
		return ErrNoIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	home, err := os.MkdirTemp(c.TempDir, "cosign-")
	if err != nil {
		return fmt.Errorf("cosign: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(home) }()
	env := []string{
		"HOME=" + home,
		"TUF_ROOT=" + filepath.Join(home, ".sigstore", "root"),
		"PATH=" + os.Getenv("PATH"),
		// Proxies the operator configured for the pod apply to cosign too.
		"HTTPS_PROXY=" + os.Getenv("HTTPS_PROXY"), "HTTP_PROXY=" + os.Getenv("HTTP_PROXY"), "NO_PROXY=" + os.Getenv("NO_PROXY"),
	}
	if c.DockerConfig != nil {
		if raw := c.DockerConfig(ctx); len(raw) > 0 {
			dir := filepath.Join(home, "docker")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return fmt.Errorf("cosign: docker config dir: %w", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "config.json"), raw, 0o600); err != nil {
				return fmt.Errorf("cosign: docker config: %w", err)
			}
			env = append(env, "DOCKER_CONFIG="+dir)
		}
	}
	bin := c.Binary
	if bin == "" {
		bin = "cosign"
	}
	cmd := exec.CommandContext(ctx, bin, "verify", ref,
		"--certificate-identity-regexp", c.IdentityRegexp,
		"--certificate-oidc-issuer", OIDCIssuer)
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("cosign verify of %s timed out after %s", ref, verifyTimeout)
		}
		return fmt.Errorf("cosign verify of %s failed: %s", ref, lastLines(out.String(), 6))
	}
	return nil
}

// lastLines keeps the tail of a command's output for an error message.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.TrimSpace(strings.Join(lines, " | "))
}
