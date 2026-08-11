// Package version exposes the running build's version metadata in a single
// shape every service can drop into its /health response.
//
// All fields read from environment variables populated by the orchestrator
// (Helm chart deployment template in Kubernetes; generated docker-compose
// service blocks in dev). The source of truth is therefore the image the
// orchestrator actually scheduled, which is what an operator most needs to
// see when diagnosing "did the upgrade take?". A previous design considered
// ldflags-stamping the binary at build time, but the v2.2.0 → v2.3.3
// upgrade bug the About page exists to catch was caused by an image
// override holding pods on a stale image — the binary's compiled-in
// version would have said v2.3.3 in that case (the bits were tagged as
// such), masking the bug.
//
// Two distinct identifiers, deliberately kept separate:
//
//   - Service is the RELEASE tag (e.g. "v2.5.3"). It is uniform across every
//     service in a release, which is what makes it a valid skew key: if two
//     services report different tags, the deployment is genuinely mixed.
//   - ImageDigest is the PER-POD content digest (e.g. "sha256:abc…"). It is
//     unique per service by construction, so it is informational only and is
//     never compared across services. Earlier this value was folded into
//     Service whenever the image was digest-pinned, which made every service
//     report a different "tag" and produced a permanent false "skew detected"
//     on digest-pinned (ECR/EKS) installs. Keeping them separate fixes that.
package version

import "os"

// Info is the version payload included in /health responses and consumed
// by monitoring-service's /version aggregator.
type Info struct {
	// Service is the release image tag (e.g. "v2.5.3"), set by the
	// orchestrator from the deployment template. Uniform across a release;
	// used as the skew key.
	Service string `json:"service"`
	// Chart is the helm chart version (Chart.yaml `version:`), set on every
	// backend pod via the shared app ConfigMap.
	Chart string `json:"chart"`
	// AppVersion is the helm chart appVersion (Chart.yaml `appVersion:`),
	// set on every backend pod via the shared app ConfigMap.
	AppVersion string `json:"app_version"`
	// ImageDigest is the per-pod image content digest when the image is
	// digest-pinned (e.g. "sha256:…"), set by the deployment template. Empty
	// when the image is referenced by tag only. Informational — never part of
	// skew detection because it is unique per service by design.
	ImageDigest string `json:"image_digest,omitempty"`
}

// Get reads the version envs the chart/compose injects and returns the
// payload. Missing values render as "unknown" so the About page renders
// without `null`s. ImageDigest is left empty (omitted) when not pinned.
func Get() Info {
	return Info{
		Service:     envOr("SERVICE_VERSION", "unknown"),
		Chart:       envOr("CHART_VERSION", "unknown"),
		AppVersion:  envOr("CHART_APP_VERSION", "unknown"),
		ImageDigest: os.Getenv("SERVICE_IMAGE_DIGEST"),
	}
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
