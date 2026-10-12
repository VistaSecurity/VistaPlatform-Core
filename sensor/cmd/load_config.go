package main

import (
	"fmt"

	"github.com/vistasecurity/vistaplatform/sensor/internal/config"
)

// loadConfig resolves the startup configuration. An empty path means no
// config file was given and none exists at the default search locations, so
// the environment-and-defaults configuration is correct. A non-empty path is
// the operator's stated intent to be configured by that file (it was passed
// explicitly or found where the binary expects it): if it cannot be read,
// parsed or validated the error is returned, naming the path, and the caller
// must exit rather than start against built-in defaults with no identity.
func loadConfig(path string) (*config.Config, error) {
	if path == "" {
		return config.Load(), nil
	}
	cfg, err := config.LoadFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("config file %s is unusable: %w", path, err)
	}
	return cfg, nil
}
