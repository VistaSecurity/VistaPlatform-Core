// Package config provides shared environment variable helpers used across all services.
package config

import (
	"os"
	"strconv"
	"time"
)

// GetEnv reads an environment variable or returns the fallback.
func GetEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// GetEnvIfPresent returns the environment variable's value when the key is
// present (even if set to the empty string), otherwise the fallback. Unlike
// GetEnv, an explicitly-set empty value is preserved rather than treated as
// unset — use this when "" is a meaningful, intentional value.
func GetEnvIfPresent(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// GetEnvRequired reads an environment variable or panics if not set.
func GetEnvRequired(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("required environment variable " + key + " is not set")
	}
	return v
}

// GetEnvAsInt reads an environment variable as int or returns the fallback.
func GetEnvAsInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

// GetEnvAsBool reads an environment variable as bool or returns the fallback.
func GetEnvAsBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

// GetEnvAsDuration reads an environment variable as time.Duration or returns the fallback.
func GetEnvAsDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
