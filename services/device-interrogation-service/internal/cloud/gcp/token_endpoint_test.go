package gcp

import "testing"

// The service-account key is tenant-supplied JSON, and its token_uri is where
// the platform POSTs a signed assertion (and, through Test Connection, reports
// what came back). Only Google's OAuth endpoints, over https, on the default
// port.
//
// MUTATION-VERIFIED: return raw unconditionally from tokenEndpoint and the
// rejected cases go red.
func TestTokenEndpoint_OnlyGoogleOAuthHosts(t *testing.T) {
	for uri, ok := range map[string]bool{
		"":                                    true, // Google's default
		"https://oauth2.googleapis.com/token": true,
		"https://accounts.google.com/o/oauth2/token":      true,
		"http://oauth2.googleapis.com/token":              false,
		"https://oauth2.googleapis.com:8443/token":        false,
		"https://metadata.google.internal/token":          false,
		"https://example.com/token":                       false,
		"https://oauth2.googleapis.com.example.com/token": false,
	} {
		c := &Client{serviceKey: &ServiceAccountKey{TokenURI: uri}}
		got, err := c.tokenEndpoint()
		if ok && (err != nil || got == "") {
			t.Errorf("%q rejected: %v", uri, err)
		}
		if !ok && err == nil {
			t.Errorf("%q accepted as %q", uri, got)
		}
	}
}
