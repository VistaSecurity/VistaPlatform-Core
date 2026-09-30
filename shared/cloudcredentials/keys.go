// Package cloudcredentials is the single list, per cloud provider, of the
// integration-config keys that hold a secret and are therefore stored
// ENCRYPTED in platform_integrations.config.
//
// It exists because the list used to be kept in three places that disagreed:
// the device-interrogation integrations handler, the provider clients that
// decrypt a row to build a client, and admin-service's platform-integration
// service. A key one of them encrypted and another did not was stored in
// plaintext and then refused ("illegal base64") — or encrypted and then handed
// to the provider as a ciphertext. Every writer and reader now builds its list
// from here.
//
// Identifiers are deliberately absent: an AWS role ARN, an Azure directory
// (tenant) ID and subscription ID, a GCP project ID. They are not secrets, and
// the integrations UI shows them.
package cloudcredentials

// AWS keys. external_id is a shared secret between the platform and the
// customer's role trust policy — half of the assume-role authorization.
var AWS = []string{
	"access_key_id",
	"secret_access_key",
	"session_token",
	"external_id",
}

// Azure keys. client_id is an application ID rather than a secret, but every
// existing row holds it encrypted, so it stays on the list: dropping it would
// hand Azure a ciphertext as the application ID.
var Azure = []string{
	"client_id",
	"client_secret",
}

// GCP keys: the three names a service-account key JSON has been accepted under.
var GCP = []string{
	"service_account_key",
	"credentials_json",
	"service_account_json",
}

// All is every provider's keys, in a fresh slice.
func All() []string {
	out := make([]string, 0, len(AWS)+len(Azure)+len(GCP))
	out = append(out, AWS...)
	out = append(out, Azure...)
	out = append(out, GCP...)
	return out
}
