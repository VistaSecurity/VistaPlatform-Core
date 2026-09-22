package services

import "github.com/vistasecurity/vistaplatform/shared/redact"

// Every job-level failure string this service persists passes through here.
//
// `device_jobs.error_message` and `asset_management.interrogation_error` are
// free text assembled from whatever failed, and both are served to tenant API
// clients (GET /jobs, GET /jobs/:id, the device detail). Neither is covered by
// the job-results projection, which enumerates result fields and walks
// Asset.Metadata with RedactMap — the error string has no field names to walk,
// so it needs the value-shaped rules instead: [redact.Text] masks PEM private
// keys by shape and credential query parameters by parameter name.
//
// The concrete case was PAN-OS, whose API key travelled in the query string:
// Go's *url.Error prints the whole URL, so a firewall that stopped answering
// mid-interrogation published a live API key through this field. That is fixed
// at the source (the key is now a header). This is the backstop for the vendor
// nobody has checked yet, and it is deliberately at the WRITE rather than at the
// read: a value that never enters the database cannot be forgotten on the way
// out of it.

// redactErrorMessage returns msg with secret material masked.
func redactErrorMessage(msg string) string {
	return redact.Text(msg)
}

// redactedErrorMessage is [redactErrorMessage] for the nullable form the update
// paths carry. A nil message stays nil — SQL NULL means "no failure recorded"
// and must not become the empty string.
func redactedErrorMessage(msg *string) *string {
	if msg == nil {
		return nil
	}
	cleaned := redactErrorMessage(*msg)
	return &cleaned
}
