package agentcreds

// ContractVector is the frozen example of the canonical credential envelope.
//
// It is the anchor of the two-sided contract test for. The platform
// (services/device-interrogation-service) and the device agent
// (device-agent/internal/security) live in separate Go modules and cannot import
// each other, so neither can assert directly against the other's code. Both CAN
// assert against this: each side's test opens this exact envelope with these
// exact parameters and must recover ExpectedCredentials, and each side's test
// also seals its own payload and opens it back. If either side ever changes the
// envelope key, the key derivation, the cipher, or the encoding, its test fails
// against the frozen vector — which is what "the two sides cannot drift apart"
// has to mean when they cannot see each other.
//
// The values here are fabricated for the test. VectorSecret is not a credential
// for anything; it stands in for an agent registration key.
//
// This lives in non-test code deliberately: a _test.go file is invisible to
// other packages, and the whole point is that both modules can reach it.
var ContractVector = struct {
	// JobID is the job identifier half of the key derivation.
	JobID string
	// Secret is the agent-registration-key half of the key derivation.
	Secret string
	// Envelope is a complete canonical envelope: the single EnvelopeField key
	// whose value is standard-base64 of nonce || AES-256-GCM ciphertext.
	Envelope map[string]interface{}
	// ExpectedCredentials is what Open(Envelope, JobID, Secret) must return.
	ExpectedCredentials map[string]interface{}
}{
	JobID:  "5f2b1c7a-9c3e-4a1f-8b6d-2e7c1a4d9f30",
	Secret: "reg-key-9d3f5c8a",
	Envelope: map[string]interface{}{
		EnvelopeField: "AAAAAAAAAAAAAAAAimVOkFCbfzy1H7FdFyezcAj5mTTn0cP50B4uKO+a2Gv9ZlFXaQ9fIZecJFhQm9CYHaQo82D7GKhliVGH4OPJ7jcjz2SF9OYbmfTLnJMx7kG95FwxDWWKDQ1F/KX479bQxQG+87WKpKL7uygdE24hYTrvd9HXqLo/jOnEaPXGacGgZp3wwQ7cm5/T/Q2grXmO7giuiNP83sfj0Q==",
	},
	ExpectedCredentials: map[string]interface{}{
		"username":             "admin",
		"password":             "s3cr3t-p@ss",
		"management_url":       "https://bigip.example.test",
		"device_type":          "f5",
		"insecure_skip_verify": true,
	},
}
