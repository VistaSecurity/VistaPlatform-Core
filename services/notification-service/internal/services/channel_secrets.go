package services

// Channel-config secrecy on the READ path.
//
// A notification channel's config holds credentials (see
// credentials.NotificationChannelPolicy): a Slack incoming-webhook URL IS the
// secret, PagerDuty's integration_key is a routing key, a generic webhook
// carries auth tokens / passwords / arbitrary header values. They are
// encrypted at rest, but the API used to decrypt them straight into every
// GET /tenant/channels response — any signed-in tenant user could read them.
//
// The contract, stated once:
//
//   - API responses NEVER carry a credential value. MaskChannelConfig replaces
//     each one with a masked form that still says which connection it is:
//     a URL keeps scheme+host ("https://hooks.example.test/••••"), anything
//     else keeps only its last four characters ("••••wxyz"; short values
//     collapse to "••••"). Non-credential fields (recipients, channel,
//     auth.type) pass through — email addresses are not secrets.
//   - On update, a credential that is ABSENT, EMPTY, or EQUAL TO THE MASKED
//     FORM WE EMITTED keeps the stored value (MergeChannelSecrets). A client
//     therefore round-trips a GET body untouched without destroying anything,
//     and only a genuinely new value replaces a secret. The one exception is
//     the free-form header bag: its keys are caller-chosen, so an omitted
//     header is a deleted header; only a header that is present-but-blank or
//     present-but-masked keeps its stored value. Likewise a config that omits
//     a whole nested object (auth, headers) is removing it.
//   - Internal delivery and the channel Test keep using the decrypted stored
//     values — masking happens only at the HTTP response boundary.
//
// Both walks are driven by credentials.NotificationChannelPolicy, the same
// policy that drives encryption at rest, so a field cannot be encrypted but
// left unmasked (or vice versa) by drift.

import (
	"net/url"

	"github.com/vistasecurity/vistaplatform/shared/security/credentials"
)

// SecretMask is the glyph run that stands in for the hidden part of a value.
const SecretMask = "••••"

// maskSecret returns the display form of one credential value.
func maskSecret(v string) string {
	if v == "" {
		return ""
	}
	if u, err := url.Parse(v); err == nil && u.Scheme != "" && u.Host != "" {
		return u.Scheme + "://" + u.Host + "/" + SecretMask
	}
	runes := []rune(v)
	if len(runes) <= 8 {
		return SecretMask
	}
	return SecretMask + string(runes[len(runes)-4:])
}

// keepsStored reports whether an incoming credential means "leave the stored
// value alone": blank, or the masked form of what is stored.
func keepsStored(incoming, stored string) bool {
	return incoming == "" || incoming == maskSecret(stored)
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// MaskChannelConfig returns a copy of cfg with every credential value masked.
func MaskChannelConfig(cfg map[string]interface{}) map[string]interface{} {
	if cfg == nil {
		return nil
	}
	p := credentials.NotificationChannelPolicy
	out := copyMap(cfg)

	for _, key := range p.Fields {
		if s, ok := out[key].(string); ok {
			out[key] = maskSecret(s)
		}
	}
	for _, key := range p.AllValuesIn {
		nested, ok := out[key].(map[string]interface{})
		if !ok {
			continue
		}
		masked := copyMap(nested)
		for k, v := range masked {
			if s, ok := v.(string); ok {
				masked[k] = maskSecret(s)
			}
		}
		out[key] = masked
	}
	for key, nestedKeys := range p.NestedFields {
		nested, ok := out[key].(map[string]interface{})
		if !ok {
			continue
		}
		masked := copyMap(nested)
		for _, nk := range nestedKeys {
			if s, ok := masked[nk].(string); ok {
				masked[nk] = maskSecret(s)
			}
		}
		out[key] = masked
	}
	return out
}

// MergeChannelSecrets builds the config to persist from the stored (decrypted)
// config and the config a client submitted, restoring stored credentials the
// client did not genuinely change. See the contract at the top of this file.
func MergeChannelSecrets(stored, incoming map[string]interface{}) map[string]interface{} {
	if incoming == nil {
		return stored
	}
	p := credentials.NotificationChannelPolicy
	out := copyMap(incoming)

	for _, key := range p.Fields {
		old, hadOld := stored[key].(string)
		if !hadOld {
			continue
		}
		cur, present := out[key]
		curStr, isStr := cur.(string)
		if !present || (isStr && keepsStored(curStr, old)) {
			out[key] = old
		}
	}

	for _, key := range p.AllValuesIn {
		nested, ok := out[key].(map[string]interface{})
		oldNested, hadOld := stored[key].(map[string]interface{})
		if !ok || !hadOld {
			continue
		}
		merged := copyMap(nested)
		for k, v := range merged {
			cur, isStr := v.(string)
			old, oldIsStr := oldNested[k].(string)
			if isStr && oldIsStr && keepsStored(cur, old) {
				merged[k] = old
			}
		}
		out[key] = merged
	}

	for key, nestedKeys := range p.NestedFields {
		nested, ok := out[key].(map[string]interface{})
		oldNested, hadOld := stored[key].(map[string]interface{})
		if !ok || !hadOld {
			continue // no parent object submitted: nothing to restore into
		}
		merged := copyMap(nested)
		for _, nk := range nestedKeys {
			old, oldIsStr := oldNested[nk].(string)
			if !oldIsStr {
				continue
			}
			cur, present := merged[nk]
			curStr, isStr := cur.(string)
			if !present || (isStr && keepsStored(curStr, old)) {
				merged[nk] = old
			}
		}
		out[key] = merged
	}
	return out
}
