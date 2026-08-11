package credentials

// The credential denylists for every store that uses this package live here,
// together, on purpose.
//
// Scattered across services they drifted: three lists disagreed about whether
// access_key_id was a secret, one treated username as one and five did not, and
// a new connector's author had no list to consult at all. Side by side, a
// divergence is either obviously deliberate (and carries a comment saying why)
// or obviously a mistake.
//
// BaseIntegrationFields is the floor. A store-specific policy should extend it,
// not replace it, unless the store genuinely cannot hold those keys.

// BaseIntegrationFields is the union of credential key names observed across
// every integration/connector config in the platform. It is the default floor
// for any store that accepts a caller-shaped auth blob, because such a store
// cannot constrain what the caller puts in it — a tenant configuring a
// "custom" integration will use whichever of these names their system uses.
//
// Deliberately NOT included:
//
//   - username — a username is an identifier, not a credential, it is displayed
//     in UI listings, and encrypting it breaks search/sort on the column's JSON.
//     Its matching password is encrypted. (device-interrogation's device
//     handler is the one site that historically encrypted username; that is a
//     device-credential-specific choice, kept there, not promoted here.)
//   - tenant_id, subscription_id, account_id, project_id, region — cloud
//     account coordinates. Public identifiers, and the UI shows them.
//   - url, base_url, endpoint, webhook_url — see the note on WebhookURL
//     policies below; these are credentials only for *unauthenticated-URL*
//     webhooks, where the store says so explicitly.
var BaseIntegrationFields = []string{
	"access_key_id",
	"access_token",
	"api_key",
	"api_token",
	"auth_token",
	"client_secret",
	"credentials_json",
	"integration_key",
	"password",
	"private_key",
	"refresh_token",
	"secret",
	"secret_access_key",
	"service_account_json",
	"service_account_key",
	"session_token",
	"token",
	"webhook_secret",
}

// NotificationChannelPolicy covers tenant_notification_channels.config and
// platform_notification_channels.config (notification-service) and
// monitoring_notification_channels.config (monitoring-service). All three hold
// the same shape and all three are read by delivery code that expects
// plaintext.
//
// webhook_url and url ARE credentials here, unlike in a generic integration: a
// Slack incoming-webhook URL is a bearer credential — anyone holding it can
// post to the channel — and there is no separate token beside it. Same for the
// generic outbound webhook target, whose URL commonly embeds the token.
//
// headers is a caller-chosen bag sent verbatim as HTTP headers, so every value
// is treated as a credential. auth is the {type, token, username, password}
// discriminated shape the webhook sender understands; type must stay readable.
var NotificationChannelPolicy = Policy{
	Fields:      append([]string{"webhook_url", "url"}, BaseIntegrationFields...),
	AllValuesIn: []string{"headers"},
	NestedFields: map[string][]string{
		// username rides along here (unlike the base list) because for HTTP
		// basic auth the pair is only ever consumed together by the sender —
		// it is never displayed, listed, or searched.
		"auth": {"token", "username", "password"},
	},
}

// IntegrationAuthConfigPolicy covers public.integrations.auth_config, which is
// written by inventory-service (tenant self-service) and admin-service's MSP
// writer, and must decode identically from either. The blob is entirely
// caller-shaped, so it gets the full floor plus the header bag.
var IntegrationAuthConfigPolicy = Policy{
	Fields:      BaseIntegrationFields,
	AllValuesIn: []string{"headers", "extra_headers"},
}
