package identity

import "strings"

// CloudResourceIDKeys are the metadata keys, in precedence order, under which a
// cloud collector records the resource's OWN identifier — the value that
// becomes a [KindCloudResourceID] identifier.
//
// It is ONE list, exported, because the two places that read it had silently
// drifted apart. device-interrogation-service read `gcp_resource_id` and
// `azure_resource_id`; inventory-service's ingest path did not, and read
// `resource_uri`, which nothing writes. So an Azure Application Gateway
// resolved by its ARM id when the collector created the asset and by hostname
// alone when the same resource arrived as a finding — two answers to the same
// question, from two hand-maintained lists nothing held together.
//
// **Ordering is load-bearing and additive-only.** Existing entries keep their
// relative order so that any metadata which resolved before resolves to the
// same value now; new keys are appended. Changing the order can silently
// re-identify resources that are already in a customer's inventory.
//
// **Every value here must be the provider's own stable id.** There is no
// hostname, address or name in this list and none may be added: falling back to
// a weak identifier is exactly what the identity work removed, and a
// weak-keyed match is worse than no match because it merges two things that
// are not one.
//
// Uniqueness of each key, checked rather than assumed:
//
//   - arn — an AWS ARN, globally unique. The Azure and GCP storage collectors
//     also write their provider's namespaced id here (an ARM resource path, a
//     `gs://` URI, a `gcp:cloudsql:` URI), all of which are self-namespacing,
//     so no cross-provider collision is possible on this key.
//   - cloud_resource_id — what cloud enumeration and the key-store collectors
//     write: an ARM path, a GCP resource name or an AWS id. Self-namespacing.
//   - resource_id — Azure/GCP-specific identifier (models.CloudResource).
//   - self_link / gcp_resource_id — a GCP selfLink URL, globally unique.
//   - resource_uri — no writer today; retained because the ingest path has read
//     it since the identifier kind was introduced and removing a read is not
//     additive.
//   - azure_resource_id — a full ARM path
//     (/subscriptions/…/resourceGroups/…/providers/…), globally unique.
//   - distribution_id — a CloudFront distribution id. Distribution ids are
//     allocated from one global CloudFront namespace, so the bare value is
//     unique without qualification. No other collector writes this key.
//   - api_id — an API Gateway v2 api id. This one is NOT formally globally
//     unique: it is unique within a region. It is included as the bare value
//     anyway because upsertDeviceAsset already passes exactly this bare value
//     as the resource id when the collector creates the asset, and the two
//     sides MUST agree or they produce the duplicate this list exists to
//     prevent. Identifiers are tenant-scoped and api ids are random
//     ten-character strings, so a collision needs one tenant to hold two AWS
//     accounts whose api ids collide.
//
// Deliberately NOT here: `key_id`. The three key-store collectors write it, but
// it is a generic field name — `shared/redact` lists it among the ordinary
// crypto-posture field names precisely because it turns up all over device
// interrogation output — and this list is consulted for EVERY finding, not just
// cloud ones. For AWS it is also a bare key UUID rather than a namespaced id.
// The key stores state `cloud_resource_id` explicitly instead, which is the
// canonical key and says what it means.
var CloudResourceIDKeys = []string{
	"arn",
	"resource_id",
	"cloud_resource_id",
	"self_link",
	"resource_uri",
	"gcp_resource_id",
	"azure_resource_id",
	"distribution_id",
	"api_id",
}

// CloudResourceIDFromMetadata digs the provider's own resource id out of a
// cloud collector's metadata (or out of a finding's flattened raw data, which
// is the same map one level up).
//
// Empty is a legitimate answer and means "this finding names no cloud
// resource": the caller records no [KindCloudResourceID] identifier rather than
// substituting something weaker.
func CloudResourceIDFromMetadata(meta map[string]interface{}) string {
	if meta == nil {
		return ""
	}
	for _, key := range CloudResourceIDKeys {
		if v, ok := meta[key].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
