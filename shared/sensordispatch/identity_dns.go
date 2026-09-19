package sensordispatch

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/google/uuid"
)

const IdentityDNSCommand = "resolve_identity_dns"
const IdentityDNSCapability = "identity_dns_v1"

// IdentityDNSRequest requests one bounded name lookup from the observing
// sensor. It grants no authority to scan or establish an asset from its answer.
type IdentityDNSRequest struct {
	RequestID     string `json:"request_id"`
	ObservationID string `json:"observation_id"`
	Hostname      string `json:"hostname"`
	NetworkScope  string `json:"network_scope"`
	SegmentCIDR   string `json:"segment_cidr"`
	TimeoutMS     int    `json:"timeout_ms"`
	MaxAddresses  int    `json:"max_addresses"`
}
type IdentityDNSResult struct {
	RequestID        string    `json:"request_id"`
	ObservationID    string    `json:"observation_id"`
	Hostname         string    `json:"hostname"`
	NetworkScope     string    `json:"network_scope"`
	Addresses        []string  `json:"addresses"`
	ObservedAt       time.Time `json:"observed_at"`
	CollectorVersion string    `json:"collector_version"`
	ErrorCode        string    `json:"error_code,omitempty"`
}

func ParseIdentityDNSRequest(raw map[string]interface{}) (IdentityDNSRequest, error) {
	var req IdentityDNSRequest
	data, err := json.Marshal(raw)
	if err != nil {
		return req, err
	}
	if err = json.Unmarshal(data, &req); err != nil {
		return req, err
	}
	if err = req.Validate(); err != nil {
		return req, err
	}
	return req, nil
}
func (r IdentityDNSRequest) Validate() error {
	for _, id := range []string{r.RequestID, r.ObservationID, r.NetworkScope} {
		if u, err := uuid.Parse(id); err != nil || u == uuid.Nil {
			return fmt.Errorf("DNS request requires request, observation and segment identifiers")
		}
	}
	prefix, err := netip.ParsePrefix(r.SegmentCIDR)
	if err != nil || prefix.Bits() == 0 {
		return fmt.Errorf("DNS request requires a bounded network segment")
	}
	if r.TimeoutMS < 1 || r.TimeoutMS > 2000 || r.MaxAddresses < 1 || r.MaxAddresses > 8 {
		return fmt.Errorf("DNS lookup exceeds time or response limits")
	}
	name := strings.TrimSuffix(r.Hostname, ".")
	if len(name) == 0 || len(name) > 253 || name != strings.ToLower(name) {
		return fmt.Errorf("DNS request requires a normalized hostname")
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return fmt.Errorf("DNS request requires a name, not an address")
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid DNS label")
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '-' {
				return fmt.Errorf("invalid DNS label")
			}
		}
	}
	return nil
}
func (r IdentityDNSResult) ToMap() map[string]interface{} {
	data, _ := json.Marshal(r)
	out := map[string]interface{}{}
	_ = json.Unmarshal(data, &out)
	return out
}
