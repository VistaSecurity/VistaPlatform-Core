package discovery

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/discovery/tlskextest"
)

// For every key-exchange fixture: the struct read back from a real probe's
// metadata is exactly what MeasureTLSKeyExchange measured — the probe's own
// ApplyTo wrote that metadata, so writing the read-back struct again must
// reproduce the same keys and values.
func TestTLSKeyExchangeFromMetadata_RoundTrips(t *testing.T) {
	for _, c := range tlskextest.Cases {
		t.Run(c.Name, func(t *testing.T) {
			srv := tlskextest.Start(t, c.Groups, c.MaxVersion)
			res, err := NewProber(3*time.Second).ProbeTLSEndpoint(context.Background(), srv.Host, srv.Port, TLSEndpointOptions{Hostname: "example.com"})
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			k := TLSKeyExchangeFromMetadata(res.Metadata)
			if k.Group != c.WantGroup || uint16(k.GroupID) != c.WantGroupRaw || k.PQCHybridGroup != c.WantPQCHybridGroup {
				t.Errorf("read back %+v, want group %q (%d), hybrid group %q", k, c.WantGroup, c.WantGroupRaw, c.WantPQCHybridGroup)
			}
			if k.SupportsClassical == nil || *k.SupportsClassical != c.WantSupportsClassical ||
				k.SupportsPQCHybrid == nil || *k.SupportsPQCHybrid != c.WantSupportsPQCHybrid {
				t.Errorf("read back support flags %v/%v, want %v/%v", k.SupportsClassical, k.SupportsPQCHybrid, c.WantSupportsClassical, c.WantSupportsPQCHybrid)
			}
			written := map[string]interface{}{}
			k.ApplyTo(written)
			want := map[string]interface{}{}
			for _, key := range []string{MetaKeyExchangeGroupRaw, MetaKeyExchangeAlgorithm, MetaKeyExchangeKeySize, MetaTLSSupportsClassicalKex, MetaTLSSupportsPQCHybridKex, MetaTLSPQCHybridKexGroup} {
				if v, ok := res.Metadata[key]; ok {
					want[key] = v
				}
			}
			if !reflect.DeepEqual(written, want) {
				t.Errorf("ApplyTo(FromMetadata(m)) = %v, want %v", written, want)
			}
		})
	}
}

// A custom finite-field exchange has no group id; its measured size is the
// only thing ApplyTo can write, and it must come back.
func TestTLSKeyExchangeFromMetadata_CustomPrimeSize(t *testing.T) {
	in := TLSKeyExchange{KeyBits: 1024}
	meta := map[string]interface{}{}
	in.ApplyTo(meta)
	if got := TLSKeyExchangeFromMetadata(meta); !reflect.DeepEqual(got, in) {
		t.Errorf("read back %+v, want %+v (metadata %v)", got, in, meta)
	}
}

// Absent keys stay absent: no group, no flags, nothing invented.
func TestTLSKeyExchangeFromMetadata_Empty(t *testing.T) {
	k := TLSKeyExchangeFromMetadata(map[string]interface{}{})
	if !reflect.DeepEqual(k, TLSKeyExchange{}) {
		t.Errorf("empty metadata read back as %+v", k)
	}
}
