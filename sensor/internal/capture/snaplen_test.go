package capture

import (
	"math"
	"testing"
)

// pcap.OpenLive takes an int32 snaplen while Capture.BufferSize is a plain int
// read from operator config. A bare int32() conversion of a value above
// MaxInt32 wraps to a negative snaplen on 64-bit builds, which libpcap either
// rejects or honours by capturing nothing — either way the sensor goes blind
// with an error that never mentions the configured number.
//
// The wrap cases below are the regression: with `int32(bufferSize)` in place of
// snapLenFromConfig they each produce a negative snaplen.
func TestSnapLenFromConfigNeverWraps(t *testing.T) {
	cases := []struct {
		name       string
		bufferSize int
		want       int32
	}{
		{"config default passes through", 1024 * 1024, 1024 * 1024},
		{"small positive passes through", 65535, 65535},
		{"exactly MaxInt32 passes through", math.MaxInt32, math.MaxInt32},

		// Would wrap to -2147483648 under a bare int32() conversion.
		{"MaxInt32+1 falls back instead of wrapping", math.MaxInt32 + 1, defaultSnapLen},
		// Would wrap to 0 — a snaplen libpcap reads as "no limit" on some
		// versions and as invalid on others.
		{"4 GiB falls back instead of wrapping to zero", 1 << 32, defaultSnapLen},
		// Would wrap to 1, truncating every packet to a single byte.
		{"4 GiB+1 falls back instead of wrapping to one", (1 << 32) + 1, defaultSnapLen},

		{"zero falls back", 0, defaultSnapLen},
		{"negative falls back", -1, defaultSnapLen},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := snapLenFromConfig(tc.bufferSize)
			if got != tc.want {
				t.Fatalf("snapLenFromConfig(%d) = %d, want %d", tc.bufferSize, got, tc.want)
			}
			if got <= 0 {
				t.Fatalf("snapLenFromConfig(%d) returned a non-positive snaplen %d; "+
					"libpcap cannot capture with it", tc.bufferSize, got)
			}
		})
	}
}

// The invariant that actually matters, stated independently of the table: no
// operator-supplied value, however absurd, may produce a snaplen that libpcap
// cannot use.
func TestSnapLenFromConfigAlwaysPositive(t *testing.T) {
	for _, bufferSize := range []int{
		math.MinInt32, -1, 0, 1, 1024, math.MaxInt32,
		math.MaxInt32 + 1, 1 << 32, 1 << 40, math.MaxInt64,
	} {
		if got := snapLenFromConfig(bufferSize); got <= 0 {
			t.Errorf("snapLenFromConfig(%d) = %d, want a positive snaplen", bufferSize, got)
		}
	}
}
