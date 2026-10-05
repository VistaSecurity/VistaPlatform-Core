package sensordispatch

import "testing"

// The platform branches on a sensor's refusal reason to decide whether an
// unattended job may simply be sent again. The literal strings are the ones
// shipped sensors send (4.3.1 sends the first two verbatim), so a reworded
// prefix that stops matching them goes red here rather than turning every
// queue-full refusal back into a tenant-facing failure.
func TestIsSensorBusyRefusal(t *testing.T) {
	for _, busy := range []string{
		"sensor busy: 8 discovery jobs already queued",
		"sensor busy: scoped DNS queue is full",
		"  sensor busy: 8 discovery jobs already queued",
	} {
		if !IsSensorBusyRefusal(busy) {
			t.Errorf("IsSensorBusyRefusal(%q) = false, want true", busy)
		}
	}
	for _, other := range []string{
		"",
		"malformed discovery_job payload: targets is empty",
		"sensor has no discovery job executor",
		"sensor job worker is not running",
		"the sensor is not busy: sensor busy is not a prefix here",
	} {
		if IsSensorBusyRefusal(other) {
			t.Errorf("IsSensorBusyRefusal(%q) = true, want false — that refusal says the job is wrong, not that the sensor is full", other)
		}
	}
}
