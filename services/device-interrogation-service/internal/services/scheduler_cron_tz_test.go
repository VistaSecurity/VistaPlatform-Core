package services

import (
	"testing"
	"time"
)

// The web UI's schedule picker (frontend-v2 schedule-cadence.ts) writes
// cron_expression as "CRON_TZ=<IANA zone> <5 fields>" so "2:00 AM" means 2:00
// AM where the person picking it is. That only works because robfig/cron
// honours the prefix — pin it, so swapping the parser cannot silently move
// every tenant's schedules to UTC (or start rejecting them).
func TestSchedulerCronParser_HonoursTimeZonePrefix(t *testing.T) {
	chicago, err := time.LoadLocation("America/Chicago")
	if err != nil {
		t.Fatalf("tzdata unavailable: %v", err)
	}
	p := NewSchedulerService(nil, nil, nil).cronParser

	// Weekdays at 23:30 Chicago time. From Friday 23:31 CDT the
	// next run is Monday 23:30 CDT = 04:30 UTC.
	sched, err := p.Parse("CRON_TZ=America/Chicago 30 23 * * 1-5")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	from := time.Date(2026, 10, 9, 23, 31, 0, 0, chicago)
	want := time.Date(2026, 10, 13, 4, 30, 0, 0, time.UTC)
	if got := sched.Next(from); !got.Equal(want) {
		t.Fatalf("next = %s, want %s", got.UTC(), want)
	}

	// Every other shape the picker emits must parse too.
	for _, expr := range []string{
		"CRON_TZ=Asia/Kolkata 15 * * * *",
		"CRON_TZ=Europe/London 0 */6 * * *",
		"CRON_TZ=UTC 0 2 * * 0,3,6",
		"CRON_TZ=Australia/Sydney 0 3 28 * *",
		"0 2 * * *", // legacy, unprefixed
	} {
		if _, err := p.Parse(expr); err != nil {
			t.Errorf("parse %q: %v", expr, err)
		}
	}
}
