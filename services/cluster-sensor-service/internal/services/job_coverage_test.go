package services

import (
	"database/sql"
	"strings"
	"testing"
)

// The warnings a person must read beside the numbers (spec §1, H11/H21).
func TestCoverageFrom_Warnings(t *testing.T) {
	cases := []struct {
		name    string
		tally   unitTally
		status  string
		exec    string
		want    []string
		notWant []string
	}{
		{
			name:  "nothing answered from the platform: a reachability hint, not 'empty network'",
			tally: unitTally{Total: 254, NoAnswer: 254, Requested: 254 * 1364, NotProbed: 254 * 1364},
			exec:  "platform", status: "completed",
			want: []string{"0 of 254 scanned addresses responded", "platform sensor may not be able to reach this network"},
		},
		{
			name:  "still running: no verdict on reachability yet",
			tally: unitTally{Total: 254, Pending: 200, NoAnswer: 54},
			exec:  "platform", status: "running",
			notWant: []string{"responded"},
		},
		{
			name:  "something answered: no reachability warning",
			tally: unitTally{Total: 3, Responded: 1, NoAnswer: 2},
			exec:  "platform", status: "completed",
			notWant: []string{"responded"},
		},
		{
			name:  "local resource limits",
			tally: unitTally{Total: 2, Responded: 2, LocalErrors: 40},
			want:  []string{"scanner resource limits were hit: 40 port probe(s)"},
		},
		{
			name:   "tarpit, time limit, refusals, cancel",
			tally:  unitTally{Total: 10, Responded: 3, Tarpits: 1, Incomplete: 1, Failed: 1, FirstFailure: nullString("not scanned: excluded"), Cancelled: 6},
			status: "cancelled",
			want: []string{"1 host(s) accepted connections on almost every port", "1 host(s) stopped at their time limit",
				"1 address(es) could not be scanned (e.g. not scanned: excluded)", "stopped at 4 of 10 hosts"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := coverageFrom(tc.tally, tc.status, tc.exec)
			all := strings.Join(c.Warnings, " | ")
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Errorf("warnings %q lack %q", all, w)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(all, w) {
					t.Errorf("warnings %q should not mention %q", all, w)
				}
			}
			if c.Warnings == nil {
				t.Error("warnings must be an empty list, never null")
			}
		})
	}
}

// Progress counts finished hosts; a cancelled host was never reached.
func TestUnitProgress(t *testing.T) {
	for _, tc := range []struct {
		t    unitTally
		want int
	}{
		{unitTally{Total: 0}, 0},
		{unitTally{Total: 4, Pending: 4}, 0},
		{unitTally{Total: 4, Pending: 1}, 75},
		{unitTally{Total: 6, Cancelled: 5}, 16},
		{unitTally{Total: 3}, 100},
	} {
		if got := unitProgress(tc.t); got != tc.want {
			t.Errorf("unitProgress(%+v) = %d, want %d", tc.t, got, tc.want)
		}
	}
}

func nullString(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
