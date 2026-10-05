package discovery

import (
	"slices"
	"strings"
	"testing"
)

func TestParsePortSpec_Valid(t *testing.T) {
	cases := []struct {
		spec string
		len  int
		str  string
	}{
		{"22", 1, "22"},
		{"22,80,8000-8100", 103, "22,80,8000-8100"},
		{" 443 , 22 ,22, 80-82 ,81", 5, "22,80-82,443"},
		{"1-65535", 65535, "1-65535"},
		{"65535", 1, "65535"},
		{"5-5", 1, "5"},
		{"10-20,15-25", 16, "10-25"},
	}
	for _, c := range cases {
		s, err := ParsePortSpec(c.spec)
		if err != nil {
			t.Errorf("ParsePortSpec(%q): %v", c.spec, err)
			continue
		}
		if s.Len() != c.len || s.String() != c.str {
			t.Errorf("ParsePortSpec(%q) = %q (%d ports), want %q (%d)", c.spec, s.String(), s.Len(), c.str, c.len)
		}
		// String() round-trips.
		back, err := ParsePortSpec(s.String())
		if err != nil || !slices.Equal(back.Ports(), s.Ports()) {
			t.Errorf("round trip of %q failed: %v", s.String(), err)
		}
	}
}

func TestParsePortSpec_ErrorsNameTheBadToken(t *testing.T) {
	cases := []struct {
		spec, mention string
	}{
		{"", "empty"},
		{"   ", "empty"},
		{"22,,80", "entry 2 is empty"},
		{"22,", "entry 2 is empty"},
		{"0", `"0"`},
		{"22,65536", `"65536"`},
		{"999999", `"999999"`},
		{"100-80", `"100-80"`},
		{"http", `"http"`},
		{"+22", `"+22"`},
		{"-5", `"-5"`},
		{"5-", `"5-"`},
		{"1-2-3", `"1-2-3"`},
		{"22;80", `"22;80"`},
		{"0x16", `"0x16"`},
		{"２２", `"２２"`}, // full-width digits are not ASCII digits
	}
	for _, c := range cases {
		_, err := ParsePortSpec(c.spec)
		if err == nil {
			t.Errorf("ParsePortSpec(%q) accepted", c.spec)
			continue
		}
		if !strings.Contains(err.Error(), c.mention) {
			t.Errorf("ParsePortSpec(%q) error %q does not mention %s", c.spec, err, c.mention)
		}
	}
	if _, err := ParsePortSpec(strings.Repeat("1,", 3000) + "1"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("oversize spec: %v, want a size-limit error", err)
	}
	if _, err := ParsePortSpec(strings.Repeat("1,", 1100) + "1"); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Errorf("too many entries: %v, want a limit error", err)
	}
}

func TestNewPortSet(t *testing.T) {
	s, err := NewPortSet(443, 22, 443, 80)
	if err != nil || !slices.Equal(s.Ports(), []int{22, 80, 443}) {
		t.Errorf("NewPortSet = %v, %v", s.Ports(), err)
	}
	for _, bad := range []int{0, -1, 65536} {
		if _, err := NewPortSet(22, bad); err == nil {
			t.Errorf("NewPortSet accepted %d", bad)
		}
	}
	if !s.Contains(80) || s.Contains(81) || s.Contains(0) || s.Contains(70000) {
		t.Error("Contains is wrong")
	}
	if got := s.Union(mustPorts("23")).Without(mustPorts("80")).String(); got != "22-23,443" {
		t.Errorf("union/without = %q", got)
	}
	if (PortSet{}).Len() != 0 || (PortSet{}).String() != "" {
		t.Error("zero PortSet must be empty")
	}
}

func TestQuickPorts_ContainCryptoPortsAndArePinned(t *testing.T) {
	q := QuickPorts()
	for p := range cryptoPortProtocols {
		if !q.Contains(p) {
			t.Errorf("Quick is missing crypto port %d", p)
		}
	}
	const want = "21-23,25,53,80,88,110,135,139,143,389,443,445,465,502,587,636,853,993,995,1433,1521,2222,3306,3389," +
		"4840,5432,5671,5900,5985-5986,6379,6443,8080,8443,8883,9443,10443,44818,47808"
	if q.String() != want {
		t.Errorf("Quick changed:\n got %s\nwant %s\n(a change to a preset is a product change: update the rationale and this pin together)", q.String(), want)
	}
}

func TestStandardPorts_Pinned(t *testing.T) {
	s := StandardPorts()
	for p := 1; p <= 1024; p++ {
		if !s.Contains(p) {
			t.Fatalf("Standard is missing %d (1-1024 is the floor)", p)
		}
	}
	if missing := QuickPorts().Without(s); missing.Len() != 0 {
		t.Errorf("Standard is missing Quick ports %s", missing)
	}
	for _, band := range []string{"8000-8100", "8440-8450", "9000-9100", "9440-9450"} {
		if missing := mustPorts(band).Without(s); missing.Len() != 0 {
			t.Errorf("Standard is missing band %s: %s", band, missing)
		}
	}
	const want = "1-1024,1080,1194,1433-1434,1521,1701,1723,1883,2049,2181,2222,2281,2375-2376,2379-2380,2483-2484," +
		"3000,3128,3260,3268-3269,3306,3389,4222,4369,4443,4646-4648,4840,4848,5000-5001,5060-5061,5222-5223,5269," +
		"5432-5433,5666,5671-5672,5900-5903,5984-5986,5988-5989,6222,6379-6380,6443,6514,6984,7000-7001,7443," +
		"8000-8100,8180-8181,8200-8201,8222,8300-8302,8440-8450,8500-8502,8800,8843,8880,8883,8888,9000-9100," +
		"9142,9200,9300,9345,9389,9440-9450,10000,10050-10051,10250,10255-10257,10259,10443,11211,15671-15672,16443," +
		"16509,16514,17988,17990,18080,18443,26257,27017-27019,33060,44818,47001,47808,50000,61613-61614,61616-61617"
	if s.String() != want {
		t.Errorf("Standard changed:\n got %s\nwant %s\n(a change to a preset is a product change: update standardCuratedPorts' rationale and this pin together)", s.String(), want)
	}
}

func TestThoroughPorts(t *testing.T) {
	if s := ThoroughPorts(); s.Len() != 65535 || s.String() != "1-65535" {
		t.Errorf("Thorough = %d ports %q", s.Len(), s.String())
	}
}

func TestOTPorts_Pinned(t *testing.T) {
	const want = "102,502,789,802,1911,1962,2404,2455,4840,4843,4911,5094,9600,18245-18246,20000,20547,44818,47808"
	if got := OTPorts().String(); got != want {
		t.Errorf("OTPorts changed: got %s want %s", got, want)
	}
	// Every OT protocol the shared prober speaks must be covered by the
	// policy, or a probe could reach it unserialized.
	for p, protos := range cryptoPortProtocols {
		for _, proto := range protos {
			switch proto {
			case "Modbus", "OPC_UA", "EtherNet_IP", "BACnet":
				if !OTPorts().Contains(p) {
					t.Errorf("OT protocol %s port %d is not in OTPorts", proto, p)
				}
			}
		}
	}
}

func TestDefaultLivenessPorts_ExcludeOT(t *testing.T) {
	l := DefaultLivenessPorts()
	if l.Len() < 8 || l.Len() > 12 {
		t.Errorf("liveness probes %d ports; the design is ~10", l.Len())
	}
	if overlap := l.Without(l.Without(OTPorts())); overlap.Len() != 0 {
		t.Errorf("default liveness ports include OT ports %s", overlap)
	}
}
