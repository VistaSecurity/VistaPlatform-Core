package discovery

import (
	"reflect"
	"testing"
)

const translateSensor = "5f0c2b9e-3d1a-4c8e-9b7f-2a6d4e8c1b30"

func TestTranslateLegacyJobRequest_PortsBecomeACustomPlan(t *testing.T) {
	for name, tc := range map[string]struct {
		in   JobRequestFields
		ot   []OTProbePort
		want JobRequestFields
	}{
		"protocols and ports, platform": {
			in:   JobRequestFields{Protocols: []string{"TLS", "SSH"}, Ports: []int{443, 22}, ExecutionMode: "async"},
			want: JobRequestFields{ScanDepth: "custom", TCPPorts: "443,22", RunFrom: RunFromPlatform},
		},
		"ports only, no mode": {
			in:   JobRequestFields{Ports: []int{8443}},
			want: JobRequestFields{ScanDepth: "custom", TCPPorts: "8443", RunFrom: RunFromPlatform},
		},
		"cloud runs on the platform": {
			in:   JobRequestFields{Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "cloud"},
			want: JobRequestFields{ScanDepth: "custom", TCPPorts: "443", RunFrom: RunFromPlatform},
		},
		"one tenant sensor": {
			in:   JobRequestFields{Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "sensors", PreferredSensorIDs: []string{translateSensor}},
			want: JobRequestFields{ScanDepth: "custom", TCPPorts: "443", RunFrom: RunFromSensor, SensorID: translateSensor},
		},
		"dry run kept": {
			in:   JobRequestFields{Ports: []int{443}, DryRun: true},
			want: JobRequestFields{ScanDepth: "custom", TCPPorts: "443", RunFrom: RunFromPlatform, DryRun: true},
		},
		// WP5: the OT opt-in's standard ports join the plan, each on the
		// transport its prober speaks.
		"OT only, TCP protocols": {
			in:   JobRequestFields{OTProbeProtocols: []string{"Modbus", "OPC_UA"}},
			ot:   []OTProbePort{{"Modbus", 502}, {"OPC_UA", 4840}},
			want: JobRequestFields{ScanDepth: "custom", TCPPorts: "502,4840", RunFrom: RunFromPlatform},
		},
		"OT only, UDP protocols": {
			in:   JobRequestFields{OTProbeProtocols: []string{"BACnet", "EtherNet_IP"}},
			ot:   []OTProbePort{{"BACnet", 47808}, {"EtherNet_IP", 44818}},
			want: JobRequestFields{ScanDepth: "custom", UDPPorts: "47808,44818", RunFrom: RunFromPlatform},
		},
		"OT beside ports, on a sensor": {
			in: JobRequestFields{Protocols: []string{"TLS"}, Ports: []int{443, 502}, OTProbeProtocols: []string{"Modbus", "BACnet"},
				ExecutionMode: "sensors", PreferredSensorIDs: []string{translateSensor}},
			ot:   []OTProbePort{{"Modbus", 502}, {"BACnet", 47808}},
			want: JobRequestFields{ScanDepth: "custom", TCPPorts: "443,502", UDPPorts: "47808", RunFrom: RunFromSensor, SensorID: translateSensor},
		},
		"OT switched off beside ports: the ports alone": {
			in:   JobRequestFields{Ports: []int{443}, OTProbeProtocols: []string{"Modbus"}},
			want: JobRequestFields{ScanDepth: "custom", TCPPorts: "443", RunFrom: RunFromPlatform},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := TranslateLegacyJobRequest(tc.in, tc.ot)
			if !ok || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v ok=%v, want %+v", got, ok, tc.want)
			}
			shape, err := ResolveJobRequest(got)
			if err != nil || !shape.Plan || shape.Spec.Depth != DepthCustom {
				t.Fatalf("the translation does not resolve to a custom plan: %+v %v", shape, err)
			}
		})
	}
}

func TestTranslateLegacyJobRequest_DeclinesWhatItCannotTranslate(t *testing.T) {
	modbus := []OTProbePort{{"Modbus", 502}}
	for name, tc := range map[string]struct {
		in JobRequestFields
		ot []OTProbePort
	}{
		"no ports (protocols only)": {in: JobRequestFields{Protocols: []string{"TLS"}}},
		"scan depth request":        {in: JobRequestFields{ScanDepth: "quick"}},
		// The operator switch dropped every OT probe: nothing to scan, and
		// the caller refuses it rather than scan nothing.
		"OT only, switched off":       {in: JobRequestFields{OTProbeProtocols: []string{"Modbus"}}},
		"OT probe nobody opted in to": {in: JobRequestFields{Ports: []int{443}}, ot: modbus},
		"OT protocol with no prober":  {in: JobRequestFields{OTProbeProtocols: []string{"DNP3"}}, ot: []OTProbePort{{"DNP3", 20000}}},
		"OT port out of range":        {in: JobRequestFields{OTProbeProtocols: []string{"Modbus"}}, ot: []OTProbePort{{"Modbus", 0}}},
		"mixed with plan fields":      {in: JobRequestFields{Ports: []int{443}, ScanDepth: "custom"}},
		"OT mixed with plan fields":   {in: JobRequestFields{OTProbeProtocols: []string{"Modbus"}, ScanDepth: "quick"}, ot: modbus},
		"sensors with no sensor":      {in: JobRequestFields{Ports: []int{443}, ExecutionMode: "sensors"}},
		"sensors with two sensors":    {in: JobRequestFields{Ports: []int{443}, ExecutionMode: "sensors", PreferredSensorIDs: []string{translateSensor, translateSensor}}},
		"sensor id not a UUID":        {in: JobRequestFields{Ports: []int{443}, ExecutionMode: "sensors", PreferredSensorIDs: []string{"not-a-uuid"}}},
		"sensor named on a platform":  {in: JobRequestFields{Ports: []int{443}, ExecutionMode: "async", PreferredSensorIDs: []string{translateSensor}}},
		"empty request is not legacy": {},
	} {
		t.Run(name, func(t *testing.T) {
			got, ok := TranslateLegacyJobRequest(tc.in, tc.ot)
			if ok || !reflect.DeepEqual(got, tc.in) {
				t.Fatalf("got %+v ok=%v, want the request untouched", got, ok)
			}
		})
	}
}
