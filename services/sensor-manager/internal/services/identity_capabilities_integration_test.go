package services

import (
	"context"
	"testing"

	"github.com/lib/pq"
	sensordb "github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_HeartbeatCapabilitiesTrackCurrentBinary(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	sensor := insertAddrTestSensor(t, db, tenant, "DNS-capabilities")
	svc := &SensorService{db: db, bypassDB: db}
	for _, step := range []struct {
		values []string
		dns    []string
		count  int
	}{{[]string{"identity_dns_v1", "identity_dns_v1", "invalid value"}, []string{"Ethernet", "Ethernet", "bad\nname"}, 1}, {nil, nil, 0}} {
		if err := svc.UpdateSensorHealthWithIP(sensor.String(), &models.SensorHealth{SensorID: sensor, Status: "active", Version: "test", Capabilities: step.values, DNSInterfaces: step.dns}, nil); err != nil {
			t.Fatal(err)
		}
		var values, dns pq.StringArray
		if err := db.QueryRow(`SELECT reported_capabilities,reported_dns_interfaces FROM sensors WHERE id=$1`, sensor).Scan(&values, &dns); err != nil {
			t.Fatal(err)
		}
		if len(values) != step.count || len(dns) != step.count {
			t.Fatalf("capabilities=%v", values)
		}
		repo := sensordb.NewSensorRepository(db, db)
		got, err := repo.GetSensorByIDForTenant(context.Background(), sensor, tenant)
		if err != nil {
			t.Fatal(err)
		}
		if len(got.ReportedCapabilities) != step.count || len(got.ReportedDNSInterfaces) != step.count {
			t.Fatalf("detail capabilities=%v", got.ReportedCapabilities)
		}
		list, err := repo.ListSensorsByTenant(context.Background(), tenant)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, listed := range list {
			if listed.ID == sensor {
				found = true
				if len(listed.ReportedCapabilities) != step.count || len(listed.ReportedDNSInterfaces) != step.count {
					t.Fatalf("list capabilities=%v", listed.ReportedCapabilities)
				}
			}
		}
		if !found {
			t.Fatal("sensor omitted from list")
		}
	}
}

// WP2b: a sensor build that runs planned scans reports scan_plan_v1 and
// is recorded as such — which is what makes the platform hand it a scan-plan
// job (cluster-sensor-service reads reported_capabilities). The same sensor
// replaced by a build that does not report it loses the capability on its
// next heartbeat, so it stops being eligible at once.
func TestIntegration_HeartbeatScanPlanCapabilityFlipsWithTheReport(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	sensor := insertAddrTestSensor(t, db, tenant, "scan-plan-capability")
	svc := &SensorService{db: db, bypassDB: db}
	has := func() bool {
		t.Helper()
		var capable bool
		if err := db.QueryRow(`SELECT $2 = ANY(reported_capabilities) FROM sensors WHERE id = $1`, sensor, sensordispatch.ScanPlanCapability).Scan(&capable); err != nil {
			t.Fatal(err)
		}
		return capable
	}
	beat := func(caps ...string) {
		t.Helper()
		if err := svc.UpdateSensorHealthWithIP(sensor.String(), &models.SensorHealth{SensorID: sensor, Status: "active", Version: "test", Capabilities: caps}, nil); err != nil {
			t.Fatal(err)
		}
	}
	beat(sensordispatch.IdentityDNSCapability, sensordispatch.ScanPlanCapability)
	if !has() {
		t.Fatal("a heartbeat reporting scan_plan_v1 was not recorded — the sensor would never be handed a planned scan")
	}
	beat(sensordispatch.IdentityDNSCapability)
	if has() {
		t.Fatal("an older build kept scan_plan_v1 after a heartbeat without it — it would be handed scans it cannot run")
	}
}
