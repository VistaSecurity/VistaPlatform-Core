package services

import (
	"context"
	"testing"

	"github.com/lib/pq"
	sensordb "github.com/vistasecurity/vistaplatform/sensor-manager/internal/database"
	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
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
