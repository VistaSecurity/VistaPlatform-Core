package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_IdentityRetainedEvidenceDetailIsBoundedTenantScopedAndSafe(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", strings.Repeat("a", 64))
	db, tenant := getTestDBAndTenant(t)
	testdb.WithSchemaShareLock(t, db.DB.DB, func() {
		service := NewAssetService(db)
		observation := uuid.New()
		seen := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
		if _, err := db.Exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at) VALUES($1,$2,$3,'measured','sensor:test','{}',$4,$4)`, tenant, observation, observation.String(), seen); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 55; i++ {
			receipt := fmt.Sprintf("receipt-%02d", i)
			at := seen.Add(time.Duration(i) * time.Minute)
			if _, err := db.Exec(`INSERT INTO identity_observation_receipts(tenant_id,observation_id,receipt_key,observed_at,evidence) VALUES($1,$2,$3,$4,'{"admission":{"collector_version":"rc14"},"source":{"ref":"sensor:original"}}')`, tenant, observation, receipt, at); err != nil {
				t.Fatal(err)
			}
			payload := fmt.Sprintf(`{"protocol":"TLS","port":443,"raw_data":{"certificates":[{"fingerprint_sha256":"%064x","not_after":"2020-01-01T00:00:00Z"}],"password":"DO_NOT_EXPOSE"}}`, i+1)
			if _, err := db.Exec(`INSERT INTO identity_observation_payloads(tenant_id,observation_id,receipt_key,payload,last_error) VALUES($1,$2,$3,$4,'DO_NOT_EXPOSE')`, tenant, observation, receipt, payload); err != nil {
				t.Fatal(err)
			}
		}
		cloudRaw := `{"Device":{"Password":"DO_NOT_EXPOSE","Metadata":{"crypto_configs":[{"protocol":"TLS","port":443}]}},"Observation":{"source":{"ref":"cloud:aws"}},"Enumeration":{"Facts":{"hw.vendor":"Example"}}}`
		sealed, err := service.integrationCipher.EncryptValue(cloudRaw)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO identity_observation_cloud_contexts(tenant_id,observation_id,receipt_key,context_enc,observed_at,materialized_at) VALUES($1,$2,'cloud',$3,$4,now())`, tenant, observation, sealed, seen.Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO identity_observation_host_inventories(tenant_id,observation_id,receipt_key,job_id,agent_id,observation,payload,observed_at,superseded_at) VALUES($1,$2,'host',$3,$4,'{}','{"facts":[{"key":"os.name","value":"Linux"}],"device_info":{"packages":[{"name":"openssl"}]}}',$5,now())`, tenant, observation, uuid.New(), uuid.New(), seen.Add(3*time.Hour)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO identity_observation_peer_contexts(tenant_id,observation_id,context_id,origin_asset_id,payload,observed_at) VALUES($1,$2,'peer',$3,'{"Observations":{"Facts":[{"key":"hw.model","value":"Example"}],"Relationships":[{}]},"Source":{"ref":"interrogation:original"}}',$4)`, tenant, observation, uuid.New(), seen.Add(4*time.Hour)); err != nil {
			t.Fatal(err)
		}
		detail, err := service.GetIdentityObservation(context.Background(), tenant, observation)
		if err != nil {
			t.Fatal(err)
		}
		page := detail.RetainedEvidence
		if page == nil || page.Total != 58 || len(page.Items) != 50 || !page.HasMore || page.Limit != 50 {
			t.Fatalf("unbounded or missing evidence %+v", page)
		}
		if page.Items[0].Kind != "peer" || page.Items[0].Scope != "source_context" || page.Items[1].Kind != "host_inventory" || page.Items[1].MaterializationState != "superseded" || page.Items[1].SoftwareCount != 1 || page.Items[2].Kind != "cloud" || page.Items[2].MaterializationState != "completed" || page.Items[2].FactsCount != 1 {
			t.Fatalf("typed receipts lost: %+v", page.Items[:3])
		}
		crypto := page.Items[3]
		if crypto.Kind != "crypto" || crypto.SourceRef != "sensor:original" || crypto.CollectorVersion != "rc14" || crypto.ObservedAt == nil || !crypto.ObservedAt.Equal(seen.Add(54*time.Minute)) || crypto.MaterializationState != "retrying" || crypto.CertificatesCount != 1 {
			t.Fatalf("receipt provenance/security evidence lost: %+v", crypto)
		}
		if !detail.LastSeenAt.Equal(seen) {
			t.Fatal("read changed sighting clock")
		}
		output, err := json.Marshal(detail)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(output), "DO_NOT_EXPOSE") || strings.Contains(string(output), "context_enc") {
			t.Fatalf("raw evidence leaked: %s", output)
		}
		if _, err := service.GetIdentityObservation(context.Background(), uuid.New(), observation); !errors.Is(err, ErrObservationNotFound) {
			t.Fatalf("cross-tenant detail: %v", err)
		}
		list, err := service.ListIdentityObservations(context.Background(), tenant, "all", 1, 20, nil)
		if err != nil {
			t.Fatal(err)
		}
		if len(list.Observations) != 1 || list.Observations[0].RetainedEvidence != nil {
			t.Fatal("list unexpectedly loaded restricted payloads")
		}
		// Damaged ciphertext never leaks an encryption error or hides the rest of
		// the observation. It produces an explicit unavailable summary.
		if _, err := db.Exec(`UPDATE identity_observation_cloud_contexts SET context_enc='enc:v1:DO_NOT_EXPOSE' WHERE tenant_id=$1 AND observation_id=$2`, tenant, observation); err != nil {
			t.Fatal(err)
		}
		detail, err = service.GetIdentityObservation(context.Background(), tenant, observation)
		if err != nil {
			t.Fatal(err)
		}
		if detail.RetainedEvidence.Items[2].Reason != "summary_temporarily_unavailable" {
			t.Fatal("damaged cipher summary not explained")
		}
		if _, err := db.Exec(`INSERT INTO identity_observation_receipts(tenant_id,observation_id,receipt_key,observed_at,evidence) VALUES($1,$2,'oversized',$3,'{}')`, tenant, observation, seen.Add(5*time.Hour)); err != nil {
			t.Fatal(err)
		}
		oversized, _ := json.Marshal(map[string]interface{}{"raw_data": map[string]string{"password": strings.Repeat("x", 1048576)}})
		if _, err := db.Exec(`INSERT INTO identity_observation_payloads(tenant_id,observation_id,receipt_key,payload) VALUES($1,$2,'oversized',$3)`, tenant, observation, oversized); err != nil {
			t.Fatal(err)
		}
		detail, err = service.GetIdentityObservation(context.Background(), tenant, observation)
		if err != nil {
			t.Fatal(err)
		}
		if detail.RetainedEvidence.Total != 59 || detail.RetainedEvidence.Items[0].Reason != "summary_payload_too_large" {
			t.Fatal("oversized receipt hidden or not bounded")
		}

	})
}
