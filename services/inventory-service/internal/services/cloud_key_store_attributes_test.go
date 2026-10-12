package services

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestKMSKeyStoreAttributes_ProjectsPostureOnly(t *testing.T) {
	created := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	r := CloudKeyRecord{
		Provider: "AWS", KeyID: "k1", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/k1",
		KeySpec: "RSA_2048", KeyUsage: "SIGN_VERIFY", KeyState: "Enabled", Origin: "AWS_KMS",
		Region: "us-east-1", AccountID: "123456789012", CreationDate: &created,
		Aliases: []string{"alias/app", " "}, RotationEnabled: false,
	}
	got := kmsKeyStoreAttributes(r)
	want := map[string]interface{}{
		"provider": "aws", "account_id": "123456789012", "region": "us-east-1", "key_id": "k1",
		"cloud_resource_id": r.KeyARN, "arn": r.KeyARN, "key_spec": "RSA_2048", "key_usage": "SIGN_VERIFY",
		"key_state": "Enabled", "origin": "AWS_KMS", "rotation_enabled": false,
		"creation_date": "2026-02-03T04:05:06Z",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("attribute %s = %v, want %v", k, got[k], v)
		}
	}
	if al, _ := got["aliases"].([]interface{}); len(al) != 1 || al[0] != "alias/app" {
		t.Errorf("aliases = %v, want [alias/app]", got["aliases"])
	}
	if len(got) != len(want)+1 {
		t.Errorf("attributes %v carry fields beyond the allowlist", got)
	}

	// A non-AWS record carries no arn and drops empty values.
	g := kmsKeyStoreAttributes(CloudKeyRecord{Provider: "gcp", KeyID: "k", KeyARN: "projects/p/k", AccountID: "p"})
	if _, ok := g["arn"]; ok {
		t.Errorf("gcp attributes carry arn: %v", g)
	}
	if _, ok := g["region"]; ok {
		t.Errorf("empty region was stored: %v", g)
	}
}

func TestKMSKeyStoreFinding_CarriesAttributesToIngest(t *testing.T) {
	r := CloudKeyRecord{Provider: "aws", KeyID: "k1", KeyARN: "arn:aws:kms:us-east-1:123456789012:key/k1", Region: "us-east-1", AccountID: "123456789012"}
	f := kmsKeyStoreFinding(r, uuid.New(), time.Now(), "internal", "private")
	attrs := kmsKeyStoreAttributesFromFinding(f)
	if attrs["account_id"] != "123456789012" || attrs["region"] != "us-east-1" {
		t.Fatalf("finding attributes = %v", attrs)
	}
	// Another producer cannot write class attributes through the same key.
	f.RawData["source"] = "sensor"
	if kmsKeyStoreAttributesFromFinding(f) != nil {
		t.Errorf("a non-cloud_discovery finding's attributes were honoured")
	}
}
