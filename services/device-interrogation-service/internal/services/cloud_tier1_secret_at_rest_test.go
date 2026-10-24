package services

import (
	"testing"
	"time"

	"github.com/google/uuid"

	awsclient "github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/cloud/aws"
)

// A Secrets Manager secret states its at-rest encryption, so it is the one
// enumerated kind that also becomes an at-rest discovery row — the path an S3
// bucket takes into crypto_applications. Without it the secret's asset exists
// but nothing ever judges it, and it reads "Not assessed" forever.
func TestAWSSecret_BecomesAnAtRestDiscoveryRow(t *testing.T) {
	if !becomesDiscoveryRow(DeviceTypeAWSSecret) {
		t.Fatal("an AWS secret does not become a discovery row; its at-rest posture never reaches inventory")
	}
	if proto, port, atRest := atRestDiscoveryShape(DeviceTypeAWSSecret); !atRest || proto != "" || port != 0 {
		t.Errorf("shape = (%q, %d, %v), want protocol-less at-rest — anything else fabricates a TLS endpoint", proto, port, atRest)
	}
	// The other providers' secrets state nothing yet and stay inventory-only.
	for _, dt := range []string{DeviceTypeAzureKeyVaultSecret, DeviceTypeGCPSecret} {
		if becomesDiscoveryRow(dt) {
			t.Errorf("%s states no at-rest posture but would become a discovery row (a TLS:443 fabrication)", dt)
		}
	}
}

func TestAWSSecretAtRestMetadata_KeyManager(t *testing.T) {
	cases := map[string]string{
		"":                         "aws-managed-kms",
		"alias/aws/secretsmanager": "aws-managed-kms",
		"arn:aws:kms:us-east-1:111122223333:alias/aws/secretsmanager": "aws-managed-kms",
		"arn:aws:kms:us-east-1:111122223333:key/0b1c2d3e":             "customer-managed-kms",
		"alias/payments": "customer-managed-kms",
	}
	for kms, want := range cases {
		md := awsSecretAtRestMetadata(awsclient.Secret{ARN: "arn:aws:secretsmanager:us-east-1:111122223333:secret:x", KMSKeyID: kms})
		if md["encryption_type"] != want {
			t.Errorf("kms %q: encryption_type = %v, want %s", kms, md["encryption_type"], want)
		}
		if md["encrypted"] != true || md["encryption_determined"] != true || md["resource_type"] != "secretsmanager" {
			t.Errorf("kms %q: metadata = %v", kms, md)
		}
	}
}

// The discovery row must resolve to the secret's existing asset, which was
// recorded under cloud_resource_id = the ARN. The device carries exactly that.
func TestAWSSecret_DeviceCarriesItsCloudResourceID(t *testing.T) {
	arn := "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-AbCdEf"
	res := awsSecretResources([]awsclient.Secret{{ARN: arn, Name: "prod/db", Region: "us-east-1"}})
	if len(res) != 1 {
		t.Fatalf("got %d resources", len(res))
	}
	d := enumeratedDevice(uuid.New(), uuid.New(), "AWS", res[0], time.Now())
	if d.Metadata["cloud_resource_id"] != arn {
		t.Errorf("cloud_resource_id = %v, want the ARN the asset was recorded under", d.Metadata["cloud_resource_id"])
	}
	if d.Metadata["encrypted"] != true || d.Metadata["encryption_type"] != "aws-managed-kms" {
		t.Errorf("metadata lost the at-rest posture: %v", d.Metadata)
	}
}
