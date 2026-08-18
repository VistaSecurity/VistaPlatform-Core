package services

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	cloudfronttypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
)

// TestCloudFrontCertificateSource pins the mapping that replaced CloudFront's
// deprecated ViewerCertificate.CertificateSource field. The three replacement
// fields are mutually exclusive in practice, but the precedence still has to be
// deliberate: a distribution on the default certificate reports "cloudfront"
// even though AWS may echo an ARN alongside it.
func TestCloudFrontCertificateSource(t *testing.T) {
	tests := []struct {
		name string
		vc   *cloudfronttypes.ViewerCertificate
		want string
	}{
		{"nil certificate", nil, ""},
		{"empty certificate", &cloudfronttypes.ViewerCertificate{}, ""},
		{
			"cloudfront default",
			&cloudfronttypes.ViewerCertificate{CloudFrontDefaultCertificate: aws.Bool(true)},
			"cloudfront",
		},
		{
			"acm",
			&cloudfronttypes.ViewerCertificate{ACMCertificateArn: aws.String("arn:aws:acm:us-east-1:1234:certificate/abc")},
			"acm",
		},
		{
			"iam legacy upload",
			&cloudfronttypes.ViewerCertificate{IAMCertificateId: aws.String("ASCAEXAMPLE")},
			"iam",
		},
		{
			"default flag wins over an echoed ARN",
			&cloudfronttypes.ViewerCertificate{
				CloudFrontDefaultCertificate: aws.Bool(true),
				ACMCertificateArn:            aws.String("arn:aws:acm:us-east-1:1234:certificate/abc"),
			},
			"cloudfront",
		},
		{
			"explicit false default flag is not a source",
			&cloudfronttypes.ViewerCertificate{CloudFrontDefaultCertificate: aws.Bool(false)},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cloudFrontCertificateSource(tt.vc); got != tt.want {
				t.Errorf("cloudFrontCertificateSource() = %q, want %q", got, tt.want)
			}
		})
	}
}
