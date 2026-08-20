package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ProbeTimeout bounds a single bucket reachability probe. The admin
// "Test connection" button is a synchronous request, so a hung endpoint must
// not hold the handler open indefinitely.
const ProbeTimeout = 10 * time.Second

// ProbeBucket verifies that the supplied credentials can actually reach the
// named S3 bucket, by issuing a HeadBucket. It is the cheapest call that
// exercises the full path the upload path uses: credential decryption,
// signing, region resolution, network reachability, and bucket authorization.
//
// It exists because the admin Test-connection endpoint used to answer
// "Storage configuration appears valid" after reading nothing but a `status`
// column — a check that could not fail for any credential or bucket problem,
// which is the only kind of problem the button is for.
//
// A nil error means the bucket was reached and the credentials were accepted.
func ProbeBucket(ctx context.Context, creds *AWSCredentials, bucket string) error {
	if creds == nil {
		return fmt.Errorf("no AWS credentials resolved")
	}
	if bucket == "" {
		return fmt.Errorf("no S3 bucket configured")
	}

	ctx, cancel := context.WithTimeout(ctx, ProbeTimeout)
	defer cancel()

	client := s3.NewFromConfig(aws.Config{
		Region: creds.Region,
		Credentials: credentials.NewStaticCredentialsProvider(
			creds.AccessKeyID,
			creds.SecretAccessKey,
			creds.SessionToken,
		),
	})

	if _, err := client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(bucket)}); err != nil {
		return fmt.Errorf("s3 HeadBucket %q failed: %w", bucket, err)
	}
	return nil
}
