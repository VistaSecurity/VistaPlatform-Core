package services

// A queued job must not count as its own concurrent job.
//
// CheckRateLimit counts queued + running jobs, which is right when a job is
// being CREATED (it is not in the queue yet). At processing time the job IS
// in the queue, so with concurrent_jobs = 5 and exactly five jobs queued, the
// oldest was refused with "too many concurrent jobs (5/5)" and FAILED while
// nothing at all was running. Skips without TEST_DATABASE_URL.

import (
	"errors"
	"strings"
	"testing"
)

func TestIntegration_RateLimit_AQueuedJobDoesNotCountAgainstItself(t *testing.T) {
	f, fake := newUnitFixture(t)
	fake.Host("10.184.0.20", nil, nil)
	limit, err := f.jp.rateLimiter.GetRateLimit(f.tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	var jobs []string
	for i := 0; i < limit.ConcurrentJobs; i++ {
		jobs = append(jobs, f.insertLegacyPlatformJob(t, "10.184.0.20"))
	}

	// Creation-time view: the pool is full, a sixth would be refused.
	var refused *RateLimitExceededError
	if err := f.jp.rateLimiter.CheckRateLimit(f.tenant.String()); !errors.As(err, &refused) || refused.Count != limit.ConcurrentJobs {
		t.Fatalf("creating another job with the pool full should be refused with a RateLimitExceededError, got %v", err)
	}
	// Processing-time view: the oldest queued job sees only the others.
	if err := f.jp.rateLimiter.CheckRateLimitForJob(f.tenant.String(), jobs[0]); err != nil {
		t.Fatalf("a queued job counted itself: %v", err)
	}

	// Through the real entry point: the job must not FAIL on the rate limit.
	// (A legacy job fails later, for its own reason — the point is which.)
	if err := f.jp.handleDiscoveryJob(jobMessage(t, jobs[0]), &countingLease{}); err != nil {
		t.Fatalf("handleDiscoveryJob: %v", err)
	}
	status, msg := f.jobStatusAndError(t, jobs[0])
	if strings.Contains(msg, "rate limit") {
		t.Fatalf("the job was failed on the rate limit as its own fifth job: status=%s error=%q", status, msg)
	}
	if status == "queued" {
		t.Fatalf("the job was never picked up: status=%s error=%q", status, msg)
	}
}
