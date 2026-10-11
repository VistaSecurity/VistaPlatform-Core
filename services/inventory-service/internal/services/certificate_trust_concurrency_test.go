package services

import (
	"sync"
	"testing"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
)

func TestCertificateTrustEvaluatorConcurrentInitialization(t *testing.T) {
	s := &CertificateService{}
	start := make(chan struct{})
	results := make(chan *certtrust.Evaluator, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Go(func() { <-start; results <- s.trustEvaluator() })
	}
	close(start)
	wg.Wait()
	close(results)
	first := s.trustEvaluator()
	for got := range results {
		if got != first {
			t.Fatal("concurrent ingestion created multiple trust evaluators")
		}
	}
}
