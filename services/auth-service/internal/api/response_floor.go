package api

import "time"

// resendVerificationMinDuration is the floor on how long POST
// /auth/resend-verification takes. An unknown or already-verified address
// returns without touching the mailer while a pending one does more work, so
// without a floor the response time alone shows which addresses have accounts.
// It mirrors the forgot-password floor in internal/auth. Tests lower it.
var resendVerificationMinDuration = 250 * time.Millisecond

// holdResponseFloor sleeps until floor has elapsed since started. Call it as
// `defer holdResponseFloor(time.Now(), floor)` so every return path is covered.
func holdResponseFloor(started time.Time, floor time.Duration) {
	if remaining := floor - time.Since(started); remaining > 0 {
		time.Sleep(remaining)
	}
}
