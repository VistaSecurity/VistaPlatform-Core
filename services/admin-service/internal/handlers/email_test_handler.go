package handlers

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	sharedemail "github.com/vistasecurity/vistaplatform/shared/email"
)

// TestEmailRequest is the body for POST /admin/settings/test-email.
type TestEmailRequest struct {
	To string `json:"to" binding:"required"`
}

// SendTestEmail sends a single test message using the currently-configured SMTP
// settings. Returns 200 on success, 400 when no recipient is given, 503 when
// SMTP is not configured or the send fails.
func SendTestEmail(db *sql.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req TestEmailRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "to is required"})
			return
		}

		svc, err := getEmailService(db)
		if err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
			return
		}

		brand := getPlatformBrandConfig(db)
		subject := fmt.Sprintf("[%s] SMTP test", brand.PlatformName)
		body := fmt.Sprintf(
			"This is a test email from %s.\n\nIf you received this, your SMTP configuration is working correctly.",
			brand.PlatformName,
		)

		if err := svc.SendEmail(sharedemail.Email{
			To:      []string{req.To},
			Subject: subject,
			Body:    body,
		}); err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("send failed: %s", err)})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Test email sent to %s", req.To)})
	}
}
