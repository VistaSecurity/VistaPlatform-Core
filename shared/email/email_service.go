package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"sort"
	"strings"
	"time"
)

// EmailService handles email sending functionality
type EmailService struct {
	smtpHost     string
	smtpPort     string
	smtpUsername string
	smtpPassword string
	fromEmail    string
	fromName     string
	brandName    string
}

// EmailConfig holds email service configuration
type EmailConfig struct {
	SMTPHost     string
	SMTPPort     string
	SMTPUsername string
	SMTPPassword string
	FromEmail    string
	FromName     string
	// BrandName is the platform display name used inside email bodies
	// ("The <brand> Team", "Welcome to <brand>", …). Resolved from the
	// white-label platform branding setting; empty falls back to "Vista".
	BrandName string
}

// NewEmailService creates a new email service instance
func NewEmailService(config EmailConfig) *EmailService {
	return &EmailService{
		smtpHost:     config.SMTPHost,
		smtpPort:     config.SMTPPort,
		smtpUsername: config.SMTPUsername,
		smtpPassword: config.SMTPPassword,
		fromEmail:    config.FromEmail,
		fromName:     config.FromName,
		brandName:    config.BrandName,
	}
}

// brand returns the platform display name for email bodies, defaulting to the
// product name when no white-label branding is configured.
func (es *EmailService) brand() string {
	if es.brandName != "" {
		return es.brandName
	}
	return "Vista"
}

// Email represents an email message
type Email struct {
	To      []string
	Subject string
	Body    string
	HTML    string
}

// SendEmail sends an email message.
//
// This deliberately drives the SMTP conversation manually instead of using
// smtp.SendMail. smtp.SendMail hardcodes "localhost" as the EHLO/HELO name
// (net/smtp's Client.localName), and strict relays — notably
// smtp-relay.gmail.com — refuse to advertise STARTTLS to a client that
// introduces itself as "localhost". The TLS upgrade then never happens, AUTH is
// skipped, and the server drops the connection with an opaque EOF. We send a
// real EHLO name (derived from the From-address domain) so STARTTLS is offered,
// then upgrade, authenticate (only when credentials are configured, so IP-based
// relays also work), and send — surfacing a precise error at each stage.
func (es *EmailService) SendEmail(email Email) error {
	// Refuse a recipient or sender that could break out of the SMTP envelope
	// before opening the connection — c.Mail/c.Rcpt below write these straight
	// into SMTP commands. See header_safety.go.
	if err := validateAddresses(es.fromEmail, email.To); err != nil {
		return err
	}

	msg, err := es.buildMessage(email)
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("%s:%s", es.smtpHost, es.smtpPort)

	c, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("failed to connect to smtp server %s: %w", addr, err)
	}
	defer func() { _ = c.Close() }()

	if err := c.Hello(es.heloName()); err != nil {
		return fmt.Errorf("smtp EHLO failed: %w", err)
	}

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: es.smtpHost}); err != nil {
			return fmt.Errorf("smtp STARTTLS failed: %w", err)
		}
	}

	if es.smtpUsername != "" {
		if ok, _ := c.Extension("AUTH"); ok {
			auth := smtp.PlainAuth("", es.smtpUsername, es.smtpPassword, es.smtpHost)
			if err := c.Auth(auth); err != nil {
				return fmt.Errorf("smtp auth failed: %w", err)
			}
		}
	}

	if err := c.Mail(es.fromEmail); err != nil {
		return fmt.Errorf("smtp MAIL FROM <%s> failed: %w", es.fromEmail, err)
	}
	for _, rcpt := range email.To {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("smtp RCPT TO <%s> failed: %w", rcpt, err)
		}
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA failed: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("failed to write message body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("failed to finalize message: %w", err)
	}

	return c.Quit()
}

// heloName returns the name to use in the SMTP EHLO/HELO greeting. A bare
// "localhost" trips strict relays (see SendEmail), so prefer the From-address
// domain, then the SMTP host, and only fall back to localhost as a last resort.
func (es *EmailService) heloName() string {
	if at := strings.LastIndex(es.fromEmail, "@"); at >= 0 && at+1 < len(es.fromEmail) {
		return es.fromEmail[at+1:]
	}
	if es.smtpHost != "" {
		return es.smtpHost
	}
	return "localhost"
}

// buildMessage builds the email message in RFC 2822 format.
//
// Returns an error only when the CSPRNG cannot supply a MIME boundary. That
// path deliberately has no fallback — see randomBoundary in header_safety.go.
func (es *EmailService) buildMessage(email Email) ([]byte, error) {
	var msg bytes.Buffer

	// Headers. Every interpolated value is sanitized: Subject and the From
	// display name carry attacker-influenced text (tenant org name, white-label
	// platform name, user-authored alert threshold name), and a bare CR/LF in
	// any of them would start a header of the attacker's choosing — classically
	// "Bcc:" on an invitation. See header_safety.go.
	//
	// Recipients are validated (not sanitized) in SendEmail before we get here,
	// because they also reach the SMTP envelope; the sanitize call below is the
	// belt to that braces, so buildMessage is safe when called directly in tests.
	sanitizedTo := make([]string, 0, len(email.To))
	for _, rcpt := range email.To {
		sanitizedTo = append(sanitizedTo, sanitizeHeaderValue(rcpt))
	}

	fmt.Fprintf(&msg, "From: %s <%s>\r\n", sanitizeHeaderValue(es.fromName), sanitizeHeaderValue(es.fromEmail))
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(sanitizedTo, ", "))
	fmt.Fprintf(&msg, "Subject: %s\r\n", sanitizeHeaderValue(email.Subject))
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	msg.WriteString("MIME-Version: 1.0\r\n")

	if email.HTML != "" {
		// Multipart message with HTML and text. The boundary is random per
		// message: Body and HTML carry unescaped attacker-influenced names, so a
		// guessable delimiter lets them forge a MIME part. See randomBoundary.
		boundary, err := randomBoundary()
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&msg, "Content-Type: multipart/alternative; boundary=%s\r\n\r\n", boundary)

		// Text part
		fmt.Fprintf(&msg, "--%s\r\n", boundary)
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		msg.WriteString(email.Body)
		msg.WriteString("\r\n\r\n")

		// HTML part
		fmt.Fprintf(&msg, "--%s\r\n", boundary)
		msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n\r\n")
		msg.WriteString(email.HTML)
		fmt.Fprintf(&msg, "\r\n--%s--\r\n", boundary)
	} else {
		// Plain text message
		msg.WriteString("Content-Type: text/plain; charset=UTF-8\r\n\r\n")
		msg.WriteString(email.Body)
	}

	return msg.Bytes(), nil
}

// SendPasswordResetEmail sends a password reset email
func (es *EmailService) SendPasswordResetEmail(to, resetLink string) error {
	subject := "Password Reset Request"

	// Text version
	textBody := fmt.Sprintf(`
Hello,

You have requested to reset your password for your %s account.

To reset your password, please click the following link:
%s

This link will expire in 1 hour for security reasons.

If you did not request this password reset, please ignore this email.

Best regards,
The %s Team
`, es.brand(), resetLink, es.brand())

	// HTML version
	htmlBody, err := renderHTML(passwordResetHTML, struct{ Brand, Link string }{es.brand(), resetLink})
	if err != nil {
		return err
	}

	email := Email{
		To:      []string{to},
		Subject: subject,
		Body:    textBody,
		HTML:    htmlBody,
	}

	return es.SendEmail(email)
}

// SendEmailVerificationEmail sends an email verification email
func (es *EmailService) SendEmailVerificationEmail(to, verificationLink string) error {
	subject := "Verify Your Email Address"

	// Text version
	textBody := fmt.Sprintf(`
Hello,

Thank you for signing up for %s!

To complete your registration, please verify your email address by clicking the following link:
%s

This link will expire in 24 hours.

If you did not create an account, please ignore this email.

Best regards,
The %s Team
`, es.brand(), verificationLink, es.brand())

	// HTML version
	htmlBody, err := renderHTML(emailVerificationHTML, struct{ Brand, Link string }{es.brand(), verificationLink})
	if err != nil {
		return err
	}

	email := Email{
		To:      []string{to},
		Subject: subject,
		Body:    textBody,
		HTML:    htmlBody,
	}

	return es.SendEmail(email)
}

// SendAlertEmail sends an alert notification email
func (es *EmailService) SendAlertEmail(to, alertType, message string, details map[string]interface{}) error {
	subject := fmt.Sprintf("%s Alert: %s", es.brand(), alertType)

	// Build details once, in a stable order. Map iteration order is random in
	// Go, so without the sort the same alert renders its details differently
	// each send -- which also made the text and HTML parts of one message
	// disagree.
	keys := make([]string, 0, len(details))
	for key := range details {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var detailsText strings.Builder
	detailRows := make([]detailRow, 0, len(keys))
	for _, key := range keys {
		fmt.Fprintf(&detailsText, "%s: %v\n", key, details[key])
		detailRows = append(detailRows, detailRow{Key: key, Value: fmt.Sprint(details[key])})
	}

	// Text version
	textBody := fmt.Sprintf(`
%s Alert

Alert Type: %s

Message: %s

Details:
%s

Please review this alert in your dashboard for more information.

Best regards,
The %s Team
`, es.brand(), alertType, message, detailsText.String(), es.brand())

	// HTML version
	htmlBody, err := renderHTML(alertHTML, struct {
		Brand, AlertType, Message string
		Details                   []detailRow
	}{es.brand(), alertType, message, detailRows})
	if err != nil {
		return err
	}

	email := Email{
		To:      []string{to},
		Subject: subject,
		Body:    textBody,
		HTML:    htmlBody,
	}

	return es.SendEmail(email)
}

// SendPlatformInviteEmail sends an invitation email to a new platform admin user.
// The email is branded with the platform name and includes a one-time link the
// recipient uses to set their password.  resetLink must already include the token.
// ssoProviders lists the display names of enabled admin-login SSO providers
// (e.g. "Google", "Microsoft"); when non-empty the email also tells the invitee
// they can skip the password and sign in with their company account directly.
func (es *EmailService) SendPlatformInviteEmail(to, platformName, inviterName, resetLink string, ssoProviders []string) error {
	subject := fmt.Sprintf("You've been invited to %s", platformName)

	// ssoNames feeds both parts. The HTML half used to be assembled here as a
	// pre-escaped fragment and pasted in raw; the template owns that block now,
	// so the provider names are escaped in their own text context.
	ssoText := ""
	ssoNames := ""
	if len(ssoProviders) > 0 {
		ssoNames = strings.Join(ssoProviders, " or ")
		ssoText = fmt.Sprintf(`
Prefer single sign-on? You can skip setting a password: open the sign-in page and choose "Continue with %s" using this email address.
`, ssoNames)
	}

	textBody := fmt.Sprintf(`Hello,

%s has invited you to join %s as a platform administrator.

To accept your invitation and set your password, please click the link below:
%s

This invitation link will expire in 24 hours.
%s
If you were not expecting this invitation, you can safely ignore this email.

Best regards,
The %s Team
`, inviterName, platformName, resetLink, ssoText, platformName)

	htmlBody, err := renderHTML(platformInviteHTML, struct{ Platform, Inviter, Link, SSONames string }{platformName, inviterName, resetLink, ssoNames})
	if err != nil {
		return err
	}

	return es.SendEmail(Email{
		To:      []string{to},
		Subject: subject,
		Body:    textBody,
		HTML:    htmlBody,
	})
}

// SendPlatformPasswordResetEmail sends a password reset email to a platform admin user.
// The email is branded with the platform name.
func (es *EmailService) SendPlatformPasswordResetEmail(to, platformName, resetLink string) error {
	subject := fmt.Sprintf("Reset your %s password", platformName)

	textBody := fmt.Sprintf(`Hello,

A password reset was requested for your %s administrator account.

To reset your password, click the link below:
%s

This link will expire in 1 hour for security reasons.

If you did not request a password reset, please ignore this email. Your password will not be changed.

Best regards,
The %s Team
`, platformName, resetLink, platformName)

	htmlBody, err := renderHTML(platformPasswordResetHTML, struct{ Platform, Link string }{platformName, resetLink})
	if err != nil {
		return err
	}

	return es.SendEmail(Email{
		To:      []string{to},
		Subject: subject,
		Body:    textBody,
		HTML:    htmlBody,
	})
}

// SendTenantInviteEmail sends an invitation email to a prospective tenant
// member. orgName is the inviting tenant's display name ("your organization"
// when blank); acceptLink must already include the invitation token. The
// accept page offers exactly the sign-in methods the tenant allows, so the
// copy stays method-agnostic.
func (es *EmailService) SendTenantInviteEmail(to, orgName, acceptLink string) error {
	if orgName == "" {
		orgName = "your organization"
	}
	subject := fmt.Sprintf("You're invited to join %s on %s", orgName, es.brand())

	textBody := fmt.Sprintf(`Hello,

You've been invited to join %s on %s.

To accept your invitation and choose how you'd like to sign in, click the link below:
%s

This invitation link will expire in 7 days.

If you were not expecting this invitation, you can safely ignore this email.

Best regards,
The %s Team
`, orgName, es.brand(), acceptLink, es.brand())

	htmlBody, err := renderHTML(tenantInviteHTML, struct{ Brand, Org, Link string }{es.brand(), orgName, acceptLink})
	if err != nil {
		return err
	}

	return es.SendEmail(Email{
		To:      []string{to},
		Subject: subject,
		Body:    textBody,
		HTML:    htmlBody,
	})
}

// SendDiscoveryJobCompleteEmail sends a discovery job completion email
func (es *EmailService) SendDiscoveryJobCompleteEmail(to, jobID string, findingsCount int) error {
	subject := "Discovery Job Completed"

	// Text version
	textBody := fmt.Sprintf(`
Hello,

Your discovery job (ID: %s) has completed successfully.

The job found %d potential crypto implementations across your network.

You can view the detailed results and approve findings in your dashboard.

Best regards,
The %s Team
`, jobID, findingsCount, es.brand())

	// HTML version
	htmlBody, err := renderHTML(discoveryJobCompleteHTML, struct {
		JobID, Brand string
		Findings     int
	}{jobID, es.brand(), findingsCount})
	if err != nil {
		return err
	}

	email := Email{
		To:      []string{to},
		Subject: subject,
		Body:    textBody,
		HTML:    htmlBody,
	}

	return es.SendEmail(email)
}
