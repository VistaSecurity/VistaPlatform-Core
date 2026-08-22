package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/smtp"
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

	msg := es.buildMessage(email)
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

// buildMessage builds the email message in RFC 2822 format
func (es *EmailService) buildMessage(email Email) []byte {
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
		// Multipart message with HTML and text
		boundary := "boundary123456789"
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

	return msg.Bytes()
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
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Password Reset Request</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px; }
        .button { display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Password Reset Request</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>You have requested to reset your password for your %s account.</p>
            <p>To reset your password, please click the button below:</p>
            <p><a href="%s" class="button">Reset Password</a></p>
            <p>This link will expire in 1 hour for security reasons.</p>
            <p>If you did not request this password reset, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The %s Team</p>
        </div>
    </div>
</body>
</html>
`, es.brand(), resetLink, es.brand())

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
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Verify Your Email Address</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #f8f9fa; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px; }
        .button { display: inline-block; background-color: #28a745; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Welcome to %s</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>Thank you for signing up for %s!</p>
            <p>To complete your registration, please verify your email address by clicking the button below:</p>
            <p><a href="%s" class="button">Verify Email Address</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you did not create an account, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The %s Team</p>
        </div>
    </div>
</body>
</html>
`, es.brand(), es.brand(), verificationLink, es.brand())

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

	// Build details text
	var detailsText strings.Builder
	for key, value := range details {
		fmt.Fprintf(&detailsText, "%s: %v\n", key, value)
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
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>%s Alert</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px; }
        .alert-type { font-size: 18px; font-weight: bold; color: #dc3545; }
        .details { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>%s Alert</h1>
        </div>
        <div class="content">
            <p class="alert-type">%s</p>
            <p><strong>Message:</strong> %s</p>
            <div class="details">
                <h3>Details:</h3>
                <pre>%s</pre>
            </div>
            <p>Please review this alert in your dashboard for more information.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The %s Team</p>
        </div>
    </div>
</body>
</html>
`, es.brand(), es.brand(), alertType, message, detailsText.String(), es.brand())

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

	ssoText := ""
	ssoHTML := ""
	if len(ssoProviders) > 0 {
		names := strings.Join(ssoProviders, " or ")
		ssoText = fmt.Sprintf(`
Prefer single sign-on? You can skip setting a password: open the sign-in page and choose "Continue with %s" using this email address.
`, names)
		ssoHTML = fmt.Sprintf(`<p>Prefer single sign-on? You can skip setting a password: open the sign-in page and choose <strong>&ldquo;Continue with %s&rdquo;</strong> using this email address.</p>`, names)
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

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>You've been invited to %s</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4f46e5; color: white; padding: 24px; text-align: center; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 22px; }
        .content { background: #fff; padding: 28px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background-color: #4f46e5; color: white !important; padding: 13px 28px; text-decoration: none; border-radius: 6px; margin: 20px 0; font-weight: 600; }
        .footer { margin-top: 24px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 13px; color: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h1>%s</h1></div>
        <div class="content">
            <p>Hello,</p>
            <p><strong>%s</strong> has invited you to join <strong>%s</strong> as a platform administrator.</p>
            <p>Click the button below to accept your invitation and set your password:</p>
            <p><a href="%s" class="button">Accept Invitation &amp; Set Password</a></p>
            <p style="font-size:13px;color:#6b7280;">This link expires in 24 hours. If the button above doesn't work, copy and paste this URL into your browser:<br><a href="%s">%s</a></p>
            %s
            <p>If you were not expecting this invitation, you can safely ignore this email.</p>
        </div>
        <div class="footer"><p>Best regards,<br>The %s Team</p></div>
    </div>
</body>
</html>`, platformName, platformName, inviterName, platformName, resetLink, resetLink, resetLink, ssoHTML, platformName)

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

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reset your %s password</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4f46e5; color: white; padding: 24px; text-align: center; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 22px; }
        .content { background: #fff; padding: 28px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background-color: #4f46e5; color: white !important; padding: 13px 28px; text-decoration: none; border-radius: 6px; margin: 20px 0; font-weight: 600; }
        .footer { margin-top: 24px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 13px; color: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h1>%s</h1></div>
        <div class="content">
            <p>Hello,</p>
            <p>A password reset was requested for your <strong>%s</strong> administrator account.</p>
            <p>Click the button below to reset your password:</p>
            <p><a href="%s" class="button">Reset Password</a></p>
            <p style="font-size:13px;color:#6b7280;">This link expires in 1 hour. If the button above doesn't work, copy and paste this URL into your browser:<br><a href="%s">%s</a></p>
            <p>If you did not request a password reset, you can safely ignore this email.</p>
        </div>
        <div class="footer"><p>Best regards,<br>The %s Team</p></div>
    </div>
</body>
</html>`, platformName, platformName, platformName, resetLink, resetLink, resetLink, platformName)

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

	htmlBody := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>You're invited to %s</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #4f46e5; color: white; padding: 24px; text-align: center; border-radius: 8px 8px 0 0; }
        .header h1 { margin: 0; font-size: 22px; }
        .content { background: #fff; padding: 28px; border: 1px solid #e5e7eb; border-top: none; border-radius: 0 0 8px 8px; }
        .button { display: inline-block; background-color: #4f46e5; color: white !important; padding: 13px 28px; text-decoration: none; border-radius: 6px; margin: 20px 0; font-weight: 600; }
        .footer { margin-top: 24px; padding-top: 16px; border-top: 1px solid #e5e7eb; font-size: 13px; color: #6b7280; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h1>%s</h1></div>
        <div class="content">
            <p>Hello,</p>
            <p>You've been invited to join <strong>%s</strong> on <strong>%s</strong>.</p>
            <p>Click the button below to accept your invitation and choose how you'd like to sign in:</p>
            <p><a href="%s" class="button">Accept Invitation</a></p>
            <p style="font-size:13px;color:#6b7280;">This link expires in 7 days. If the button above doesn't work, copy and paste this URL into your browser:<br><a href="%s">%s</a></p>
            <p>If you were not expecting this invitation, you can safely ignore this email.</p>
        </div>
        <div class="footer"><p>Best regards,<br>The %s Team</p></div>
    </div>
</body>
</html>`, es.brand(), es.brand(), orgName, es.brand(), acceptLink, acceptLink, acceptLink, es.brand())

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
	htmlBody := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Discovery Job Completed</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #28a745; color: white; padding: 20px; text-align: center; border-radius: 5px; }
        .content { padding: 20px; }
        .stats { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; text-align: center; }
        .button { display: inline-block; background-color: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; margin: 20px 0; }
        .footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; font-size: 14px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Discovery Job Completed</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>Your discovery job has completed successfully!</p>
            <div class="stats">
                <h2>Job ID: %s</h2>
                <h3>Findings: %d potential crypto implementations</h3>
            </div>
            <p>You can view the detailed results and approve findings in your dashboard.</p>
            <p><a href="#" class="button">View Results</a></p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The %s Team</p>
        </div>
    </div>
</body>
</html>
`, jobID, findingsCount, es.brand())

	email := Email{
		To:      []string{to},
		Subject: subject,
		Body:    textBody,
		HTML:    htmlBody,
	}

	return es.SendEmail(email)
}
