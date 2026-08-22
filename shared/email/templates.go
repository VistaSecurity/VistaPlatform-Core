package email

import (
	"bytes"
	"html/template"
)

// HTML email bodies.
//
// These were fmt.Sprintf format strings until the CodeQL go/email-injection
// alert was worked through properly. Every value interpolated below is at least
// partly attacker-influenced -- the white-label brand, the tenant organisation
// name, the inviter's name, a user-authored alert threshold name and the
// arbitrary keys and values of an alert's details map -- and Sprintf pastes all
// of them in raw.
//
// html/template is the fix rather than escaping at each call site, for a reason
// that matters here: escaping is CONTEXT-dependent and a helper applied by hand
// gets the context wrong. Two of these bodies put a link in href="...", where
// html.EscapeString is no defence at all -- it passes "javascript:..." through
// untouched, because nothing in it is an HTML metacharacter. html/template
// knows href is a URL context and filters the scheme; it knows <title> and
// <strong> are text contexts and entity-escapes; and it knows the difference
// without being told.
//
// Parsed once at init: template.Must panics at program start on a malformed
// template rather than at the moment someone needs a password-reset mail.
//
// The plain-text bodies are deliberately NOT templated. Escaping there would be
// actively wrong -- a text/plain part is not markup, and "&amp;" in a password
// reset mail is a defect, not a defence. They carry no structure to subvert,
// and the MIME delimiter that used to be forgeable through them is random per
// message now (see randomBoundary).

// detailRow is one entry of an alert's details map. The map is rendered through
// a range rather than a pre-formatted string so the key and the value are each
// escaped in their own right.
type detailRow struct {
	Key   string
	Value string
}

func mustTemplate(name, body string) *template.Template {
	return template.Must(template.New(name).Parse(body))
}

// renderHTML executes t and returns the result.
func renderHTML(t *template.Template, data any) (string, error) {
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

var passwordResetHTML = mustTemplate("passwordReset", `
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
            <p>You have requested to reset your password for your {{.Brand}} account.</p>
            <p>To reset your password, please click the button below:</p>
            <p><a href="{{.Link}}" class="button">Reset Password</a></p>
            <p>This link will expire in 1 hour for security reasons.</p>
            <p>If you did not request this password reset, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The {{.Brand}} Team</p>
        </div>
    </div>
</body>
</html>
`)

var emailVerificationHTML = mustTemplate("emailVerification", `
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
            <h1>Welcome to {{.Brand}}</h1>
        </div>
        <div class="content">
            <p>Hello,</p>
            <p>Thank you for signing up for {{.Brand}}!</p>
            <p>To complete your registration, please verify your email address by clicking the button below:</p>
            <p><a href="{{.Link}}" class="button">Verify Email Address</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you did not create an account, please ignore this email.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The {{.Brand}} Team</p>
        </div>
    </div>
</body>
</html>
`)

var alertHTML = mustTemplate("alert", `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{{.Brand}} Alert</title>
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
            <h1>{{.Brand}} Alert</h1>
        </div>
        <div class="content">
            <p class="alert-type">{{.AlertType}}</p>
            <p><strong>Message:</strong> {{.Message}}</p>
            <div class="details">
                <h3>Details:</h3>
                <pre>{{range .Details}}{{.Key}}: {{.Value}}
{{end}}</pre>
            </div>
            <p>Please review this alert in your dashboard for more information.</p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The {{.Brand}} Team</p>
        </div>
    </div>
</body>
</html>
`)

var platformInviteHTML = mustTemplate("platformInvite", `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>You've been invited to {{.Platform}}</title>
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
        <div class="header"><h1>{{.Platform}}</h1></div>
        <div class="content">
            <p>Hello,</p>
            <p><strong>{{.Inviter}}</strong> has invited you to join <strong>{{.Platform}}</strong> as a platform administrator.</p>
            <p>Click the button below to accept your invitation and set your password:</p>
            <p><a href="{{.Link}}" class="button">Accept Invitation &amp; Set Password</a></p>
            <p style="font-size:13px;color:#6b7280;">This link expires in 24 hours. If the button above doesn't work, copy and paste this URL into your browser:<br><a href="{{.Link}}">{{.Link}}</a></p>
            {{if .SSONames}}<p>Prefer single sign-on? You can skip setting a password: open the sign-in page and choose <strong>&ldquo;Continue with {{.SSONames}}&rdquo;</strong> using this email address.</p>{{end}}
            <p>If you were not expecting this invitation, you can safely ignore this email.</p>
        </div>
        <div class="footer"><p>Best regards,<br>The {{.Platform}} Team</p></div>
    </div>
</body>
</html>`)

var platformPasswordResetHTML = mustTemplate("platformPasswordReset", `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Reset your {{.Platform}} password</title>
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
        <div class="header"><h1>{{.Platform}}</h1></div>
        <div class="content">
            <p>Hello,</p>
            <p>A password reset was requested for your <strong>{{.Platform}}</strong> administrator account.</p>
            <p>Click the button below to reset your password:</p>
            <p><a href="{{.Link}}" class="button">Reset Password</a></p>
            <p style="font-size:13px;color:#6b7280;">This link expires in 1 hour. If the button above doesn't work, copy and paste this URL into your browser:<br><a href="{{.Link}}">{{.Link}}</a></p>
            <p>If you did not request a password reset, you can safely ignore this email.</p>
        </div>
        <div class="footer"><p>Best regards,<br>The {{.Platform}} Team</p></div>
    </div>
</body>
</html>`)

var tenantInviteHTML = mustTemplate("tenantInvite", `<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>You're invited to {{.Brand}}</title>
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
        <div class="header"><h1>{{.Brand}}</h1></div>
        <div class="content">
            <p>Hello,</p>
            <p>You've been invited to join <strong>{{.Org}}</strong> on <strong>{{.Brand}}</strong>.</p>
            <p>Click the button below to accept your invitation and choose how you'd like to sign in:</p>
            <p><a href="{{.Link}}" class="button">Accept Invitation</a></p>
            <p style="font-size:13px;color:#6b7280;">This link expires in 7 days. If the button above doesn't work, copy and paste this URL into your browser:<br><a href="{{.Link}}">{{.Link}}</a></p>
            <p>If you were not expecting this invitation, you can safely ignore this email.</p>
        </div>
        <div class="footer"><p>Best regards,<br>The {{.Brand}} Team</p></div>
    </div>
</body>
</html>`)

var discoveryJobCompleteHTML = mustTemplate("discoveryJobComplete", `
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
                <h2>Job ID: {{.JobID}}</h2>
                <h3>Findings: {{.Findings}} potential crypto implementations</h3>
            </div>
            <p>You can view the detailed results and approve findings in your dashboard.</p>
            <p><a href="#" class="button">View Results</a></p>
        </div>
        <div class="footer">
            <p>Best regards,<br>The {{.Brand}} Team</p>
        </div>
    </div>
</body>
</html>
`)
