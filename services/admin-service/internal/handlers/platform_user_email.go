package handlers

// Email + branding seams for the two IO-coupled platform-user handlers
// (InvitePlatformUser, AdminSendPasswordReset). These were deferred from the
// platform-users contract slice (see platform_user_repository.go scope note)
// because they reach SMTP and branding config, which the stub harness couldn't
// reach. This file introduces narrow interfaces over getEmailService /
// getPlatformBrandConfig so the handlers become stub-testable with no database
// and no SMTP. The DB-backed impls just delegate to the existing helpers, so
// production behaviour is unchanged.

import "database/sql"

// emailSender is the subset of *sharedemail.EmailService the invite/reset
// handlers call. The concrete email service satisfies it.
type emailSender interface {
	SendPlatformInviteEmail(to, platformName, inviterName, resetLink string, ssoProviders []string) error
	SendPlatformPasswordResetEmail(to, platformName, resetLink string) error
}

// emailProvider resolves a configured emailSender, mirroring getEmailService:
// it returns an error when email is not configured, which both handlers treat
// as a non-fatal "user created / token stored, email skipped" path that returns
// the link inline.
type emailProvider interface {
	EmailSender() (emailSender, error)
}

// brandingProvider supplies platform branding for email content + reset links,
// mirroring getPlatformBrandConfig.
type brandingProvider interface {
	BrandConfig() platformBrandConfig
}

// dbEmailProvider is the production emailProvider — it reads SMTP config from
// platform_settings via the existing getEmailService helper.
type dbEmailProvider struct{ db *sql.DB }

func (p dbEmailProvider) EmailSender() (emailSender, error) {
	svc, err := getEmailService(p.db)
	if err != nil {
		return nil, err
	}
	return svc, nil
}

// dbBrandingProvider is the production brandingProvider — it reads branding from
// platform_settings via the existing getPlatformBrandConfig helper.
type dbBrandingProvider struct{ db *sql.DB }

func (p dbBrandingProvider) BrandConfig() platformBrandConfig {
	return getPlatformBrandConfig(p.db)
}
