package handlers

import passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"

var platformPasswordService = passwordsvc.NewPasswordService()

// SetPasswordService allows tests to override the default password service.
func SetPasswordService(ps *passwordsvc.PasswordService) {
	if ps != nil {
		platformPasswordService = ps
	}
}
