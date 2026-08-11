package auth

import (
	"database/sql"
	"testing"
)

// Signup is the ONLY way into a deployment — there is no admin tenant-create,
// that lives in the MSP management plane. So the work-email blocklist was the
// single front door, and it rejected consumer domains unconditionally. On a
// self-hosted Core install that meant an operator evaluating the product with a
// personal address could not create an account on their own hardware, and was
// told to "use your work email address".
//
// The rule is now opt-in via platform_settings.block_personal_email_domains and
// defaults OFF. These tests pin the default, because a regression here is
// invisible until someone tries to sign up.

// A nil DB stands in for "no settings available at all", which must behave as
// permissive rather than locking everyone out.
func TestWorkEmailPolicyDefaultsToAllowingPersonalDomains(t *testing.T) {
	var noDB *sql.DB

	for _, email := range []string{
		"someone@gmail.com",
		"someone@outlook.com",
		"someone@protonmail.com",
		"someone@icloud.com",
	} {
		if err := EnforceWorkEmailPolicy(noDB, email); err != nil {
			t.Errorf("EnforceWorkEmailPolicy(%q) = %v; want nil — the blocklist must be "+
				"opt-in, or a self-hosted operator cannot sign up at all", email, err)
		}
	}
}

// Work addresses were never affected and must stay unaffected.
func TestWorkEmailPolicyAllowsCorporateDomains(t *testing.T) {
	var noDB *sql.DB

	for _, email := range []string{
		"bob@vistasecurity.io",
		"someone@example.com",
	} {
		if err := EnforceWorkEmailPolicy(noDB, email); err != nil {
			t.Errorf("EnforceWorkEmailPolicy(%q) = %v; want nil", email, err)
		}
	}
}

// The predicate itself is unchanged and still rejects consumer domains — that is
// what an operator opts INTO. If this ever starts passing for gmail, the setting
// would be a no-op when switched on, which is the failure mode that would make
// the hosted offering silently unfiltered.
func TestValidateWorkEmailStillRejectsPersonalDomains(t *testing.T) {
	if err := ValidateWorkEmail("someone@gmail.com"); err == nil {
		t.Error("ValidateWorkEmail(gmail.com) = nil; want an error — enabling the " +
			"setting would then filter nothing")
	}
	if err := ValidateWorkEmail("bob@vistasecurity.io"); err != nil {
		t.Errorf("ValidateWorkEmail(work domain) = %v; want nil", err)
	}
}
