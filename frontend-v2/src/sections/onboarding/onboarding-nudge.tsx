// Login nudge — once per session, if onboarding is still pending (show_banner)
// and this user can act on it, raise a clickable toast pointing at the Getting
// Started checklist. Recurs each login (sessionStorage key resets on a fresh
// session) until onboarding is complete or dismissed. Mounted in the AppShell.
// Spec: docsv4/internal/developer/standards/features/onboarding-wizard.md
import { useEffect } from 'react';
import { useNavigate } from 'react-router';
import toast from 'react-hot-toast';
import { usePermissions } from '@vistasecurity/primitives/rbac';
import { useOnboardingStatus } from './queries';
import { ONBOARDING_PERMISSIONS } from './step-meta';

const SESSION_KEY = 'onboarding_nudged';

export function OnboardingNudge() {
  const navigate = useNavigate();
  const { hasAnyPermission, isLoading } = usePermissions();
  const { data: status } = useOnboardingStatus();

  useEffect(() => {
    if (isLoading || !status) return;
    if (!status.show_banner) return; // complete / dismissed / org-disabled
    if (!hasAnyPermission(ONBOARDING_PERMISSIONS)) return; // read-only viewers aren't nagged
    if (sessionStorage.getItem(SESSION_KEY) === '1') return; // once per session
    sessionStorage.setItem(SESSION_KEY, '1');

    toast(
      (t) => (
        <span
          onClick={() => {
            toast.dismiss(t.id);
            navigate('/getting-started');
          }}
          style={{ cursor: 'pointer', fontSize: 13 }}
        >
          Finish setting up your workspace to get the most out of the platform — <strong>open the setup guide</strong>.
        </span>
      ),
      { duration: 9000, icon: '👋', id: 'onboarding-nudge' },
    );
  }, [isLoading, status, hasAnyPermission, navigate]);

  return null;
}
