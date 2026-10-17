// The asset page's Config Context tab (DCIM BUILD_PLAN row 5.3): the asset's
// rendered config -- the weight-ordered deep merge of every active config
// context that matches it -- and the list of contexts that contributed. Reading
// needs dcim.read. Five states: loading, error, "no context applies" (not
// "the asset has no config"), the rendered config, and the no-permission note.
import { Link } from 'react-router';
import type { Asset } from '@vistasecurity/api-contract';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { SectionLabel } from '../../../components/ui';
import { useAssetConfigContext } from './config-context-queries';
import { PanelEmpty, PanelError, PanelLoading } from './substrate-states';

export function ConfigContextTab({ asset }: { asset: Asset }) {
  return (
    <PermissionGate
      permission={TENANT_PERMISSIONS.dcim.read}
      fallback={<PanelEmpty icon="lock" title="You can't view the config context" message="The rendered config needs the DCIM read permission. Ask an organisation admin to grant it to your role." />}
    >
      <Body assetId={asset.id} />
    </PermissionGate>
  );
}

function Body({ assetId }: { assetId: string }) {
  const q = useAssetConfigContext(assetId);
  if (q.isLoading) return <PanelLoading label="Rendering the config context…" />;
  if (q.isError || !q.data) {
    return <PanelError message={q.error instanceof Error ? q.error.message : 'Request failed'} onRetry={() => { void q.refetch(); }} />;
  }
  const { data, contributing } = q.data;
  if (contributing.length === 0) {
    return (
      <PanelEmpty
        icon="braces" title="No config context applies to this asset"
        message="No active config context matches this asset's location, device type, role, platform, business unit or tags. Define one under Infrastructure → Device catalog."
      />
    );
  }
  return (
    <div data-testid="config-context-tab">
      <SectionLabel icon="braces">Rendered config</SectionLabel>
      <pre data-testid="config-context-json" className="mono" style={{ margin: 0, padding: 14, borderRadius: 10, border: '1px solid var(--app-border2)', background: 'var(--app-panel)', fontSize: 12.5, lineHeight: 1.55, overflow: 'auto', maxHeight: 460 }}>
        {JSON.stringify(data, null, 2)}
      </pre>
      <SectionLabel icon="layers">Contributed by</SectionLabel>
      <ol data-testid="config-context-contributors" style={{ margin: 0, paddingLeft: 20, fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.9 }}>
        {contributing.map((c) => (
          <li key={c.id}>
            <b style={{ color: 'var(--app-t1)' }}>{c.name}</b>
            <span style={{ color: 'var(--app-t3)' }}> · weight {c.weight}</span>
          </li>
        ))}
      </ol>
      <div style={{ fontSize: 12, color: 'var(--app-t3)', marginTop: 8 }}>
        Merged lightest first, so a heavier context wins a conflict. Lists are replaced, not joined.{' '}
        <Link to="/inventory/manage/config-contexts">Manage config contexts</Link>
      </div>
    </div>
  );
}
