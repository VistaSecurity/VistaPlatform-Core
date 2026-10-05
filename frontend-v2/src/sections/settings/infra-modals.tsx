// Create / edit / delete modals for Settings → Locations and Network Segments.
// Wired to the now-contracted inventory-service write endpoints:
// POST/PUT/DELETE /locations and /network-segments. Per-type value validation
// for segments mirrors the old web-ui (CIDR / IP-range / domain / cloud VPC).
import { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import type { inventoryComponents } from '@vistasecurity/api-contract';
import { clients } from '../../lib/clients';
import { Modal, ModalField, ModalInput, ModalSelect } from '../../components/ui';
import { dhcpBody, initialDhcpChoice, segmentPosture, segmentProvenance, type DhcpChoice } from './segment-provenance';

type Location = inventoryComponents['schemas']['Location'];
type NetworkSegment = inventoryComponents['schemas']['NetworkSegment'];
type LocationInput = inventoryComponents['schemas']['LocationInput'];
type NetworkSegmentInput = inventoryComponents['schemas']['NetworkSegmentInput'];

const LOCATION_TYPES = ['region', 'country', 'datacenter', 'cloud_region', 'office', 'site', 'colo', 'building', 'floor', 'rack'];
const PHYSICAL_TYPES = new Set(['datacenter', 'office', 'site', 'colo', 'building', 'floor', 'rack']);
// cloud_vpc is intentionally NOT user-creatable: cloud_vpc segments are
// created automatically during cloud discovery (FindOrCreateCloudSegment) and
// are not matched by the query-time GetSegmentForIP path, so a hand-authored
// one is inert. The type remains valid in the schema/back end and is still
// rendered by the SEGMENT_TYPE_LABEL map so auto-discovered VPC segments show.
const SEGMENT_TYPES = [
  { value: 'cidr', label: 'CIDR', placeholder: '10.0.0.0/24' },
  { value: 'ip_range', label: 'IP range', placeholder: '10.0.0.1 - 10.0.0.254' },
  { value: 'domain', label: 'Domain', placeholder: '*.example.com' },
];
const NETWORK_TYPES = ['private', 'public', 'vpn', 'cloud'];
const ENVIRONMENTS = ['production', 'staging', 'development', 'test'];

const IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;
function validateSegmentValue(type: string, value: string): boolean {
  const v = value.trim();
  if (!v) return false;
  switch (type) {
    case 'cidr': return /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(v);
    case 'ip_range': {
      const parts = v.split('-');
      return parts.length === 2 && IPV4.test(parts[0].trim()) && IPV4.test(parts[1].trim());
    }
    case 'domain': return /^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(v);
    case 'cloud_vpc': return true; // free-form (provider VPC/VNet id)
    default: return true;
  }
}

function useLocationsList(enabled: boolean) {
  return useQuery({
    queryKey: ['settings', 'locations'],
    enabled,
    queryFn: async () => {
      const { data, error } = await clients.inventory.GET('/locations', {});
      if (error || !data) throw new Error('Failed to load locations');
      return data.locations ?? [];
    },
  });
}

// ---- Location create / edit ----------------------------------------------
export function LocationModal({ open, location, onClose }: { open: boolean; location: Location | null; onClose: () => void }) {
  const qc = useQueryClient();
  const isEdit = !!location;
  const locsQ = useLocationsList(open);

  const [name, setName] = useState('');
  const [type, setType] = useState('datacenter');
  const [parentId, setParentId] = useState('');
  const [description, setDescription] = useState('');
  const [address, setAddress] = useState('');
  const [city, setCity] = useState('');
  const [stateProvince, setStateProvince] = useState('');
  const [country, setCountry] = useState('');
  const [timezone, setTimezone] = useState('');
  const [cloudProvider, setCloudProvider] = useState('');
  const [cloudRegion, setCloudRegion] = useState('');

  useEffect(() => {
    setName(location?.name ?? '');
    setType(location?.location_type ?? 'datacenter');
    setParentId(location?.parent_id ?? '');
    setDescription(location?.description ?? '');
    setAddress(location?.address ?? '');
    setCity(location?.city ?? '');
    setStateProvince(location?.state_province ?? '');
    setCountry(location?.country ?? '');
    setTimezone(location?.timezone ?? '');
    setCloudProvider(location?.cloud_provider ?? '');
    setCloudRegion(location?.cloud_region ?? '');
  }, [location, open]);

  const isCloud = type === 'cloud_region';
  const isPhysical = PHYSICAL_TYPES.has(type);
  const valid = name.trim().length > 0 && !!type;

  const save = useMutation({
    mutationFn: async () => {
      const body: LocationInput = {
        name: name.trim(),
        location_type: type,
        parent_id: parentId || undefined,
        description: description.trim() || undefined,
        timezone: timezone.trim() || undefined,
        address: isPhysical ? address.trim() || undefined : undefined,
        city: isPhysical ? city.trim() || undefined : undefined,
        state_province: isPhysical ? stateProvince.trim() || undefined : undefined,
        country: isPhysical ? country.trim() || undefined : undefined,
        cloud_provider: isCloud ? cloudProvider.trim() || undefined : undefined,
        cloud_region: isCloud ? cloudRegion.trim() || undefined : undefined,
      };
      const res = isEdit
        ? await clients.inventory.PUT('/locations/{id}', { params: { path: { id: location.id } }, body })
        : await clients.inventory.POST('/locations', { body });
      if (!res.response.ok || res.error) throw new Error('Failed to save location');
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['settings', 'locations'] }); onClose(); },
  });

  // Parent options exclude self (a location can't be its own parent).
  const parentOptions = (locsQ.data ?? []).filter((l) => l.id !== location?.id);

  return (
    <Modal
      open={open} onClose={save.isPending ? undefined : onClose} dismissible={!save.isPending}
      size="md" tone="accent" icon="map-pin" eyebrow="Settings · Locations"
      title={isEdit ? `Edit ${location.name}` : 'New location'}
      description="Locations form the physical / cloud hierarchy that Inventory and Discovery organize assets by."
      primary={<button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create location'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={save.isError ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : undefined}
    >
      <div style={{ display: 'flex', gap: 14 }}>
        <div style={{ flex: 1.4 }}><ModalField label="Name"><ModalInput data-autofocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. US-East DC1" /></ModalField></div>
        <div style={{ flex: 1 }}>
          <ModalField label="Type">
            <ModalSelect value={type} onChange={(e) => setType(e.target.value)}>
              {LOCATION_TYPES.map((t) => <option key={t} value={t}>{t.replace('_', ' ')}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
      </div>
      <ModalField label="Parent location" hint="Optional — nest under another location.">
        <ModalSelect value={parentId} onChange={(e) => setParentId(e.target.value)} disabled={locsQ.isLoading}>
          <option value="">None (top level)</option>
          {parentOptions.map((l) => <option key={l.id} value={l.id}>{l.full_path || l.name}</option>)}
        </ModalSelect>
      </ModalField>
      <ModalField label="Description"><ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" /></ModalField>

      {isCloud && (
        <div style={{ display: 'flex', gap: 14 }}>
          <div style={{ flex: 1 }}><ModalField label="Cloud provider"><ModalInput value={cloudProvider} onChange={(e) => setCloudProvider(e.target.value)} placeholder="aws / azure / gcp" /></ModalField></div>
          <div style={{ flex: 1 }}><ModalField label="Cloud region"><ModalInput value={cloudRegion} onChange={(e) => setCloudRegion(e.target.value)} placeholder="us-east-1" /></ModalField></div>
        </div>
      )}
      {isPhysical && (
        <>
          <ModalField label="Address"><ModalInput value={address} onChange={(e) => setAddress(e.target.value)} placeholder="Optional" /></ModalField>
          <div style={{ display: 'flex', gap: 14 }}>
            <div style={{ flex: 1 }}><ModalField label="City"><ModalInput value={city} onChange={(e) => setCity(e.target.value)} /></ModalField></div>
            <div style={{ flex: 1 }}><ModalField label="State / province"><ModalInput value={stateProvince} onChange={(e) => setStateProvince(e.target.value)} /></ModalField></div>
            <div style={{ flex: 1 }}><ModalField label="Country"><ModalInput value={country} onChange={(e) => setCountry(e.target.value)} /></ModalField></div>
          </div>
        </>
      )}
      <ModalField label="Timezone" hint="IANA name, e.g. America/New_York."><ModalInput value={timezone} onChange={(e) => setTimezone(e.target.value)} placeholder="Optional" /></ModalField>
    </Modal>
  );
}

// ---- Network segment create / edit ---------------------------------------
export function NetworkSegmentModal({ open, segment, onClose }: { open: boolean; segment: NetworkSegment | null; onClose: () => void }) {
  const qc = useQueryClient();
  const isEdit = !!segment;
  const locsQ = useLocationsList(open);

  const [name, setName] = useState('');
  const [segType, setSegType] = useState('cidr');
  const [value, setValue] = useState('');
  const [networkType, setNetworkType] = useState('private');
  const [environment, setEnvironment] = useState('production');
  const [locationId, setLocationId] = useState('');
  const [businessUnit, setBusinessUnit] = useState('');
  const [ownerEmail, setOwnerEmail] = useState('');
  const [description, setDescription] = useState('');
  const [isActive, setIsActive] = useState(true);
  const [autoApprove, setAutoApprove] = useState(false);
  // Which discovery sources auto-approval covers. Sensor-only is the stored
  // default for every segment that predates the setting, so cloud coverage is
  // always something the tenant ticks on purpose.
  const [approveSensor, setApproveSensor] = useState(true);
  const [approveCloud, setApproveCloud] = useState(false);
  // The operator's DHCP answer: on, off, or automatic (what devices and network
  // traffic report). `initialDhcp` is where the dialog opened, so an untouched
  // control sends nothing and cannot rewrite a posture by accident.
  const [dhcp, setDhcp] = useState<DhcpChoice>('auto');
  const initialDhcp = initialDhcpChoice(segment);

  useEffect(() => {
    setName(segment?.name ?? '');
    setSegType(segment?.segment_type ?? 'cidr');
    setValue(segment?.value ?? '');
    setNetworkType(segment?.network_type ?? 'private');
    setEnvironment(segment?.environment ?? 'production');
    setLocationId(segment?.location_id ?? '');
    setBusinessUnit(segment?.business_unit ?? '');
    setOwnerEmail(segment?.owner_email ?? '');
    setDescription(segment?.description ?? '');
    setIsActive(segment?.is_active ?? true);
    setAutoApprove(segment?.auto_approve_discoveries ?? false);
    const sources = segment?.auto_approve_sources ?? ['sensor'];
    setApproveSensor(sources.includes('sensor'));
    setApproveCloud(sources.includes('cloud'));
    setDhcp(initialDhcpChoice(segment));
  }, [segment, open]);

  // A cloud VPC segment can only ever be matched by cloud discoveries — no IP
  // ever falls inside "cloud://aws/us-east-1". Default a NEW one to cloud, so
  // turning auto-approve on there does not quietly cover nothing. Existing
  // segments keep whatever is stored.
  const pickSegType = (next: string) => {
    setSegType(next);
    if (isEdit) return;
    const cloudish = next === 'cloud_vpc';
    setApproveSensor(!cloudish);
    setApproveCloud(cloudish);
  };

  const valueValid = validateSegmentValue(segType, value);
  const sourcesValid = !autoApprove || approveSensor || approveCloud;
  const valid = name.trim().length > 0 && valueValid && !!networkType && !!environment && sourcesValid;
  const placeholder = SEGMENT_TYPES.find((t) => t.value === segType)?.placeholder;
  // Identity places an address by CIDR or range; a domain or cloud-VPC segment
  // cannot hold a lease, so the control is not offered there.
  const hasLeases = segType === 'cidr' || segType === 'ip_range';

  const save = useMutation({
    mutationFn: async () => {
      const body: NetworkSegmentInput = {
        name: name.trim(),
        segment_type: segType,
        value: value.trim(),
        network_type: networkType,
        environment,
        location_id: locationId || undefined,
        business_unit: businessUnit.trim() || undefined,
        owner_email: ownerEmail.trim() || undefined,
        description: description.trim() || undefined,
        is_active: isActive,
        auto_approve_discoveries: autoApprove,
        auto_approve_sources: [
          ...(approveSensor ? ['sensor' as const] : []),
          ...(approveCloud ? ['cloud' as const] : []),
        ],
        // Only address-scoped segments hold a lease; sending it for a domain
        // segment would be a 400 the form gave no way to avoid.
        ...(hasLeases ? dhcpBody(initialDhcp, dhcp) : {}),
      };
      const res = isEdit
        ? await clients.inventory.PUT('/network-segments/{id}', { params: { path: { id: segment.id } }, body })
        : await clients.inventory.POST('/network-segments', { body });
      if (!res.response.ok || res.error) {
        // A 400 carries a message written for the person at this form — for
        // example a CIDR too broad to be anybody's network ( W5.13), which
        // they can only fix if they are told the rule. A 409 names the segment
        // already holding the value — and, for a range learned from a device,
        // points at "Claim as mine" instead.
        const msg = res.response.status === 400 || res.response.status === 409 ? (res.error as { error?: unknown } | undefined)?.error : undefined;
        throw new Error(typeof msg === 'string' && msg ? msg : 'Failed to save network segment');
      }
    },
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['settings', 'network-segments'] }); onClose(); },
  });

  // The server refuses a DHCP answer it cannot place with a message about that
  // field; show it where the person is looking, not in the footer.
  const dhcpError = save.isError && /^dhcp\b/i.test(save.error.message) ? save.error.message : null;
  const current = isEdit ? segmentPosture(segment) : null;

  const Toggle = ({ on, onChange }: { on: boolean; onChange: (v: boolean) => void }) => (
    <button onClick={() => onChange(!on)} aria-pressed={on} style={{ width: 38, height: 22, borderRadius: 40, border: 'none', cursor: 'pointer', padding: 0, background: on ? 'var(--accent-gradient)' : 'var(--app-track)', position: 'relative', flex: 'none' }}>
      <span style={{ position: 'absolute', top: 2, left: on ? 18 : 2, width: 18, height: 18, borderRadius: 50, background: '#fff', transition: 'left .18s' }} />
    </button>
  );

  return (
    <Modal
      open={open} onClose={save.isPending ? undefined : onClose} dismissible={!save.isPending}
      size="lg" tone="accent" icon="network" eyebrow="Settings · Network Segments"
      title={isEdit ? `Edit ${segment.name}` : 'New network segment'}
      description="Network boundaries Discovery scopes its scans against, by CIDR, IP range, domain, or cloud VPC."
      primary={<button className="ui-btn accent" disabled={!valid || save.isPending} onClick={() => save.mutate()}>{save.isPending ? 'Saving…' : isEdit ? 'Save changes' : 'Create segment'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={save.isPending}>Cancel</button>}
      footerNote={save.isError && !dhcpError ? <span style={{ color: 'var(--danger-text)' }}>{save.error.message}</span> : undefined}
    >
      <div style={{ display: 'flex', gap: 14 }}>
        <div style={{ flex: 1.4 }}><ModalField label="Name"><ModalInput data-autofocus value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Prod DMZ" /></ModalField></div>
        <div style={{ flex: 1 }}>
          <ModalField label="Type">
            <ModalSelect value={segType} onChange={(e) => pickSegType(e.target.value)}>
              {SEGMENT_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
      </div>
      <ModalField label="Value" hint={value && !valueValid ? undefined : `Expected format for ${SEGMENT_TYPES.find((t) => t.value === segType)?.label}: ${placeholder}`}>
        <ModalInput value={value} className="mono" onChange={(e) => setValue(e.target.value)} placeholder={placeholder} style={value && !valueValid ? { borderColor: 'var(--danger)' } : undefined} />
        {value && !valueValid && <div style={{ fontSize: 11, color: 'var(--danger-text)', marginTop: 5 }}>Not a valid {SEGMENT_TYPES.find((t) => t.value === segType)?.label} value.</div>}
      </ModalField>
      <div style={{ display: 'flex', gap: 14 }}>
        <div style={{ flex: 1 }}>
          <ModalField label="Network type">
            <ModalSelect value={networkType} onChange={(e) => setNetworkType(e.target.value)}>
              {NETWORK_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
        <div style={{ flex: 1 }}>
          <ModalField label="Environment">
            <ModalSelect value={environment} onChange={(e) => setEnvironment(e.target.value)}>
              {ENVIRONMENTS.map((e) => <option key={e} value={e}>{e}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
        <div style={{ flex: 1 }}>
          <ModalField label="Location" hint="Optional.">
            <ModalSelect value={locationId} onChange={(e) => setLocationId(e.target.value)} disabled={locsQ.isLoading}>
              <option value="">None</option>
              {(locsQ.data ?? []).map((l) => <option key={l.id} value={l.id}>{l.full_path || l.name}</option>)}
            </ModalSelect>
          </ModalField>
        </div>
      </div>
      <div style={{ display: 'flex', gap: 14 }}>
        <div style={{ flex: 1 }}><ModalField label="Business unit"><ModalInput value={businessUnit} onChange={(e) => setBusinessUnit(e.target.value)} placeholder="Optional" /></ModalField></div>
        <div style={{ flex: 1 }}><ModalField label="Owner email"><ModalInput type="email" value={ownerEmail} onChange={(e) => setOwnerEmail(e.target.value)} placeholder="Optional" /></ModalField></div>
      </div>
      <ModalField label="Description"><ModalInput value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional" /></ModalField>
      <div style={{ display: 'flex', gap: 28, marginTop: 4 }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
          <Toggle on={isActive} onChange={setIsActive} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>Active</span>
        </label>
        <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
          <Toggle on={autoApprove} onChange={setAutoApprove} />
          <span style={{ fontSize: 12.5, color: 'var(--app-t1)' }}>Auto-approve discoveries</span>
        </label>
      </div>
      {hasLeases && (
        <fieldset
          disabled={save.isPending}
          aria-describedby="segment-dhcp-help"
          style={{ margin: '14px 0 0', padding: '10px 12px', border: '1px solid var(--app-border)', borderRadius: 8 }}
        >
          <legend style={{ fontSize: 12.5, color: 'var(--app-t1)', padding: '0 6px' }}>This network hands out addresses (DHCP)</legend>
          <div id="segment-dhcp-help" style={{ fontSize: 11.5, color: 'var(--app-t2)', marginBottom: 8 }}>
            On a DHCP network an address does not identify a device — it belongs to whoever holds
            the lease today — so Vista Platform stops letting an address decide which device
            something is. {current ? <>Currently: {current.text}.</> : null}
          </div>
          <div style={{ display: 'flex', gap: 22, flexWrap: 'wrap' }}>
            {([
              ['auto', 'Automatic', 'use what devices and network traffic report'],
              ['on', 'Yes', 'it hands out addresses'],
              ['off', 'No', 'addresses are fixed'],
            ] as const).map(([value, label, hint]) => (
              <label key={value} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: save.isPending ? 'default' : 'pointer', fontSize: 12.5, color: 'var(--app-t1)' }}>
                <input type="radio" name="segment-dhcp" value={value} checked={dhcp === value} onChange={() => setDhcp(value)} />
                <span>{label}<span style={{ color: 'var(--app-t3)' }}> — {hint}</span></span>
              </label>
            ))}
          </div>
          {dhcpError && <div role="alert" style={{ fontSize: 11, color: 'var(--danger-text)', marginTop: 8 }}>{dhcpError}</div>}
        </fieldset>
      )}
      {autoApprove && (
        <div style={{ marginTop: 10, padding: '10px 12px', border: '1px solid var(--app-border)', borderRadius: 8 }}>
          <div style={{ fontSize: 11.5, color: 'var(--app-t2)', marginBottom: 8 }}>
            Auto-approve which discoveries on this segment? Assets from a checked source skip
            Discovery → Approvals and go straight to monitoring.
          </div>
          <div style={{ display: 'flex', gap: 24 }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 12.5, color: 'var(--app-t1)' }}>
              <input type="checkbox" checked={approveSensor} onChange={(e) => setApproveSensor(e.target.checked)} />
              Sensor discoveries
            </label>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 12.5, color: 'var(--app-t1)' }}>
              <input type="checkbox" checked={approveCloud} onChange={(e) => setApproveCloud(e.target.checked)} />
              Cloud discoveries
            </label>
          </div>
          {segType === 'cloud_vpc' && !approveCloud && (
            <div style={{ fontSize: 11, color: 'var(--app-t3)', marginTop: 8 }}>
              A cloud VPC segment is only ever matched by cloud discoveries — with “Cloud
              discoveries” unchecked, this segment auto-approves nothing.
            </div>
          )}
          {!sourcesValid && (
            <div style={{ fontSize: 11, color: 'var(--danger-text)', marginTop: 8 }}>
              Pick at least one source, or turn auto-approve off.
            </div>
          )}
        </div>
      )}
    </Modal>
  );
}

// ---- Delete confirm (locations or segments) -------------------------------
export function DeleteInfraModal({ open, kind, id, name, onClose }: {
  open: boolean; kind: 'location' | 'segment'; id: string; name: string; onClose: () => void;
}) {
  const qc = useQueryClient();
  const del = useMutation({
    mutationFn: async () => {
      const res = kind === 'location'
        ? await clients.inventory.DELETE('/locations/{id}', { params: { path: { id } } })
        : await clients.inventory.DELETE('/network-segments/{id}', { params: { path: { id } } });
      if (!res.response.ok || res.error) throw new Error('Delete failed');
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['settings', kind === 'location' ? 'locations' : 'network-segments'] });
      onClose();
    },
  });

  return (
    <Modal
      open={open} onClose={del.isPending ? undefined : onClose} dismissible={!del.isPending}
      size="sm" tone="danger" icon="octagon-alert" eyebrow="Settings"
      title={`Delete ${kind === 'location' ? 'location' : 'network segment'}?`}
      description={`“${name}” will be removed.${kind === 'location' ? ' Child locations and assigned assets may be affected.' : ''}`}
      primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }} disabled={del.isPending} onClick={() => del.mutate()}>{del.isPending ? 'Deleting…' : 'Delete'}</button>}
      secondary={<button className="ui-btn" onClick={onClose} disabled={del.isPending}>Cancel</button>}
      footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{del.error.message}</span> : undefined}
    />
  );
}

// ---- Claim a learned public range ----------------------------------
//
// One click with a confirmation that says, in plain words, what the person is
// stating and what it lets the platform do. There is no proof-of-control step
// behind it — the claim is the person's own word, recorded in the audit log —
// so the dialog has to carry the warning about ranges they do not control.
export function ClaimSegmentModal({ open, segment, mode, onClose }: {
  open: boolean; segment: NetworkSegment; mode: 'claim' | 'revoke'; onClose: () => void;
}) {
  const qc = useQueryClient();
  const learned = segmentProvenance(segment.metadata);
  const from = learned ? learned.label.replace(/^Learned from /, '').replace(/^Learned by interrogation$/, 'a device') : 'a device';
  const act = useMutation({
    mutationFn: async () => {
      const params = { params: { path: { id: segment.id } } };
      const res = mode === 'claim'
        ? await clients.inventory.POST('/network-segments/{id}/claim', params)
        : await clients.inventory.DELETE('/network-segments/{id}/claim', params);
      if (!res.response.ok || res.error) {
        const msg = (res.error as { error?: string } | undefined)?.error;
        throw new Error(msg ?? (mode === 'claim' ? 'The claim could not be saved.' : 'The claim could not be revoked.'));
      }
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ['settings', 'network-segments'] });
      onClose();
    },
  });

  const claim = mode === 'claim';
  return (
    <Modal
      open={open} onClose={act.isPending ? undefined : onClose} dismissible={!act.isPending}
      size="md" tone={claim ? 'accent' : 'danger'} icon={claim ? 'shield-check' : 'shield-off'} eyebrow="Network Segments"
      title={claim ? `Claim ${segment.value} as yours?` : `Revoke your claim on ${segment.value}?`}
      description={claim
        ? `Vista Platform learned this public range from ${from}. A device's settings cannot show whether a public range is yours or your internet provider's, so it is not treated as yours until someone says so.`
        : 'Vista Platform will go back to treating this range as one it learned, not one you own.'}
      primary={
        <button className={claim ? 'ui-btn accent' : 'ui-btn'} style={claim ? undefined : { background: 'var(--danger)', color: '#fff', borderColor: 'var(--danger)' }}
          disabled={act.isPending} onClick={() => act.mutate()}>
          {act.isPending ? (claim ? 'Claiming…' : 'Revoking…') : (claim ? 'Claim as mine' : 'Revoke claim')}
        </button>
      }
      secondary={<button className="ui-btn" onClick={onClose} disabled={act.isPending}>Cancel</button>}
      footerNote={act.isError ? <span role="alert" style={{ color: 'var(--danger-text)' }}>{act.error.message}</span> : undefined}
    >
      {claim ? (
        <ul data-testid="claim-consequences" style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 6, fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.5 }}>
          <li>You are stating that this range belongs to your organization.</li>
          <li>Vista Platform will then be able to scan it when someone in your organization asks. It is never scanned automatically.</li>
          <li>Sensors will treat it as yours, and may check the services they see your systems use on it.</li>
          <li><strong>Do not claim a range you don&apos;t control</strong> — your internet provider&apos;s link, for example. Scanning it would be scanning someone else&apos;s network.</li>
          <li>Vista Platform does not verify the claim. It is recorded in the audit log under your name, and you can revoke it at any time.</li>
        </ul>
      ) : (
        <ul style={{ margin: 0, paddingLeft: 18, display: 'grid', gap: 6, fontSize: 12.5, color: 'var(--app-t2)', lineHeight: 1.5 }}>
          <li>Scans of addresses in this range will need the same confirmation as any other external address.</li>
          <li>Sensors will stop treating it as yours.</li>
          <li>The range stays in your segment list, and you can claim it again later.</li>
        </ul>
      )}
    </Modal>
  );
}
