// A Business Unit picker: choose one, none, or create a new one by name. Used by
// the asset form and the bulk edit. A new name is sent as `business_unit` (the
// server resolves-or-creates it), a chosen unit as `business_unit_id`.
import { ModalInput, ModalSelect } from '../../components/ui';
import { flattenTree, useBusinessUnits } from './business-units-queries';

export interface BusinessUnitChoice { id: string; newName: string | null }
export const NO_BUSINESS_UNIT: BusinessUnitChoice = { id: '', newName: null };
const NEW = '__new__';

/** The asset-write fields for a choice. Unchanged/none sends the clear spelling only when `clear`. */
export function businessUnitFields(c: BusinessUnitChoice, clear: boolean): { business_unit_id?: string; business_unit?: string } {
  if (c.newName !== null) return c.newName.trim() ? { business_unit: c.newName.trim() } : {};
  if (c.id) return { business_unit_id: c.id };
  return clear ? { business_unit_id: '' } : {};
}

export function BusinessUnitSelect({ value, onChange, disabled, label = 'Business unit' }: {
  value: BusinessUnitChoice; onChange: (c: BusinessUnitChoice) => void; disabled?: boolean; label?: string;
}) {
  const q = useBusinessUnits();
  const rows = flattenTree(q.data ?? []);
  return (
    <>
      <ModalSelect
        aria-label={label}
        disabled={(disabled ?? false) || q.isLoading}
        value={value.newName !== null ? NEW : value.id}
        onChange={(e) => {
          const v = e.target.value;
          onChange(v === NEW ? { id: '', newName: '' } : { id: v, newName: null });
        }}
      >
        <option value="">{q.isLoading ? 'Loading…' : q.isError ? 'Could not load business units' : 'None'}</option>
        {rows.map(({ unit, depth }) => (
          <option key={unit.id} value={unit.id}>{`${'  '.repeat(depth)}${unit.name}`}</option>
        ))}
        <option value={NEW}>Create new…</option>
      </ModalSelect>
      {value.newName !== null && (
        <ModalInput
          aria-label={`New ${label.toLowerCase()} name`}
          style={{ marginTop: 6 }}
          value={value.newName}
          onChange={(e) => onChange({ id: '', newName: e.target.value })}
          placeholder="Name of the new business unit"
        />
      )}
    </>
  );
}
