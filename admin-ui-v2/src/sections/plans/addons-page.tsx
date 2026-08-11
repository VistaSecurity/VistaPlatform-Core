// Add-ons — placeholder until Slice 6 of (gated on the pricing call's
// decision to keep flat add-on packs). Add-ons are flat à-la-carte lever bundles.
import { PackagePlus } from 'lucide-react';

export function AddonsPage() {
  return (
    <div className="op-fade" style={{ padding: 40, display: 'flex', justifyContent: 'center' }}>
      <div style={{ maxWidth: 560, textAlign: 'center', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, paddingTop: 40 }}>
        <PackagePlus size={28} style={{ color: 'var(--op-t3)' }} />
        <div style={{ fontFamily: 'var(--font-head)', fontSize: 18, fontWeight: 700, color: 'var(--op-t1)' }}>Add-ons — coming in Slice 6</div>
        <div style={{ fontSize: 13, color: 'var(--op-t3)', lineHeight: 1.6 }}>
          Flat à-la-carte lever packs (e.g. <em>+5,000 assets</em>, <em>+5 sensors</em>, an OT
          module) a customer buys on top of their tier — no metering required. Pending the
          pricing call's decision on whether add-ons are in the model. Tracked in epic #828.
        </div>
      </div>
    </div>
  );
}
