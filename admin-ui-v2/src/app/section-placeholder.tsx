// Generic placeholder for a not-yet-built section. The IA, routing, shell, and
// theme are real; each leaf renders this until its body is built from the design
// kit. `source` names the v1 admin-ui page it supersedes (the Migration Ledger
// row), so nothing is silently lost.
export function SectionPlaceholder({ title, source }: { title: string; source?: string }) {
  return (
    <div className="op-fade" style={{ padding: '20px 24px 40px' }}>
      <div className="op-panel" style={{ padding: '30px 26px', display: 'flex', alignItems: 'center', gap: 18 }}>
        <span style={{ width: 44, height: 44, borderRadius: 'var(--r-md)', flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--op-panel2)', border: '1px solid var(--op-border)', color: 'var(--op-accent-text)', fontFamily: 'var(--font-head)', fontWeight: 700 }}>◆</span>
        <div>
          <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 18, color: 'var(--op-t1)' }}>{title}</div>
          <div style={{ fontSize: 12.5, color: 'var(--op-t3)', marginTop: 4, lineHeight: 1.55, maxWidth: 580 }}>
            Routing, shell, and theme are wired. This screen is built from the design kit next.
            {source && <> Supersedes: <span className="mono">{source}</span>.</>}
          </div>
        </div>
      </div>
    </div>
  );
}
