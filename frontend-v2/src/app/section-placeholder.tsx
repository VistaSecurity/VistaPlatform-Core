// Generic placeholder for a not-yet-built section/page. The IA, routing, and
// shell are real; each leaf renders this until its content is built from the
// design mock. `mockFile` points at the source screen in the mock zip.
export function SectionPlaceholder({ title, mockFile }: { title: string; mockFile?: string }) {
  return (
    <div style={{ padding: '20px 26px', height: '100%' }}>
      <div className="fade-up panel" style={{ padding: '30px 26px', display: 'flex', alignItems: 'center', gap: 18 }}>
        <span style={{ width: 46, height: 46, borderRadius: 12, flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'var(--app-panel2)', border: '1px solid var(--app-border)', color: 'var(--accent)' }}>◆</span>
        <div>
          <div style={{ fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 18, color: 'var(--app-t1)' }}>{title}</div>
          <div style={{ fontSize: 12.5, color: 'var(--app-t3)', marginTop: 4, lineHeight: 1.55, maxWidth: 560 }}>
            Routing and shell are wired. This screen is built from the design mock next.
            {mockFile && <> Source: <span className="mono">{mockFile}</span>.</>}
          </div>
        </div>
      </div>
    </div>
  );
}
