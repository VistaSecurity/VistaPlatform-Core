// Top-level React error boundary. A render error anywhere below this component
// is caught here instead of white-screening the whole SPA. Class component
// because error boundaries require the lifecycle hooks (getDerivedStateFromError
// / componentDidCatch) — there is no hooks equivalent. The fallback is built
// from the existing design tokens (panel / ui-btn / app-* colors) so it matches
// the rest of the app. In dev the error + stack are shown to speed debugging;
// in prod the user sees only a clean "Something went wrong" card.
import { Component, type ErrorInfo, type ReactNode } from 'react';
import { Icon } from '../components/ui';

interface Props {
  children: ReactNode;
  // When true, render the compact in-shell fallback (no full-viewport centering)
  // so a single crashing section doesn't take down the surrounding shell.
  section?: boolean;
}

interface State {
  error: Error | null;
  info: ErrorInfo | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, info: null };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    // Surface to the console so it lands in browser logs / error reporting.
    console.error('[ErrorBoundary] caught render error', error, info);
    this.setState({ info });
  }

  handleReload = () => {
    window.location.reload();
  };

  render() {
    const { error, info } = this.state;
    if (!error) return this.props.children;

    const isDev = import.meta.env.DEV;
    const { section } = this.props;

    const card = (
      <div className="panel fade-up" style={{ maxWidth: 560, width: '100%', padding: '30px 30px 26px' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
          <span
            style={{
              width: 40, height: 40, borderRadius: 11, flex: 'none', display: 'flex',
              alignItems: 'center', justifyContent: 'center',
              background: 'color-mix(in srgb, var(--danger) 13%, transparent)', color: 'var(--danger)',
            }}
          >
            <Icon name="alert-triangle" size={20} />
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="eyebrow-app" style={{ color: 'var(--danger)', marginBottom: 5 }}>Unexpected error</div>
            <h2 style={{ margin: 0, fontFamily: 'var(--font-head)', fontWeight: 700, fontSize: 18, letterSpacing: '-.01em', color: 'var(--app-t1)' }}>
              Something went wrong
            </h2>
            <p style={{ margin: '7px 0 0', fontSize: 13, lineHeight: 1.55, color: 'var(--app-t3)' }}>
              {section
                ? 'This section ran into a problem and couldn’t be displayed. The rest of the app is still available — try reloading.'
                : 'The application ran into an unexpected problem. Reloading usually clears it.'}
            </p>
          </div>
        </div>

        {isDev && (
          <pre
            className="mono"
            style={{
              marginTop: 18, padding: '12px 14px', borderRadius: 9, maxHeight: 260, overflow: 'auto',
              background: 'var(--app-panel2)', border: '1px solid var(--app-border2)',
              color: 'var(--app-t2)', fontSize: 11.5, lineHeight: 1.5, whiteSpace: 'pre-wrap', wordBreak: 'break-word',
            }}
          >
            {error.toString()}
            {info?.componentStack ? `\n${info.componentStack}` : error.stack ? `\n${error.stack}` : ''}
          </pre>
        )}

        <div style={{ display: 'flex', gap: 9, marginTop: 20 }}>
          <button className="ui-btn accent" onClick={this.handleReload}>
            <Icon name="recycle" size={15} />Reload
          </button>
        </div>
      </div>
    );

    if (section) {
      return <div style={{ padding: '20px 26px', height: '100%' }}>{card}</div>;
    }

    return (
      <div
        style={{
          minHeight: '100vh', width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center',
          padding: 24, background: 'var(--app-bg)',
        }}
      >
        {card}
      </div>
    );
  }
}
