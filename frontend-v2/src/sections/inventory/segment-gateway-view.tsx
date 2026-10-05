// The markup the gateway surfaces share ( slice C): a gateway link and a
// coverage note. The decisions are in `segment-gateway.ts`; these only draw
// them, so the asset page, the map and Settings → Network Segments render a
// gateway and a sensor-less network identically.
import { Link } from 'react-router';
import {
  coverageNote, gatewayAddress, gatewayHref, gatewayName, reportedText,
  type SegmentCoverage, type SegmentGateway,
} from './segment-gateway';

const ELLIPSIS = { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } as const;

/**
 * A gateway as "name (address)", the name linking to its asset page.
 *
 * Long names and IPv6 addresses ellipsize inside whatever cell holds this; the
 * full text is one hover away in the title.
 */
export function GatewayLink({ gateway, size = 12 }: { gateway: SegmentGateway; size?: number }) {
  const name = gatewayName(gateway);
  const address = gatewayAddress(gateway);
  const showAddress = address !== '' && address !== name;
  const reported = reportedText(gateway.observed_at);
  return (
    <span data-testid="gateway-link" style={{ display: 'inline-flex', alignItems: 'baseline', gap: 5, minWidth: 0, maxWidth: '100%' }}>
      <Link
        to={gatewayHref(gateway)}
        title={`${name}${showAddress ? ` · ${address}` : ''} — open the gateway's asset page${reported ? `\n${reported}` : ''}`}
        style={{ ...ELLIPSIS, fontSize: size, color: 'var(--accent)', textDecoration: 'none', fontWeight: 600, minWidth: 0 }}
      >
        {name}
      </Link>
      {showAddress && (
        <span className="mono" title={address} style={{ ...ELLIPSIS, fontSize: size - 1, color: 'var(--app-t3)', minWidth: 0 }}>
          ({address})
        </span>
      )}
    </span>
  );
}

/**
 * A network's coverage note: the sensor that reaches it, "No sensor on this
 * network" in a warning tone (a fact about the network, not a failure), or a
 * dash with an explanation for a network type coverage does not apply to.
 */
export function CoverageText({ segmentType, coverage, size = 12 }: {
  segmentType: string; coverage: SegmentCoverage | null | undefined; size?: number;
}) {
  const note = coverageNote(segmentType, coverage);
  if (note.kind === 'not-applicable') {
    return (
      <span data-testid="coverage-note" data-coverage="not-applicable" title="Sensor coverage is worked out for CIDR networks only."
        style={{ fontSize: size, color: 'var(--app-t3)' }}>—</span>
    );
  }
  if (note.kind === 'none') {
    return (
      <span data-testid="coverage-note" data-coverage="none" title={note.title}
        style={{ ...ELLIPSIS, display: 'inline-block', maxWidth: '100%', fontSize: size, color: 'var(--warn)' }}>
        {note.text}
      </span>
    );
  }
  return (
    <span data-testid="coverage-note" data-coverage="sensor" title={note.text}
      style={{ ...ELLIPSIS, display: 'inline-block', maxWidth: '100%', fontSize: size, color: 'var(--app-t2)' }}>
      {note.text}
    </span>
  );
}
