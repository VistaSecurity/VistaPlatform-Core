// B-28: these three fetchers used to destructure only `data` and never throw,
// so a non-2xx (device-interrogation-service / sensor-manager / compliance-engine
// down, or a discovery.read permission gate on /agents) resolved as an empty
// fleet / undefined ticket stats instead of an error — the Discovery stage and
// the Overdue-tickets tile then read "0/0" with nothing on the page to say the
// number is actually "we don't know". Extracted from dashboard-page.tsx's
// useRollups() so the throw-on-failure behavior is unit-testable without
// mounting the page (this file has no JSX/DOM dependency).
import { clients } from '../../lib/clients';

export async function fetchDashboardSensors() {
  const { data, error } = await clients.sensors.GET('/sensors', {});
  if (error || !data) throw new Error('Failed to load sensors');
  return data.sensors ?? [];
}

// Discovery agents are a SECOND fleet, in device-interrogation-service's own
// table — the Discovery card counted only /sensors and so under-reported the
// fleet by every registered agent. Same source Command Center uses.
export async function fetchDashboardDeviceAgents() {
  const { data, error } = await clients.devices.GET('/agents', {});
  if (error || !data) throw new Error('Failed to load device agents');
  return data.agents ?? [];
}

export async function fetchDashboardTicketStats() {
  const { data, error } = await clients.compliance.GET('/tickets/stats', {});
  if (error || !data) throw new Error('Failed to load ticket stats');
  return data.stats;
}
